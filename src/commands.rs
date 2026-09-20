//! Admin/oper commands over the passwordless transport (commands.c,
//! irchub/docs/passwordless.md 4):
//!
//!   ~A2A <sig_b64> <ts>:<nonce>   auth request, Ed25519-signed
//!   ~A2K <b64(eph|iv|ct|tag)>     NOTICE reply: this bot's pubkey, sealed to
//!                                 the user's X25519 key
//!   ~A2  <b64(eph|iv|ct|tag)>     command, sealed to this bot's X25519 key
//!                                 with the user's static key mixed in
//!   ~A2S <b64(...)>               the same, asking for sealed replies
//!   ~A2R <b64(iv|ct|tag)>         a reply to a ~A2S command
//!
//! Every context string is LABEL "\0" lc(botnick) "\0" lc(user nick) ...,
//! so a frame is only valid for one bot and one sender nick.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::consts::*;
use crate::crypto::{self, Key32};
use crate::cstr::{atoi, display_width, eq_ic, now, pad_right, trunc, trunc_string, Tok};
use crate::state::{
    has_control_bytes, is_rfc_nick, is_valid_bot_nick, lww_next_ts, A2rCtx, BotState, ChanStatus, MaskRecord, TrustedBot,
    UserRecord, S_CONNECTED, S_DIE,
};
use crate::{auth, bot_comms, channel, config, dcc, hub_client, irc_client, ircf, logm, updater};

// ---- Reply helpers ---------------------------------------------------------------

/// Anti-flood pause between reply lines on IRC (a DCC chat is not paced).
fn reply_pace(state: &BotState, ms: u64) {
    if state.dcc_reply.is_none() {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Rows a list reply may print: capped on IRC, everything over DCC.
fn reply_row_cap(state: &BotState) -> usize {
    if state.dcc_reply.is_some() {
        usize::MAX
    } else {
        BOT_STATUS_MAX_LINES
    }
}

fn reply_rows_omitted(state: &mut BotState, nick: &str, omitted: usize, what: &str) {
    if omitted > 0 {
        ircf!(state, "PRIVMSG {} :| (+{} more {} not shown -- ask over 'dcc' for the full list)\r\n", nick, omitted, what);
    }
}

fn say(state: &mut BotState, nick: &str, text: &str) {
    ircf!(state, "PRIVMSG {} :{}\r\n", nick, text);
}

const RULE: &str = "+----------------------------------------------------------------------------";
const FOOT: &str = "`----------------------------------------------------------------------------";

fn gm_time(ts: i64, fmt: &str) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(t) => t.format(fmt).to_string(),
        None => "invalid".into(),
    }
}

fn last_seen_str(ts: i64) -> String {
    if ts == 0 {
        "never".into()
    } else {
        gm_time(ts, "%Y-%m-%d %H:%M:%S UTC")
    }
}

/// "0d 16h 31m 55s" since `since`.
fn fmt_elapsed(since: i64) -> String {
    let mut d = now() - since;
    if since <= 0 || d < 0 {
        d = 0;
    }
    format!("{}d {}h {}m {}s", d / 86400, (d % 86400) / 3600, (d % 3600) / 60, d % 60)
}

/// "3d4h", "16h31m", "45s": two units for the bot tree.
fn tree_fmt_uptime(secs: i64) -> String {
    if secs <= 0 {
        return "-".into();
    }
    let (d, h, m, s) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    if d != 0 {
        format!("{d}d{h}h")
    } else if h != 0 {
    format!("{h}h{m}m")
    } else if m != 0 {
    format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

// ---- The 'bots' table ----------------------------------------------------------------

const BOTS_NAME_COL_MIN: usize = 19;
const BOTS_NAME_COL_MAX: usize = 48;
const BOTS_VERSION_COL_MIN: usize = 12;
const BOTS_UPTIME_COL_MIN: usize = 13;
const BOTS_COL_GAP: usize = 2;

struct BotsRow {
    name: String,
    version: String,
    uptime: String,
    server: String,
}

/// A node is the last child at its level when no later row shares its depth
/// before a shallower one appears; 'd' rows are a flat tail.
fn tree_is_last(state: &BotState, i: usize) -> bool {
    let d = state.bot_tree[i].depth;
    for r in &state.bot_tree[i + 1..] {
        if r.kind == 'd' || r.depth < d {
            return true;
        }
        if r.depth == d {
            return false;
        }
    }
    true
}

fn tree_has_children(state: &BotState, i: usize) -> bool {
    match state.bot_tree.get(i + 1) {
        Some(r) if r.kind != 'd' => r.depth > state.bot_tree[i].depth,
        _ => false,
    }
}

/// Box-drawing prefix for one row; last_at[a] says whether the ancestor at
/// level a was the last of its siblings.
fn tree_prefix(depth: i32, last_at: &[bool], is_last: bool, has_kids: bool) -> String {
    if depth <= 0 {
        return String::new();
    }
    let mut out = String::new();
    for a in 1..depth as usize {
        out.push_str(if last_at.get(a).copied().unwrap_or(false) { "  " } else { "\u{2502} " });
    }
    out.push_str(if is_last { "\u{2514}" } else { "\u{251c}" });
    out.push('\u{2500}');
    out.push_str(if has_kids { "\u{252c}" } else { "\u{2500}" });
    out.push(' ');
    out
}

fn bots_tree_row(state: &BotState, i: usize, last_at: &mut [bool; 10]) -> BotsRow {
    let r = &state.bot_tree[i];
    let is_last = tree_is_last(state, i);
    if r.depth >= 0 && (r.depth as usize) < last_at.len() {
        last_at[r.depth as usize] = is_last;
    }
    let prefix = tree_prefix(r.depth, last_at, is_last, tree_has_children(state, i));
    let label = if r.kind == 'h' {
        format!("{}{}", if r.name.is_empty() { "(hub)" } else { r.name.as_str() }, if r.online { "" } else { " (unlinked)" })
    } else if r.name.is_empty() {
    "(unnamed)".to_string()
} else {
    r.name.clone()
};
let age = (now() - state.bot_tree_ts).max(0);
BotsRow {
    name: format!("{prefix}{}", trunc(&label, TREE_NAME_MAX + 32)),
        version: if r.version.is_empty() { "-".into() } else { r.version.clone() },
        uptime: tree_fmt_uptime(if r.kind == 'h' && !r.online { 0 } else { r.uptime + age }),
        server: if r.kind == 'h' {
            "(hub)".into()
        } else if r.server.is_empty() {
        "-".into()
    } else {
        r.server.clone()
    },
}
}

fn bots_self_row(state: &BotState) -> BotsRow {
BotsRow {
    name: if state.current_nick.is_empty() { "me".into() } else { state.current_nick.clone() },
    version: BOT_VERSION.into(),
    uptime: tree_fmt_uptime(now() - state.bot_start_time),
    server: if state.status & S_CONNECTED != 0 && !state.actual_server_name.is_empty() {
        trunc_string(&state.actual_server_name, TREE_SERVER_MAX + 1)
    } else {
        "-".into()
    },
}
}

fn bots_trusted_row(state: &BotState, i: usize) -> BotsRow {
let bnick = state.trusted_bots[i].nick();
let prefix = tree_prefix(1, &[], i + 1 == state.trusted_bots.len(), false);
BotsRow {
    name: format!("{}{}", prefix, if bnick.is_empty() { "(unnamed)" } else { bnick }),
    version: "-".into(),
    uptime: "-".into(),
    server: "-".into(),
}
}

fn bots_widen(c: &BotsRow, cols: &mut (usize, usize, usize)) {
cols.0 = cols.0.max((display_width(&c.name) + BOTS_COL_GAP).min(BOTS_NAME_COL_MAX));
cols.1 = cols.1.max(display_width(&c.version) + BOTS_COL_GAP);
cols.2 = cols.2.max(display_width(&c.uptime) + BOTS_COL_GAP);
}

/// Spaces taking a cell of width w out to col, never fewer than the gap.
fn bots_pad(col: usize, w: usize, cap: usize) -> String {
let n = if w + BOTS_COL_GAP <= col { col - w } else { BOTS_COL_GAP };
" ".repeat(n.min(cap - 1))
}

fn bots_emit(state: &mut BotState, nick: &str, c: &BotsRow, cols: (usize, usize, usize)) {
let p1 = bots_pad(cols.0, display_width(&c.name), BOTS_NAME_COL_MAX + 1);
let p2 = bots_pad(cols.1, display_width(&c.version), TREE_VERSION_MAX + 1 + BOTS_COL_GAP + 1);
let p3 = bots_pad(cols.2, display_width(&c.uptime), 32 + BOTS_COL_GAP + 1);
ircf!(state, "PRIVMSG {} :| {}{}{}{}{}{}{}\r\n", nick, c.name, p1, c.version, p2, c.uptime, p3, c.server);
}

// ---- CMD-log redaction -----------------------------------------------------------------

/// Commands whose arguments may be logged; bit i flags argument i+1 as a
/// secret.  A verb missing from the list is logged without its name or
/// arguments (a typo can put anything anywhere).
const LOGGABLE_CMDS: &[(&str, u32)] = &[
("+admin", 0), ("+oper", 0), ("chkey", 0), ("die", 0), ("jump", 0), ("join", 0), ("part", 0), ("op", 0),
("invite", 0), ("+bot", 0), ("-bot", 0), ("status", 0), ("givenick", 0), ("chnick", 0), ("saveconf", 0),
("setlog", 0), ("getlog", 0), ("admins", 0), ("opers", 0), ("match", 0), ("-admin", 0), ("-oper", 0),
("+usermask", 0), ("-usermask", 0), ("+server", 0), ("-server", 0), ("update", 0), ("+hub", 0), ("-hub", 0),
("rekey", 0), ("help", 0), ("dcc", 0), ("servers", 0), ("bots", 0),
];
const REDACT_MASK: &str = "********";

fn log_user_command(state: &BotState, tag: &str, who: usize, user_host: &str, command: &str, args: [Option<&str>; 3]) {
let mut line = String::new();
let cap = MAX_LOG_LINE_LEN - 1;
let mut append = |s: &str| {
    for ch in s.chars() {
        if line.len() + ch.len_utf8() > cap {
            break;
        }
            line.push(ch);
        }
    };
    append(state.user_records.get(who).map_or("?", |u| u.name.as_str()));
    append(" (");
    append(user_host);
    append(if state.dcc_reply.is_some() { " via DCC): " } else { "): " });
    match LOGGABLE_CMDS.iter().find(|(n, _)| eq_ic(command, n)) {
        None => append("unrecognized command (not logged)"),
        Some((name, secret)) => {
            append(name);
            for (i, a) in args.iter().enumerate() {
                let Some(a) = a else { break };
                append(" ");
                append(if secret & (1 << i) != 0 { REDACT_MASK } else { a });
            }
        }
    }
    logm!(state, L_CMD, "[{}] {}\n", tag, line);
}

// ---- The passwordless transport ------------------------------------------------------

/// ASCII-lowercase copy; None unless 0 < len < cap.
fn lc_copy(s: &str, cap: usize) -> Option<String> {
    (!s.is_empty() && s.len() < cap).then(|| s.to_ascii_lowercase())
}

/// label "\0" lc(botnick) "\0" lc(usernick) [ "\0" extra ], None when it
/// would not fit a buffer of `cap` bytes.
fn a2_context(cap: usize, label: &str, botnick: &str, usernick: &str, extra: Option<&str>) -> Option<Vec<u8>> {
    let b = lc_copy(botnick, A2_NICK_MAX)?;
    let u = lc_copy(usernick, A2_NICK_MAX)?;
    let mut out = Vec::new();
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend_from_slice(b.as_bytes());
    out.push(0);
    out.extend_from_slice(u.as_bytes());
    if let Some(e) = extra {
        out.push(0);
        out.extend_from_slice(e.as_bytes());
    }
    (!out.is_empty() && out.len() < cap).then_some(out)
}

/// ~A2A: verify the signed auth request and answer with the ~A2K lockbox.
/// Silent on the wire for every failure (no oracle for which masks exist).
fn a2_handle_auth(state: &mut BotState, nick: &str, user_host: &str, dest: &str, arg: &str) {
    // arg = "<sig_b64:88> <ts>:<nonce:16 hex>"
    if arg.find(' ') != Some(88) {
        logm!(state, L_CMD, "[CMD] ~A2A from {}: malformed\n", user_host);
        return;
    }
    let sig_b64 = &arg[..88];
    let tsn = &arg[89..];
    if tsn.len() >= 40 {
        logm!(state, L_CMD, "[CMD] ~A2A from {}: malformed\n", user_host);
        return;
    }
    // Validate "<ts>:<nonce>" with the envelope parser and a dummy command.
    let probe = format!("{tsn}:x");
    let Some((ts, nonce, _)) = bot_comms::envelope_parse(&probe).filter(|(_, _, d)| *d == "x") else {
        logm!(state, L_CMD, "[CMD] ~A2A from {}: bad ts/nonce\n", user_host);
        return;
    };
    let now = now();
    if (now - ts).abs() > A2_TS_SKEW {
        logm!(state, L_CMD, "[CMD] ~A2A from {}: timestamp skew {}s\n", user_host, now - ts);
        return;
    }
    let sig = crypto::b64_decode(sig_b64);
    let msg = a2_context(256, A2A_LABEL, dest, nick, Some(tsn));
    let (Some(sig), Some(msg)) = (sig.filter(|s| s.len() == 64), msg) else {
        logm!(state, L_CMD, "[CMD] ~A2A from {}: malformed\n", user_host);
        return;
    };

    let cands = auth::user_candidates(state, user_host);
    let who = cands.iter().copied().find(|&(ui, _)| {
        crypto::pubkey_b64_decode(&state.user_records[ui].pubkey_b64)
            .is_some_and(|p| crypto::ed25519_verify(&crypto::pub_halves(&p).0, &msg, &sig))
    });
    let Some((who, who_mask)) = who else {
        logm!(
            state,
            L_CMD,
            "[CMD] ~A2A from {}: no matching key verified ({} candidate{})\n",
            user_host,
            cands.len(),
            if cands.len() == 1 { "" } else { "s" }
        );
        return;
    };
    if state.admin_nonces.seen(nonce, now) {
        logm!(state, L_CMD, "[CMD] ~A2A replay from {}\n", user_host);
        return;
    }
    state.admin_nonces.record(nonce, now);
    let name = state.user_records[who].name.clone();
    if now - state.user_records[who].last_auth_reply < A2_AUTH_REPLY_MIN_INTERVAL
        || now - state.last_auth_reply_any < A2_AUTH_REPLY_GLOBAL_INTERVAL
    {
        logm!(state, L_CMD, "[CMD] ~A2A from {} ({}): throttled\n", name, user_host);
        return;
    }
    if !state.self_pub_set {
        logm!(state, L_CMD, "[CMD] ~A2A: this bot has no identity key\n");
        return;
    }
    // Lockbox: our public key, sealed anonymously to the user's X25519 key
    // and bound to this request's ts:nonce.
    let frame = a2_context(256, A2K_LABEL, dest, nick, Some(tsn)).and_then(|aad| {
        let upub = crypto::pubkey_b64_decode(&state.user_records[who].pubkey_b64)?;
        crypto::seal(None, &crypto::pub_halves(&upub).1, A2K_LABEL, &aad, &state.self_pub)
    });
    let Some(frame) = frame else {
        logm!(state, L_CMD, "[CMD] ~A2A: sealing the lockbox failed\n");
        return;
    };
    state.user_records[who].last_auth_reply = now;
    state.last_auth_reply_any = now;
    auth::mark_used(state, Some(who), Some(who_mask), now);
    ircf!(state, "NOTICE {} :~A2K {}\r\n", nick, crypto::b64_encode(&frame));
    logm!(state, L_CMD, "[CMD] ~A2A: {} ({}) authenticated; key sent\n", name, user_host);
}

/// An opened sealed command: who sent it, the command text, and (for ~A2S)
/// the reply key.
struct Opened {
    who: usize,
    cmd: Zeroizing<String>,
    rk: Option<Key32>,
}

/// ~A2 / ~A2S: try the key of every record whose usermask matches the
/// sender; the one whose tag verifies is the sender.  `only_uuid` (a DCC
/// chat's owner) limits that to one record.  None: logged, silent on wire.
fn a2_open_command(
    state: &mut BotState,
    nick: &str,
    user_host: &str,
    dest: &str,
    only_uuid: Option<&str>,
    b64: &str,
    sealed_replies: bool,
) -> Option<Opened> {
    let (tag, label) = if sealed_replies { ("~A2S", A2S_LABEL) } else { ("~A2", A2_LABEL) };
    if b64.len() > A2_B64_MAX {
        logm!(state, L_CMD, "[CMD] {} from {}: oversized\n", tag, user_host);
        return None;
    }
    let aad = a2_context(160, label, dest, nick, None);
    let frame = crypto::b64_decode(b64);
    let (Some(aad), Some(frame)) = (aad, frame.filter(|f| f.len() >= SEAL_OVERHEAD)) else {
        logm!(state, L_CMD, "[CMD] {} from {}: malformed\n", tag, user_host);
        return None;
    };
    if !state.self_pub_set {
        logm!(state, L_CMD, "[CMD] {} from {}: malformed\n", tag, user_host);
        return None;
    }

    let cands = auth::user_candidates(state, user_host);
    let mut opened = None;
    if !cands.is_empty()
        && let Some((_ed, x)) = hub_client::bot_key_decode(state) {
        let (_, self_x) = crypto::pub_halves(&state.self_pub);
        for &(ui, mi) in &cands {
            let u = &state.user_records[ui];
            if only_uuid.is_some_and(|o| o != u.uuid) {
                continue;
            }
            let Some(upub) = crypto::pubkey_b64_decode(&u.pubkey_b64) else { continue };
            let (_, ux) = crypto::pub_halves(&upub);
            if let Some(r) = crypto::open_rk(
                &x,
                &self_x,
                Some(&ux),
                label,
                &aad,
                &frame,
                sealed_replies.then_some(A2R_LABEL),
            ) {
                opened = Some((ui, mi, r));
                break;
            }
        }
    }
    let Some((who, who_mask, (pt, rk))) = opened else {
        logm!(
            state,
            L_CMD,
            "[CMD] {} from {}: did not open for any matching key ({} candidate{})\n",
            tag,
            user_host,
            cands.len(),
            if cands.len() == 1 { "" } else { "s" }
        );
        return None;
    };
    // Reject, don't repair: a CR/LF in an argument would split into a
    // second IRC command.
    if has_control_bytes(&pt) {
        logm!(state, L_CMD, "[CMD] {} from {}: control character in command; dropped\n", tag, user_host);
        return None;
    }
    let text = Zeroizing::new(String::from_utf8_lossy(&pt).into_owned());
    drop(pt);
    let Some((ts, nonce, cmd)) = bot_comms::envelope_parse(&text) else {
        logm!(state, L_CMD, "[CMD] {} from {}: bad envelope\n", tag, user_host);
        return None;
    };
    let now = now();
    if (now - ts).abs() > A2_TS_SKEW {
        logm!(state, L_CMD, "[CMD] {} from {}: timestamp skew {}s\n", tag, user_host, now - ts);
        return None;
    }
    if state.admin_nonces.seen(nonce, now) {
        logm!(state, L_CMD, "[CMD] {} replay from {}\n", tag, user_host);
        return None;
    }
    state.admin_nonces.record(nonce, now);
    auth::mark_used(state, Some(who), Some(who_mask), now);
    let u = &state.user_records[who];
    logm!(state, L_DEBUG, "[CMD_DEBUG] {} verified: User='{}' Type={}\n", tag, u.name, u.typ);
    Some(Opened { who, cmd: Zeroizing::new(cmd.to_string()), rk })
}

/// Split, screen and dispatch one opened command line.
fn run_user_command(state: &mut BotState, nick: &str, user_host: &str, who: usize, cmd_line: &str) {
    let mut t = Tok::new(cmd_line);
    let command = t.next(" ");
    let args = [t.next(" "), t.next(" "), t.next(" ")];
    let typ = state.user_records[who].typ;
    let Some(command) = command.filter(|_| typ == 'a' || typ == 'o') else {
        logm!(state, L_CMD, "[CMD_DEBUG] Auth failed for {}.\n", user_host);
        return;
    };
    let is_admin = typ == 'a';
    // Every stored value lands in a '|'-delimited record, where a '|' would
    // shift the fields after it.
    if std::iter::once(Some(command)).chain(args).flatten().any(|s| s.contains('|')) {
        let name = state.user_records[who].name.clone();
        logm!(state, L_CMD, "[CMD] '|' in command from {} ({}); dropped\n", name, user_host);
        say(state, nick, "Error: '|' is not allowed in commands.");
        return;
    }
    log_user_command(state, if is_admin { "CMD_ADMIN" } else { "CMD_OP" }, who, user_host, command, args);
    let a = Args { a1: args[0], a2: args[1], a3: args[2] };
    if is_admin {
        admin_command(state, nick, user_host, who, command, a);
    } else {
        oper_command(state, nick, who, command, a);
    }
}

/// Run an opened command; for ~A2S its replies to `nick` are sealed under
/// `rk` while it runs, and the reply state is wiped afterwards either way.
fn a2_dispatch(state: &mut BotState, nick: &str, user_host: &str, botnick: &str, who: usize, cmd_line: &str, rk: Option<Key32>) {
    if let Some(rk) = rk {
        let aad = a2_context(A2_NICK_MAX * 2 + 16, A2R_LABEL, botnick, nick, None);
        let Some(aad) = aad.filter(|_| nick.len() < A2_NICK_MAX) else {
            logm!(state, L_CMD, "[CMD] ~A2S from {}: no reply context; dropped\n", user_host);
            state.a2r = A2rCtx::default();
            return;
        };
        state.a2r = A2rCtx { active: true, key: rk, aad, nick: nick.to_string(), seq: 0 };
    }
    run_user_command(state, nick, user_host, who, cmd_line);
    state.a2r = A2rCtx::default();
}

pub fn handle_private_message(state: &mut BotState, nick: &str, user: &str, host: &str, dest: &str, message: &str) {
    if !eq_ic(dest, &state.current_nick) {
        return;
    }
    let user_host = trunc_string(&format!("{nick}!{user}@{host}"), 256);
    logm!(state, L_MSG, "[MSG] ({}): {}\n", user_host, message);

    // Trusted-bot commands (~B2).
    if bot_comms::handle_privmsg(state, nick, &user_host, message) {
        return;
    }
    // Admin/oper: ~A2A auth, ~A2 / ~A2S commands.  Anything else --
    // including the retired ~A1 / ~A1c password frames -- is dropped.
    if let Some(arg) = message.strip_prefix("~A2A ") {
        a2_handle_auth(state, nick, &user_host, dest, arg);
        return;
    }
    let sealed = message.starts_with("~A2S ");
    let opened = if sealed || message.starts_with("~A2 ") {
        let b64 = &message[if sealed { 5 } else { 4 }..];
        a2_open_command(state, nick, &user_host, dest, None, b64, sealed)
    } else {
        if message.starts_with("~A1") {
            logm!(
                state,
                L_CMD,
                "[CMD] Retired password frame (~A1/~A1c) from {}; the client script needs updating to the key-based ~A2\n",
                user_host
            );
        }
        None
    };
    // Nothing past this point may run for an unauthenticated sender.
    match opened {
        Some(o) => a2_dispatch(state, nick, &user_host, dest, o.who, &o.cmd, o.rk),
        None => logm!(state, L_CMD, "[CMD_DEBUG] Auth failed for {}.\n", user_host),
    }
}

/// One line from open DCC chat `i`: only a sealed frame from the admin who
/// opened the chat runs; false means the chat must be closed.
pub fn handle_dcc_line(state: &mut BotState, i: usize, line: &str) -> bool {
    let (name, uh, nick, botnick, uuid) = {
        let s = &state.dcc[i];
        (s.name.clone(), s.user_host.clone(), s.nick.clone(), s.botnick.clone(), s.uuid.clone())
    };
    let sealed = line.starts_with("~A2S ");
    if !sealed && !line.starts_with("~A2 ") {
        logm!(state, L_CMD, "[CMD] DCC line from {} ({}) is not a sealed command\n", name, uh);
        return false;
    }
    // Same checks as PRIVMSG, with the chat's owner as the only key and the
    // chat's nicks as the context.  A record demoted since ends the chat.
    let b64 = &line[if sealed { 5 } else { 4 }..];
    let opened = a2_open_command(state, &nick, &uh, &botnick, Some(&uuid), b64, sealed);
    let Some(o) = opened.filter(|o| state.user_records[o.who].typ == 'a') else { return false };
    state.dcc[i].last_active = now();
    state.dcc_reply = Some(i);
    a2_dispatch(state, &nick, &uh, &botnick, o.who, &o.cmd, o.rk);
    if state.dcc_reply == Some(i) {
        state.dcc_reply = None;
    }
    true
}

// ---- Key helpers ------------------------------------------------------------------------

/// Fingerprint of a user's key for listings, or "(no key)".
fn user_key_fp(u: &UserRecord) -> String {
    match crypto::pubkey_b64_decode(&u.pubkey_b64).filter(|_| u.has_pubkey) {
        Some(p) => crypto::key_fingerprint(&p),
        None => "(no key)".into(),
    }
}

/// A user public-key argument: canonical 88-char key, held by no other
/// active user.  `me` is the record being re-keyed.
fn user_key_arg_ok(state: &mut BotState, nick: &str, key: Option<&str>, me: Option<usize>, cmdname: &str) -> bool {
    let Some(key) = key.filter(|k| crypto::pubkey_b64_decode(k).is_some()) else {
        ircf!(
            state,
            "PRIVMSG {} :Error: {} needs the user's public key — the 88-char contents of their <ts>_<name>.public.b64. Ask them for it; 'help {}' shows how they make one.\r\n",
            nick,
            cmdname,
            cmdname
        );
        return false;
    };
    let owner = state
        .user_records
        .iter()
        .enumerate()
        .find(|(i, o)| Some(*i) != me && o.is_active && o.has_pubkey && o.pubkey_b64 == key)
        .map(|(_, o)| o.name.clone());
    if let Some(owner) = owner {
        ircf!(state, "PRIVMSG {} :Error: that key already belongs to '{}'. Each user needs their own keypair.\r\n", nick, owner);
        return false;
    }
    true
}

fn set_user_key(state: &mut BotState, ui: usize, key: &str) {
    let u = &mut state.user_records[ui];
    u.pubkey_b64 = key.to_string();
    u.has_pubkey = true;
    u.timestamp = lww_next_ts(u.timestamp);
    u.last_auth_reply = 0;
    config::write_with_state_pass(state);
    hub_client::push_admin_delta(state);
}

fn help_keypair(state: &mut BotState, nick: &str) {
    const LINES: &[&str] = &[
        "<pubkey> is the user's 88-char public key. The user makes a keypair on their own machine, keeps the .private.b64 (chmod 600) for their IRC script, and sends you only the .public.b64 contents:",
        "  keygen <name>     (ircbot/utils/keygen or irchub/bin/keygen; writes <YYYYMMDDHHMMSS>_<name>.private.b64 and .public.b64)",
        "  or with openssl 1.1.1+:  umask 077; openssl genpkey -algorithm ED25519 -out ed.pem; openssl genpkey -algorithm X25519 -out x.pem",
        "  (openssl pkey -in ed.pem -outform DER | tail -c 32; openssl pkey -in x.pem -outform DER | tail -c 32) | openssl base64 -A > NAME.private.b64",
        "  (openssl pkey -in ed.pem -pubout -outform DER | tail -c 32; openssl pkey -in x.pem -pubout -outform DER | tail -c 32) | openssl base64 -A > NAME.public.b64",
        "  shred -u ed.pem x.pem    (or rm -f; the .pem files hold the private key)",
    ];
    for l in LINES {
        say(state, nick, l);
        reply_pace(state, 100);
    }
}

fn help_auth(state: &mut BotState, nick: &str) {
    const LINES: &[&str] = &[
        "Admins and opers sign in with their Curve25519 key; there are no passwords. Use a client script from ircbot/utils (irssi, hexchat, weechat, mIRC via bot-auth.exe, or the bot-auth CLI) pointed at your .private.b64.",
        "On the first command to a bot the script sends a signed ~A2A request; the bot answers with a ~A2K notice carrying its public key (the script shows its fingerprint). Commands then travel sealed as ~A2 frames; as ~A2S, the bot's replies are sealed too (~A2R) and the script shows them decrypted, marked with a lock.",
        "Compare that fingerprint once with this bot's 'status' or hub_admin's bot list. After a bot 'rekey', run /botforget <bot> so the script fetches the new key.",
    ];
    for l in LINES {
        say(state, nick, l);
        reply_pace(state, 100);
    }
}

// ---- Dispatch ------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Args<'a> {
    a1: Option<&'a str>,
    a2: Option<&'a str>,
    a3: Option<&'a str>,
}

/// Commands refused locally under opt 'h' (hub-only mutations).  +hub/-hub
/// are bot-local connection settings and stay allowed.
const HUB_ONLY_CMDS: &[&str] = &["+admin", "-admin", "+oper", "-oper", "+usermask", "-usermask", "+bot", "-bot", "join", "part", "chkey"];

fn chan_arg(arg: &str, amp_ok: bool) -> String {
    if arg.starts_with('#') || (amp_ok && arg.starts_with('&')) {
        trunc_string(arg, MAX_CHAN)
    } else {
        trunc_string(&format!("#{arg}"), MAX_CHAN)
    }
}

fn admin_command(state: &mut BotState, nick: &str, user_host: &str, who: usize, command: &str, a: Args<'_>) {
    if state.is_opt_set(OPT_HUB_ONLY_MUTATIONS)
        && let Some(c) = HUB_ONLY_CMDS.iter().find(|c| eq_ic(command, c)) {
        ircf!(
            state,
            "PRIVMSG {} :Error: '{}' is disabled — network is in hub-only-mutation mode (opt 'h'). Use hub_admin.\r\n",
            nick,
            c
        );
        return;
    }
    let cmd = command.to_ascii_lowercase();
    match cmd.as_str() {
        "die" => {
            ircf!(state, "QUIT :Sayonara.\r\n");
            state.status |= S_DIE;
        }
        "dcc" => {
            if state.dcc_reply.is_some() {
                say(state, nick, "You are already in a DCC chat with me.");
            } else {
                dcc::offer(state, nick, user_host, who);
            }
        }
        "jump" => cmd_jump(state, nick, a),
        "join" => cmd_join(state, nick, a),
        "part" => {
            let Some(arg1) = a.a1 else {
                say(state, nick, "Syntax: part <#channel>");
                return;
            };
            let name = chan_arg(arg1, false);
            if let Some(ci) = channel::find(state, &name) {
                // Soft delete: tombstone rather than remove.
                let c = &mut state.chans[ci];
                c.is_managed = false;
                c.timestamp = lww_next_ts(c.timestamp);
                let ts = c.timestamp;
                logm!(state, L_DEBUG, "[PART-OP] Channel {}: soft delete ts={}\n", name, ts);
                ircf!(state, "PART {}\r\n", name);
                config::write_with_state_pass(state);
            }
        }
        "op" => match a.a1 {
            Some(ch) => {
                ircf!(state, "MODE {} +o {}\r\n", ch, nick);
            }
            None => say(state, nick, "Syntax: op <#channel>"),
        },
        "invite" => cmd_invite(state, nick, a),
        "+bot" => cmd_add_bot(state, nick, a),
        "-bot" => cmd_del_bot(state, nick, a),
        "status" => cmd_status(state, nick),
        "givenick" => {
            ircf!(state, "PRIVMSG {} :You have about {} seconds to retrieve.\r\n", nick, NICK_TAKE_TIME);
            irc_client::generate_new_nick(state);
            state.nick_release_time = now();
        }
        "chnick" => cmd_chnick(state, nick, a),
        "saveconf" => {
            config::write_with_state_pass(state);
            ircf!(state, "PRIVMSG {} :Configuration state saved to {}.\r\n", nick, CONFIG_FILE);
        }
        "setlog" => {
            let Some(arg1) = a.a1 else {
                say(state, nick, "Syntax: setlog <loglevel> :: LOGLEVELS: 0=NONE,15=INFO,63=DEBUG");
                return;
            };
            if arg1.bytes().all(|c| c.is_ascii_digit()) {
                let lvl = atoi(arg1);
                state.log.level = lvl as u32;
                ircf!(state, "PRIVMSG {} :Log level set to {}.\r\n", nick, lvl);
                config::write_with_state_pass(state);
            } else {
                say(state, nick, "Invalid log level. Please provide a valid integer.");
            }
        }
        "getlog" => cmd_getlog(state, nick, a),
        "admins" => cmd_list_users(state, nick, 'a'),
        "opers" => cmd_list_users(state, nick, 'o'),
        "match" => cmd_match(state, nick, a),
        "+admin" | "+oper" => cmd_add_user(state, nick, cmd == "+admin", a),
        "-admin" | "-oper" => cmd_del_user(state, nick, if cmd == "-admin" { 'a' } else { 'o' }, a),
        "+usermask" => cmd_add_usermask(state, nick, a),
        "-usermask" => cmd_del_usermask(state, nick, a),
        "bots" => cmd_bots(state, nick, a),
        "servers" => cmd_servers(state, nick),
        "+server" => {
            let Some(arg1) = a.a1 else {
                say(state, nick, "Syntax: +server <irc.server.net:6667>");
                return;
            };
            if state.server_list.len() < MAX_SERVERS {
                let slot = state.server_list.len();
                irc_client::server_block_clear(state, slot);
                state.server_list.push(arg1.to_string());
                config::write_with_state_pass(state);
                ircf!(state, "PRIVMSG {} :Added server '{}' and saved config.\r\n", nick, arg1);
            } else {
                say(state, nick, "Error: Server list is full.");
            }
        }
        "-server" => {
            let Some(arg1) = a.a1 else {
                say(state, nick, "Syntax: -server <server>");
                return;
            };
            match state.server_list.iter().position(|s| eq_ic(s, arg1)) {
                Some(i) => {
                    irc_client::server_block_remove(state, i);
                    state.server_list.remove(i);
                    config::write_with_state_pass(state);
                    ircf!(state, "PRIVMSG {} :Removed server '{}' and saved config.\r\n", nick, arg1);
                }
                None => {
                    ircf!(state, "PRIVMSG {} :Error: Server '{}' not found.\r\n", nick, arg1);
                }
            }
        }
        "update" => match a.a1 {
            Some(v) => updater::perform_upgrade(state, nick, v),
            None => updater::check_for_updates(state, nick),
        },
        "+hub" => cmd_add_hub(state, nick, a),
        "-hub" => cmd_del_hub(state, nick, a),
        "rekey" => cmd_rekey(state, nick),
        "chkey" => {
            let (Some(arg1), Some(arg2)) = (a.a1, a.a2) else {
                say(state, nick, "Syntax: chkey <name> <pubkey>");
                return;
            };
            let Some(ui) = state.user_records.iter().position(|u| u.is_active && eq_ic(&u.name, arg1)) else {
                ircf!(state, "PRIVMSG {} :Error: user '{}' not found.\r\n", nick, arg1);
                return;
            };
            if !user_key_arg_ok(state, nick, Some(arg2), Some(ui), "chkey") {
                return;
            }
            set_user_key(state, ui, arg2);
            let (name, fp) = (state.user_records[ui].name.clone(), user_key_fp(&state.user_records[ui]));
            ircf!(
                state,
                "PRIVMSG {} :Key for {} changed (key {}). They must use the new private key from now on.\r\n",
                nick,
                name,
                fp
            );
        }
        "help" => admin_help(state, nick, a.a1),
        _ => {}
    }
}

fn cmd_jump(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(arg1) = a.a1 else {
        ircf!(state, "QUIT :Jumping servers...\r\n");
        irc_client::disconnect(state);
        return;
    };
    // Match by hostname only; ports are ignored.
    let host_of = |s: &str| -> String {
        let s = trunc(s, 256);
        match s.rfind(':') {
            Some(i) => s[..i].to_string(),
            None => s.to_string(),
        }
    };
    let arg_host = host_of(arg1);
    let Some(idx) = state.server_list.iter().position(|s| eq_ic(&host_of(s), &arg_host)) else {
        ircf!(state, "PRIVMSG {} :Error: Server '{}' not in list.\r\n", nick, arg1);
        return;
    };
    // An explicit jump overrides any ban/throttle hold on the target.
    let held = irc_client::server_block_desc(state, idx);
    if !held.is_empty() {
        let srv = state.server_list[idx].clone();
        logm!(state, L_INFO, "[BAN] {}: hold ({}) cleared by jump.\n", srv, held);
    }
    irc_client::server_block_clear(state, idx);
    state.current_server_index = idx;
    ircf!(state, "QUIT :Jumping to {}...\r\n", arg1);
    irc_client::disconnect(state);
}

fn cmd_join(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(arg1) = a.a1 else {
        say(state, nick, "Syntax: join <#channel>");
        return;
    };
    let name = chan_arg(arg1, false);
    let found = channel::find(state, &name);
    if found.is_some_and(|ci| state.chans[ci].is_managed) {
        ircf!(state, "PRIVMSG {} :Error: Channel {} is already in my list.\r\n", nick, name);
        return;
    }
    // Past any stamp this channel had (a part in this same second).
    let prev_ts = found.map_or(0, |ci| state.chans[ci].timestamp);
    let ci = found.or_else(|| channel::add(state, &name));
    if let Some(ci) = ci {
        let c = &mut state.chans[ci];
        if let Some(k) = a.a2 {
            c.key = trunc_string(k, MAX_KEY);
        }
        c.is_managed = true;
        c.timestamp = lww_next_ts(prev_ts);
        let ts = c.timestamp;
        logm!(state, L_DEBUG, "[JOIN] Channel {}: re-enabled ts={}\n", name, ts);
    }
    config::write_with_state_pass(state);
    hub_client::push_config(state);
    ircf!(state, "PRIVMSG {} :JOIN {} and saving config file.\r\n", nick, arg1);
}

fn cmd_invite(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(arg1) = a.a1 else {
        say(state, nick, "Syntax: invite <#channel>");
        return;
    };
    let ch = chan_arg(arg1, true);
    if let Some(ci) = channel::find(state, &ch) {
        // i_am_opped, not our roster entry (not re-read while opped).
        if state.chans[ci].status == ChanStatus::In && state.chans[ci].i_am_opped {
            ircf!(state, "INVITE {} {}\r\n", nick, ch);
            ircf!(state, "PRIVMSG {} :Inviting you to {}\r\n", nick, ch);
            return;
        }
    }
    // Escalate: hub, else a sealed ~B2 to each trusted bot.
    if !hub_client::send_invite_request(state, nick, &ch) {
        let nicks: Vec<String> = state.trusted_bots.iter().map(|t| t.nick().to_string()).filter(|n| !n.is_empty()).collect();
        for tb in nicks {
            bot_comms::send_command(state, &tb, &format!("INVITE {ch} {nick}"));
        }
    }
}

fn cmd_add_bot(state: &mut BotState, nick: &str, a: Args<'_>) {
    if !state.hubs.is_empty() {
        say(
            state,
            nick,
            "Error: Bot management disabled when hub is configured. Bot additions/deletions must be performed on the hub.",
        );
        return;
    }
    // +bot <nick!user@host> <uuid> <pubkey>, all from the other bot's status.
    let (Some(mask), Some(uuid), Some(key)) = (a.a1, a.a2, a.a3) else {
        say(state, nick, "Syntax: +bot <nick!user@host> <uuid> <pubkey> - copy the UUID and Pubkey lines from that bot's 'status'.");
        return;
    };
    if mask.len() >= MAX_MASK_LEN || !mask.contains('!') || !mask.contains('@') {
        ircf!(state, "PRIVMSG {} :Error: mask must be nick!user@host (max {} chars).\r\n", nick, MAX_MASK_LEN - 1);
        return;
    }
    if !crate::cstr::has_uuid_dashes(uuid) {
        ircf!(state, "PRIVMSG {} :Error: '{}' is not a bot UUID.\r\n", nick, uuid);
        return;
    }
    let Some(pub_key) = crypto::pubkey_b64_decode(key) else {
        say(state, nick, "Error: pubkey must be the bot's 88-char public key (Pubkey line of its 'status').");
        return;
    };
    if uuid == state.bot_uuid {
        say(state, nick, "Error: that is this bot.");
        return;
    }
    if state.trusted_bots.iter().any(|t| eq_ic(&t.mask, mask) || t.uuid == uuid) {
        ircf!(
            state,
            "PRIVMSG {} :Error: Trusted bot '{}' already exists (same mask or UUID). Remove it with -bot first.\r\n",
            nick,
            mask
        );
        return;
    }
    if state.trusted_bots.len() >= MAX_TRUSTED_BOTS {
        say(state, nick, "Error: trusted bot list is full.");
        return;
    }
    state.trusted_bots.push(TrustedBot { mask: mask.to_string(), uuid: uuid.to_string(), pub_key, has_pub: true, ts: now() });
    config::write_with_state_pass(state);
    ircf!(state, "PRIVMSG {} :Added trusted bot: {} (key {})\r\n", nick, mask, crypto::key_fingerprint(&pub_key));
}

fn cmd_del_bot(state: &mut BotState, nick: &str, a: Args<'_>) {
    if !state.hubs.is_empty() {
        say(
            state,
            nick,
            "Error: Bot management disabled when hub is configured. Bot additions/deletions must be performed on the hub.",
        );
        return;
    }
    let Some(mask) = a.a1 else {
        say(state, nick, "Syntax: -bot <nick*!*user@hostmask.com>");
        return;
    };
    match state.trusted_bots.iter().position(|t| eq_ic(&t.mask, mask)) {
        Some(i) => {
            state.trusted_bots.remove(i);
            config::write_with_state_pass(state);
            ircf!(state, "PRIVMSG {} :Removed trusted bot: {}\r\n", nick, mask);
        }
        None => {
            ircf!(state, "PRIVMSG {} :Error: no trusted bot with mask '{}' (see 'status').\r\n", nick, mask);
        }
    }
}

/// Join entries with ", " into a line of at most cap-1 bytes, adding each
/// separator and entry only while it fits (the C fixed-buffer rules).
fn join_bounded(entries: &[String], cap: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for e in entries {
        let e = e.as_bytes();
        if !buf.is_empty() && buf.len() + 2 + e.len() < cap - 1 {
            buf.extend_from_slice(b", ");
        }
        if buf.len() + e.len() < cap - 1 {
            buf.extend_from_slice(e);
        }
    }
    buf
}

/// Comma-list of trusted-bot nicks wrapped at `cw` columns.
fn emit_bot_names(state: &mut BotState, nick: &str) {
    const TRUST_MAX: usize = 100;
    const PFX1: &str = "| Bots   : ";
    const PFX2: &str = "|          ";
    const CW: usize = 66;
    let names: Vec<String> = state.trusted_bots.iter().take(TRUST_MAX).map(|t| t.nick().to_string()).collect();
    let mut line = String::new();
    let mut first = true;
    for n in names {
        let need = if line.is_empty() { n.len() } else { n.len() + 2 };
        if !line.is_empty() && line.len() + need > CW {
            ircf!(state, "PRIVMSG {} :{}{}\r\n", nick, if first { PFX1 } else { PFX2 }, line);
            first = false;
            line.clear();
        }
        if !line.is_empty() {
            line.push_str(", ");
        }
        line.push_str(&n);
    }
    if !line.is_empty() {
        ircf!(state, "PRIVMSG {} :{}{}\r\n", nick, if first { PFX1 } else { PFX2 }, line);
    }
    if state.trusted_bots.len() > TRUST_MAX {
        ircf!(state, "PRIVMSG {} :|          ...and {} more\r\n", nick, state.trusted_bots.len() - TRUST_MAX);
    }
}

fn cmd_status(state: &mut BotState, nick: &str) {
    let uptime = if state.bot_start_time > 0 { fmt_elapsed(state.bot_start_time) } else { "N/A".into() };
    // Network: the name the server reported, with the configured port.
    let prev = state.current_server_index.checked_sub(1).and_then(|i| state.server_list.get(i)).cloned();
    let srv = if !state.actual_server_name.is_empty() {
        let port = prev.as_deref().and_then(|s| s.rfind(':').map(|c| atoi(&s[c + 1..]))).unwrap_or(0);
        if port > 0 {
            format!("{}:{}", state.actual_server_name, port)
        } else {
            state.actual_server_name.clone()
        }
    } else if let Some(p) = prev {
    p
} else {
    "N/A".into()
};
let srv = trunc_string(&srv, 300);
let conn = if state.status & S_CONNECTED != 0 {
    if state.connection_time > 0 {
        format!("CONNECTED {}", fmt_elapsed(state.connection_time))
    } else {
            "CONNECTED".into()
        }
    } else {
        "DISCONNECTED".into()
    };
    let admins = state.user_records.iter().filter(|u| u.is_active && u.typ == 'a').count();
    let opers = state.user_records.iter().filter(|u| u.is_active && u.typ == 'o').count();
    let tls = state.irc.as_ref().is_some_and(|c| c.is_tls());

    ircf!(state, "PRIVMSG {} :| ircbot {} status\r\n", nick, BOT_VERSION);
    ircf!(state, "PRIVMSG {} :{}\r\n", nick, RULE);
    ircf!(
        state,
        "PRIVMSG {} :| Identity : {} (Target: {}) | UUID: {}\r\n",
        nick,
        state.current_nick,
        state.target_nick,
        if state.bot_uuid.is_empty() { "none" } else { state.bot_uuid.as_str() }
    );
    if state.self_pub_set {
        let (pb, fp) = (crypto::b64_encode(&state.self_pub), crypto::key_fingerprint(&state.self_pub));
        ircf!(state, "PRIVMSG {} :| Pubkey   : {} (fp {})\r\n", nick, pb, fp);
    } else {
        say(state, nick, "| Pubkey   : NONE (re-run -setup)");
    }
    ircf!(state, "PRIVMSG {} :| Uptime   : {}\r\n", nick, uptime);
    ircf!(state, "PRIVMSG {} :| Network  : {} ({}, TLS: {})\r\n", nick, srv, conn, if tls { "YES" } else { "NO" });
    reply_pace(state, 80);

    if state.server_list.len() > 1 {
        say(state, nick, "+-[ Servers ]---------------------------------------------------------------");
        let entries: Vec<String> = (0..state.server_list.len())
            .map(|i| {
                let is_cur = state.current_server_index > 0
        && i == state.current_server_index - 1
        && state.status & S_CONNECTED != 0;
                let held = irc_client::server_block_desc(state, i);
                let e = format!(
                    "{}{}{}{}{}",
                    if is_cur { "*" } else { " " },
                    state.server_list[i],
                    if held.is_empty() { "" } else { " (" },
                    held,
                    if held.is_empty() { "" } else { ")" }
                );
                trunc_string(&e, 200)
            })
            .collect();
        let line = join_bounded(&entries, 600);
        ircf!(state, "PRIVMSG {} :| {}\r\n", nick, String::from_utf8_lossy(&line));
        reply_pace(state, 80);
    }

    say(state, nick, "+-[ Channels ]---------------------------------------------------------------");
    let mut ins = Vec::new();
    let mut outs = Vec::new();
    for c in state.chans.iter().filter(|c| c.is_managed) {
        if c.status == ChanStatus::In {
            ins.push(trunc_string(&format!("{}{}", if c.i_am_opped { "@" } else { "" }, c.name), 128));
        } else {
            outs.push(c.name.clone());
        }
    }
    let in_buf = join_bounded(&ins, 800);
    let out_buf = join_bounded(&outs, 400);
    if in_buf.is_empty() {
        say(state, nick, "| (IN)  (none)");
    } else {
        // Wrap at 68 columns, backing up to the last ", ".
        const CW: usize = 68;
        let mut p = 0usize;
        let mut first = true;
        while p < in_buf.len() {
            let mut n = (in_buf.len() - p).min(CW);
            if p + n < in_buf.len() {
                let seg = &in_buf[p..p + n];
                let mut back = n;
                while back > 0 && !(seg[back - 1] == b' ' && back > 1 && seg[back - 2] == b',') {
                    back -= 1;
                }
                if back > 0 {
                    n = back;
                }
            }
            let seg = String::from_utf8_lossy(&in_buf[p..p + n]).into_owned();
            ircf!(state, "PRIVMSG {} :{}{}\r\n", nick, if first { "| (IN)  " } else { "|        " }, seg);
            first = false;
            p += n;
        }
    }
    if !out_buf.is_empty() {
        ircf!(state, "PRIVMSG {} :| (OUT) {}\r\n", nick, String::from_utf8_lossy(&out_buf));
    }
    reply_pace(state, 80);

    say(state, nick, "+-[ Access Control ]---------------------------------------------------------");
    ircf!(state, "PRIVMSG {} :| Admins : {:<4}  Ops: {}\r\n", nick, admins, opers);
    reply_pace(state, 80);

    if !state.hubs.is_empty() {
        say(state, nick, "+-[ Hub Config ]-------------------------------------------------------------");
        if state.hub_connected && !state.current_hub.is_empty() {
            let hub = state.current_hub.clone();
            if state.hub_connect_time > 0 && state.hub_authenticated {
                let up = fmt_elapsed(state.hub_connect_time);
                ircf!(state, "PRIVMSG {} :| Hub    : {} (CONNECTED {})\r\n", nick, hub, up);
            } else {
                ircf!(state, "PRIVMSG {} :| Hub    : {} (CONNECTED)\r\n", nick, hub);
            }
        } else {
            say(state, nick, "| Hub    : DISCONNECTED");
        }
        let mut hubs_line = String::new();
        for h in &state.hubs {
            if !hubs_line.is_empty() {
                hubs_line.push_str(", ");
            }
            if hubs_line.len() + h.addr.len() < 299 {
                hubs_line.push_str(&h.addr);
            }
        }
        ircf!(state, "PRIVMSG {} :| Hubs   : {}\r\n", nick, hubs_line);
        if state.trusted_bots.is_empty() {
            say(state, nick, "| Bots   : (none)");
        } else {
            emit_bot_names(state, nick);
        }
        say(state, nick, FOOT);
    } else if !state.trusted_bots.is_empty() {
    say(state, nick, "+-[ Bots ]-------------------------------------------------------------------");
    emit_bot_names(state, nick);
    say(state, nick, FOOT);
} else {
    say(state, nick, FOOT);
}
}

fn cmd_chnick(state: &mut BotState, nick: &str, a: Args<'_>) {
let (Some(old), Some(new)) = (a.a1, a.a2) else {
    say(state, nick, "Syntax: chnick <oldnick> <newnick>");
    return;
};
if !is_valid_bot_nick(new) {
if new.contains('|') {
    say(state, nick, "Error: New nick cannot contain '|'.");
} else {
        ircf!(state, "PRIVMSG {} :Error: New nick too long (max {} chars).\r\n", nick, MAX_NICK - 1);
    }
    return;
}
    // Names are unique across bots, admins and opers.
    if state.user_records.iter().any(|u| u.is_active && eq_ic(&u.name, new)) {
        ircf!(state, "PRIVMSG {} :Error: Name '{}' already in use.\r\n", nick, new);
        return;
    }
    if eq_ic(&state.target_nick, new) {
        ircf!(state, "PRIVMSG {} :Error: Name '{}' already in use by this bot.\r\n", nick, new);
        return;
    }
    if state.trusted_bots.iter().any(|t| eq_ic(t.nick(), new)) {
        ircf!(state, "PRIVMSG {} :Error: Name '{}' already in use by a bot.\r\n", nick, new);
        return;
    }
    // A bot's new name is its IRC nick, so it must be one the ircd takes.
    let rfc_err = |state: &mut BotState| {
        ircf!(
            state,
            "PRIVMSG {} :Error: '{}' is not a valid IRC nick: a letter or one of []\\`_^{{}} first, then letters, digits, those or '-'.\r\n",
            nick,
            new
        );
    };
    // This bot's own target nick.
    if eq_ic(&state.target_nick, old) {
        if !is_rfc_nick(new) {
            rfc_err(state);
            return;
        }
        state.target_nick = new.to_string();
        state.current_nick_ts = now();
        config::write_with_state_pass(state);
        let ts = state.current_nick_ts;
        hub_client::push_delta(state, "n", new, ts);
        ircf!(state, "PRIVMSG {} :This bot's nick changed to '{}' and saved.\r\n", nick, new);
        return;
    }
    // An admin or oper.
    if let Some(ui) = state.user_records.iter().position(|u| u.is_active && eq_ic(&u.name, old)) {
        let u = &mut state.user_records[ui];
        u.name = new.to_string();
        u.timestamp = lww_next_ts(u.timestamp);
        config::write_with_state_pass(state);
        hub_client::push_admin_delta(state);
        ircf!(state, "PRIVMSG {} :User '{}' renamed to '{}'.\r\n", nick, old, new);
        return;
    }
    // A trusted bot.
    if let Some(ti) = state.trusted_bots.iter().position(|t| eq_ic(t.nick(), old)) {
        if !is_rfc_nick(new) {
            rfc_err(state);
            return;
        }
        let mask = &state.trusted_bots[ti].mask;
        let newmask = match mask.find('!') {
            Some(b) => format!("{}{}", new, &mask[b..]),
            None => new.to_string(),
        };
        if newmask.len() >= MAX_MASK_LEN {
            say(state, nick, "Error: resulting mask too long.");
            return;
        }
        // Notify first: the SETNICK is addressed by the old nick.
        bot_comms::send_command(state, old, &format!("SETNICK {new}"));
        if let Some(tb) = state.trusted_bots.get_mut(ti) {
            tb.mask = newmask;
            tb.ts = now();
        }
        config::write_with_state_pass(state);
        ircf!(state, "PRIVMSG {} :Bot '{}' renamed to '{}' and notified.\r\n", nick, old, new);
        return;
    }
    ircf!(state, "PRIVMSG {} :Error: No bot/admin/oper named '{}' found.\r\n", nick, old);
}

fn cmd_getlog(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(level) = a.a1 else {
        ircf!(
            state,
            "PRIVMSG {} :Syntax: getlog <level> [lines]. Levels are 'msg' 'ctcp' 'info' 'cmd' 'raw' 'debug'. Default: {}. Max: {}.\r\n",
            nick,
            DEFAULT_LOG_LINES,
            MAX_LOG_LINES
        );
        return;
    };
    let names = ["msg", "ctcp", "info", "cmd", "raw", "debug"];
    let Some(bi) = names.iter().position(|n| eq_ic(level, n)) else {
        ircf!(state, "PRIVMSG {} :Error: Unknown log level '{}'.\r\n", nick, level);
        return;
    };
    let mut show = DEFAULT_LOG_LINES;
    if let Some(n) = a.a2 {
        show = atoi(n);
        if show <= 0 {
            show = DEFAULT_LOG_LINES;
        }
        if show > MAX_LOG_LINES {
            ircf!(state, "PRIVMSG {} :Warning: Line count capped at {}.\r\n", nick, MAX_LOG_LINES);
            show = MAX_LOG_LINES;
        }
    }
    let matches = state.log.ring_entries(bi);
    let print = matches.len().min(show as usize);
    let start = matches.len() - print;
    ircf!(
        state,
        "PRIVMSG {} :--- Start of Log ({}) - Showing last {} of {} lines --- \r\n",
        nick,
        level,
        print,
        matches.len()
    );
    for line in matches[start..].iter().rev() {
        ircf!(state, "PRIVMSG {} :{}\r\n", nick, line);
        reply_pace(state, 250);
    }
    ircf!(state, "PRIVMSG {} :--- End of Log ({}) --- \r\n", nick, level);
}

fn cmd_list_users(state: &mut BotState, nick: &str, typ: char) {
    let what = if typ == 'a' { "admins" } else { "opers" };
    let name_w = state.user_records.iter().filter(|u| u.typ == typ).map(|u| u.name.len()).fold(8, usize::max);
    ircf!(state, "PRIVMSG {} :| ircbot {} {}\r\n", nick, BOT_VERSION, what);
    say(state, nick, RULE);
    let cap = reply_row_cap(state);
    let (mut shown, mut omitted) = (0usize, 0usize);
    let rows: Vec<String> = state
        .user_records
        .iter()
        .filter(|u| u.typ == typ)
        .map(|u| {
            format!(
                "| {}  key {}  (last seen: {}){}",
                pad_right(&u.name, name_w),
                user_key_fp(u),
                last_seen_str(u.last_seen),
                if u.is_active { "" } else { " [deleted]" }
            )
        })
        .collect();
    for r in rows {
        if shown >= cap {
            omitted += 1;
            continue;
        }
        say(state, nick, &r);
        shown += 1;
        reply_pace(state, 100);
    }
    if shown == 0 {
        ircf!(state, "PRIVMSG {} :| (no {})\r\n", nick, what);
    }
    reply_rows_omitted(state, nick, omitted, what);
    say(state, nick, FOOT);
}

fn cmd_match(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(arg1) = a.a1 else {
        say(state, nick, "Syntax: match <name|*>");
        return;
    };
    let all = arg1 == "*";
    ircf!(state, "PRIVMSG {} :| ircbot {} match{}\r\n", nick, BOT_VERSION, if all { " *" } else { "" });
    say(state, nick, RULE);
    let cap = reply_row_cap(state);
    let (mut shown, mut omitted) = (0usize, 0usize);
    let users: Vec<UserRecord> = state
        .user_records
        .iter()
        .filter(|u| (all || eq_ic(&u.name, arg1)) && u.is_active)
        .cloned()
        .collect();
    for u in users {
        let masks: Vec<MaskRecord> = state.mask_records.iter().filter(|m| m.is_active && m.uuid == u.uuid).cloned().collect();
        if shown >= cap {
            omitted += 1 + masks.len();
            continue;
        }
        ircf!(
            state,
            "PRIVMSG {} :| [{}] {}  key {}  (last seen: {})\r\n",
            nick,
            u.typ,
            pad_right(&u.name, 20),
            user_key_fp(&u),
            last_seen_str(u.last_seen)
        );
        reply_pace(state, 100);
        shown += 1;
        for m in masks {
            if shown >= cap {
                omitted += 1;
                continue;
            }
            ircf!(state, "PRIVMSG {} :|   {}  (last used: {})\r\n", nick, m.mask, last_seen_str(m.last_used));
            reply_pace(state, 100);
            shown += 1;
        }
    }
    // No user by that name: maybe a trusted bot.
    if shown == 0 && !all
        && let Some(tb) = state.trusted_bots.iter().find(|t| eq_ic(t.nick(), arg1)).cloned() {
        ircf!(state, "PRIVMSG {} :| [b] {}  (last seen: {})\r\n", nick, pad_right(tb.nick(), 20), last_seen_str(tb.ts));
        reply_pace(state, 100);
        if !tb.mask.is_empty() {
            ircf!(state, "PRIVMSG {} :|   mask: {}\r\n", nick, tb.mask);
        }
        if !tb.uuid.is_empty() {
            ircf!(state, "PRIVMSG {} :|   uuid: {}\r\n", nick, tb.uuid);
        }
        if tb.has_pub {
            ircf!(state, "PRIVMSG {} :|   key : {}\r\n", nick, crypto::key_fingerprint(&tb.pub_key));
        } else {
            say(state, nick, "|   key : (none on file)");
        }
        let hub = if state.hub_connected && !state.current_hub.is_empty() { state.current_hub.clone() } else { "none".into() };
        ircf!(state, "PRIVMSG {} :|   hub : {}\r\n", nick, hub);
        shown += 1;
        reply_pace(state, 100);
    }
    if shown == 0 && !all {
        ircf!(state, "PRIVMSG {} :| unknown user: {}\r\n", nick, arg1);
    }
    reply_rows_omitted(state, nick, omitted, "records");
    say(state, nick, FOOT);
}

/// +admin|+oper <name> <pubkey> <nick!user@host>: the user makes their own
/// keypair and hands over only the public half.
fn cmd_add_user(state: &mut BotState, nick: &str, add_admin: bool, a: Args<'_>) {
    let what = if add_admin { "+admin" } else { "+oper" };
    let (Some(name), Some(key), Some(mask)) = (a.a1, a.a2, a.a3) else {
        ircf!(
            state,
            "PRIVMSG {} :Syntax: {} <name> <pubkey> <nick!user@host> - <pubkey> is the user's 88-char public key. Ask them for it; 'help {}' shows how they make one.\r\n",
            nick,
            what,
            what
        );
        return;
    };
    if name.len() > 63 {
        say(state, nick, "Error: name too long (max 63).");
        return;
    }
    if !mask.contains('!') || !mask.contains('@') || mask.len() >= MAX_MASK_LEN {
        ircf!(state, "PRIVMSG {} :Error: mask must be nick!user@host (max {} chars)\r\n", nick, MAX_MASK_LEN - 1);
        return;
    }
    if state.user_records.iter().any(|u| u.is_active && eq_ic(&u.name, name)) {
        ircf!(state, "PRIVMSG {} :Error: name '{}' already exists.\r\n", nick, name);
        return;
    }
    if !user_key_arg_ok(state, nick, Some(key), None, what) {
        return;
    }
    if state.user_records.len() >= MAX_USER_RECORDS {
        say(state, nick, "Error: user record table full.");
        return;
    }
    if state.mask_records.len() >= MAX_USER_MASKS {
        say(state, nick, "Error: mask table full.");
        return;
    }
    let Some(uuid) = crypto::gen_uuid_v4() else {
        say(state, nick, "Error: RNG failure.");
        return;
    };
    let now = now();
    let u = UserRecord {
        uuid: uuid.clone(),
        name: name.to_string(),
        pubkey_b64: key.to_string(),
        has_pubkey: true,
        typ: if add_admin { 'a' } else { 'o' },
        is_active: true,
        timestamp: now,
        ..UserRecord::default()
    };
    let fp = user_key_fp(&u);
    state.user_records.push(u);
    state.mask_records.push(MaskRecord { uuid, mask: mask.to_string(), is_active: true, last_used: 0, timestamp: now });
    config::write_with_state_pass(state);
    hub_client::push_admin_delta(state);
    ircf!(
        state,
        "PRIVMSG {} :{} '{}' added with mask {} (key {})\r\n",
        nick,
        if add_admin { "Admin" } else { "Oper" },
        name,
        mask,
        fp
    );
}

fn cmd_del_user(state: &mut BotState, nick: &str, typ: char, a: Args<'_>) {
    let what = if typ == 'a' { "admin" } else { "oper" };
    let Some(name) = a.a1 else {
        ircf!(state, "PRIVMSG {} :Syntax: -{} <name>\r\n", nick, what);
        return;
    };
    let Some(ui) = state.user_records.iter().position(|u| u.is_active && u.typ == typ && eq_ic(&u.name, name)) else {
        ircf!(state, "PRIVMSG {} :Error: {} '{}' not found.\r\n", nick, what, name);
        return;
    };
    let u = &mut state.user_records[ui];
    u.is_active = false;
    u.timestamp = lww_next_ts(u.timestamp);
    let uuid = u.uuid.clone();
    for m in state.mask_records.iter_mut().filter(|m| m.uuid == uuid) {
        m.is_active = false;
        m.timestamp = lww_next_ts(m.timestamp);
    }
    config::write_with_state_pass(state);
    hub_client::push_admin_delta(state);
    ircf!(
        state,
        "PRIVMSG {} :{} '{}' and all their masks removed.\r\n",
        nick,
        if typ == 'a' { "Admin" } else { "Oper" },
        name
    );
}

fn cmd_add_usermask(state: &mut BotState, nick: &str, a: Args<'_>) {
    let (Some(name), Some(mask)) = (a.a1, a.a2) else {
        say(state, nick, "Syntax: +usermask <name> <nick!user@host>");
        return;
    };
    if !mask.contains('!') || !mask.contains('@') {
        say(state, nick, "Error: mask must contain ! and @");
        return;
    }
    let Some(ui) = state.user_records.iter().position(|u| u.is_active && eq_ic(&u.name, name)) else {
        ircf!(state, "PRIVMSG {} :Error: user '{}' not found.\r\n", nick, name);
        return;
    };
    let uuid = state.user_records[ui].uuid.clone();
    let mut tomb = None;
    for (i, m) in state.mask_records.iter().enumerate() {
        if m.uuid != uuid || !eq_ic(&m.mask, mask) {
            continue;
        }
        if m.is_active {
            say(state, nick, "Error: mask already exists.");
            return;
        }
        tomb = Some(i);
    }
    if let Some(i) = tomb {
        // Revive the tombstone past its stamp so the add cannot tie the remove.
        let m = &mut state.mask_records[i];
        m.is_active = true;
        m.timestamp = lww_next_ts(m.timestamp);
    } else {
        if state.mask_records.len() >= MAX_USER_MASKS {
            say(state, nick, "Error: mask table full.");
            return;
        }
        state.mask_records.push(MaskRecord {
            uuid,
            mask: trunc_string(mask, MAX_MASK_LEN),
            is_active: true,
            last_used: 0,
            timestamp: now(),
        });
    }
    config::write_with_state_pass(state);
    hub_client::push_admin_delta(state);
    ircf!(state, "PRIVMSG {} :Mask {} added to {}\r\n", nick, mask, name);
}

fn cmd_del_usermask(state: &mut BotState, nick: &str, a: Args<'_>) {
    let (Some(name), Some(mask)) = (a.a1, a.a2) else {
        say(state, nick, "Syntax: -usermask <name> <mask>");
        return;
    };
    let Some(ui) = state.user_records.iter().position(|u| u.is_active && eq_ic(&u.name, name)) else {
        ircf!(state, "PRIVMSG {} :Error: user '{}' not found.\r\n", nick, name);
        return;
    };
    let uuid = state.user_records[ui].uuid.clone();
    let Some(mi) = state.mask_records.iter().position(|m| m.is_active && m.uuid == uuid && eq_ic(&m.mask, mask)) else {
        ircf!(state, "PRIVMSG {} :Error: mask '{}' not found for {}.\r\n", nick, mask, name);
        return;
    };
    let m = &mut state.mask_records[mi];
    m.is_active = false;
    m.timestamp = lww_next_ts(m.timestamp);
    config::write_with_state_pass(state);
    hub_client::push_admin_delta(state);
    ircf!(state, "PRIVMSG {} :Mask {} removed from {}\r\n", nick, mask, name);
}

/// bots -- the mesh as this bot sees it: the hub-pushed tree (cached, so
/// the reply can still be sealed), or the trusted bots when there is none.
fn cmd_bots(state: &mut BotState, nick: &str, a: Args<'_>) {
    if a.a1.is_some() {
        say(state, nick, "Syntax: bots");
        return;
    }
    let have_tree = state.bot_tree_ts != 0 && !state.bot_tree.is_empty();
    ircf!(state, "PRIVMSG {} :| ircbot {} bots  [ version,  uptime,  irc server ]\r\n", nick, BOT_VERSION);
    say(state, nick, RULE);

    // Two passes over the same rows: size the columns, then print.  The hub
    // tree prints whole; the trusted-bot fallback keeps the row cap.
    let mut cols = (BOTS_NAME_COL_MIN, BOTS_VERSION_COL_MIN, BOTS_UPTIME_COL_MIN);
    let cap = reply_row_cap(state);
    let mut rows_omitted = 0;
    for pass in 0..2 {
        let mut last_at = [false; 10];
        let mut shown = 0usize;
        if have_tree {
            for i in 0..state.bot_tree.len() {
                if state.bot_tree[i].kind == 'd' {
                    continue; // offline: listed below
                }
                let row = bots_tree_row(state, i, &mut last_at);
                if pass == 0 {
                    bots_widen(&row, &mut cols);
                } else {
                    bots_emit(state, nick, &row, cols);
                    reply_pace(state, 100);
                }
            }
            continue;
        }
        let row = bots_self_row(state);
        if pass == 0 {
            bots_widen(&row, &mut cols);
        } else {
            bots_emit(state, nick, &row, cols);
        }
        shown += 1;
        for i in 0..state.trusted_bots.len() {
            if shown >= cap {
                if pass == 1 {
                    rows_omitted += 1;
                }
                continue;
            }
            let row = bots_trusted_row(state, i);
            if pass == 0 {
                bots_widen(&row, &mut cols);
            } else {
                bots_emit(state, nick, &row, cols);
                reply_pace(state, 100);
            }
            shown += 1;
        }
        if pass == 1 && state.trusted_bots.is_empty() {
            say(state, nick, "| (no other bots known)");
        }
    }
    reply_rows_omitted(state, nick, rows_omitted, "bots");

    // Disconnected bots, one message.
    if have_tree {
        let mut offline = String::new();
        let (mut listed, mut omitted) = (0, 0);
        for r in state.bot_tree.iter().filter(|r| r.kind == 'd') {
            let ts = if r.uptime <= 0 { "never".to_string() } else { gm_time(r.uptime, "%Y-%m-%d %H:%M UTC") };
            let w = format!(
                "{}{} ({})",
                if offline.is_empty() { "" } else { ", " },
                if r.name.is_empty() { "(unnamed)" } else { r.name.as_str() },
                ts
            );
            if offline.len() + w.len() >= 419 {
                omitted += 1;
                continue;
            }
            offline.push_str(&w);
            listed += 1;
        }
        if listed > 0 || omitted > 0 {
            if omitted > 0 {
                ircf!(state, "PRIVMSG {} :| Disconnected: {} (+{} more)\r\n", nick, offline, omitted);
            } else {
                ircf!(state, "PRIVMSG {} :| Disconnected: {}\r\n", nick, offline);
            }
        }
        let age = now() - state.bot_tree_ts;
        if age > BOT_TREE_STALE_AFTER {
            ircf!(state, "PRIVMSG {} :| (hub last refreshed this {} ago)\r\n", nick, tree_fmt_uptime(age));
        }
    } else if !state.hubs.is_empty() {
    say(state, nick, "| (no hub tree yet -- showing trusted bots only)");
}
say(state, nick, FOOT);
}

/// Every configured server and its port.  The live link is irc_server_idx
/// (current_server_index is the rotation cursor, already past it).
fn cmd_servers(state: &mut BotState, nick: &str) {
let split = |s: &str| -> (String, String) {
    match s.rfind(':') {
        Some(c) if c + 1 < s.len() => (trunc_string(&s[..c], 256), s[c + 1..].to_string()),
        _ => (trunc_string(s, 256), "default".to_string()),
    }
    };
    let host_w = state
        .server_list
        .iter()
        .map(|s| s.rfind(':').unwrap_or(s.len()))
        .fold(8, usize::max);
    let up = state.status & S_CONNECTED != 0;
    let connected_idx = if up { state.irc_server_idx } else { None };
    let next_idx = if connected_idx.is_none() {
        Some(if state.current_server_index < state.server_list.len() { state.current_server_index } else { 0 })
    } else {
        None
    };
    ircf!(state, "PRIVMSG {} :| ircbot {} servers\r\n", nick, BOT_VERSION);
    say(state, nick, RULE);
    let mut shown = 0;
    for i in 0..state.server_list.len().min(BOT_STATUS_MAX_LINES) {
        let (host, port) = split(&state.server_list[i]);
        let marker = if Some(i) == connected_idx {
            "*"
        } else if Some(i) == next_idx {
            ">"
        } else {
            " "
        };
        let held = irc_client::server_block_desc(state, i);
        let note = if held.is_empty() { String::new() } else { format!("  [{held}]") };
        ircf!(state, "PRIVMSG {} :| {} {}  port {}{}\r\n", nick, marker, pad_right(&host, host_w), pad_right(&port, 7), note);
        shown += 1;
        reply_pace(state, 100);
    }
    if shown == 0 {
        say(state, nick, "| (no servers configured)");
    } else if connected_idx.is_some() {
    say(state, nick, "| '*' connected, [..] on hold");
} else {
    say(state, nick, "| not connected; '>' tried next, [..] on hold");
}
say(state, nick, FOOT);
}

/// +hub <host:port> <pubkey-b64>: the hub's pinned Ed25519 key, 44-char raw
/// or 88-char combined (first 32 bytes).  Pinning is required.
fn cmd_add_hub(state: &mut BotState, nick: &str, a: Args<'_>) {
let (Some(addr), Some(key)) = (a.a1, a.a2) else {
    say(state, nick, "Syntax: +hub <host:port> <pubkey-b64>");
    return;
};
match addr.rfind(':') {
    Some(c) if c > 0 && atoi(&addr[c + 1..]) > 0 => {}
        _ => {
            say(state, nick, "Error: address must be HOST:PORT (e.g. hub.example.com:7000).");
            return;
        }
    }
    if state.hubs.iter().any(|h| h.addr == addr) {
        ircf!(state, "PRIVMSG {} :Error: Hub '{}' already exists. Remove it with -hub first to change its key.\r\n", nick, addr);
        return;
    }
    if state.hubs.len() >= MAX_SERVERS {
        say(state, nick, "Error: Hub list is full.");
        return;
    }
    let Some(dec) = crypto::b64_decode(key).filter(|d| d.len() == 32 || d.len() == HUB_KEY_RAW_LEN) else {
        say(
            state,
            nick,
            "Error: pubkey must be base64 of a 32-byte Ed25519 key (44 chars) or 64-byte combined Curve25519 key (88 chars).",
        );
        return;
    };
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&dec[..32]);
    state.hubs.push(crate::state::HubEntry { addr: trunc_string(addr, 256), ed_pub, ed_pub_set: true });
    config::write_with_state_pass(state);
    ircf!(state, "PRIVMSG {} :Added Hub: {} (pubkey pinned)\r\n", nick, addr);
    // Not connected to any hub yet: try the new one now.
    if state.hub.is_none() {
        state.last_hub_connect_attempt = 0;
        hub_client::connect(state);
    }
}

fn cmd_del_hub(state: &mut BotState, nick: &str, a: Args<'_>) {
    let Some(addr) = a.a1 else {
        say(state, nick, "Syntax: -hub <host:port>");
        return;
    };
    let Some(i) = state.hubs.iter().position(|h| h.addr == addr) else {
        ircf!(state, "PRIVMSG {} :Error: Hub '{}' not found.\r\n", nick, addr);
        return;
    };
    let is_current = state.hub_connected && state.current_hub == addr;
    if is_current {
        ircf!(state, "PRIVMSG {} :Disconnecting from current hub: {}\r\n", nick, addr);
        hub_client::disconnect(state);
    }
    state.hubs.remove(i);
    config::write_with_state_pass(state);
    ircf!(state, "PRIVMSG {} :Removed Hub: {}\r\n", nick, addr);
    if is_current && !state.hubs.is_empty() {
        say(state, nick, "Reconnecting to another hub...");
        state.last_hub_connect_attempt = 0;
        hub_client::connect(state);
    } else if is_current {
    say(state, nick, "No other hubs available to connect to.");
}
}

/// Rotate this bot's identity keypair.  The new PUBLIC key is pushed under
/// the current (old-key) session first; only if that succeeds is the new
/// private key committed, then the bot reconnects so the hub re-verifies it.
fn cmd_rekey(state: &mut BotState, nick: &str) {
if state.hubs.is_empty() {
    say(state, nick, "Error: no hub configured; nothing to rekey.");
    return;
}
if !state.hub_authenticated || state.hub.is_none() {
    say(
        state,
        nick,
        "Error: not authenticated to a hub. Rekey needs an active session so the new key is pushed under the old one. Try again once connected.",
    );
    return;
}
let Some((new_priv, new_pub)) = crypto::generate_combined_keypair() else {
    say(state, nick, "Error: keypair generation failed.");
    return;
};
let new_priv_b64 = Zeroizing::new(crypto::b64_encode(new_priv.as_ref()));
let new_pub_b64 = crypto::b64_encode(&new_pub);
if !hub_client::push_delta(state, "pub", &new_pub_b64, now()) {
    say(state, nick, "Error: failed to push new pubkey to hub; key left UNCHANGED.");
    return;
}
state.hub_key_raw.set(&new_priv);
*state.hub_key = new_priv_b64.to_string();
drop(new_priv_b64);
hub_client::self_pub_refresh(state);
config::write_with_state_pass(state);
let (fp, me) = (crypto::key_fingerprint(&new_pub), state.current_nick.clone());
ircf!(
    state,
    "PRIVMSG {} :\u{2713} Rekeyed (new key {}). New pubkey pushed to hub; reconnecting with new key. Clients must re-auth (/botforget {}).\r\n",
    nick,
    fp,
    me
);
logm!(state, L_INFO, "[HUB] Rekey: generated new identity, pushed new pub to hub, reconnecting.\n");
hub_client::disconnect(state);
state.last_hub_connect_attempt = 0;
hub_client::connect(state);
}

fn help_header(state: &mut BotState, nick: &str) {
ircf!(state, "PRIVMSG {} : | {} {} help\r\n", nick, BOT_NAME, BOT_VERSION);
ircf!(state, "PRIVMSG {} : {}\r\n", nick, RULE);
say(state, nick, " | ");
}

fn help_footer(state: &mut BotState, nick: &str) {
say(state, nick, " |");
ircf!(state, "PRIVMSG {} : {}\r\n", nick, FOOT);
}

fn admin_help(state: &mut BotState, nick: &str, topic: Option<&str>) {
let Some(t) = topic else {
    help_header(state, nick);
    if state.is_opt_set(OPT_HUB_ONLY_MUTATIONS) {
        say(state, nick, " |   die, jump, op, invite, status, givenick, chnick");
        say(state, nick, " |   +server, -server, servers, bots, admins, opers, match, dcc");
        say(state, nick, " |   +hub, -hub, rekey, saveconf, setlog, getlog, update, help");
        say(state, nick, " |   (hub-only-mutation mode: users, masks, keys, channels via hub_admin)");
    } else {
            say(state, nick, " |   die, jump, op, invite, join, part, status, givenick, chnick");
            say(state, nick, " |   +server, -server, servers, bots, admins, opers, match, dcc");
            say(state, nick, " |   +admin, -admin, +oper, -oper, +usermask, -usermask, chkey");
            say(state, nick, " |   +bot, -bot, +hub, -hub, rekey");
            say(state, nick, " |   saveconf, setlog, getlog, update, help");
        }
        say(state, nick, " |   'help auth' explains how clients sign in with their key");
        help_footer(state, nick);
        return;
    };
    let lower = t.to_ascii_lowercase();
    let text: &str = match lower.as_str() {
        "die" => "Syntax: die - Kills the bot process.",
        "jump" => "Syntax: jump [server] - Jump to the next IRC server, or to a specific server by hostname (port-independent match). Servers that banned or throttled the bot are skipped; naming one clears its hold and retries it now.",
        "op" => "Syntax: op <#channel> - Get operator status on a channel.",
        "status" => "Syntax: status - Show bot status.",
        "givenick" => "Syntax: givenick - Temporarily changes the bot nick to an alternate. Will try to regain primary nick after 20 seconds until it accomplishes the task.",
        "chnick" => "Syntax: chnick <oldnick> <newnick> - Renames a bot, admin, or oper. Nicks must be unique across all types. For bots, propagates the change via hub mesh.",
        "+server" => "Syntax: +server <irc.network.net:6667> - Add another irc server to the bot's server list. Port not required.",
        "-server" => "Syntax: -server <irc.network.net:6667> - Removes a server from the bot's server list. Specify server as it is listed in 'status' command.",
        "servers" => "Syntax: servers - List every configured IRC server and its port. '*' marks the one we are on, '>' the one selected, and [..] a ban or throttle hold.",
        "bots" => {
            say(state, nick, "Syntax: bots - Draw the bot tree: this bot's hub at the root, peer hubs beneath it, each hub's bots under it.");
            "  Every row shows version, uptime and IRC server (hubs show '(hub)'). Bots that are known but offline are listed last with their last-seen time. With no hub, all trusted bots list on one branch."
        }
        "admins" => "Syntax: admins - List all admins.",
        "opers" => "Syntax: opers - List all opers.",
        "+admin" => {
            say(state, nick, "Syntax: +admin <name> <pubkey> <nick!user@host> - Add a named admin with a first usermask. Name must be unique across admins and opers.");
            help_keypair(state, nick);
            return;
        }
        "-admin" => "Syntax: -admin <name> - Remove admin and all their masks.",
        "+oper" => {
            say(state, nick, "Syntax: +oper <name> <pubkey> <nick!user@host> - Add a named oper with a first usermask. Opers may use op, chkey (own key) and help.");
            help_keypair(state, nick);
            return;
        }
        "-oper" => "Syntax: -oper <name> - Remove oper and all their masks.",
        "+usermask" => "Syntax: +usermask <name> <mask> - Add a usermask to admin or oper.",
        "-usermask" => "Syntax: -usermask <name> <mask> - Remove a specific usermask from admin or oper.",
        "chkey" => {
            say(state, nick, "Syntax: chkey <name> <pubkey> - Replace the public key of a named admin or oper (UUID and usermasks are kept). Opers may only change their own key.");
            help_keypair(state, nick);
            return;
        }
        "invite" => "Syntax: invite <#channel> - Invite yourself to a channel (asks the hub or a trusted bot if this bot is not opped there).",
        "auth" => {
            help_auth(state, nick);
            return;
        }
        "dcc" => {
            say(state, nick, "Syntax: dcc - Open a DCC chat with this bot for long replies. The bot never accepts connections: it sends a passive offer and connects out to the port your client opens, so open your client's DCC port range in your firewall and set its DCC address to your public IP.");
            "Commands in the chat are still sealed: while it is open, the client script seals what you type there (and /botcmd <bot> <command>) and the replies come back there; anything unsealed closes it. A command sent by PRIVMSG is still answered by PRIVMSG. Admins only."
        }
        "match" => "Syntax: match <name|*> - Show all records for a user, or * for all users.",
        "+bot" => "Syntax: +bot <nick!user@host> <uuid> <pubkey> - Standalone bots only (hub-managed bots get peers from the hub): trust another bot for encrypted bot-to-bot commands. Copy the UUID and Pubkey from that bot's 'status' (or its -setup output). The mask should be the one the network shows for it.",
        "-bot" => "Syntax: -bot <nick*!*user@hostmask.com> - Removes a bot from the known bot list as shown in the 'status' command.",
        "saveconf" => "Syntax: saveconf - Immediately save config file.",
        "setlog" => "Syntax: setlog <loglevel> - Set loglevel for output to a log file. 0=NONE,15=INFO,63=DEBUG.",
        "getlog" => {
            ircf!(
                state,
                "PRIVMSG {} :Syntax: getlog <loglevel> [lines]. Get latest logs for requested loglevel. Levels are 'msg' 'ctcp' 'info' 'cmd' 'raw' 'debug'. Default number of lines: {}. Max number of lines: {}.\r\n",
                nick,
                DEFAULT_LOG_LINES,
                MAX_LOG_LINES
            );
            return;
        }
        "update" => "Syntax: update without argument shows available versions. Run with update <ver> to download/compile/and update bot binary.",
        "join" => "Syntax: join <#channel> - Joins a channel.",
        "part" => "Syntax: part <#channel> - Parts a channel.",
        "+hub" => "Syntax: +hub <host:port> <pubkey-b64> - Add a hub and pin its Ed25519 pubkey (44 or 88 char base64 from the hub's hub_public.b64).",
        "-hub" => "Syntax: -hub <host:port> - Remove a configured hub.",
        "rekey" => "Syntax: rekey - Generate a new Curve25519 identity keypair locally, push the new public key to the hub, and reconnect. UUID is unchanged. Requires an active hub session. Clients holding the old key must re-auth (/botforget <bot>).",
        _ => {
            ircf!(state, "PRIVMSG {} :No help available for command '{}'.\r\n", nick, t);
            return;
        }
    };
    say(state, nick, text);
}

fn oper_command(state: &mut BotState, nick: &str, who: usize, command: &str, a: Args<'_>) {
    if eq_ic(command, "op") {
        if let Some(ch) = a.a1.and_then(|x| Tok::new(x).next(" ")) {
            ircf!(state, "MODE {} +o {}\r\n", ch, nick);
        }
    } else if eq_ic(command, "chkey") {
    // Own key only, and refused under opt 'h' like every local mutation
    // of a hub-authoritative record.
    if state.is_opt_set(OPT_HUB_ONLY_MUTATIONS) {
        say(state, nick, "Error: 'chkey' is disabled — network is in hub-only-mutation mode (opt 'h'). Ask a hub admin.");
        return;
    }
        let (Some(name), Some(key)) = (a.a1, a.a2) else {
            say(state, nick, "Syntax: chkey <yourname> <pubkey>");
            return;
        };
        if !eq_ic(&state.user_records[who].name, name) {
            say(state, nick, "Error: opers may only change their own key.");
            return;
        }
        if !user_key_arg_ok(state, nick, Some(key), Some(who), "chkey") {
            return;
        }
        set_user_key(state, who, key);
        let fp = user_key_fp(&state.user_records[who]);
        ircf!(state, "PRIVMSG {} :Your key has been changed (key {}). Use the new private key from now on.\r\n", nick, fp);
    } else if eq_ic(command, "help") {
    match a.a1 {
        None => {
            help_header(state, nick);
            say(state, nick, " |   op, chkey, help");
            help_footer(state, nick);
        }
        Some(t) if eq_ic(t, "op") => say(state, nick, "Syntax: op <#channel> - Get operator status on a channel."),
        Some(t) if eq_ic(t, "chkey") => {
            say(state, nick, "Syntax: chkey <yourname> <pubkey> - Replace your own public key.");
            help_keypair(state, nick);
        }
        Some(t) if eq_ic(t, "auth") => help_auth(state, nick),
        Some(t) if eq_ic(t, "help") => say(state, nick, "Syntax: help [command] - Show available commands."),
        Some(t) => {
            ircf!(state, "PRIVMSG {} :No help available for command '{}'.\r\n", nick, t);
        }
    }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_bytes() {
        let c = a2_context(160, A2_LABEL, "Bot", "Admin", None).unwrap();
        assert_eq!(c, b"ircbot-A2-v1\0bot\0admin".to_vec());
        let c = a2_context(256, A2A_LABEL, "b", "u", Some("1:00")).unwrap();
        assert_eq!(c, b"ircbot-A2A-v1\0b\0u\x001:00".to_vec());
        assert!(a2_context(160, A2_LABEL, "", "x", None).is_none());
    }

    #[test]
    fn tree_prefixes() {
        assert_eq!(tree_prefix(0, &[], true, false), "");
        assert_eq!(tree_prefix(1, &[], true, false), "\u{2514}\u{2500}\u{2500} ");
        assert_eq!(tree_prefix(2, &[false, false], false, true), "\u{2502} \u{251c}\u{2500}\u{252c} ");
        assert_eq!(tree_fmt_uptime(59), "59s");
        assert_eq!(tree_fmt_uptime(90061), "1d1h");
    }

    #[test]
    fn bounded_join() {
        let v = vec!["#a".to_string(), "#b".to_string()];
        assert_eq!(join_bounded(&v, 800), b"#a, #b".to_vec());
    }
}
