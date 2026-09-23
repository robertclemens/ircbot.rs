//! The hub link (hub_client.c).
//!
//! Handshake (v2): the bot sends its UUID; the hub answers challenge(32) ||
//! hub_eph_pub(32) || Ed25519 signature over "irchub-hub-auth-v2|" uuid "|"
//! challenge eph_pub, verified against the hub's pinned key.  Session key =
//! HKDF-SHA256(X25519(bot_x, hub_eph), salt = challenge,
//! info = "irchub-bot-session-v1|" uuid); the bot proves itself with an
//! Ed25519 signature over "irchub-bot-challenge-v1|" uuid "|" eph_pub
//! challenge, and the hub ACKs with an encrypted 0x01.
//!
//! Every frame after that: len(4, BE) || iv(12) || AES-GCM(cmd(1) ||
//! payload_len(4, BE) || payload) || tag(16).

use zeroize::Zeroizing;

use crate::consts::*;
use crate::crypto::{self, Key32};
use crate::cstr::{
    Conv, Fmt, atoi, atoll, eq_ic, has_uuid_dashes, now, sscanf, trunc_string, until_nul,
};
use crate::net::{self, ReadOutcome};
use crate::state::{
    BotState, BotTreeRow, ChanReq, ChanStatus, HubAuthState, MaskRecord, S_CONNECTED, UserRecord,
    lww_accepts, opt_accepts,
};
use crate::{bot_comms, channel, config, ircf, logm, updater};

/// Unsent bytes past which a hub that stopped reading is dropped.
const HUB_WBUF_MAX: usize = 4 * 1024 * 1024;
const P: &[u8] = b"|";

pub struct HubConn {
    pub sock: mio::net::TcpStream,
    pub token: mio::Token,
    rbuf: Vec<u8>,
    wbuf: Vec<u8>,
}

/// The identity key's halves (ed_seed, x_priv).  Falls back to decoding the
/// base64 form (and caches it) when the raw copy was never filled.
pub fn bot_key_decode(state: &mut BotState) -> Option<(Key32, Key32)> {
    if !state.hub_key_raw.is_zero() {
        return Some(crypto::split_priv(state.hub_key_raw.get()));
    }
    match crypto::b64_decode(&state.hub_key) {
        Some(dec) if dec.len() == HUB_KEY_RAW_LEN => {
            let mut raw = Zeroizing::new([0u8; HUB_KEY_RAW_LEN]);
            raw.copy_from_slice(&dec);
            state.hub_key_raw.set(&raw);
            Some(crypto::split_priv(&raw))
        }
        _ => {
            logm!(
                state,
                L_INFO,
                "[HUB] hub_key is not a valid 64-byte Curve25519 key\n"
            );
            None
        }
    }
}

/// Recompute self_pub from the identity key; false if there is none.
pub fn self_pub_refresh(state: &mut BotState) -> bool {
    state.self_pub_set = false;
    state.self_pub = [0; HUB_KEY_RAW_LEN];
    if state.hub_key.is_empty() && state.hub_key_raw.is_zero() {
        return false;
    }
    let Some((ed, x)) = bot_key_decode(state) else {
        return false;
    };
    let mut priv_key = Zeroizing::new([0u8; HUB_KEY_RAW_LEN]);
    priv_key[..32].copy_from_slice(ed.as_ref());
    priv_key[32..].copy_from_slice(x.as_ref());
    state.self_pub = crypto::combined_pub_from_priv(&priv_key);
    state.self_pub_set = true;
    true
}

/// Queue raw bytes to the hub; false (after disconnecting) on a hard error.
fn send_raw(state: &mut BotState, data: &[u8]) -> bool {
    let res = match state.hub.as_mut() {
        None => return false,
        Some(h) => {
            if h.wbuf.len() + data.len() > HUB_WBUF_MAX {
                Err(std::io::Error::other("send queue overflow"))
            } else {
                h.wbuf.extend_from_slice(data);
                net::flush(&mut h.sock, &mut h.wbuf)
            }
        }
    };
    if res.is_err() {
        disconnect(state);
        return false;
    }
    true
}

/// Encrypt one [cmd][len][payload] frame under the session key and send it.
fn send_frame(state: &mut BotState, cmd: u8, payload: &[u8]) -> bool {
    if !state.hub_authenticated || state.hub.is_none() {
        return false;
    }
    if payload.len() > MAX_BUFFER - 64 {
        return false;
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(5 + payload.len()));
    plain.push(cmd);
    plain.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    plain.extend_from_slice(payload);
    let Some(body) = crypto::gcm_seal(state.hub_session_key.get(), &[], &plain) else {
        return false;
    };
    drop(plain);
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    send_raw(state, &frame)
}

/// "irchub-bot-challenge-v1|" uuid "|" hub_eph_pub challenge, signed.
fn sign_challenge(state: &mut BotState, challenge: &[u8], hub_eph_pub: &[u8]) -> Option<[u8; 64]> {
    let (ed, _x) = bot_key_decode(state)?;
    let mut msg = Zeroizing::new(Vec::new());
    msg.extend_from_slice(b"irchub-bot-challenge-v1|");
    msg.extend_from_slice(state.bot_uuid.as_bytes());
    msg.push(b'|');
    msg.extend_from_slice(hub_eph_pub);
    msg.extend_from_slice(challenge);
    Some(crypto::ed25519_sign(&ed, &msg))
}

/// Session key: HKDF(X25519(bot_x, hub_eph), salt = challenge,
/// info = "irchub-bot-session-v1|" uuid).
fn derive_session_key(
    state: &mut BotState,
    hub_eph_pub: &[u8; 32],
    challenge: &[u8],
) -> Option<Key32> {
    let (_ed, x) = bot_key_decode(state)?;
    let Some(shared) = crypto::x25519_derive(&x, hub_eph_pub) else {
        logm!(state, L_INFO, "[HUB] X25519 derive failed\n");
        return None;
    };
    let info = format!("irchub-bot-session-v1|{}", state.bot_uuid);
    let mut key = Zeroizing::new([0u8; 32]);
    if !crypto::hkdf_sha256(shared.as_ref(), challenge, info.as_bytes(), key.as_mut()) {
        logm!(state, L_INFO, "[HUB] HKDF failed\n");
        return None;
    }
    Some(key)
}

fn close_socket(state: &mut BotState) {
    if let Some(mut h) = state.hub.take() {
        let _ = state.registry.deregister(&mut h.sock);
        let _ = h.sock.shutdown(std::net::Shutdown::Both);
    }
}

pub fn disconnect(state: &mut BotState) {
    close_socket(state);
    state.hub_connected = false;
    state.hub_authenticated = false;
    state.hub_connecting = false;
    state.hub_connect_time = 0;
    state.hub_auth_state = HubAuthState::None;
    state.hub_session_key.wipe();
    state.current_hub.clear();
    state.last_hub_connect_attempt = now();
    state.last_hub_pong_sent = 0;
    // Keep the tree for 'bots', but re-report presence on the next auth.
    state.presence_server.clear();
    state.last_presence_sent = 0;
}

/// The watchdog's drop (irc_check_status): close the link and clear the
/// flags; the next tick reconnects.
pub fn drop_link(state: &mut BotState) {
    close_socket(state);
    state.hub_connected = false;
    state.hub_authenticated = false;
    state.hub_connecting = false;
    state.hub_auth_state = HubAuthState::None;
    state.hub_session_key.wipe();
}

fn link_ready(state: &BotState) -> bool {
    !state.hubs.is_empty() && state.hub.is_some() && state.hub_authenticated
}

/// Keepalive every 30 s, plus the self-throttling presence report.
pub fn heartbeat(state: &mut BotState) {
    if state.hubs.is_empty()
        || !state.hub_connected
        || !state.hub_authenticated
        || state.hub.is_none()
    {
        return;
    }
    let now = now();
    send_presence(state, false);
    if now - state.last_hub_ping_time < 30 {
        return;
    }
    state.last_hub_ping_time = now;
    send_frame(state, CMD_PING, &[]);
}

pub fn sync_hostmask(state: &mut BotState) {
    if state.actual_hostname.is_empty() || !link_ready(state) {
        return;
    }
    logm!(
        state,
        L_DEBUG,
        "[DEBUG] Syncing hostmask via delta: {}\n",
        state.actual_hostname
    );
    let (h, ts) = (state.actual_hostname.clone(), state.actual_hostname_ts);
    push_delta(state, "h", &h, ts);
}

/// Report version / IRC server / start time for the 'bots' tree: when it
/// changes, on a slow refresh timer, or when forced.
pub fn send_presence(state: &mut BotState, force: bool) {
    if !link_ready(state) {
        return;
    }
    // The server name the link reported beats the configured entry.
    let mut server = String::new();
    if state.status & S_CONNECTED != 0 {
        if !state.actual_server_name.is_empty() {
            server = trunc_string(&state.actual_server_name, TREE_SERVER_MAX + 1);
        } else if let Some(cfg) = state.irc_server_idx.and_then(|i| state.server_list.get(i)) {
            server = trunc_string(cfg, TREE_SERVER_MAX + 1);
        }
    }
    let now = now();
    let changed = server != state.presence_server;
    if !force
        && !changed
        && state.last_presence_sent != 0
        && now - state.last_presence_sent < BOT_PRESENCE_REPORT_INTERVAL
    {
        return;
    }
    // The variant rides last: a hub that predates it reads the start time
    // with atoll(), which stops at the '|', so older hubs are unaffected.
    let payload = format!(
        "{}|{}|{}|{}",
        BOT_VERSION, server, state.bot_start_time, BOT_UPDATE_VARIANT
    );
    if send_frame(state, CMD_BOT_PRESENCE, payload.as_bytes()) {
        state.presence_server = server.clone();
        state.last_presence_sent = now;
        if changed {
            logm!(
                state,
                L_DEBUG,
                "[HUB] Presence: {} on {}\n",
                BOT_VERSION,
                if server.is_empty() {
                    "(no server)"
                } else {
                    server.as_str()
                }
            );
        }
    }
}

// ---- Network upgrade (hub-orchestrated rolling upgrade) ------------------
// The bot is a follower here.  It answers CMD_UPGRADE_PREPARE with what it is
// and whether it could take the target build, touches nothing until
// CMD_UPGRADE_COMMIT names the same upgrade, and restores the retained build
// on CMD_UPGRADE_ABORT.  None of this is reachable from IRC or DCC: the
// frames only arrive on the authenticated hub link, which is the whole point
// of the standalone-only gate on the 'update' command.

/// Copy `src` into a '|'-free, control-byte-free field.  Reasons carry text
/// that originated in a manifest, and the wire format splits on '|'.
fn upgrade_field(src: &str) -> String {
    src.chars()
        .map(|c| match c {
            '|' => '/',
            c if (c as u32) < 0x20 || c == '\u{7f}' => ' ',
            c => c,
        })
        .take(191)
        .collect()
}

/// id|uuid|cur_ver|variant|arch|libc|ready|reason
fn send_upgrade_ready(state: &mut BotState, id: &str, ready: bool, reason: &str) {
    let clean = upgrade_field(reason);
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        id,
        state.bot_uuid,
        BOT_VERSION,
        updater::host_variant(),
        updater::host_arch(),
        updater::host_libc(),
        if ready { 1 } else { 0 },
        clean
    );
    send_frame(state, CMD_UPGRADE_READY, payload.as_bytes());
    logm!(
        state,
        L_INFO,
        "[UPGRADE] {} upgrade {}{}{}\n",
        if ready { "Ready for" } else { "Cannot take" },
        id,
        if clean.is_empty() { "" } else { ": " },
        clean
    );
}

/// id|uuid|status|new_ver|detail
pub fn send_upgrade_result(state: &mut BotState, id: &str, status: &str, detail: &str) {
    let payload = format!(
        "{}|{}|{}|{}|{}",
        id,
        state.bot_uuid,
        status,
        BOT_VERSION,
        upgrade_field(detail)
    );
    send_frame(state, CMD_UPGRADE_RESULT, payload.as_bytes());
}

/// Called once per authenticated link.  If this process is the product of a
/// hub-driven upgrade, the marker left behind by updater::hub_commit() says
/// which run it belongs to; report whether we came up on the version that run
/// was aiming at.  The hub also infers success from the presence frame, so a
/// lost RESULT costs nothing.
pub fn report_upgrade_result(state: &mut BotState) {
    let Some((id, want)) = updater::take_pending_upgrade() else {
        return;
    };
    let ok = updater::version_cmp(BOT_VERSION, &want) == std::cmp::Ordering::Equal;
    logm!(
        state,
        L_INFO,
        "[UPGRADE] Restarted after {}: running {} (wanted {})\n",
        id,
        BOT_VERSION,
        want
    );
    let status = if ok { "ok" } else { "version-mismatch" };
    send_upgrade_result(state, &id, status, if ok { "" } else { &want });
}

/// id|target_ver|variant|kind|min_from|manifest_base — the hub is asking
/// whether we could move to target_ver.  Answer only; nothing is downloaded
/// and nothing on disk is touched until COMMIT.
fn handle_upgrade_prepare(state: &mut BotState, payload: &str) {
    // id|ver|variant|kind|min_from|base — base is a bounded field, not the
    // tail: a hub's peer-facing PREPARE appends the hubs' own target and base
    // after it, and anything past the sixth field is not the bot's.
    let f: Vec<&str> = payload.split('|').collect();
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() || f[0].len() > 63 || f[1].len() > 63 {
        logm!(state, L_INFO, "[UPGRADE] Malformed UPGRADE_PREPARE\n");
        return;
    }
    let (id, ver) = (f[0], f[1]);
    let variant = f.get(2).copied().unwrap_or("");
    let min_from = f.get(4).copied().unwrap_or("");
    let base = f.get(5).copied().unwrap_or("");

    let mut reason = "";
    let ready = match updater::version_cmp(ver, BOT_VERSION) {
        std::cmp::Ordering::Equal => {
            reason = "already running the target version";
            false
        }
        std::cmp::Ordering::Less => {
            reason = "target is older than the running version";
            false
        }
        std::cmp::Ordering::Greater => {
            if !min_from.is_empty()
                && min_from != "*"
                && updater::version_cmp(BOT_VERSION, min_from) == std::cmp::Ordering::Less
            {
                // The hub walks the intermediate releases when it sees this.
                reason = "running version is below the target's min_from";
                false
            } else if !std::path::Path::new(PASS_FILE).exists() {
                // Without the machine-bound password file the replacement
                // binary would stop at a prompt with nobody to answer it.
                reason = "no .ircbot.pass; cannot restart unattended";
                false
            } else if !state.executable_path.starts_with('/') {
                reason = "executable path is not absolute";
                false
            } else {
                true
            }
        }
    };

    if ready {
        // Remember the plan: COMMIT repeats only the id and the version.
        state.upgrade_id = id.to_string();
        state.upgrade_target = ver.to_string();
        state.upgrade_variant = if variant.is_empty() {
            updater::host_variant().to_string()
        } else {
            variant.to_string()
        };
        state.upgrade_base = base.to_string();
        state.upgrade_prepared = now();
    }
    // The artifact kind is chosen from the manifest at COMMIT, so f[3] is
    // read for the wire format's sake and not used here.
    let id = id.to_string();
    send_upgrade_ready(state, &id, ready, reason);
}

/// id|target_ver|variant — go.  Only an id we acknowledged at PREPARE, and
/// only while that acknowledgement is still fresh, may commit.
fn handle_upgrade_commit(state: &mut BotState, payload: &str) {
    let f: Vec<&str> = payload.splitn(3, '|').collect();
    if f.len() < 2 || f[0].is_empty() || f[1].is_empty() || f[0].len() > 63 || f[1].len() > 63 {
        logm!(state, L_INFO, "[UPGRADE] Malformed UPGRADE_COMMIT\n");
        return;
    }
    let (id, ver) = (f[0].to_string(), f[1].to_string());
    let variant = f.get(2).copied().unwrap_or("").to_string();

    if state.upgrade_id.is_empty() || state.upgrade_id != id {
        send_upgrade_result(state, &id, "fail", "no matching UPGRADE_PREPARE");
        return;
    }
    if state.upgrade_target != ver {
        send_upgrade_result(state, &id, "fail", "commit version differs from prepare");
        return;
    }
    if now() - state.upgrade_prepared > UPGRADE_PREPARE_TTL {
        state.upgrade_id.clear();
        send_upgrade_result(state, &id, "fail", "prepare expired");
        return;
    }

    let variant = if variant.is_empty() {
        state.upgrade_variant.clone()
    } else {
        variant
    };
    let base = state.upgrade_base.clone();
    // On success hub_commit() does not return: the process is replaced and
    // report_upgrade_result() reports in after the restart.
    if let Err(e) = updater::hub_commit(state, &id, &ver, &variant, &base) {
        // Nothing was changed on disk; stay on this build and say why.
        logm!(state, L_INFO, "[UPGRADE] Commit {} refused: {}\n", id, e);
        send_upgrade_result(state, &id, "fail", &e);
        state.upgrade_id.clear();
    }
}

/// id|reason — put the retained build back.  By the time this arrives the new
/// binary is usually already the running process, so undoing it is another
/// exec; a bot that has nothing retained just says so.
fn handle_upgrade_abort(state: &mut BotState, payload: &str) {
    let (id, reason) = payload.split_once('|').unwrap_or((payload, ""));
    let id = if id.is_empty() { "-" } else { id }.to_string();
    let reason = if reason.is_empty() {
        "hub aborted the upgrade".to_string()
    } else {
        upgrade_field(reason)
    };
    logm!(state, L_INFO, "[UPGRADE] Abort {}: {}\n", id, reason);
    state.upgrade_id.clear();
    state.upgrade_prepared = 0;
    // A successful rollback execs; the hub sees the old version reappear.
    if !updater::hub_rollback(state, &reason) {
        send_upgrade_result(state, &id, "aborted", "nothing retained to roll back to");
    }
}

/// Ingest a CMD_BOT_TREE push.  A malformed row is skipped, never partially
/// applied.
fn process_tree(state: &mut BotState, payload: &str) {
    let mut rows = Vec::new();
    for line in payload.split('\n').filter(|l| !l.is_empty()) {
        if rows.len() >= MAX_BOT_TREE_ROWS {
            break;
        }
        let b = line.as_bytes();
        if b.len() < 2 || b[1] != b'|' {
            continue;
        }
        let f: Vec<&str> = line[2..].splitn(9, '|').take(8).collect();
        let n = f.len();
        let mut row = BotTreeRow {
            kind: (b[0] as char).to_ascii_lowercase(),
            ..BotTreeRow::default()
        };
        match row.kind {
            'h' if n >= 5 => {
                row.depth = atoi(f[0]);
                row.name = trunc_string(f[1], TREE_NAME_MAX);
                row.uuid = trunc_string(f[2], 64);
                row.online = atoi(f[3]) != 0;
                row.uptime = atoll(f[4]);
                if n >= 6 && f[5] != "-" {
                    row.version = trunc_string(f[5], TREE_VERSION_MAX + 1);
                }
                // The code base (c / rs) came after it; blank if absent.
                if n >= 7 && f[6] != "-" {
                    row.variant = trunc_string(f[6], TREE_VARIANT_MAX + 1);
                }
            }
            'b' if n >= 6 => {
                row.depth = atoi(f[0]);
                row.name = trunc_string(f[1], TREE_NAME_MAX);
                row.uuid = trunc_string(f[2], 64);
                if f[3] != "-" {
                    row.version = trunc_string(f[3], TREE_VERSION_MAX + 1);
                }
                if f[4] != "-" {
                    row.server = trunc_string(f[4], TREE_SERVER_MAX + 1);
                }
                row.uptime = atoll(f[5]);
                if n >= 7 && f[6] != "-" {
                    row.variant = trunc_string(f[6], TREE_VARIANT_MAX + 1);
                }
                row.online = true;
            }
            'd' if n >= 3 => {
                row.name = trunc_string(f[0], TREE_NAME_MAX);
                row.uuid = trunc_string(f[1], 64);
                row.uptime = atoll(f[2]); // last seen, not a duration
                row.online = false;
            }
            _ => continue,
        }
        if row.name == "-" {
            row.name.clear();
        }
        if !(0..=8).contains(&row.depth) {
            row.depth = 0;
        }
        rows.push(row);
    }
    state.bot_tree = rows;
    state.bot_tree_ts = now();
}

/// One key=value change as CMD_BOT_DELTA (the hub fans it out as one delta
/// per peer instead of a full config push).
pub fn push_delta(state: &mut BotState, key: &str, value: &str, ts: i64) -> bool {
    if key.is_empty() || !link_ready(state) {
        return false;
    }
    let payload = format!("{}|{}|{}", key, value, if ts != 0 { ts } else { now() });
    if payload.len() >= MAX_BUFFER {
        return false;
    }
    if send_frame(state, CMD_BOT_DELTA, payload.as_bytes()) {
        logm!(
            state,
            L_DEBUG,
            "[HUB] Delta pushed: {}={} ts={}\n",
            key,
            value,
            ts
        );
        true
    } else {
        logm!(state, L_INFO, "[HUB] Delta push failed, falling back\n");
        false
    }
}

fn chan_line(c: &crate::state::Chan) -> String {
    format!(
        "c|{}|{}|{}|{}|{}\n",
        c.name,
        c.key,
        c.modes as i32,
        if c.is_managed { "add" } else { "del" },
        c.timestamp
    )
}

/// The bot's own config for the hub: c| (unless opt 'h'), v|, h|, n|.
/// a|/o|/m| are hub-authoritative and go via push_admin_delta; s|, u|, g|,
/// l|, i|, k| are local-only.
pub fn generate_config_payload(state: &BotState) -> String {
    let max = MAX_BUFFER - 64;
    let mut out = String::new();
    if !state.is_opt_set(OPT_HUB_ONLY_MUTATIONS) {
        for c in &state.chans {
            logm!(
                state,
                L_DEBUG,
                "[HUB-PUSH] Channel {}: is_managed={} op={} ts={}\n",
                c.name,
                c.is_managed as i32,
                if c.is_managed { "add" } else { "del" },
                c.timestamp
            );
            let l = chan_line(c);
            if out.len() + l.len() >= max {
                break;
            }
            out.push_str(&l);
        }
    }
    let mut add = |s: String| {
        if out.len() + s.len() < max {
            out.push_str(&s);
        }
    };
    // Protocol capability (passwordless.md 3.4); the ts field is unused.
    add(format!("v|{}|{}\n", BOT_PROTO_VERSION, 1));
    // Stable timestamps: now() here would make every push look new.
    if !state.actual_hostname.is_empty() && state.actual_hostname_ts > 0 {
        add(format!(
            "h|{}|{}\n",
            state.actual_hostname, state.actual_hostname_ts
        ));
    }
    if !state.current_nick.is_empty() && state.current_nick_ts > 0 {
        add(format!(
            "n|{}|{}\n",
            state.current_nick, state.current_nick_ts
        ));
    }
    out
}

/// Ask a bot for ops through the hub; false means fall back to PRIVMSG.
pub fn request_op(state: &mut BotState, target_uuid: &str, channel: &str) -> bool {
    if !state.hub_connected
        || !state.hub_authenticated
        || state.hub.is_none()
        || target_uuid == state.bot_uuid
    {
        return false;
    }
    let payload = trunc_string(&format!("{target_uuid}|{channel}"), 256);
    logm!(
        state,
        L_INFO,
        "[HUB] Requesting ops via hub: target={} chan={}\n",
        target_uuid,
        channel
    );
    send_frame(state, CMD_OP_REQUEST, payload.as_bytes())
}

/// Route a sealed "~B2 <b64>" to a bot by UUID; the hub forwards it
/// opaquely as "<sender_uuid>|~B2 <b64>".
pub fn relay_bot_command(state: &mut BotState, target_uuid: &str, frame_line: &str) -> bool {
    if !state.hub_connected || !state.hub_authenticated || state.hub.is_none() {
        return false;
    }
    let payload = format!("{target_uuid}|{frame_line}");
    if payload.len() >= MAX_BUFFER || !send_frame(state, CMD_BOT_RELAY, payload.as_bytes()) {
        return false;
    }
    logm!(
        state,
        L_DEBUG,
        "[BOT-COMM] CMD_BOT_RELAY sent to hub for {}\n",
        target_uuid
    );
    true
}

/// CMD_INVITE_REQUEST: the hub broadcasts it to every bot.
pub fn send_invite_request(state: &mut BotState, nick: &str, channel: &str) -> bool {
    if !state.hub_connected || !state.hub_authenticated || state.hub.is_none() {
        return false;
    }
    let payload = format!("{nick}|{channel}");
    if payload.len() >= 256 {
        return false;
    }
    if send_frame(state, CMD_INVITE_REQUEST, payload.as_bytes()) {
        logm!(
            state,
            L_INFO,
            "[HUB] Sent INVITE_REQUEST for {} in {}\n",
            nick,
            channel
        );
        return true;
    }
    false
}

/// kind|channel only: the hub resolves our nick and mask itself.
pub fn send_chan_request(state: &mut BotState, kind: &str, channel: &str) -> bool {
    if !state.hub_connected || !state.hub_authenticated || state.hub.is_none() {
        return false;
    }
    let payload = format!("{kind}|{channel}");
    if payload.len() >= MAX_CHAN + 16 || !send_frame(state, CMD_CHAN_REQUEST, payload.as_bytes()) {
        return false;
    }
    logm!(
        state,
        L_INFO,
        "[CHANREQ] Sent {} request for {} to hub\n",
        kind,
        channel
    );
    true
}

/// Answer a channel-access request (today only `key`); the payload carries
/// the key and is wiped.
pub fn send_chan_reply(
    state: &mut BotState,
    request_id: &str,
    kind: &str,
    channel: &str,
    status: &str,
    data: &str,
) -> bool {
    if !state.hub_connected || !state.hub_authenticated || state.hub.is_none() {
        return false;
    }
    let payload = Zeroizing::new(format!("{request_id}|{kind}|{channel}|{status}|{data}"));
    if payload.len() >= MAX_CHAN + MAX_KEY + 96 {
        return false;
    }
    send_frame(state, CMD_CHAN_REPLY, payload.as_bytes())
}

/// Push every user/mask record (CMD_CONFIG_PUSH, split at line boundaries);
/// the hub keeps only newer stamps.  With no link the push is remembered in
/// admin_delta_pending and made after the next authentication.
pub fn push_admin_delta(state: &mut BotState) {
    if !state.hub_authenticated || state.hub.is_none() {
        if !state.hubs.is_empty() && !state.admin_delta_pending {
            state.admin_delta_pending = true;
            config::write_local_with_state_pass(state);
        }
        return;
    }
    state.admin_delta_pending = true;
    state.config_dirty = true;

    let chunk_cap = MAX_BUFFER - 64;
    let line_cap = CFG_MASK_LINE_MAX.max(CFG_USER_LINE_MAX);
    let mut lines: Vec<String> = state
        .user_records
        .iter()
        .map(config::format_user_line)
        .collect();
    lines.extend(state.mask_records.iter().map(config::format_mask_line));
    let mut payload = String::new();
    let mut frames = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.len() >= line_cap {
            logm!(
                state,
                L_INFO,
                "[HUB] Admin delta: record {} too long; skipped\n",
                i
            );
            continue;
        }
        if payload.len() + line.len() > chunk_cap {
            if !send_frame(state, CMD_CONFIG_PUSH, payload.as_bytes()) {
                return;
            }
            frames += 1;
            payload.clear();
        }
        payload.push_str(line);
    }
    if !payload.is_empty() {
        if !send_frame(state, CMD_CONFIG_PUSH, payload.as_bytes()) {
            return;
        }
        frames += 1;
    }
    state.admin_delta_pending = false;
    if frames > 0 {
        logm!(
            state,
            L_INFO,
            "[HUB] Admin delta pushed ({} user, {} mask records, {} frame{})\n",
            state.user_records.len(),
            state.mask_records.len(),
            frames,
            if frames == 1 { "" } else { "s" }
        );
    }
}

/// Push this bot's own config (after authentication, after changes).
pub fn push_config(state: &mut BotState) {
    if !link_ready(state) {
        logm!(
            state,
            L_DEBUG,
            "[HUB-PUSH] Skipped push: hub_count={} hub_fd={} auth={}\n",
            state.hubs.len(),
            if state.hub.is_some() { 1 } else { -1 },
            state.hub_authenticated as i32
        );
        return;
    }
    let payload = generate_config_payload(state);
    if payload.is_empty() {
        logm!(state, L_DEBUG, "[HUB] No config to push\n");
        return;
    }
    logm!(
        state,
        L_DEBUG,
        "[HUB-SYNC] Pushing config to hub ({} bytes)\n",
        payload.len()
    );
    if send_frame(state, CMD_CONFIG_PUSH, payload.as_bytes()) {
        logm!(state, L_INFO, "[HUB] Config pushed to hub\n");
    } else {
        logm!(state, L_INFO, "[HUB] Failed to push config\n");
    }
}

/// Push one channel after a live MODE change.
pub fn push_channel(state: &mut BotState, ci: usize) {
    if !link_ready(state) {
        return;
    }
    let Some(c) = state.chans.get(ci) else { return };
    let (payload, name, modes) = (chan_line(c), c.name.clone(), c.modes as i32);
    if payload.len() >= MAX_BUFFER {
        return;
    }
    if send_frame(state, CMD_CONFIG_PUSH, payload.as_bytes()) {
        logm!(
            state,
            L_INFO,
            "[HUB] Pushed channel {} modes={} to hub\n",
            name,
            modes
        );
    } else {
        logm!(state, L_INFO, "[HUB] Failed to push channel {}\n", name);
    }
}

/// PURGE|<cutoff>: drop tombstones stamped before cutoff (0: all).
fn apply_purge(state: &mut BotState, arg: &str) -> usize {
    let cutoff = match arg
        .trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r'])
        .parse::<i64>()
    {
        Ok(v) if v >= 0 => v,
        _ => {
            logm!(state, L_INFO, "[HUB] Rejected malformed PURGE line\n");
            return 0;
        }
    };
    let old = |ts: i64| cutoff == 0 || ts < cutoff;
    let before = state.chans.len() + state.user_records.len() + state.mask_records.len();
    state.chans.retain(|c| c.is_managed || !old(c.timestamp));
    state
        .user_records
        .retain(|u| u.is_active || !old(u.timestamp));
    state
        .mask_records
        .retain(|m| m.is_active || !old(m.timestamp));
    let purged = before - (state.chans.len() + state.user_records.len() + state.mask_records.len());
    if purged > 0 {
        logm!(
            state,
            L_INFO,
            "[HUB] Purged {} tombstoned entries\n",
            purged
        );
        config::write_with_state_pass(state);
    }
    purged
}

fn set<'a>(r: &[Conv<'a>], i: usize) -> Option<Conv<'a>> {
    r.get(i).copied()
}

/// c| from the hub: chan|key|modes|op|ts, chan||modes|op|ts, or the older
/// chan|key|op|ts / chan||op|ts.  Variables carry over between the attempts
/// exactly as the chained sscanf calls in hub_client.c do.
fn parse_hub_chan(data: &str) -> Option<(String, String, u32, String, i64)> {
    let (mut chan, mut key, mut op) = ("", "", "");
    let (mut modes, mut ts) = (0i64, 0i64);
    let r = sscanf(
        data,
        &[
            Fmt::Set(64, P),
            Fmt::Lit("|"),
            Fmt::Set(30, P),
            Fmt::Lit("|"),
            Fmt::Int,
            Fmt::Lit("|"),
            Fmt::Set(7, P),
            Fmt::Lit("|"),
            Fmt::Int,
        ],
    );
    if let Some(v) = set(&r, 0) {
        chan = v.s();
    }
    if let Some(v) = set(&r, 1) {
        key = v.s();
    }
    if let Some(v) = set(&r, 2) {
        modes = v.i();
    }
    if let Some(v) = set(&r, 3) {
        op = v.s();
    }
    if let Some(v) = set(&r, 4) {
        ts = v.i();
    }
    let mut parsed = r.len();
    if parsed < 5 {
        modes = 0;
        let r = sscanf(
            data,
            &[
                Fmt::Set(64, P),
                Fmt::Lit("||"),
                Fmt::Int,
                Fmt::Lit("|"),
                Fmt::Set(7, P),
                Fmt::Lit("|"),
                Fmt::Int,
            ],
        );
        if let Some(v) = set(&r, 0) {
            chan = v.s();
        }
        if let Some(v) = set(&r, 1) {
            modes = v.i();
        }
        if let Some(v) = set(&r, 2) {
            op = v.s();
        }
        if let Some(v) = set(&r, 3) {
            ts = v.i();
        }
        parsed = r.len();
        if parsed >= 4 {
            key = "";
        } else {
            modes = 0;
            let r = sscanf(
                data,
                &[
                    Fmt::Set(64, P),
                    Fmt::Lit("|"),
                    Fmt::Set(30, P),
                    Fmt::Lit("|"),
                    Fmt::Set(7, P),
                    Fmt::Lit("|"),
                    Fmt::Int,
                ],
            );
            if let Some(v) = set(&r, 0) {
                chan = v.s();
            }
            if let Some(v) = set(&r, 1) {
                key = v.s();
            }
            if let Some(v) = set(&r, 2) {
                op = v.s();
            }
            if let Some(v) = set(&r, 3) {
                ts = v.i();
            }
            parsed = r.len();
            if parsed < 3 {
                let r = sscanf(
                    data,
                    &[
                        Fmt::Set(64, P),
                        Fmt::Lit("||"),
                        Fmt::Set(7, P),
                        Fmt::Lit("|"),
                        Fmt::Int,
                    ],
                );
                if let Some(v) = set(&r, 0) {
                    chan = v.s();
                }
                if let Some(v) = set(&r, 1) {
                    op = v.s();
                }
                if let Some(v) = set(&r, 2) {
                    ts = v.i();
                }
                parsed = r.len();
                key = "";
            }
        }
    }
    (parsed >= 3).then(|| {
        (
            chan.to_string(),
            key.to_string(),
            modes as i32 as u32,
            op.to_string(),
            ts,
        )
    })
}

fn sync_channel_line(state: &mut BotState, data: &str) -> bool {
    let Some((chan, key, modes, op, ts)) = parse_hub_chan(data) else {
        return false;
    };
    let is_add = op == "add";
    let ci = channel::find(state, &chan);
    logm!(
        state,
        L_DEBUG,
        "[HUB-SYNC] Channel {}: hub_ts={} local_ts={} op={}\n",
        chan,
        ts,
        ci.map_or(0, |i| state.chans[i].timestamp),
        op
    );
    match ci {
        None if is_add => {
            let Some(ci) = channel::add(state, &chan) else {
                return false;
            };
            let c = &mut state.chans[ci];
            if !key.is_empty() {
                c.key = trunc_string(&key, MAX_KEY);
            }
            c.modes = modes;
            c.is_managed = true;
            c.timestamp = ts;
            logm!(state, L_INFO, "[HUB] Added channel: {}\n", chan);
            true
        }
        None => {
            logm!(
                state,
                L_DEBUG,
                "[HUB-SYNC] Skipped del for non-existent channel: {}\n",
                chan
            );
            false
        }
        Some(ci) => {
            let c = &state.chans[ci];
            if !lww_accepts(ts, is_add, c.timestamp, c.is_managed) {
                logm!(
                    state,
                    L_DEBUG,
                    "[HUB-SYNC] Rejected channel {}: hub_ts={} local_ts={} (not newer)\n",
                    chan,
                    ts,
                    c.timestamp
                );
                return false;
            }
            let c = &mut state.chans[ci];
            if !key.is_empty() {
                c.key = trunc_string(&key, MAX_KEY);
            }
            c.modes = modes;
            let was_managed = c.is_managed;
            c.is_managed = is_add;
            c.timestamp = ts;
            let (status, ckey) = (c.status, c.key.clone());
            logm!(state, L_INFO, "[HUB] Updated channel: {} ({})\n", chan, op);
            if was_managed && !is_add && status == ChanStatus::In {
                logm!(
                    state,
                    L_INFO,
                    "[HUB] Parting channel {} (synced del)\n",
                    chan
                );
                ircf!(state, "PART {} :Hub sync\r\n", chan);
                if let Some(c) = state.chans.get_mut(ci) {
                    c.status = ChanStatus::Out;
                }
            }
            if !was_managed && is_add && status != ChanStatus::In {
                logm!(
                    state,
                    L_INFO,
                    "[HUB] Joining channel {} (synced add)\n",
                    chan
                );
                if ckey.is_empty() {
                    ircf!(state, "JOIN {}\r\n", chan);
                } else {
                    ircf!(state, "JOIN {} {}\r\n", chan, ckey);
                }
            }
            true
        }
    }
}

fn sync_mask_line(state: &mut BotState, data: &str) -> bool {
    let first = data
        .find('|')
        .map(|p| &data[..p])
        .filter(|f| f.len() < 40)
        .unwrap_or("");
    if !has_uuid_dashes(first) {
        return false;
    }
    let f: Vec<&str> = data.splitn(5, '|').collect();
    if f.len() < 5 {
        return false;
    }
    let uuid = trunc_string(f[0], UUID_BUF);
    let mask = trunc_string(f[1], MAX_MASK_LEN);
    let act = trunc_string(f[2], 8);
    let (last_used, ts) = (atoll(f[3]), atoll(f[4]));
    let is_active = act.starts_with("add");
    let mut mi = state
        .mask_records
        .iter()
        .position(|m| m.uuid == uuid && eq_ic(&m.mask, &mask));
    if mi.is_none() && state.mask_records.len() < MAX_USER_MASKS {
        state.mask_records.push(MaskRecord {
            uuid: uuid.clone(),
            mask: mask.clone(),
            ..MaskRecord::default()
        });
        mi = Some(state.mask_records.len() - 1);
    }
    let Some(mi) = mi else { return false };
    let m = &mut state.mask_records[mi];
    if !lww_accepts(ts, is_active, m.timestamp, m.is_active) {
        return false;
    }
    m.is_active = is_active;
    if last_used > m.last_used {
        m.last_used = last_used;
    }
    m.timestamp = ts;
    logm!(state, L_INFO, "[HUB] Synced mask {} ({})\n", mask, act);
    true
}

fn sync_user_line(state: &mut BotState, typ: char, data: &str) -> bool {
    let Some(ul) = config::parse_user_line(data) else {
        logm!(
            state,
            L_DEBUG,
            "[HUB-SYNC] Malformed {}| record ignored\n",
            typ
        );
        return false;
    };
    let mut ui = state.user_records.iter().position(|u| u.uuid == ul.uuid);
    if ui.is_none() && state.user_records.len() < MAX_USER_RECORDS {
        state.user_records.push(UserRecord {
            uuid: ul.uuid.clone(),
            typ: '\0',
            ..UserRecord::default()
        });
        ui = Some(state.user_records.len() - 1);
    }
    let Some(ui) = ui else { return false };
    let u = &mut state.user_records[ui];
    if !lww_accepts(ul.timestamp, ul.is_active, u.timestamp, u.is_active) {
        return false;
    }
    u.name = ul.name.clone();
    // The hub is authoritative for the key too: keyless stays keyless.
    u.pubkey_b64 = ul.pubkey_b64.clone();
    u.has_pubkey = ul.has_pubkey;
    u.typ = typ;
    u.is_active = ul.is_active;
    if ul.last_seen > u.last_seen {
        u.last_seen = ul.last_seen;
    }
    u.timestamp = ul.timestamp;
    logm!(
        state,
        L_INFO,
        "[HUB] Synced user {} ({}/{}{})\n",
        ul.name,
        typ,
        if ul.is_active { "add" } else { "del" },
        if ul.has_pubkey { "" } else { ", no key" }
    );
    true
}

fn sync_bot_line(state: &mut BotState, data: &str, listed: &mut Vec<String>) -> bool {
    let Some(mut inb) = config::parse_bot_line(data) else {
        // Never stored truncated: a clipped mask or uuid mis-keys matches.
        logm!(
            state,
            L_INFO,
            "[HUB] Rejected malformed/oversized trusted-bot line\n"
        );
        return false;
    };
    if !inb.uuid.is_empty() && listed.len() < MAX_TRUSTED_BOTS {
        listed.push(inb.uuid.clone());
    }
    // Prefer the UUID (survives nick/host changes) and sweep duplicates of
    // it; fall back to the exact mask.
    let mut existing: Option<usize> = None;
    if !inb.uuid.is_empty() {
        let mut i = 0;
        while i < state.trusted_bots.len() {
            if state.trusted_bots[i].uuid != inb.uuid {
                i += 1;
                continue;
            }
            if existing.is_none() {
                existing = Some(i);
                i += 1;
            } else {
                state.trusted_bots.remove(i);
            }
        }
    }
    if existing.is_none() {
        existing = state.trusted_bots.iter().position(|t| t.mask == inb.mask);
    }
    match existing {
        Some(ei) => {
            let ex = &state.trusted_bots[ei];
            let key_is_new = inb.has_pub && (!ex.has_pub || ex.pub_key != inb.pub_key);
            // ts = max(hostmask ts, key ts) on the hub, so a rekey alone
            // bumps it; the tie case covers a keyless legacy line first.
            if inb.ts > ex.ts || (inb.ts == ex.ts && key_is_new) {
                if !inb.has_pub && ex.has_pub && ex.uuid == inb.uuid {
                    // Legacy-shaped line (hub has not seen our v|2): keep ours.
                    inb.has_pub = true;
                    inb.pub_key = ex.pub_key;
                }
                let mask = inb.mask.clone();
                state.trusted_bots[ei] = inb;
                logm!(
                    state,
                    L_INFO,
                    "[HUB] Updated trusted bot: {}{}\n",
                    mask,
                    if key_is_new { " (new key)" } else { "" }
                );
                return true;
            }
            false
        }
        None if state.trusted_bots.len() < MAX_TRUSTED_BOTS => {
            logm!(
                state,
                L_INFO,
                "[HUB] Added trusted bot: {}{}\n",
                inb.mask,
                if inb.has_pub { "" } else { " (no key yet)" }
            );
            state.trusted_bots.push(inb);
            true
        }
        None => false,
    }
}

/// CMD_CONFIG_DATA from the hub.  The hub is authoritative for user and
/// mask records: a payload carrying a|/o| (or m|) lines replaces that table
/// (keeping newer local last_seen / last_used); a T| marker makes the b|
/// lines the whole trusted set.  Saved locally, never echoed back.
pub fn process_config_data(state: &mut BotState, payload: &str) {
    logm!(
        state,
        L_DEBUG,
        "[HUB-SYNC] Processing config data from hub\n"
    );
    let mut has_user_lines = false;
    let mut has_mask_lines = false;
    let mut has_trust_set = false;
    for l in payload.split('\n') {
        let b = l.as_bytes();
        if b.len() >= 2 && b[1] == b'|' {
            match b[0] {
                b'a' | b'o' => has_user_lines = true,
                b'm' => has_mask_lines = true,
                b'T' => has_trust_set = true,
                _ => {}
            }
        }
    }
    let saved_users = state.user_records.clone();
    let saved_masks = state.mask_records.clone();
    if has_user_lines {
        state.user_records.clear();
    }
    if has_mask_lines {
        state.mask_records.clear();
    }

    let work = crate::cstr::trunc(payload, MAX_CONFIG_PAYLOAD);
    let mut listed: Vec<String> = Vec::new();
    let mut updates = 0;
    for line in work.split('\n').filter(|l| !l.is_empty()) {
        if line.len() < 2 || line.starts_with('#') {
            continue;
        }
        // PURGE is the one line whose type is a word, not a letter.
        if let Some(arg) = line.strip_prefix("PURGE|") {
            apply_purge(state, arg);
            continue;
        }
        let b = line.as_bytes();
        if b[1] != b'|' {
            continue;
        }
        let data = &line[2..];
        let applied = match b[0] {
            b'c' => sync_channel_line(state, data),
            b'm' => sync_mask_line(state, data),
            b'a' | b'o' => sync_user_line(state, b[0] as char, data),
            b'O' => match config::parse_opt_line(data) {
                Some((flags, ts))
                    if opt_accepts(ts, &flags, state.opt_flags_ts, &state.opt_flags) =>
                {
                    state.opt_flags = flags;
                    state.opt_flags_ts = if ts > 0 { ts } else { now() };
                    logm!(
                        state,
                        L_INFO,
                        "[HUB-SYNC] opt flags updated -> '{}'\n",
                        state.opt_flags
                    );
                    true
                }
                _ => false,
            },
            b'p' => {
                logm!(state, L_DEBUG, "[HUB-SYNC] Ignored retired p| line\n");
                false
            }
            b'b' => sync_bot_line(state, data, &mut listed),
            b'T' => false, // end of the complete trusted-bot list: swept below
            other => {
                logm!(
                    state,
                    L_DEBUG,
                    "[HUB-SYNC] Unrecognized line type '{}': {}\n",
                    other as char,
                    line
                );
                false
            }
        };
        if applied {
            updates += 1;
        }
    }

    if has_trust_set {
        let mut i = 0;
        while i < state.trusted_bots.len() {
            let tb = &state.trusted_bots[i];
            if !tb.uuid.is_empty() && listed.contains(&tb.uuid) {
                i += 1;
                continue;
            }
            logm!(
                state,
                L_INFO,
                "[HUB] Revoked trusted bot: {} ({}) - no longer registered on the hub\n",
                tb.mask,
                if tb.uuid.is_empty() {
                    "no uuid"
                } else {
                    tb.uuid.as_str()
                }
            );
            state.trusted_bots.remove(i);
            updates += 1;
        }
    }

    // Keep locally newer last_seen / last_used (auths not yet pushed).
    for u in &mut state.user_records {
        if let Some(s) = saved_users.iter().find(|s| s.uuid == u.uuid)
            && s.last_seen > u.last_seen
        {
            u.last_seen = s.last_seen;
        }
    }
    for m in &mut state.mask_records {
        if let Some(s) = saved_masks
            .iter()
            .find(|s| s.uuid == m.uuid && eq_ic(&s.mask, &m.mask))
            && s.last_used > m.last_used
        {
            m.last_used = s.last_used;
        }
    }

    if updates > 0 {
        logm!(
            state,
            L_INFO,
            "[HUB] Applied {} config updates from hub\n",
            updates
        );
        // Local only: echoing hub records back would loop forever.
        config::write_local_with_state_pass(state);
    } else {
        logm!(
            state,
            L_DEBUG,
            "[HUB-SYNC] No updates applied (all timestamps older or equal)\n"
        );
    }
}

fn handle_response(state: &mut BotState, cmd: u8, payload: &str) {
    match cmd {
        CMD_PING => {
            if !HIDEPINGPONG {
                logm!(state, L_DEBUG, "[HUB] Received PING from hub\n");
            }
        }
        CMD_BOT_TREE => process_tree(state, payload),
        CMD_CONFIG_PULL => logm!(state, L_INFO, "[HUB] Hub requested config sync\n"),
        CMD_CONFIG_DATA => {
            logm!(
                state,
                L_INFO,
                "[HUB] Received config from hub ({} bytes)\n",
                payload.len()
            );
            if !payload.is_empty() {
                process_config_data(state, payload);
            }
        }
        CMD_UPDATE_PUBKEY => {}
        CMD_BOT_KEY_UPDATE => {
            // Private keys never cross the wire; rekey is bot-local.
            logm!(
                state,
                L_INFO,
                "[HUB] Rejected CMD_BOT_KEY_UPDATE: per-bot independent keys; private keys do not cross the wire.\n"
            );
        }
        CMD_OP_GRANT => {
            // requester_hostmask|channel
            let r = sscanf(payload, &[Fmt::Set(255, P), Fmt::Lit("|"), Fmt::Word(64)]);
            if r.len() != 2 {
                logm!(state, L_INFO, "[HUB] Invalid OP_GRANT payload\n");
                return;
            }
            let (hostmask, chan) = (r[0].s(), r[1].s());
            let nick = crate::cstr::mask_nick(hostmask, MAX_NICK).to_string();
            match channel::find(state, chan) {
                Some(ci) if state.chans[ci].status == ChanStatus::In => {
                    if state.chans[ci].i_am_opped {
                        logm!(
                            state,
                            L_INFO,
                            "[HUB] Granting ops to {} in {} (hub request)\n",
                            nick,
                            chan
                        );
                        ircf!(state, "MODE {} +o {}\r\n", chan, nick);
                    } else {
                        logm!(
                            state,
                            L_INFO,
                            "[HUB] Cannot grant ops to {} in {} - I'm not opped\n",
                            nick,
                            chan
                        );
                    }
                }
                _ => logm!(
                    state,
                    L_INFO,
                    "[HUB] Cannot grant ops - not in channel {}\n",
                    chan
                ),
            }
        }
        CMD_OP_FAILED => {
            logm!(state, L_INFO, "[HUB] Op request failed: {}\n", payload);
            // Clear pending so the channel manager retries in ~30 s.
            let t = now() - 30;
            for c in state.chans.iter_mut().filter(|c| c.op_request_pending) {
                c.op_request_pending = false;
                c.last_op_request_time = t;
            }
        }
        CMD_INVITE_REQUEST => {
            let r = sscanf(
                payload,
                &[Fmt::Set(9, P), Fmt::Lit("|"), Fmt::Set(64, b"\n")],
            );
            if r.len() == 2 {
                let (nick, chan) = (r[0].s(), r[1].s());
                if let Some(ci) = channel::find(state, chan)
                    && state.chans[ci].status == ChanStatus::In
                    && state.chans[ci].i_am_opped
                {
                    logm!(
                        state,
                        L_INFO,
                        "[INVITE] Inviting {} into {} (hub request)\n",
                        nick,
                        chan
                    );
                    ircf!(state, "INVITE {} {}\r\n", nick, chan);
                }
            }
        }
        CMD_CHAN_ACTION => {
            // id|kind|channel|requester_uuid|nick|hostmask -- all past the
            // kind filled in by the hub from its own records.
            let r = sscanf(
                payload,
                &[
                    Fmt::Set(63, P),
                    Fmt::Lit("|"),
                    Fmt::Set(15, P),
                    Fmt::Lit("|"),
                    Fmt::Set(64, P),
                    Fmt::Lit("|"),
                    Fmt::Set(63, P),
                    Fmt::Lit("|"),
                    Fmt::Set(9, P),
                    Fmt::Lit("|"),
                    Fmt::Set(255, P),
                ],
            );
            if r.len() < 4 {
                logm!(state, L_INFO, "[CHANREQ] Malformed CHAN_ACTION\n");
                return;
            }
            let (id, kind, chan) = (r[0].s(), r[1].s(), r[2].s());
            let nick = r.get(4).map_or("", |c| c.s());
            let mask = r.get(5).map_or("", |c| c.s());
            match ChanReq::from_token(kind) {
                Some(k) => {
                    channel::access_service(state, id, k, chan, Some(nick), Some(mask), None)
                }
                None => logm!(
                    state,
                    L_DEBUG,
                    "[DEBUG] [CHANREQ] Unknown action kind '{}'\n",
                    kind
                ),
            }
        }
        CMD_CHAN_REPLY => {
            // id|kind|channel|status|data; data is everything after the
            // 4th '|', never re-split (a key may contain one).
            let r = sscanf(
                payload,
                &[
                    Fmt::Set(63, P),
                    Fmt::Lit("|"),
                    Fmt::Set(15, P),
                    Fmt::Lit("|"),
                    Fmt::Set(64, P),
                    Fmt::Lit("|"),
                    Fmt::Set(15, P),
                ],
            );
            if r.len() == 4 {
                let (kind, chan, status) = (r[1].s(), r[2].s(), r[3].s());
                let data = payload.splitn(5, '|').nth(4).unwrap_or("");
                if ChanReq::from_token(kind) == Some(ChanReq::Key) && status == "ok" {
                    channel::access_accept_key(state, chan, data);
                } else {
                    logm!(
                        state,
                        L_DEBUG,
                        "[DEBUG] [CHANREQ] Reply {} for {}: {}\n",
                        kind,
                        chan,
                        status
                    );
                }
            }
        }
        CMD_UPGRADE_PREPARE if !payload.is_empty() => handle_upgrade_prepare(state, payload),
        CMD_UPGRADE_COMMIT if !payload.is_empty() => handle_upgrade_commit(state, payload),
        CMD_UPGRADE_ABORT if !payload.is_empty() => handle_upgrade_abort(state, payload),
        CMD_BOT_MSG if !payload.is_empty() => {
            logm!(
                state,
                L_DEBUG,
                "[BOT-COMM] Received relayed bot command via hub ({} bytes)\n",
                payload.len()
            );
            bot_comms::process_payload(state, payload);
        }
        _ => {}
    }
}

/// Dial a random configured hub (blocking connect, 10 s) and send our UUID.
pub fn connect(state: &mut BotState) {
    if state.hubs.is_empty() || state.hub.is_some() || state.hub_connecting {
        return;
    }
    let hold = |state: &mut BotState| state.last_hub_connect_attempt = now() + 3600;
    if state.bot_uuid.is_empty() {
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect: UUID not set (it is generated at bot creation — re-run 'ircbot -setup').\n"
        );
        hold(state);
        return;
    }
    if !has_uuid_dashes(&state.bot_uuid) {
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect: Invalid UUID format ({}). Re-run 'ircbot -setup' to regenerate identity.\n",
            state.bot_uuid
        );
        hold(state);
        return;
    }
    if state.hub_key.is_empty() {
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect: bot keypair not set (generated at creation — re-run 'ircbot -setup').\n"
        );
        hold(state);
        return;
    }
    if state.hub_key.len() != COMBINED_KEY_B64 {
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect: bot key length wrong ({} chars, need {}). Re-run 'ircbot -setup' to regenerate identity.\n",
            state.hub_key.len(),
            COMBINED_KEY_B64
        );
        hold(state);
        return;
    }
    if state.hubs[0].addr.is_empty() {
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect: No hubs configured. Use '+hub <host:port> <pubkey>'.\n"
        );
        hold(state);
        return;
    }
    let now = now();
    if now - state.last_hub_connect_attempt < HUB_RECONNECT_DELAY {
        return;
    }
    state.last_hub_connect_attempt = now;
    state.hub_connecting = true;
    let idx = crypto::random_index(state.hubs.len());
    let hub_original = state.hubs[idx].addr.clone();

    // Authenticate against this hub's own pinned key, or not at all.
    if state.hubs[idx].ed_pub_set {
        state.hub_remote_ed_pub = state.hubs[idx].ed_pub;
        state.hub_remote_ed_pub_set = true;
    } else {
        state.hub_remote_ed_pub_set = false;
        logm!(
            state,
            L_INFO,
            "[HUB] Cannot connect to {}: no pinned pubkey. Re-add with '+hub {} <pubkey>'.\n",
            hub_original,
            hub_original
        );
        state.hub_connecting = false;
        state.last_hub_connect_attempt = crate::cstr::now() + 60;
        return;
    }
    let Some(colon) = hub_original.rfind(':') else {
        logm!(
            state,
            L_INFO,
            "[HUB] Invalid hub address (missing port): {}\n",
            hub_original
        );
        state.hub_connecting = false;
        return;
    };
    let (host, port) = (&hub_original[..colon], &hub_original[colon + 1..]);
    let addrs = match net::resolve(host, port) {
        Ok(a) => a,
        Err(e) => {
            logm!(
                state,
                L_INFO,
                "[HUB] Cannot resolve hub address '{}': {}\n",
                host,
                e
            );
            state.hub_connecting = false;
            return;
        }
    };
    let mut stream = None;
    for addr in &addrs {
        let Ok(sock) = net::new_socket(addr, None) else {
            continue;
        };
        if let Ok(s) = net::connect_timeout(sock, addr, CONNECT_TIMEOUT_SECS) {
            stream = Some(s);
            break;
        }
    }
    let Some(stream) = stream else {
        logm!(
            state,
            L_INFO,
            "[HUB] Failed to connect to {}:{}\n",
            host,
            port
        );
        state.hub_connecting = false;
        return;
    };
    let token = state.new_token(net::SLOT_HUB);
    let sock = match net::into_mio(stream).and_then(|mut s| {
        state
            .registry
            .register(&mut s, token, net::INTEREST)
            .map(|_| s)
    }) {
        Ok(s) => s,
        Err(e) => {
            logm!(
                state,
                L_INFO,
                "[HUB] Could not register hub socket: {}\n",
                e
            );
            state.hub_connecting = false;
            return;
        }
    };
    state.hub = Some(HubConn {
        sock,
        token,
        rbuf: Vec::new(),
        wbuf: Vec::new(),
    });
    state.hub_connected = true;
    state.hub_authenticated = false;
    state.hub_auth_state = HubAuthState::None;
    state.current_hub = hub_original;

    let uuid = state.bot_uuid.clone();
    let mut frame = (uuid.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(uuid.as_bytes());
    if send_raw(state, &frame) {
        state.hub_auth_state = HubAuthState::SentUuid;
        logm!(state, L_INFO, "[HUB] Connected to {}.\n", state.current_hub);
    }
    state.hub_connecting = false;
}

/// A poll event for the hub socket.
pub fn handle_event(state: &mut BotState, token: mio::Token, readable: bool, writable: bool) {
    if state.hub.as_ref().map(|h| h.token) != Some(token) {
        return;
    }
    if writable {
        let res = state
            .hub
            .as_mut()
            .map(|h| net::flush(&mut h.sock, &mut h.wbuf));
        if let Some(Err(_)) = res {
            disconnect(state);
            return;
        }
    }
    if !readable {
        return;
    }
    loop {
        let outcome = {
            let Some(h) = state.hub.as_mut().filter(|h| h.token == token) else {
                return;
            };
            net::read_available(&mut h.sock, &mut h.rbuf, MAX_HUB_FRAME + 4)
        };
        // Every complete frame, one at a time (a handler may drop the link).
        loop {
            let packet = {
                let Some(h) = state.hub.as_mut().filter(|h| h.token == token) else {
                    return;
                };
                if h.rbuf.len() < 4 {
                    None
                } else {
                    let len =
                        u32::from_be_bytes([h.rbuf[0], h.rbuf[1], h.rbuf[2], h.rbuf[3]]) as usize;
                    if len == 0 || len > MAX_HUB_FRAME || len > i32::MAX as usize {
                        Some(Err(()))
                    } else if h.rbuf.len() < 4 + len {
                        None
                    } else {
                        let body: Vec<u8> = h.rbuf[4..4 + len].to_vec();
                        h.rbuf.drain(..4 + len);
                        Some(Ok(body))
                    }
                }
            };
            match packet {
                None => break,
                Some(Err(())) => {
                    disconnect(state);
                    return;
                }
                Some(Ok(body)) => process_packet(state, &body),
            }
        }
        match outcome {
            Ok(ReadOutcome::Full) => continue,
            Ok(ReadOutcome::Drained) => return,
            Ok(ReadOutcome::Eof) | Err(_) => {
                if state.hub.as_ref().map(|h| h.token) == Some(token) {
                    disconnect(state);
                }
                return;
            }
        }
    }
}

fn process_packet(state: &mut BotState, body: &[u8]) {
    if !state.hub_authenticated {
        match state.hub_auth_state {
            HubAuthState::SentUuid => handle_challenge(state, body),
            HubAuthState::SentSignature => handle_ack(state, body),
            _ => {}
        }
        return;
    }
    state.last_hub_activity = now();
    if body.len() <= GCM_IV_LEN + GCM_TAG_LEN {
        return;
    }
    let plain = match crypto::gcm_open(state.hub_session_key.get(), &[], body) {
        Some(p) if !p.is_empty() => p,
        _ => {
            disconnect(state);
            return;
        }
    };
    let cmd = plain[0];
    if cmd == CMD_PING {
        // Answer at most once per 5 s.
        let now = now();
        if now - state.last_hub_pong_sent >= 5 {
            if !send_frame(state, CMD_PING, &[]) {
                return;
            }
            state.last_hub_pong_sent = now;
        }
        return;
    }
    if plain.len() <= 5 {
        return;
    }
    let payload_len = u32::from_be_bytes([plain[1], plain[2], plain[3], plain[4]]) as usize;
    if payload_len == 0 || payload_len > plain.len() - 5 || payload_len > i32::MAX as usize {
        return;
    }
    let payload = Zeroizing::new(String::from_utf8_lossy(&plain[5..5 + payload_len]).into_owned());
    drop(plain);
    handle_response(state, cmd, until_nul(&payload));
}

/// v2 challenge: challenge(32) || hub_eph_pub(32) || hub_sig(64).
fn handle_challenge(state: &mut BotState, body: &[u8]) {
    if body.len() != 128 {
        logm!(
            state,
            L_INFO,
            "[HUB] Expected 128-byte v2 challenge, got {} bytes\n",
            body.len()
        );
        disconnect(state);
        return;
    }
    let challenge = &body[..32];
    let mut hub_eph_pub = [0u8; 32];
    hub_eph_pub.copy_from_slice(&body[32..64]);
    let hub_sig = &body[64..128];

    if !state.hub_remote_ed_pub_set {
        logm!(
            state,
            L_INFO,
            "[HUB] ERROR: hub pubkey not pinned. Re-add with '+hub <host:port> <pubkey>' before connecting.\n"
        );
        disconnect(state);
        return;
    }
    let mut transcript = Vec::with_capacity(19 + state.bot_uuid.len() + 1 + 64);
    transcript.extend_from_slice(b"irchub-hub-auth-v2|");
    transcript.extend_from_slice(state.bot_uuid.as_bytes());
    transcript.push(b'|');
    transcript.extend_from_slice(challenge);
    transcript.extend_from_slice(&hub_eph_pub);
    if !crypto::ed25519_verify(&state.hub_remote_ed_pub, &transcript, hub_sig) {
        logm!(
            state,
            L_INFO,
            "[HUB] v2 hub signature INVALID — possible MITM. Disconnecting.\n"
        );
        disconnect(state);
        return;
    }
    logm!(state, L_INFO, "[HUB] v2 hub signature verified.\n");

    let Some(session_key) = derive_session_key(state, &hub_eph_pub, challenge) else {
        logm!(state, L_INFO, "[HUB] Failed to derive session key\n");
        disconnect(state);
        return;
    };
    state.hub_session_key.set(&session_key);
    drop(session_key);

    let Some(sig) = sign_challenge(state, challenge, &hub_eph_pub) else {
        logm!(state, L_INFO, "[HUB] Failed to sign challenge\n");
        disconnect(state);
        return;
    };
    let mut frame = 64u32.to_be_bytes().to_vec();
    frame.extend_from_slice(&sig);
    if send_raw(state, &frame) {
        state.hub_auth_state = HubAuthState::SentSignature;
        logm!(state, L_INFO, "[HUB] Ed25519 signature sent.\n");
    } else {
        logm!(state, L_INFO, "[HUB] Failed to send signature\n");
    }
}

/// The hub's ACK: an encrypted single byte 0x01.
fn handle_ack(state: &mut BotState, body: &[u8]) {
    if body.len() < GCM_IV_LEN + 1 + GCM_TAG_LEN {
        logm!(
            state,
            L_INFO,
            "[HUB] Bad ACK from hub (len={})\n",
            body.len()
        );
        disconnect(state);
        return;
    }
    let ack = crypto::gcm_open(state.hub_session_key.get(), &[], body);
    let ok = matches!(&ack, Some(p) if p.len() == 1 && p[0] == 0x01);
    if !ok {
        logm!(
            state,
            L_INFO,
            "[HUB] v2 ACK decrypt/parse failed (len={})\n",
            ack.map_or(-1, |p| p.len() as i64)
        );
        disconnect(state);
        return;
    }
    let t = now();
    state.hub_authenticated = true;
    state.hub_auth_state = HubAuthState::Complete;
    state.last_hub_activity = t;
    state.hub_connect_time = t;
    logm!(state, L_INFO, "[HUB] Authenticated (Curve25519 v2)!\n");
    push_config(state);
    // No presence for us on this hub yet: report unconditionally.
    send_presence(state, true);
    // If this process is the product of a hub-driven upgrade, close that run
    // out now that there is a hub to tell.
    report_upgrade_result(state);
    if state.admin_delta_pending {
        // After the config push, so the hub already knows v|2.
        logm!(
            state,
            L_INFO,
            "[HUB] Pushing user/mask changes made while the hub was unreachable\n"
        );
        push_admin_delta(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_chan_formats() {
        assert_eq!(
            parse_hub_chan("#a|k|64|add|5"),
            Some(("#a".into(), "k".into(), 64, "add".into(), 5))
        );
        assert_eq!(
            parse_hub_chan("#a||128|del|6"),
            Some(("#a".into(), String::new(), 128, "del".into(), 6))
        );
        assert_eq!(
            parse_hub_chan("#a|k|add|7"),
            Some(("#a".into(), "k".into(), 0, "add".into(), 7))
        );
        assert_eq!(
            parse_hub_chan("#a||add|8"),
            Some(("#a".into(), String::new(), 0, "add".into(), 8))
        );
        assert_eq!(parse_hub_chan("#a"), None);
    }
}
