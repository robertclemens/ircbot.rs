//! Channel settings, network defaults and network bans (chancfg.c,
//! modes.md sections 2, 4, 6.3).
//!
//! Three replicated records reach the bot from a hub config push or from its
//! own config file, and all three are parsed here:
//!   C|#chan|<modes>|<settings>|add/del|ts    per-channel (kept in `Chan`)
//!   D|<modes>|<settings>|ts                  network defaults (`BotState`)
//!   B|<#chan|*>|<mask>|<expires>|<flags>|<setter>|<reason>|add/del|ts
//! Each is last-writer-wins on its own stamp.  The settings field is
//! "name=value,name=value"; only overrides appear.  A name this build does
//! not know is kept verbatim in the raw field (so it is written back
//! unchanged) and otherwise ignored.  A known name with an out-of-range value
//! is ignored too: the setting falls back to the next level, never to
//! something unvetted.
//!
//! Reading a value is [`get`]: channel override -> D| -> built-in.

use crate::consts::*;
use crate::cstr::{eq_ic, now, trunc_string};
use crate::state::{
    BotState, CS_COUNT, CfgBan, Chan, ChanSettings, CsetId, FL_CHAN_COUNT, FL_COUNT, FloodKind,
    FloodSpec, lww_accepts, lww_next_ts,
};
use crate::{channel, hub_client, logm};

struct CsetDef {
    name: &'static str,
    /// Flags are 0..1.
    lo: i64,
    hi: i64,
    builtin: i64,
    net_only: bool,
}

const fn def(name: &'static str, lo: i64, hi: i64, builtin: i64, net_only: bool) -> CsetDef {
    CsetDef {
        name,
        lo,
        hi,
        builtin,
        net_only,
    }
}

/// Built-ins: plan section 4 table, 4.1, 9.1.  Indexed by `CsetId`.
const CSET: [CsetDef; CS_COUNT] = [
    def("enforcemodes", 0, 1, 0, false),
    def("bitch", 0, 1, 0, false),
    def("protectops", 0, 1, 1, false),
    def("revenge", 0, 1, 0, false),
    def("stopnethack", 0, 1, 0, false),
    def("enforcebans", 0, 1, 0, false),
    def("dynamicbans", 0, 1, 1, false),
    def("dontkickops", 0, 1, 1, false),
    def("cycle", 0, 1, 1, false),
    def("dynamiclimit", 0, 1, 0, false),
    def("bantime", 0, 525_600, 120, false),
    def("bantype", 0, 9, 2, false),
    def("banidle", 1, 10_080, 60, false),
    def("limitgap", 1, 1000, 5, false),
    def("limitdelay", 10, 3600, 60, false),
    def("ignoretime", 1, 1440, 10, true),
];

const FL_NAME: [&str; FL_COUNT] = [
    "flood chan",
    "flood ctcp",
    "flood join",
    "flood nick",
    "flood deop",
    "flood kick",
    "flood ban",
    "bflood cmd",
    "bflood msg",
    "bflood ctcp",
    "sendq",
];
const FL_BUILTIN: [(i32, i32); FL_COUNT] = [
    (15, 60),
    (3, 60),
    (5, 60),
    (5, 60),
    (3, 10),
    (3, 10),
    (3, 10),
    (10, 30),
    (5, 60),
    (3, 60),
    (SENDQ_DEF_BURST as i32, SENDQ_DEF_INTERVAL_MS as i32),
];

/// Value bounds of a flood-table entry: (n lo, n hi, s lo, s hi, `off` ok).
/// `off` is only for the real floods.  sendq is B:I (burst, interval ms).
fn fl_bounds(kind: usize) -> (i64, i64, i64, i64, bool) {
    if kind == FloodKind::Sendq as usize {
        (
            SENDQ_MIN_BURST,
            SENDQ_MAX_BURST,
            SENDQ_MIN_INTERVAL_MS,
            SENDQ_MAX_INTERVAL_MS,
            false,
        )
    } else {
        (1, 1000, 1, 3600, true)
    }
}

/// Opt 'h' (D43): true when an ADMIN-initiated change to hub records must be
/// refused.  Enforcement writes (learned keys, modes, auto bans) never ask.
pub fn admin_change_refused(state: &BotState) -> bool {
    state.is_opt_set(OPT_HUB_ONLY_MUTATIONS)
}

// ---- small parsers ------------------------------------------------------------

fn parse_ll(s: &str) -> Option<i64> {
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// No control byte, DEL or '|' (record delimiter).
fn plain_text(s: &str) -> bool {
    s.bytes().all(|c| c >= 0x20 && c != 0x7f && c != b'|')
}

fn valid_chan_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter()
        .all(|&c| c > 0x20 && c != 0x7f && c != b',' && c != b'|')
}

/// The modes field: printable ASCII only (letters, signs, spaces, a limit).
fn valid_modes_field(s: &str) -> bool {
    s.len() <= C_MODES_MAX && s.bytes().all(|c| (0x20..=0x7e).contains(&c) && c != b'|')
}

// ---- settings field -------------------------------------------------------------

/// Parse a settings field into the overrides it names.  Too long a field
/// parses to nothing.
pub fn parse_settings(s: &str, net: bool) -> ChanSettings {
    let mut out = ChanSettings::default();
    if s.len() > C_SETTINGS_MAX {
        return out;
    }
    for tok in s.split(',') {
        let Some(eq) = tok.find('=').filter(|&e| e > 0) else {
            continue;
        };
        let (name, val) = (&tok[..eq], &tok[eq + 1..]);
        if let Some(i) = CSET.iter().position(|d| d.name == name) {
            if CSET[i].net_only && !net {
                continue; // not a channel setting: unknown here
            }
            if let Some(v) = parse_ll(val)
                && v >= CSET[i].lo
                && v <= CSET[i].hi
            {
                out.present |= 1u32 << i;
                out.val[i] = v;
            }
        } else if let Some(i) = FL_NAME.iter().position(|n| *n == name) {
            if i >= FL_CHAN_COUNT && !net {
                continue;
            }
            let (nlo, nhi, slo, shi, off_ok) = fl_bounds(i);
            if off_ok && val == "off" {
                out.fl[i] = FloodSpec {
                    present: true,
                    off: true,
                    n: 0,
                    s: 0,
                };
            } else if let Some((n, sec)) = val.split_once(':')
                && let (Some(n), Some(sec)) = (parse_ll(n), parse_ll(sec))
                && (nlo..=nhi).contains(&n)
                && (slo..=shi).contains(&sec)
            {
                out.fl[i] = FloodSpec {
                    present: true,
                    off: false,
                    n: n as i32,
                    s: sec as i32,
                };
            } else if i == FloodKind::Sendq as usize {
                out.bad_sendq = true;
            }
        }
    }
    out
}

// ---- effective values -------------------------------------------------------------

/// Effective value: channel override -> D| -> built-in.  `c` may be None
/// (net level only).  Flags return 0/1.
pub fn get(state: &BotState, c: Option<&Chan>, id: CsetId) -> i64 {
    let i = id as usize;
    if !CSET[i].net_only
        && let Some(c) = c
        && c.cfg_active
        && c.cfg_ts > 0
        && c.cfg_set.present & (1u32 << i) != 0
    {
        return c.cfg_set.val[i];
    }
    if state.net_ts > 0 && state.net_set.present & (1u32 << i) != 0 {
        return state.net_set.val[i];
    }
    CSET[i].builtin
}

/// Flood limits (n events in s seconds); None when the flood is off.  The
/// bot floods ignore `c`.
pub fn get_flood(state: &BotState, c: Option<&Chan>, kind: FloodKind) -> Option<(i32, i32)> {
    let k = kind as usize;
    let sp = match c {
        Some(c) if k < FL_CHAN_COUNT && c.cfg_active && c.cfg_ts > 0 && c.cfg_set.fl[k].present => {
            Some(&c.cfg_set.fl[k])
        }
        _ if state.net_ts > 0 && state.net_set.fl[k].present => Some(&state.net_set.fl[k]),
        _ => None,
    };
    match sp {
        Some(sp) if sp.off => None,
        Some(sp) => Some((sp.n, sp.s)),
        None => Some(FL_BUILTIN[k]),
    }
}

/// Stored modes string: C| -> D| -> "+nt".
pub fn get_modes<'a>(state: &'a BotState, c: Option<&'a Chan>) -> &'a str {
    if let Some(c) = c
        && c.cfg_active
        && c.cfg_ts > 0
        && !c.cfg_modes.is_empty()
    {
        return &c.cfg_modes;
    }
    if state.net_ts > 0 && !state.net_modes.is_empty() {
        return &state.net_modes;
    }
    "+nt"
}

// ---- field splitting ----------------------------------------------------------------

/// Split `data` on '|' into at most `max` fields; the last takes the rest.
fn split_pipes(data: &str, max: usize) -> Vec<&str> {
    data.splitn(max, '|').collect()
}

fn add_op(f: &str) -> Option<bool> {
    match f {
        "add" => Some(true),
        "del" => Some(false),
        _ => None,
    }
}

// ---- C| -----------------------------------------------------------------------------

/// Apply the body of a C| line under LWW.  True when the stored record
/// changed.
pub fn apply_c_line(state: &mut BotState, data: &str) -> bool {
    if data.len() > C_LINE_MAX {
        return false;
    }
    let f = split_pipes(data, 6);
    if f.len() < 5 {
        return false;
    }
    let (Some(add), Some(ts)) = (add_op(f[3]), parse_ll(f[4])) else {
        return false;
    };
    if !valid_chan_name(f[0])
        || !valid_modes_field(f[1])
        || f[2].len() > C_SETTINGS_MAX
        || !plain_text(f[2])
        || ts <= 0
    {
        return false;
    }
    let ci = match channel::find(state, f[0]) {
        Some(ci) => ci,
        None => {
            if !add {
                return false; // a delete for a channel we never heard of
            }
            let Some(ci) = channel::add(state, f[0]) else {
                return false;
            };
            // Settings before the channel record: held unmanaged (never
            // joined) until its c| add arrives and wins LWW against
            // timestamp 0.
            state.chans[ci].is_managed = false;
            state.chans[ci].timestamp = 0;
            ci
        }
    };
    let c = &mut state.chans[ci];
    if !lww_accepts(ts, add, c.cfg_ts, c.cfg_active) {
        return false;
    }
    c.cfg_modes = f[1].to_string();
    c.cfg_settings = f[2].to_string();
    c.cfg_set = parse_settings(&c.cfg_settings, false);
    c.cfg_ts = ts;
    c.cfg_active = add;
    state.cfg_gen = state.cfg_gen.wrapping_add(1);
    true
}

/// "C|...\n" for a channel.  Some("") when it has no C| record; None on
/// overflow of the C line buffer.
pub fn format_c_line(c: &Chan) -> Option<String> {
    if c.cfg_ts <= 0 {
        return Some(String::new());
    }
    let l = format!(
        "C|{}|{}|{}|{}|{}\n",
        c.name,
        c.cfg_modes,
        c.cfg_settings,
        if c.cfg_active { "add" } else { "del" },
        c.cfg_ts
    );
    (l.len() < C_LINE_MAX + 2).then_some(l)
}

// ---- D| -----------------------------------------------------------------------------

/// Apply the body of a D| line.  One record, no op: newer stamp wins; on a
/// tie the greater string wins (same rule as the opt flags, so every node
/// settles on the same one).
pub fn apply_d_line(state: &mut BotState, data: &str) -> bool {
    if data.len() > D_LINE_MAX {
        return false;
    }
    let f = split_pipes(data, 3);
    if f.len() < 3 {
        return false;
    }
    let Some(ts) = parse_ll(f[2]) else {
        return false;
    };
    if !valid_modes_field(f[0]) || f[1].len() > D_SETTINGS_MAX || !plain_text(f[1]) || ts <= 0 {
        return false;
    }
    if ts < state.net_ts {
        return false;
    }
    if ts == state.net_ts {
        let cur = format!("{}|{}", state.net_modes, state.net_settings);
        let inc = format!("{}|{}", f[0], f[1]);
        if inc.as_bytes() <= cur.as_bytes() {
            return false;
        }
    }
    state.net_modes = f[0].to_string();
    state.net_settings = f[1].to_string();
    let old_sq = state.net_set.fl[FloodKind::Sendq as usize];
    state.net_set = parse_settings(&state.net_settings, true);
    state.net_ts = ts;
    if state.net_set.bad_sendq {
        // Bad sendq value: ignore it, keep the one in force.
        state.net_set.fl[FloodKind::Sendq as usize] = old_sq;
        logm!(
            state,
            L_INFO,
            "[SENDQ] Ignoring bad D| sendq value (want B:I, B 1..100, I 0..10000ms); keeping {}:{}\n",
            state.sendq.burst,
            state.sendq.interval_ms
        );
    } else {
        let (b, iv) = get_flood(state, None, FloodKind::Sendq)
            .map_or((SENDQ_DEF_BURST, SENDQ_DEF_INTERVAL_MS), |(b, iv)| {
                (i64::from(b), i64::from(iv))
            });
        crate::sendq::set_limits(state, b, iv);
    }
    state.cfg_gen = state.cfg_gen.wrapping_add(1);
    true
}

/// "D|...\n".  Some("") when there is no D| record; None on overflow.
pub fn format_d_line(state: &BotState) -> Option<String> {
    if state.net_ts <= 0 {
        return Some(String::new());
    }
    let l = format!(
        "D|{}|{}|{}\n",
        state.net_modes, state.net_settings, state.net_ts
    );
    (l.len() < D_LINE_MAX + 2).then_some(l)
}

// ---- B| -----------------------------------------------------------------------------

fn ban_find<'a>(state: &'a BotState, chan: &str, mask: &str) -> Option<&'a CfgBan> {
    state
        .cfg_bans
        .iter()
        .find(|b| eq_ic(&b.chan, chan) && eq_ic(&b.mask, mask))
}

/// Room for one more active ban on `chan` under the per-channel / global caps.
fn ban_active_room(state: &BotState, chan: &str) -> bool {
    let n = state
        .cfg_bans
        .iter()
        .filter(|b| b.active && eq_ic(&b.chan, chan))
        .count();
    n < if chan == "*" {
        MAX_GLOBAL_BANS
    } else {
        MAX_BANS_PER_CHAN
    }
}

/// Index of a slot for a new entry: the table grows up to CFG_MAX_BANS, then
/// reuses the oldest tombstone.  None when it is full of live bans.
fn ban_slot(state: &mut BotState) -> Option<usize> {
    if state.cfg_bans.len() < CFG_MAX_BANS {
        state.cfg_bans.push(CfgBan::default());
        return Some(state.cfg_bans.len() - 1);
    }
    let mut oldest: Option<usize> = None;
    for (i, b) in state.cfg_bans.iter().enumerate() {
        if !b.active && oldest.is_none_or(|o| b.ts < state.cfg_bans[o].ts) {
            oldest = Some(i);
        }
    }
    oldest
}

/// Store `inb` under LWW.  True when the table changed.
fn ban_store(state: &mut BotState, inb: &CfgBan) -> bool {
    let found = state
        .cfg_bans
        .iter()
        .position(|b| eq_ic(&b.chan, &inb.chan) && eq_ic(&b.mask, &inb.mask));
    if let Some(i) = found {
        let b = &state.cfg_bans[i];
        if !lww_accepts(inb.ts, inb.active, b.ts, b.active) {
            return false;
        }
        if inb.active && !b.active && !ban_active_room(state, &inb.chan) {
            return false;
        }
        state.cfg_bans[i] = inb.clone();
        state.cfg_gen = state.cfg_gen.wrapping_add(1);
        return true;
    }
    if inb.active && !ban_active_room(state, &inb.chan) {
        return false;
    }
    let Some(i) = ban_slot(state) else {
        return false;
    };
    state.cfg_bans[i] = inb.clone();
    state.cfg_gen = state.cfg_gen.wrapping_add(1);
    true
}

/// Apply the body of a B| line under LWW.  True when the table changed.
pub fn apply_b_line(state: &mut BotState, data: &str) -> bool {
    if data.len() > B_LINE_MAX {
        return false;
    }
    // op and ts are the last two fields; the reason between is everything
    // the hub put there, kept whole.
    let Some(last) = data.rfind('|').filter(|&l| l > 0) else {
        return false;
    };
    let db = data.as_bytes();
    let mut prev = last - 1;
    while prev > 0 && db[prev] != b'|' {
        prev -= 1;
    }
    if db[prev] != b'|' {
        return false;
    }
    let opf = &data[prev + 1..last];
    let tsf = &data[last + 1..];
    let head = &data[..prev];

    let f = split_pipes(head, 6);
    if f.len() < 6 {
        return false;
    }
    let (Some(add), Some(ts)) = (add_op(opf), parse_ll(tsf)) else {
        return false;
    };
    if ts <= 0 {
        return false;
    }
    if f[0] != "*" && !valid_chan_name(f[0]) {
        return false;
    }
    if f[1].is_empty() || f[1].len() > BAN_MASK_MAX || !plain_text(f[1]) || f[1].contains(' ') {
        return false;
    }
    let Some(expires) = parse_ll(f[2]) else {
        return false;
    };
    // flags[8]
    if f[3].len() >= 8 || !plain_text(f[3]) {
        return false;
    }
    if f[4].len() > BAN_SETTER_MAX || !plain_text(f[4]) {
        return false;
    }
    // The reason is the sixth field of head: all that remains.  It may not
    // hold control bytes, and is at most BAN_REASON_MAX.
    if f[5].len() > BAN_REASON_MAX || f[5].bytes().any(|c| c < 0x20 || c == 0x7f) {
        return false;
    }
    let b = CfgBan {
        chan: f[0].to_string(),
        mask: f[1].to_string(),
        flags: f[3].to_string(),
        setter: f[4].to_string(),
        reason: f[5].to_string(),
        expires,
        ts,
        active: add,
        push_pending: false,
    };
    ban_store(state, &b)
}

/// "B|...\n" for one ban; None on overflow of the B line buffer.
pub fn format_b_line(b: &CfgBan) -> Option<String> {
    let l = format!(
        "B|{}|{}|{}|{}|{}|{}|{}|{}\n",
        b.chan,
        b.mask,
        b.expires,
        b.flags,
        b.setter,
        b.reason,
        if b.active { "add" } else { "del" },
        b.ts
    );
    (l.len() < B_LINE_MAX + 2).then_some(l)
}

/// Drop B| tombstones stamped before cutoff (0 = all); returns the count.
pub fn purge_bans(state: &mut BotState, cutoff: i64) -> usize {
    let mut removed = 0;
    let mut i = 0;
    while i < state.cfg_bans.len() {
        let b = &state.cfg_bans[i];
        if !b.active && (cutoff == 0 || b.ts < cutoff) {
            state.cfg_bans.swap_remove(i);
            removed += 1;
        } else {
            i += 1;
        }
    }
    removed
}

/// Active bans for `chan` (its own and "*"), at most `max`.
pub fn bans_for<'a>(state: &'a BotState, chan: &str, max: usize) -> Vec<&'a CfgBan> {
    let t = now();
    state
        .cfg_bans
        .iter()
        .filter(|b| b.active && !(b.expires > 0 && b.expires <= t))
        .filter(|b| b.chan == "*" || eq_ic(&b.chan, chan))
        .take(max)
        .collect()
}

/// A B| reason as stored: control bytes and '|' become spaces, cut at
/// BAN_REASON_MAX bytes (back to a character boundary, so it stays UTF-8).
fn clean_reason_field(r: &str) -> String {
    let mut out = String::new();
    for ch in r.chars() {
        if out.len() + ch.len_utf8() > BAN_REASON_MAX {
            break;
        }
        out.push(if (ch as u32) < 0x20 || ch == '\x7f' || ch == '|' {
            ' '
        } else {
            ch
        });
    }
    out
}

/// A ban this bot sets on its own (flood, revenge): stored, pushed to the
/// hub as a bot-written B| (hub rules: timed, <= bantime, setter == our uuid,
/// del only of our own) and saved by the next debounced config flush.  Never
/// gated by opt 'h' -- it is enforcement, not an admin change (D43).
/// `del` writes the "del" for a ban this bot wrote.
pub fn bot_ban(
    state: &mut BotState,
    chan: &str,
    mask: &str,
    expires: i64,
    flags: Option<&str>,
    reason: Option<&str>,
    del: bool,
) -> bool {
    if state.bot_uuid.is_empty() {
        return false;
    }
    if mask.is_empty()
        || mask.len() > BAN_MASK_MAX
        || !plain_text(mask)
        || mask.contains(' ')
        || (chan != "*" && !valid_chan_name(chan))
    {
        return false;
    }
    let t = now();
    let mut b = CfgBan {
        chan: trunc_string(chan, MAX_CHAN),
        mask: mask.to_string(),
        setter: trunc_string(&state.bot_uuid, BAN_SETTER_MAX + 1),
        ..CfgBan::default()
    };
    let old = ban_find(state, &b.chan, &b.mask).cloned();
    if del {
        let Some(old) = old.filter(|o| o.active && o.setter == state.bot_uuid) else {
            return false;
        };
        b = old;
        b.active = false;
        b.ts = lww_next_ts(b.ts);
    } else {
        if expires <= t {
            return false; // the hub takes only timed bot bans
        }
        if old
            .as_ref()
            .is_some_and(|o| o.active && o.setter != state.bot_uuid)
        {
            return false; // never overwrite another setter's active ban (hub rule)
        }
        let c = if b.chan.starts_with(['#', '&']) {
            channel::find(state, &b.chan).map(|ci| &state.chans[ci])
        } else {
            None
        };
        let bt = get(state, c, CsetId::BanTime);
        b.expires = if bt > 0 && expires > t + bt * 60 {
            t + bt * 60
        } else {
            expires
        };
        b.active = true;
        b.ts = old.map_or(t, |o| lww_next_ts(o.ts));
        if let Some(f) = flags {
            b.flags = trunc_string(f, 8);
        }
        if let Some(r) = reason {
            b.reason = clean_reason_field(r);
        }
    }
    b.push_pending = true;
    if !ban_store(state, &b) {
        return false;
    }
    if let Some(line) = format_b_line(&b)
        && hub_client::push_lines(state, &line)
        && let Some(i) = state
            .cfg_bans
            .iter()
            .position(|x| eq_ic(&x.chan, &b.chan) && eq_ic(&x.mask, &b.mask))
    {
        state.cfg_bans[i].push_pending = false;
    }
    state.config_dirty = true;
    true
}

// ---- local writes (bot commands, modes.md section 5.2) ---------------------------------

/// Push complete record lines to the hub when linked, and save the config.
/// Best effort: a hub that is down gets the records in the next full push.
fn local_commit(state: &mut BotState, line: &str) {
    if !line.is_empty() {
        hub_client::push_lines(state, line);
    }
    state.config_dirty = true;
    for c in &mut state.chans {
        c.enf_dirty = true;
        c.enf_ops_check = true;
    }
}

/// Write the channel's own C| record (LWW-stamped past the stored one),
/// apply it at once, push it to a connected hub and save.  Not gated here:
/// the caller checks [`admin_change_refused`].
pub fn local_c(state: &mut BotState, ci: usize, modes: &str, settings: &str) -> bool {
    let Some(c) = state.chans.get(ci) else {
        return false;
    };
    let ts = lww_next_ts(c.cfg_ts);
    let data = format!("{}|{}|{}|add|{}", c.name, modes, settings, ts);
    if data.len() >= C_LINE_MAX + 2 || !apply_c_line(state, &data) {
        return false;
    }
    let line = format_c_line(&state.chans[ci]).unwrap_or_default();
    local_commit(state, &line);
    true
}

/// The same for the network default D| record.
pub fn local_d(state: &mut BotState, modes: &str, settings: &str) -> bool {
    let ts = lww_next_ts(state.net_ts);
    let data = format!("{modes}|{settings}|{ts}");
    if data.len() >= D_LINE_MAX + 2 || !apply_d_line(state, &data) {
        return false;
    }
    let line = format_d_line(state).unwrap_or_default();
    local_commit(state, &line);
    true
}

/// Active network ban for chan + mask.
pub fn ban_get<'a>(state: &'a BotState, chan: &str, mask: &str) -> Option<&'a CfgBan> {
    state
        .cfg_bans
        .iter()
        .find(|b| b.active && eq_ic(&b.chan, chan) && eq_ic(&b.mask, mask))
}

/// Add (or, with `del`, remove) a network ban written by an admin command:
/// B| line with the admin's name as setter, LWW-stamped, stored, pushed and
/// saved.  Not gated here.
#[allow(clippy::too_many_arguments)]
pub fn local_ban(
    state: &mut BotState,
    chan: &str,
    mask: &str,
    expires: i64,
    flags: &str,
    setter: &str,
    reason: &str,
    del: bool,
) -> bool {
    if mask.is_empty()
        || mask.len() > BAN_MASK_MAX
        || !plain_text(mask)
        || mask.contains(' ')
        || (chan != "*" && !valid_chan_name(chan))
        || setter.is_empty()
        || setter.len() > BAN_SETTER_MAX
        || !plain_text(setter)
    {
        return false;
    }
    let old = ban_find(state, chan, mask).cloned();
    let b = if del {
        let Some(mut b) = old.filter(|o| o.active) else {
            return false;
        };
        b.active = false;
        b.ts = lww_next_ts(b.ts);
        b.push_pending = false;
        b
    } else {
        CfgBan {
            chan: trunc_string(chan, MAX_CHAN),
            mask: mask.to_string(),
            setter: setter.to_string(),
            flags: trunc_string(flags, 8),
            reason: clean_reason_field(reason),
            expires,
            active: true,
            ts: old.map_or_else(now, |o| lww_next_ts(o.ts)),
            push_pending: false,
        }
    };
    if !ban_store(state, &b) {
        return false;
    }
    let line = format_b_line(&b).unwrap_or_default();
    local_commit(state, &line);
    true
}

// ---- settings editing and listing ------------------------------------------------------

/// Index into the setting list (0..CS_COUNT the settings, then the floods);
/// None for an unknown name or a D|-only one when `net` is false.
fn item_index(name: &str, net: bool) -> Option<usize> {
    if let Some(i) = CSET.iter().position(|d| d.name == name) {
        return (net || !CSET[i].net_only).then_some(i);
    }
    FL_NAME
        .iter()
        .position(|n| *n == name)
        .and_then(|i| (net || i < FL_CHAN_COUNT).then_some(CS_COUNT + i))
}

/// An on/off setting (0..1 range).
pub fn setting_is_flag(name: &str) -> bool {
    item_index(name, true).is_some_and(|i| i < CS_COUNT && CSET[i].lo == 0 && CSET[i].hi == 1)
}

/// Listing support: index 0..CS_COUNT-1 are the settings, then the FL_COUNT
/// floods.  None past the end or for a hidden one.
pub fn item_name(idx: usize, net: bool) -> Option<&'static str> {
    if idx < CS_COUNT {
        return (net || !CSET[idx].net_only).then_some(CSET[idx].name);
    }
    let k = idx - CS_COUNT;
    (k < FL_COUNT && (net || k < FL_CHAN_COUNT)).then_some(FL_NAME[k])
}

/// Where an item's effective value comes from: 2 = channel override,
/// 1 = network default, 0 = built-in.
pub fn item_source(state: &BotState, c: Option<&Chan>, idx: usize) -> u8 {
    let chan_ok = c.filter(|c| c.cfg_active && c.cfg_ts > 0);
    let net_ok = state.net_ts > 0;
    if idx < CS_COUNT {
        return if chan_ok
            .is_some_and(|c| !CSET[idx].net_only && c.cfg_set.present & (1u32 << idx) != 0)
        {
            2
        } else if net_ok && state.net_set.present & (1u32 << idx) != 0 {
            1
        } else {
            0
        };
    }
    let k = idx - CS_COUNT;
    if k >= FL_COUNT {
        return 0;
    }
    if chan_ok.is_some_and(|c| k < FL_CHAN_COUNT && c.cfg_set.fl[k].present) {
        2
    } else if net_ok && state.net_set.fl[k].present {
        1
    } else {
        0
    }
}

/// Edit a settings field in place: set name=value or (value "default") drop
/// it.  `name` is "bitch", "bantime", "flood join", "bflood cmd", ...; `net`
/// allows the D|-only names.  Err carries the reason for the user.  `cap` is
/// the size of the caller's buffer, as in C.
pub fn settings_edit(
    settings: &mut String,
    cap: usize,
    net: bool,
    name: &str,
    value: &str,
) -> Result<(), String> {
    const OUT_CAP: usize = D_SETTINGS_MAX + 64;
    let full = || "settings field is full".to_string();
    let Some(idx) = item_index(name, net) else {
        return Err(format!("unknown setting '{name}'"));
    };
    let drop = value == "default";
    let mut nv = String::new();
    if !drop {
        if idx < CS_COUNT {
            match parse_ll(value).filter(|v| *v >= CSET[idx].lo && *v <= CSET[idx].hi) {
                Some(v) => nv = v.to_string(),
                None => {
                    return Err(format!(
                        "{} must be {}..{}",
                        name, CSET[idx].lo, CSET[idx].hi
                    ));
                }
            }
        } else if idx - CS_COUNT != FloodKind::Sendq as usize && value == "off" {
            nv = "off".into();
        } else {
            let (nlo, nhi, slo, shi, off_ok) = fl_bounds(idx - CS_COUNT);
            let ok = value
                .split_once(':')
                .and_then(|(a, b)| Some((parse_ll(a)?, parse_ll(b)?)))
                .filter(|(n, sec)| (nlo..=nhi).contains(n) && (slo..=shi).contains(sec));
            match ok {
                Some((n, sec)) => nv = format!("{n}:{sec}"),
                None if off_ok => {
                    return Err(format!(
                        "{name} must be N:S (N 1..1000, S 1..3600), off or default"
                    ));
                }
                None => {
                    return Err(format!(
                        "{name} must be B:I (burst 1..100, interval 0..10000 ms) or default"
                    ));
                }
            }
        }
    }
    let nl = name.len();
    let mut out = String::new();
    for tok in settings.split(',').filter(|t| !t.is_empty()) {
        let same = tok.len() > nl && tok.starts_with(name) && tok.as_bytes()[nl] == b'=';
        if same {
            continue;
        }
        if out.len() + tok.len() + 2 >= OUT_CAP {
            return Err(full());
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(tok);
    }
    if !drop {
        let add = format!("{}{}={}", if out.is_empty() { "" } else { "," }, name, nv);
        if out.len() + add.len() >= OUT_CAP {
            return Err(full());
        }
        out.push_str(&add);
    }
    if out.len() >= cap || out.len() > if net { D_SETTINGS_MAX } else { C_SETTINGS_MAX } {
        return Err(full());
    }
    *settings = out;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_field() {
        let s = parse_settings(
            "bitch=1,bantime=90,bantype=12,flood chan=5:10,bflood cmd=1:2,x=y",
            false,
        );
        assert_eq!(
            s.present,
            (1 << CsetId::Bitch as u32) | (1 << CsetId::BanTime as u32)
        );
        assert_eq!(s.val[CsetId::BanTime as usize], 90);
        assert!(s.fl[FloodKind::Chan as usize].present);
        assert!(!s.fl[FloodKind::BotCmd as usize].present);
        let n = parse_settings("ignoretime=5,flood kick=off,bflood msg=2:3", true);
        assert_eq!(n.val[CsetId::IgnoreTime as usize], 5);
        assert!(n.fl[FloodKind::Kick as usize].off);
        assert_eq!(n.fl[FloodKind::BotMsg as usize].n, 2);
    }

    #[test]
    fn record_validation() {
        assert!(valid_chan_name("#a"));
        assert!(!valid_chan_name("#a,b"));
        assert!(!valid_chan_name("a"));
        assert!(valid_modes_field("+nt"));
        assert!(!valid_modes_field("+n|t"));
        assert_eq!(parse_ll("0012"), Some(12));
        assert_eq!(parse_ll("-1"), None);
        assert_eq!(parse_ll(&"9".repeat(19)), None);
    }

    #[test]
    fn bot_ban_keeps_another_setters_active_ban() {
        let mut st = BotState::for_test();
        let t = now();
        let other = CfgBan {
            chan: "#c".into(),
            mask: "*!*@bad.host".into(),
            setter: "22222222-2222-4222-8222-222222222222".into(),
            expires: t + 3600,
            ts: t,
            active: true,
            ..CfgBan::default()
        };
        st.cfg_bans.push(other);
        assert!(!bot_ban(
            &mut st,
            "#c",
            "*!*@bad.host",
            t + 600,
            None,
            None,
            false
        ));
        assert_eq!(st.cfg_bans[0].expires, t + 3600);
        assert_eq!(
            st.cfg_bans[0].setter,
            "22222222-2222-4222-8222-222222222222"
        );
        // its own ban is renewed, an inactive one of another setter is replaced
        st.cfg_bans[0].setter = st.bot_uuid.clone();
        assert!(bot_ban(
            &mut st,
            "#c",
            "*!*@bad.host",
            t + 600,
            None,
            None,
            false
        ));
        st.cfg_bans[0].setter = "22222222-2222-4222-8222-222222222222".into();
        st.cfg_bans[0].active = false;
        assert!(bot_ban(
            &mut st,
            "#c",
            "*!*@bad.host",
            t + 600,
            None,
            None,
            false
        ));
        assert_eq!(st.cfg_bans[0].setter, st.bot_uuid);
    }

    const SQ: usize = FloodKind::Sendq as usize;

    fn d_rec(settings: &str, ts: i64) -> String {
        format!("+nt|{settings}|{ts}")
    }

    #[test]
    fn sendq_parse() {
        let s = parse_settings("sendq=5:250", true);
        assert!(s.fl[SQ].present && !s.bad_sendq);
        assert_eq!((s.fl[SQ].n, s.fl[SQ].s), (5, 250));
        assert_eq!(parse_settings("sendq=100:0", true).fl[SQ].s, 0);
        for bad in [
            "sendq=off",
            "sendq=0:100",
            "sendq=101:100",
            "sendq=10:10001",
            "sendq=10",
            "sendq=1:2:3",
            "sendq=:5",
            "sendq=5:",
            "sendq=-1:5",
            "sendq=1:+5",
            "sendq=1234567890123456789:5",
        ] {
            let s = parse_settings(bad, true);
            assert!(s.bad_sendq && !s.fl[SQ].present, "{bad}");
        }
        // D| only: ignored (not even flagged) in a channel field
        let s = parse_settings("sendq=zz", false);
        assert!(!s.bad_sendq && !s.fl[SQ].present);
        // duplicate tokens: processed in order; a bad one sets the flag
        let s = parse_settings("sendq=5:5,sendq=zz", true);
        assert!(s.bad_sendq && s.fl[SQ].present);
        let s = parse_settings("sendq=zz,sendq=7:70", true);
        assert!(s.bad_sendq && s.fl[SQ].n == 7);
    }

    #[test]
    fn sendq_d_line() {
        let mut st = BotState::for_test();
        assert!(apply_d_line(&mut st, &d_rec("sendq=3:40", 100)));
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (3, 40));
        // bad value: previous spec and live values kept, rest still applies
        assert!(apply_d_line(&mut st, &d_rec("bitch=1,sendq=0:0", 200)));
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (3, 40));
        assert_eq!(st.net_set.fl[SQ].n, 3);
        assert_eq!(get(&st, None, CsetId::Bitch), 1);
        // LWW-rejected record applies nothing
        assert!(!apply_d_line(&mut st, &d_rec("sendq=9:9", 50)));
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (3, 40));
        // absent: defaults
        assert!(apply_d_line(&mut st, &d_rec("bitch=1", 300)));
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (10, 100));
        // duplicate tokens with a bad one: keep in force
        assert!(apply_d_line(&mut st, &d_rec("sendq=2:20", 400)));
        assert!(apply_d_line(&mut st, &d_rec("sendq=8:8,sendq=x", 500)));
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (2, 20));
    }

    #[test]
    fn sendq_edit() {
        let mut s = String::new();
        assert!(settings_edit(&mut s, 256, true, "sendq", "5:0").is_ok());
        assert_eq!(s, "sendq=5:0");
        let e = settings_edit(&mut s, 256, true, "sendq", "off").unwrap_err();
        assert_eq!(
            e,
            "sendq must be B:I (burst 1..100, interval 0..10000 ms) or default"
        );
        assert!(settings_edit(&mut s, 256, true, "sendq", "default").is_ok());
        assert!(s.is_empty());
        assert!(settings_edit(&mut s, 256, false, "sendq", "5:5").is_err());
    }
}
