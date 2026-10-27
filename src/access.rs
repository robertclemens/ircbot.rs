//! Admin flags (`uf|`) and oper channel bindings (`uc|`) on the bot -- C
//! `access.c` (ircbot), which mirrors irchub `hub_access.c`.
//!
//! irchub docs/plans/2026-10-16_user_flags_plan.md §3.  Fail closed: no flags
//! record = no flags, no live binding = no channel access.  Every writer
//! (config load, hub config, local commands) goes through `uflag_put` /
//! `uchan_put`, which validate and cap every field.

use crate::consts::*;
use crate::cstr::atoll;
use crate::state::{BotState, UchanRecord, UflagRecord, lww_accepts, lww_next_ts};

fn uuid_shape(u: &str) -> bool {
    let b = u.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn canon_of(have: &[bool]) -> String {
    USER_FLAG_LETTERS
        .chars()
        .zip(have.iter())
        .filter(|&(_, h)| *h)
        .map(|(c, _)| c)
        .collect()
}

/// C `access_flags_canon`.
pub fn flags_canon(input: &str) -> Option<String> {
    let mut have = [false; USER_FLAG_LETTERS.len()];
    for c in input.bytes() {
        have[USER_FLAG_LETTERS.bytes().position(|l| l == c)?] = true;
    }
    Some(canon_of(&have))
}

/// "+c-u" edits `cur`; "chu" / "+chu" / "+a" replaces it.  C
/// `access_flags_edit`.
pub fn flags_edit(cur: &str, spec: &str) -> Option<String> {
    if spec.is_empty() {
        return None;
    }
    if !spec.contains('-') {
        let body = spec.strip_prefix('+').unwrap_or(spec);
        if spec.starts_with('+') && body.is_empty() {
            return None;
        }
        return flags_canon(body);
    }
    let work = flags_canon(cur).unwrap_or_default();
    let mut have = [false; USER_FLAG_LETTERS.len()];
    for c in work.bytes() {
        have[USER_FLAG_LETTERS.bytes().position(|l| l == c)?] = true;
    }
    let (mut sign, mut any) = (0, false);
    for c in spec.bytes() {
        if c == b'+' || c == b'-' {
            sign = if c == b'+' { 1 } else { -1 };
            continue;
        }
        let at = USER_FLAG_LETTERS.bytes().position(|l| l == c)?;
        if sign == 0 {
            return None;
        }
        have[at] = sign > 0;
        any = true;
    }
    any.then(|| canon_of(&have))
}

/// Newer stamp wins; a tie keeps the fewer rights.  C `access_flags_accepts`.
pub fn flags_accepts(in_ts: i64, input: &str, cur_ts: i64, cur: &str) -> bool {
    if in_ts != cur_ts {
        return in_ts > cur_ts;
    }
    let (ia, ca) = (input.contains('a'), cur.contains('a'));
    if ia != ca {
        return !ia;
    }
    if input.len() != cur.len() {
        return input.len() < cur.len();
    }
    input < cur
}

/// C `access_chan_name_ok`.
pub fn chan_name_ok(chan: &str) -> bool {
    if chan == "*" {
        return true;
    }
    let b = chan.as_bytes();
    if b.len() < 2 || b.len() >= MAX_CHAN || (b[0] != b'#' && b[0] != b'&') {
        return false;
    }
    b.iter()
        .all(|&c| c > 0x20 && c != 0x7f && c != b',' && c != b'|' && c != b':')
}

pub fn uflag_find(state: &BotState, uuid: &str) -> Option<usize> {
    state.uflag_records.iter().position(|r| r.uuid == uuid)
}

pub fn uchan_find(state: &BotState, uuid: &str, chan: &str) -> Option<usize> {
    state
        .uchan_records
        .iter()
        .position(|r| r.uuid == uuid && r.chan.eq_ignore_ascii_case(chan))
}

/// C `access_uflag_put`.
pub fn uflag_put(state: &mut BotState, uuid: &str, flags: &str, ts: i64) -> bool {
    let Some(canon) = flags_canon(flags) else {
        return false;
    };
    if !uuid_shape(uuid) || ts <= 0 {
        return false;
    }
    let i = match uflag_find(state, uuid) {
        Some(i) => {
            let r = &state.uflag_records[i];
            if !flags_accepts(ts, &canon, r.timestamp, &r.flags) {
                return false;
            }
            i
        }
        None => {
            if state.uflag_records.len() >= MAX_USER_FLAGS {
                crate::logm!(
                    state,
                    L_INFO,
                    "[ACCESS] Flag table full ({}): uf| for {} dropped\n",
                    MAX_USER_FLAGS,
                    crate::auth::who(state, 'u', uuid)
                );
                return false;
            }
            state.uflag_records.push(UflagRecord {
                uuid: uuid.to_string(),
                ..Default::default()
            });
            state.uflag_records.len() - 1
        }
    };
    let r = &mut state.uflag_records[i];
    r.flags = canon;
    r.timestamp = ts;
    true
}

/// C `access_uchan_put`.
pub fn uchan_put(state: &mut BotState, uuid: &str, chan: &str, active: bool, ts: i64) -> bool {
    if !uuid_shape(uuid) || !chan_name_ok(chan) || ts <= 0 {
        return false;
    }
    let i = match uchan_find(state, uuid, chan) {
        Some(i) => {
            let r = &state.uchan_records[i];
            if !lww_accepts(ts, active, r.timestamp, r.is_active) {
                return false;
            }
            i
        }
        None => {
            if state.uchan_records.len() >= MAX_CHAN_BINDS {
                crate::logm!(
                    state,
                    L_INFO,
                    "[ACCESS] Binding table full ({}): uc| {} for {} dropped\n",
                    MAX_CHAN_BINDS,
                    chan,
                    crate::auth::who(state, 'u', uuid)
                );
                return false;
            }
            state.uchan_records.push(UchanRecord {
                uuid: uuid.to_string(),
                chan: chan.to_string(),
                ..Default::default()
            });
            state.uchan_records.len() - 1
        }
    };
    let r = &mut state.uchan_records[i];
    r.is_active = active;
    r.timestamp = ts;
    true
}

pub fn user_flags<'a>(state: &'a BotState, uuid: &str) -> &'a str {
    uflag_find(state, uuid).map_or("", |i| state.uflag_records[i].flags.as_str())
}

/// 'a' passes every letter.
pub fn user_has_flag(state: &BotState, uuid: &str, flag: char) -> bool {
    let f = user_flags(state, uuid);
    f.contains('a') || (flag != '\0' && f.contains(flag))
}

/// An oper's channel access: a live "*" or a live binding to `chan`.
pub fn user_chan_ok(state: &BotState, uuid: &str, chan: Option<&str>) -> bool {
    state.uchan_records.iter().any(|r| {
        r.is_active
            && r.uuid == uuid
            && (r.chan == "*" || chan.is_some_and(|c| r.chan.eq_ignore_ascii_case(c)))
    })
}

/// Live bindings of one user, and whether "*" is among them.
pub fn user_chan_count(state: &BotState, uuid: &str) -> (usize, bool) {
    let (mut n, mut global) = (0, false);
    for r in state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.uuid == uuid)
    {
        n += 1;
        global |= r.chan == "*";
    }
    (n, global)
}

pub fn format_uflag(r: &UflagRecord) -> String {
    format!("uf|{}|{}|{}\n", r.uuid, r.flags, r.timestamp)
}

pub fn format_uchan(r: &UchanRecord) -> String {
    format!(
        "uc|{}|{}|{}|{}\n",
        r.uuid,
        r.chan,
        if r.is_active { "add" } else { "del" },
        r.timestamp
    )
}

/// One record body (after "uf|" / "uc|").  Some(changed), None when
/// malformed.  C `access_ingest`.
pub fn ingest(state: &mut BotState, kind: char, body: &str, need_user: bool) -> Option<bool> {
    if body.len() >= CFG_UC_LINE_MAX {
        return None;
    }
    let body = body.trim_end_matches(['\n', '\r']);
    let f: Vec<&str> = body.splitn(6, '|').collect();
    if need_user && !state.user_records.iter().any(|u| u.uuid == f[0]) {
        return None;
    }
    if kind == 'f' {
        if f.len() != 3 {
            return None;
        }
        Some(uflag_put(state, f[0], f[1], atoll(f[2])))
    } else {
        if f.len() != 4 || (f[2] != "add" && f[2] != "del") {
            return None;
        }
        Some(uchan_put(state, f[0], f[1], f[2] == "add", atoll(f[3])))
    }
}

/// §3.3: a live admin without `uf|` becomes "a", a live oper without any
/// `uc|` "*", stamped `USER_ACCESS_MIGRATE_TS`.  C `access_migrate`.
pub fn migrate(state: &mut BotState) -> usize {
    let ts = USER_ACCESS_MIGRATE_TS;
    let mut made = 0;
    let users: Vec<(String, char)> = state
        .user_records
        .iter()
        .filter(|u| u.is_active)
        .map(|u| (u.uuid.clone(), u.typ))
        .collect();
    for (uuid, typ) in users {
        if typ == 'a' && uflag_find(state, &uuid).is_none() {
            if uflag_put(state, &uuid, "a", ts) {
                made += 1;
            }
        } else if typ == 'o'
            && !state.uchan_records.iter().any(|r| r.uuid == uuid)
            && uchan_put(state, &uuid, "*", true, ts)
        {
            made += 1;
        }
    }
    if made > 0 {
        crate::logm!(
            state,
            L_INFO,
            "[ACCESS] Migrated {} user{} to flags / channel bindings (admins: +a, opers: *)\n",
            made,
            if made == 1 { "" } else { "s" }
        );
    }
    made
}

/// Drop records whose user is gone, and duplicates.  C `access_prune`.
pub fn prune(state: &mut BotState) {
    let users: Vec<String> = state.user_records.iter().map(|u| u.uuid.clone()).collect();
    let mut kept: Vec<UflagRecord> = Vec::new();
    for r in std::mem::take(&mut state.uflag_records) {
        if users.contains(&r.uuid) && !kept.iter().any(|k| k.uuid == r.uuid) {
            kept.push(r);
        }
    }
    state.uflag_records = kept;
    let mut kept: Vec<UchanRecord> = Vec::new();
    for r in std::mem::take(&mut state.uchan_records) {
        if users.contains(&r.uuid)
            && !kept
                .iter()
                .any(|k| k.uuid == r.uuid && k.chan.eq_ignore_ascii_case(&r.chan))
        {
            kept.push(r);
        }
    }
    state.uchan_records = kept;
}

/// Binding tombstones older than `cutoff` (0 = all); a live user's "*" del
/// stays.  C `access_purge`.
pub fn purge(state: &mut BotState, cutoff: i64) -> usize {
    let live: Vec<String> = state
        .user_records
        .iter()
        .filter(|u| u.is_active)
        .map(|u| u.uuid.clone())
        .collect();
    // a live binding to a channel no one manages is an orphan (irchub)
    let orphan: Vec<bool> = state
        .uchan_records
        .iter()
        .map(|r| {
            r.is_active
                && r.chan != "*"
                && crate::channel::find(state, &r.chan).is_none_or(|ci| !state.chans[ci].is_managed)
        })
        .collect();
    let before = state.uchan_records.len();
    let mut i = 0;
    state.uchan_records.retain(|r| {
        i += 1;
        !(orphan[i - 1]
            || (!r.is_active
                && (cutoff == 0 || r.timestamp < cutoff)
                && !(live.contains(&r.uuid) && r.chan == "*")))
    });
    let dropped = before - state.uchan_records.len();
    prune(state);
    dropped
}

/// "*" when global, else the live channels comma-joined.  C
/// `access_user_chans` (cap bytes with the NUL).
pub fn user_chans(state: &BotState, uuid: &str, cap: usize) -> String {
    if user_chan_count(state, uuid).1 {
        return "*".to_string();
    }
    let mut out = String::new();
    for r in state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.uuid == uuid)
    {
        let add = usize::from(!out.is_empty()) + r.chan.len();
        if out.len() + add >= cap {
            break;
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&r.chan);
    }
    out
}

/// C `access_next_ts`.
pub fn next_ts(state: &BotState, uuid: &str) -> i64 {
    let mut prev = uflag_find(state, uuid).map_or(0, |i| state.uflag_records[i].timestamp);
    for r in state.uchan_records.iter().filter(|r| r.uuid == uuid) {
        prev = prev.max(r.timestamp);
    }
    lww_next_ts(prev)
}

/// An oper binding change the U10 way; the number of records written, None
/// when the table is full.  C `access_chan_change`.
pub fn chan_change(state: &mut BotState, uuid: &str, add: bool, chan: &str) -> Option<usize> {
    let ts = next_ts(state, uuid);
    let star = chan == "*";
    let mut n = 0;
    let live_of = |state: &BotState| -> Vec<String> {
        state
            .uchan_records
            .iter()
            .filter(|r| r.is_active && r.uuid == uuid)
            .map(|r| r.chan.clone())
            .collect()
    };
    let mut put = |state: &mut BotState, c: &str, act: bool| -> Option<()> {
        uchan_put(state, uuid, c, act, ts).then(|| n += 1)
    };
    if add {
        put(state, chan, true)?;
        for c in live_of(state) {
            let c_star = c == "*";
            if if star { !c_star } else { c_star } {
                put(state, &c, false)?;
            }
        }
        if !star && uchan_find(state, uuid, "*").is_none() {
            put(state, "*", false)?;
        }
    } else if star {
        for c in live_of(state) {
            put(state, &c, false)?;
        }
        if uchan_find(state, uuid, "*").is_none() {
            put(state, "*", false)?;
        }
    } else {
        put(state, chan, false)?;
    }
    Some(n)
}

/// A channel removed takes its oper bindings with it, at the c| del stamp
/// (plan U6).  "*" stays.  C `access_chan_cascade`.
pub fn chan_cascade(state: &mut BotState, chan: &str, ts: i64) -> usize {
    let hits: Vec<(String, String)> = state
        .uchan_records
        .iter()
        .filter(|r| r.is_active && r.chan != "*" && r.chan.eq_ignore_ascii_case(chan))
        .map(|r| (r.uuid.clone(), r.chan.clone()))
        .collect();
    hits.into_iter()
        .filter(|(u, c)| uchan_put(state, u, c, false, ts))
        .count()
}
