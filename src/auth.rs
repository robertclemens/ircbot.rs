//! Usermask matching and trusted-bot lookup (auth.c).

use crate::consts::*;
use crate::glob_overlap::hostmask_overlap;
use crate::logm;
use crate::state::BotState;

/// Case-insensitive IRC-style glob ('*', '?'), greedy with backtracking to
/// the last '*'.  Used for usermasks and for matching a requester's hostmask
/// against channel ban masks.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            star_t = ti;
        } else if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Every active, keyed user record that owns an active mask matching
/// `user_host`, once each, with the first matching mask index.  No side
/// effects: see [`mark_used`].
pub fn user_candidates(state: &BotState, user_host: &str) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (mi, mr) in state.mask_records.iter().enumerate() {
        if out.len() >= MAX_USER_RECORDS {
            break;
        }
        if !mr.is_active || mr.mask.is_empty() || !wildcard_match(&mr.mask, user_host) {
            continue;
        }
        if let Some(ui) = state
            .user_records
            .iter()
            .position(|u| u.is_active && u.has_pubkey && u.uuid == mr.uuid)
            && !out.iter().any(|&(u, _)| u == ui)
        {
            out.push((ui, mi));
        }
    }
    if out.is_empty() {
        logm!(
            state,
            L_DEBUG,
            "[AUTH] no keyed user mask matched {}\n",
            user_host
        );
    }
    out
}

/// True when `now` opens a new ACTIVITY_BUCKET after `prev`: the first use
/// within a clock hour, the only one reported to the hub.
fn activity_new_bucket(prev: i64, now: i64) -> bool {
    prev / ACTIVITY_BUCKET < now / ACTIVITY_BUCKET
}

/// Record a successful authentication; the debounced flush in main persists
/// last_seen / last_used.  The first use of a record within a clock hour is
/// also reported to the hub (CMD_ACTIVITY), with this use's exact time.
pub fn mark_used(state: &mut BotState, user: Option<usize>, mask_idx: Option<usize>, now: i64) {
    if let Some(u) = user.and_then(|u| state.user_records.get_mut(u)) {
        if activity_new_bucket(u.last_seen, now) {
            u.act_pending = now;
        }
        u.last_seen = now;
    }
    if let Some(m) = mask_idx.and_then(|m| state.mask_records.get_mut(m)) {
        if activity_new_bucket(m.last_used, now) {
            m.act_pending = now;
        }
        m.last_used = now;
    }
    state.config_dirty = true;
    crate::hub_client::send_activity(state);
}

/// Drop a leading '~' from the ident of nick!ident@host: stored masks and
/// live WHO results may differ in it.
fn strip_ident_tilde(s: &str) -> String {
    match s.find('!') {
        Some(b) if s[b + 1..].starts_with('~') => format!("{}{}", &s[..=b], &s[b + 2..]),
        _ => s.to_string(),
    }
}

/// Two full masks are the same identity: nick!ident@host part by part, the
/// nick and the host ignoring ASCII case, the ident exactly.  Nothing is
/// wildcarded and no '~' is dropped: a bot is the mask the server shows for
/// it (2026-11-23: bots match exactly, users by their stored patterns).  C
/// `auth_mask_equal`.
pub fn mask_equal(a: &str, b: &str) -> bool {
    let split = |m: &str| -> Option<(String, String, String)> {
        let bang = m.find('!')?;
        let at = bang + 1 + m[bang + 1..].find('@')?;
        let (n, i, h) = (&m[..bang], &m[bang + 1..at], &m[at + 1..]);
        (!n.is_empty() && !i.is_empty() && !h.is_empty()).then(|| (n.into(), i.into(), h.into()))
    };
    match (split(a), split(b)) {
        (Some((an, ai, ah)), Some((bn, bi, bh))) => {
            an.eq_ignore_ascii_case(&bn) && ai == bi && ah.eq_ignore_ascii_case(&bh)
        }
        _ => false,
    }
}

/// Whether a stored trusted-bot mask stands for live mask `live`.  A
/// hub-configured bot (any h| line, linked now or not) holds the masks the
/// other bots published: exactly (mask_equal).  A purely standalone bot
/// holds the masks an admin typed (+bot, config b|): as patterns, like user
/// masks -- the ~B2 key is what authenticates.  C `auth_bot_mask_ok`.
pub fn bot_mask_ok(state: &BotState, stored: &str, live: &str) -> bool {
    mask_equal(stored, live) || (state.hubs.is_empty() && wildcard_match(stored, live))
}

/// The stored trusted-bot entry for `user_host` (bot_mask_ok); an entry
/// whose mask IS the host wins over an earlier pattern that also matches it
/// (two bots on one host must not answer for each other).
pub fn trusted_bot_by_host(state: &BotState, user_host: &str) -> Option<usize> {
    let mut first = None;
    for (i, tb) in state.trusted_bots.iter().enumerate() {
        if mask_equal(&tb.mask, user_host) {
            return Some(i);
        }
        if first.is_none() && bot_mask_ok(state, &tb.mask, user_host) {
            first = Some(i);
        }
    }
    first
}

/// A person's live mask still stands for that user in chan: an active user
/// record, one of its own active usermask patterns matches the live mask,
/// and it may act there (an admin anywhere, an oper only where it is bound).
/// C `auth_user_live_ok`.
pub fn user_live_ok(state: &BotState, uuid: &str, nuh: &str, chan: &str) -> bool {
    if uuid.is_empty() || nuh.is_empty() {
        return false;
    }
    let Some(ur) = state
        .user_records
        .iter()
        .find(|u| u.is_active && u.uuid == uuid)
    else {
        return false;
    };
    let mask_ok = state.mask_records.iter().any(|m| {
        m.is_active && !m.mask.is_empty() && m.uuid == uuid && wildcard_match(&m.mask, nuh)
    });
    mask_ok && (ur.typ == 'a' || crate::access::user_chan_ok(state, uuid, Some(chan)))
}

/// Log label for another bot or a user named by uuid (C `bot_who`):
/// "bot bunny_ (<uuid>)", "admin admin (<uuid>)"; a name nobody knows reads
/// "?".  kind: 'b' bot, 'u' admin/oper.
pub fn who(state: &BotState, kind: char, uuid: &str) -> String {
    let mut word = if kind == 'u' { "user" } else { "bot" };
    let mut name = String::new();
    if !uuid.is_empty() && kind == 'b' {
        if let Some(tb) = state.trusted_bots.iter().find(|tb| tb.uuid == uuid) {
            let n = tb.mask.split('!').next().unwrap_or("");
            name = crate::cstr::trunc_string(n, MAX_NICK);
        }
    } else if !uuid.is_empty()
        && kind == 'u'
        && let Some(u) = state.user_records.iter().find(|u| u.uuid == uuid)
    {
        word = if u.typ == 'a' { "admin" } else { "oper" };
        name = u.name.clone();
    }
    let s = format!(
        "{word} {} ({})",
        crate::cstr::trunc(if name.is_empty() { "?" } else { &name }, 64),
        crate::cstr::trunc(if uuid.is_empty() { "?" } else { uuid }, 64)
    );
    // names come from the hub: no control byte reaches a log line through one
    s.chars()
        .map(|q| {
            if (q as u32) < 0x20 || q as u32 == 0x7f {
                '_'
            } else {
                q
            }
        })
        .collect()
}

pub fn trusted_bot_by_uuid(state: &BotState, uuid: &str) -> Option<usize> {
    if uuid.is_empty() {
        return None;
    }
    state.trusted_bots.iter().position(|tb| tb.uuid == uuid)
}

pub fn trusted_bot_by_nick(state: &BotState, nick: &str) -> Option<usize> {
    if nick.is_empty() {
        return None;
    }
    state
        .trusted_bots
        .iter()
        .position(|tb| tb.nick().eq_ignore_ascii_case(nick))
}

pub fn is_trusted_bot(state: &BotState, user_host: &str) -> bool {
    trusted_bot_by_host(state, user_host).is_some()
}

/// Index of the active user record (admin or oper) owning `uuid`; it need
/// not hold a key.
fn mask_has_active_user(state: &BotState, uuid: &str) -> Option<usize> {
    state
        .user_records
        .iter()
        .position(|u| u.is_active && u.uuid == uuid)
}

/// A user whose standing counts in `chan` (user_flags plan §6, U12): every
/// active admin everywhere (network staff, whatever their flags); an oper in
/// the channels it is bound to, or everywhere with "*".  chan None =
/// anywhere: an oper with any live binding.  C `user_counts_in`.
fn user_counts_in(state: &BotState, uuid: &str, chan: Option<&str>) -> Option<usize> {
    let ui = mask_has_active_user(state, uuid)?;
    let u = &state.user_records[ui];
    let ok = u.typ == 'a'
        || match chan {
            None => crate::access::user_chan_count(state, uuid).0 > 0,
            Some(c) => crate::access::user_chan_ok(state, uuid, Some(c)),
        };
    ok.then_some(ui)
}

/// modes.md section 1: "authorised" = matches a trusted-bot mask, or an
/// active usermask of an active admin/oper -- an oper only in its channels
/// (plan §6).  The user record need not hold a key: what matters is the
/// operator's standing, not whether they can sign ~A2.
pub fn is_authorised(state: &BotState, nuh: &str, chan: Option<&str>) -> bool {
    if nuh.is_empty() {
        return false;
    }
    if is_trusted_bot(state, nuh) {
        return true;
    }
    state.mask_records.iter().any(|mr| {
        mr.is_active
            && !mr.mask.is_empty()
            && wildcard_match(&mr.mask, nuh)
            && user_counts_in(state, &mr.uuid, chan).is_some()
    })
}

/// Section 6.2 step 2: Some(label of the first conflict) when ban mask `mask`
/// could also hit a bot or an operator who is not in the channel right now.
/// Pattern-vs-pattern, so '*' on either side is taken at its widest.
pub fn mask_overlaps_authorised(
    state: &BotState,
    mask: &str,
    chan: Option<&str>,
) -> Option<String> {
    // matching drops a leading '~' of the ident (strip_ident_tilde), so the
    // overlap test does too, on both sides
    let nmask = strip_ident_tilde(mask);
    if let Some(tb) = state
        .trusted_bots
        .iter()
        .find(|tb| hostmask_overlap(&nmask, &strip_ident_tilde(&tb.mask)))
    {
        return Some(format!("bot {}", tb.mask));
    }
    for mr in &state.mask_records {
        if !mr.is_active
            || mr.mask.is_empty()
            || !hostmask_overlap(&nmask, &strip_ident_tilde(&mr.mask))
        {
            continue;
        }
        if let Some(ui) = user_counts_in(state, &mr.uuid, chan) {
            return Some(format!("user {}", state.user_records[ui].name));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::wildcard_match as m;

    #[test]
    fn glob() {
        assert!(m("*!*@*.example.com", "Nick!user@host.EXAMPLE.com"));
        assert!(m("n?ck!*@*", "nick!u@h"));
        assert!(!m("nick!*@a", "nick!u@b"));
        assert!(m("*", ""));
        assert!(m("a*b*c", "aXXbYYc"));
        assert!(!m("a*b*c", "aXXbYY"));
        assert!(!m("", "x"));
    }

    #[test]
    fn trusted_bots_exact_when_hub_configured_patterns_when_standalone() {
        use crate::state::{BotState, HubEntry, TrustedBot};
        let mut st = BotState::for_test();
        for (mask, uuid) in [("*!*@shared.host", "a"), ("bot6!~b@shared.host", "b")] {
            st.trusted_bots.push(TrustedBot {
                mask: mask.into(),
                uuid: uuid.into(),
                ..TrustedBot::default()
            });
        }
        // standalone (no hub): the admin's masks are patterns; the entry
        // whose mask IS the host still wins over an earlier pattern
        assert_eq!(
            super::trusted_bot_by_host(&st, "bot6!~b@shared.host"),
            Some(1)
        );
        assert_eq!(
            super::trusted_bot_by_host(&st, "bot7!c@shared.host"),
            Some(0)
        );
        // hub-configured: exact only -- nick and host ignore case, the ident
        // is exact ('~' included), a stored pattern never matches
        st.hubs.push(HubEntry {
            addr: "127.0.0.1:7000".into(),
            ed_pub: [0; 32],
            ed_pub_set: false,
        });
        assert_eq!(
            super::trusted_bot_by_host(&st, "BOT6!~b@SHARED.host"),
            Some(1)
        );
        assert_eq!(super::trusted_bot_by_host(&st, "bot6!b@shared.host"), None);
        assert_eq!(super::trusted_bot_by_host(&st, "bot6!~B@shared.host"), None);
        assert_eq!(super::trusted_bot_by_host(&st, "bot7!c@shared.host"), None);
        assert!(!super::mask_equal("a!b@c", "a!b@c.d"));
        assert!(!super::mask_equal("a!@c", "a!@c"));
    }
}
