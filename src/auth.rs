//! Usermask matching and trusted-bot lookup (auth.c).

use crate::consts::*;
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

/// Record a successful authentication; the debounced flush in main persists
/// last_seen / last_used.
pub fn mark_used(state: &mut BotState, user: Option<usize>, mask_idx: Option<usize>, now: i64) {
    if let Some(u) = user.and_then(|u| state.user_records.get_mut(u)) {
        u.last_seen = now;
    }
    if let Some(m) = mask_idx.and_then(|m| state.mask_records.get_mut(m)) {
        m.last_used = now;
    }
    state.config_dirty = true;
}

/// Drop a leading '~' from the ident of nick!ident@host: stored masks and
/// live WHO results may differ in it.
fn strip_ident_tilde(s: &str) -> String {
    match s.find('!') {
        Some(b) if s[b + 1..].starts_with('~') => format!("{}{}", &s[..=b], &s[b + 2..]),
        _ => s.to_string(),
    }
}

/// Index of the trusted bot whose stored mask matches `user_host`.
pub fn trusted_bot_by_host(state: &BotState, user_host: &str) -> Option<usize> {
    if state.trusted_bots.is_empty() {
        return None;
    }
    let norm = strip_ident_tilde(crate::cstr::trunc(user_host, MAX_MASK_LEN));
    state
        .trusted_bots
        .iter()
        .position(|tb| wildcard_match(&strip_ident_tilde(&tb.mask), &norm))
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
}
