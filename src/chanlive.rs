//! Live channel state from the server (chanlive.c, modes.md section 5.4):
//! 005 values, the mode letters / key / limit of each channel (324 + MODE),
//! its ban list (367 + MODE +b/-b), and the election-driven "apply the stored
//! modes" job.  Everything here is volatile; nothing is persisted or sent to
//! a hub.  Server data is hostile: every token is length-checked before it is
//! copied and a list can never grow past [`Isupport::ban_cap`].

use crate::consts::*;
use crate::cstr::{Tok, eq_ic, now, trunc, trunc_string};
use crate::state::{BotState, Chan, CsetId, Isupport, LiveBan};
use crate::{auth, chancfg, channel, ircf, logm};

// ---- 005 (RPL_ISUPPORT) -------------------------------------------------------

/// isupport_reset(): back to what a server that says nothing is assumed to
/// have (called on every connect and disconnect).
pub fn isupport_reset(state: &mut BotState) {
    state.isup = Isupport::default();
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 6 && s.bytes().all(|c| c.is_ascii_digit())
}

/// Timestamp field of a 329 / 367: 1-20 digits, parsed with an overflow check
/// (a value that does not fit an i64 reads as 0 = unknown).  Real unix times
/// are 10 digits; the old 6-digit cap of [`all_digits`] rejected every one.
fn parse_ts(s: &str) -> i64 {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    s.parse().unwrap_or(0)
}

fn isupport_token(is: &mut Isupport, tok: &str) {
    let neg = tok.starts_with('-');
    let tok = if neg { &tok[1..] } else { tok };
    let (name, val) = match tok.find('=') {
        Some(e) => (&tok[..e], &tok[e + 1..]),
        None => (tok, ""),
    };

    match name {
        "MODES" => {
            if neg {
                is.modes = ISUPPORT_MODES_DEFAULT;
            } else if val.is_empty() {
                is.modes = ISUPPORT_MODES_MAX; // no limit
            } else if all_digits(val) {
                let v: i32 = val.parse().unwrap_or(0);
                if v >= 1 {
                    is.modes = v.min(ISUPPORT_MODES_MAX);
                }
            }
        }
        "MAXLIST" => {
            if neg {
                is.maxlist_b = 0;
                return;
            }
            // "beI:100,k:5": a letter group, a colon, a number
            let mut p = val;
            while let Some(colon) = p.find(':') {
                let rest = &p[colon + 1..];
                let (num, next) = match rest.find(',') {
                    Some(e) => (&rest[..e], Some(&rest[e + 1..])),
                    None => (rest, None),
                };
                if p[..colon].contains('b') && all_digits(num) {
                    let v: i32 = num.parse().unwrap_or(0);
                    if v >= 1 {
                        is.maxlist_b = v;
                    }
                }
                match next {
                    Some(n) => p = n,
                    None => break,
                }
            }
        }
        "MAXBANS" => {
            if is.maxlist_b == 0 && all_digits(val) {
                let v: i32 = val.parse().unwrap_or(0);
                if v >= 1 {
                    is.maxlist_b = v;
                }
            }
        }
        "NICKLEN" => {
            if neg {
                is.nicklen = NICKLEN_DEFAULT;
                return;
            }
            if all_digits(val) {
                let v: i32 = val.parse().unwrap_or(0);
                if v >= 1 {
                    is.nicklen = v;
                }
            }
        }
        "PREFIX" => {
            if neg {
                is.prefix_modes = "ov".into();
                is.prefix_syms = "@+".into();
                return;
            }
            // "(ohv)@%+": equal numbers of mode letters and symbols, at most 8
            if !val.starts_with('(') {
                return;
            }
            let Some(close) = val.find(')') else { return };
            let (ml, sl) = (close - 1, val.len() - close - 1);
            if ml == 0 || ml != sl || ml >= 9 {
                return;
            }
            if !val.as_bytes()[1..1 + ml]
                .iter()
                .all(|c| c.is_ascii_alphabetic())
            {
                return;
            }
            is.prefix_modes = val[1..1 + ml].to_string();
            is.prefix_syms = val[close + 1..].to_string();
        }
        "CHANMODES" => {
            if neg {
                return;
            }
            let cap = [64usize; 4];
            let mut tmp: [&str; 4] = [""; 4];
            let mut p = val;
            for i in 0..4 {
                let comma = p.find(',');
                let fl = comma.unwrap_or(p.len());
                if i < 3 && comma.is_none() {
                    return; // malformed: keep what we had
                }
                // A, B, C name the modes that take arguments: a clipped one
                // would misread every MODE line, so an oversized one is
                // refused.  D (the flag modes) is only ever looked up for a
                // letter, so it is cut.
                if fl >= cap[i] && i < 3 {
                    return;
                }
                tmp[i] = trunc(&p[..fl], cap[i]);
                p = match comma {
                    Some(c) => &p[c + 1..],
                    None => &p[fl..],
                };
            }
            is.cm_a = tmp[0].to_string();
            is.cm_b = tmp[1].to_string();
            is.cm_c = tmp[2].to_string();
            is.cm_d = tmp[3].to_string();
        }
        _ => {}
    }
}

/// 005 parameters: "<me> TOKEN[=v] ... :are supported by this server".
pub fn isupport_parse(state: &mut BotState, params: &str) {
    let mut t = Tok::new(params);
    t.next(" "); // our nick
    while let Some(tok) = t.next(" ") {
        if tok.starts_with(':') {
            break; // trailing "are supported by this server"
        }
        if tok.len() < 120 {
            isupport_token(&mut state.isup, tok);
        }
    }
}

impl Isupport {
    pub fn is_prefix_mode(&self, m: u8) -> bool {
        m != 0 && self.prefix_modes.as_bytes().contains(&m)
    }

    /// Does MODE letter `m` take an argument when set (adding) / cleared?
    pub fn mode_has_arg(&self, m: u8, adding: bool) -> bool {
        if self.is_prefix_mode(m) {
            return true;
        }
        if self.cm_a.as_bytes().contains(&m) || self.cm_b.as_bytes().contains(&m) {
            return true;
        }
        if self.cm_c.as_bytes().contains(&m) {
            return adding;
        }
        false
    }

    /// Longest member nick we accept: the server's NICKLEN, held to our
    /// buffers (isupport_nicklen).
    pub fn nicklen(&self) -> usize {
        let n = if self.nicklen > 0 {
            self.nicklen
        } else {
            NICKLEN_DEFAULT
        };
        (n as usize).min(MAX_MEMBER_NICK - 1)
    }

    /// min(MAXLIST, BAN_LIST_CAP)
    pub fn ban_cap(&self) -> usize {
        let n = if self.maxlist_b > 0 {
            self.maxlist_b
        } else {
            MAXLIST_DEFAULT
        };
        n.min(BAN_LIST_CAP) as usize
    }
}

// ---- live modes -----------------------------------------------------------------

/// Bit of a mode letter in `Chan.live_flags`; 0 if it is not a letter.
pub fn live_bit(letter: u8) -> u64 {
    match letter {
        b'a'..=b'z' => 1u64 << (letter - b'a'),
        b'A'..=b'Z' => 1u64 << (26 + (letter - b'A')),
        _ => 0,
    }
}

pub fn live_has(c: &Chan, letter: u8) -> bool {
    let b = live_bit(letter);
    b != 0 && c.live_flags & b != 0
}

/// channel_live_reset(): free a channel's live ban list and flood windows and
/// reset its live state.
pub fn live_reset(c: &mut Chan) {
    c.bans.clear();
    c.flood = Vec::new(); // flood windows start afresh with each stay
    c.live_flags = 0;
    c.live_key.clear();
    c.live_limit = 0;
    c.live_known = false;
    c.live_created = 0;
    c.ban_list_open = false;
    c.ban_list_known = false;
    c.ban_overflow_logged = false;
    c.who_done = false;
}

pub fn ban_add(state: &mut BotState, ci: usize, mask: &str, setter: &str, when: i64) {
    if mask.is_empty() || mask.len() >= MAX_MASK_LEN {
        return; // never store a clipped mask
    }
    if state.chans[ci].bans.iter().any(|b| eq_ic(&b.mask, mask)) {
        return;
    }
    let cap = state.isup.ban_cap();
    if state.chans[ci].bans.len() >= cap {
        let c = &mut state.chans[ci];
        if !c.ban_overflow_logged {
            c.ban_overflow_logged = true;
            let name = c.name.clone();
            logm!(
                state,
                L_INFO,
                "[MODE] Ban list of {} is past {} entries; not tracking more\n",
                name,
                cap
            );
        }
        return;
    }
    state.chans[ci].bans.push(LiveBan {
        mask: mask.to_string(),
        setter: trunc_string(setter, MAX_MEMBER_NICK + 32),
        when,
    });
}

pub fn ban_del(c: &mut Chan, mask: &str) {
    if let Some(i) = c.bans.iter().position(|b| eq_ic(&b.mask, mask)) {
        c.bans.swap_remove(i);
    }
}

pub fn ban_list_end(c: &mut Chan) {
    if !c.ban_list_open {
        c.bans.clear(); // 368 with no 367: the list is empty
    }
    c.ban_list_open = false;
    c.ban_list_known = true;
}

/// Apply "<modes> [args...]" (a 324 or a MODE) to the channel's live state.
/// `from_324` resets the live modes first.
pub fn apply(state: &mut BotState, ci: usize, modes: &str, args: &str, from_324: bool) {
    if from_324 {
        let c = &mut state.chans[ci];
        c.live_flags = 0;
        c.live_key.clear();
        c.live_limit = 0;
        c.live_known = true;
    }
    let mut toks = Tok::new(args);
    let mut arg = toks.next(" ");
    let mut adding = true;
    for ch in modes.bytes() {
        if ch == b'+' {
            adding = true;
            continue;
        }
        if ch == b'-' {
            adding = false;
            continue;
        }
        let has_arg = state.isup.mode_has_arg(ch, adding);
        let mut a: Option<&str> = None;
        if has_arg && let Some(x) = arg {
            a = Some(x);
            arg = toks.next(" ");
        }
        if has_arg && a.is_none() && ch != b'k' {
            continue; // malformed: an argument is missing
        }

        if ch == b'b' {
            if let Some(a) = a
                && !from_324
            {
                if adding {
                    ban_add(state, ci, a, "", now());
                } else {
                    ban_del(&mut state.chans[ci], a);
                }
            }
        } else if ch == b'k' {
            let c = &mut state.chans[ci];
            if adding {
                c.live_flags |= live_bit(b'k');
                if let Some(a) = a {
                    c.live_key = trunc_string(a, MAX_KEY);
                }
            } else {
                c.live_flags &= !live_bit(b'k');
                c.live_key.clear();
            }
        } else if ch == b'l' {
            let c = &mut state.chans[ci];
            if adding && let Some(a) = a.filter(|a| all_digits(a)) {
                c.live_flags |= live_bit(b'l');
                c.live_limit = a.parse().unwrap_or(0);
            } else if !adding {
                c.live_flags &= !live_bit(b'l');
                c.live_limit = 0;
            }
        } else if state.isup.is_prefix_mode(ch) {
            let c = &mut state.chans[ci];
            let r = a.and_then(|a| c.roster.iter_mut().find(|r| eq_ic(&r.nick, a)));
            if let Some(r) = r {
                if ch == b'h' {
                    r.is_halfop = adding;
                } else if ch == b'v' {
                    r.is_voice = adding;
                }
            }
            // 'o' is kept by irc_parser::handle_mode_change (it also reacts
            // to us)
        } else if !has_arg && ch.is_ascii_alphabetic() {
            let bit = live_bit(ch);
            let c = &mut state.chans[ci];
            if adding {
                c.live_flags |= bit;
            } else {
                c.live_flags &= !bit;
            }
        }
    }
}

/// 324 / 329 / 367 / 368 numerics: `params` are those after the command word
/// ("<me> <chan> <rest...>").
pub fn numeric(state: &mut BotState, command: &str, params: &str) {
    if params.len() >= 1024 {
        return; // no real 324/329/367 is this long
    }
    let mut t = Tok::new(params);
    if t.next(" ").is_none() {
        return;
    }
    let Some(chan) = t.next(" ") else { return };
    let Some(ci) = channel::find(state, chan) else {
        return;
    };
    let rest = t.remaining();
    match command {
        "324" => {
            let mut t = Tok::new(rest);
            if let Some(modes) = t.next(" ") {
                apply(state, ci, modes, t.remaining(), true);
            }
            state.chans[ci].enf_dirty = true;
        }
        "329" => {
            let mut t = Tok::new(rest);
            state.chans[ci].live_created = t.next(" ").map_or(0, parse_ts);
        }
        "367" => {
            let mut t = Tok::new(rest);
            let mask = t.next(" ");
            let setter = t.next(" ");
            let ts = t.next(" ");
            let Some(mask) = mask else { return };
            if !state.chans[ci].ban_list_open {
                state.chans[ci].bans.clear();
                state.chans[ci].ban_list_open = true;
            }
            let when = ts.map_or(0, parse_ts);
            ban_add(state, ci, mask, setter.unwrap_or(""), when);
        }
        "368" => {
            ban_list_end(&mut state.chans[ci]);
            state.chans[ci].enf_dirty = true;
        }
        _ => {}
    }
}

/// Ask the server for a channel's modes and ban list (own JOIN).
pub fn request(state: &mut BotState, ci: usize) {
    let name = state.chans[ci].name.clone();
    ircf!(state, "MODE {}\r\n", name);
    ircf!(state, "MODE {} +b\r\n", name);
}

/// (found, authorised): whether `nick` is in the channel's roster at all, and
/// whether it is authorised.
pub fn member_authorised(state: &BotState, ci: usize, nick: &str) -> (bool, bool) {
    match state.chans[ci].roster.iter().find(|r| eq_ic(&r.nick, nick)) {
        Some(r) => (true, auth::is_authorised(state, &r.hostmask)),
        None => (false, false),
    }
}

// ---- election kind `mode`: move the live modes to the stored ones -------------------

/// Queue the MODE lines that move the live modes to the stored C| modes +
/// c| key.  Returns (lines queued, summary); -1 lines = no stored/known state
/// to act on.
pub fn apply_stored(state: &mut BotState, ci: usize) -> (i32, String) {
    sync(state, ci, false, false, false)
}

/// chanmode_sync(): core of the mode apply / mode job.  `skip_limit` leaves
/// +l / -l alone (the dynamic limit owns it); `dry` only counts what it would
/// send; `require_known` refuses to act on a live-mode picture we never
/// received (the enforcement path -- the one-shot apply sends everything when
/// unknown).
pub fn sync(
    state: &mut BotState,
    ci: usize,
    skip_limit: bool,
    dry: bool,
    require_known: bool,
) -> (i32, String) {
    let spec = chancfg::get_modes(state, state.chans.get(ci)).to_string();
    if spec.len() >= 128 {
        return (-1, "stored modes too long".into());
    }

    // Stored form: "+stnkl 20" -- one letters token, then the limit if +l.
    let mut t = Tok::new(&spec);
    let letters = t.next(" ");
    let limit_arg = t.next(" ");
    let mut dir = [0u8; 128]; // per letter: '+', '-' or 0
    let mut want_limit = 0i64;
    let mut adding = true;
    let Some(letters) = letters else {
        return (-1, "no stored modes".into());
    };
    for m in letters.chars() {
        if m == '+' {
            adding = true;
            continue;
        }
        if m == '-' {
            adding = false;
            continue;
        }
        if !"imnpstkl".contains(m) {
            return (-1, format!("stored modes hold '{m}'"));
        }
        dir[m as usize & 0x7f] = if adding { b'+' } else { b'-' };
    }
    if dir[b'l' as usize] == b'+' {
        match limit_arg
            .filter(|a| all_digits(a))
            .map(|a| a.parse::<i64>())
        {
            Some(Ok(v)) if (1..=99999).contains(&v) => want_limit = v,
            _ => return (-1, "stored limit is not usable".into()),
        }
    }
    let c = &state.chans[ci];
    let (name, key, live_key, live_limit) = (
        c.name.clone(),
        c.key.clone(),
        c.live_key.clone(),
        c.live_limit,
    );
    let known = c.live_known;
    if require_known && !known {
        return (-1, "live modes not known yet".into());
    }
    let has = |l: u8| live_has(c, l);
    let flags: Vec<(u8, bool)> = "imnpst".bytes().map(|l| (l, has(l))).collect();
    let (live_k, live_l) = (has(b'k'), has(b'l'));

    let mut queued = 0;
    for (p, h) in flags {
        let d = dir[p as usize];
        if d == 0 {
            continue;
        }
        if d == b'+' && (!known || !h) {
            if !dry {
                ircf!(state, "MODE {} +{}\r\n", name, p as char);
            }
            queued += 1;
        } else if d == b'-' && (!known || h) {
            if !dry {
                ircf!(state, "MODE {} -{}\r\n", name, p as char);
            }
            queued += 1;
        }
    }
    let kd = dir[b'k' as usize];
    let key_ok = !key.is_empty() && !key.contains([' ', ',', '\r', '\n', '\t']);
    if kd == b'+' && key_ok {
        if !known || !live_k || live_key != key {
            if live_k && !live_key.is_empty() && live_key != "*" && live_key != key {
                if !dry {
                    ircf!(state, "MODE {} -k {}\r\n", name, live_key);
                }
                queued += 1;
            }
            if !dry {
                ircf!(state, "MODE {} +k {}\r\n", name, key);
            }
            queued += 1;
        }
    } else if kd == b'-' && known && live_k && !live_key.is_empty() && live_key != "*" {
        if !dry {
            ircf!(state, "MODE {} -k {}\r\n", name, live_key);
        }
        queued += 1;
    }
    let ld = if skip_limit { 0 } else { dir[b'l' as usize] };
    if ld == b'+' {
        if !known || !live_l || live_limit != want_limit {
            if !dry {
                ircf!(state, "MODE {} +l {}\r\n", name, want_limit);
            }
            queued += 1;
        }
    } else if ld == b'-' && (!known || live_l) {
        if !dry {
            ircf!(state, "MODE {} -l\r\n", name);
        }
        queued += 1;
    }
    (
        queued,
        format!(
            "{} change{} queued",
            queued,
            if queued == 1 { "" } else { "s" }
        ),
    )
}

/// The `bitch` setting, as the election's `op` job reads it.
pub fn bitch(state: &BotState, ci: usize) -> bool {
    chancfg::get(state, state.chans.get(ci), CsetId::Bitch) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isupport_tokens() {
        let mut is = Isupport::default();
        isupport_token(&mut is, "MODES=6");
        isupport_token(&mut is, "MAXLIST=beI:60,k:5");
        isupport_token(&mut is, "PREFIX=(ohv)@%+");
        isupport_token(&mut is, "CHANMODES=beI,k,l,imnpst");
        assert_eq!((is.modes, is.maxlist_b), (6, 60));
        assert_eq!(
            (is.prefix_modes.as_str(), is.prefix_syms.as_str()),
            ("ohv", "@%+")
        );
        assert!(is.mode_has_arg(b'l', true) && !is.mode_has_arg(b'l', false));
        isupport_token(&mut is, "MODES=99");
        assert_eq!(is.modes, ISUPPORT_MODES_MAX);
        isupport_token(&mut is, "PREFIX=(ov)@");
        assert_eq!(is.prefix_modes, "ohv");
        isupport_token(&mut is, "-MODES");
        assert_eq!(is.modes, ISUPPORT_MODES_DEFAULT);
    }

    #[test]
    fn timestamps() {
        assert_eq!(parse_ts("1790000000"), 1_790_000_000);
        assert_eq!(parse_ts("12345678901234567890"), 0); // 20 digits, > i64
        assert_eq!(parse_ts("1234567890123456789"), 1_234_567_890_123_456_789);
        assert_eq!(parse_ts("123456789012345678901"), 0); // 21 digits
        assert_eq!(parse_ts("12a"), 0);
        assert_eq!(parse_ts(""), 0);
    }

    #[test]
    fn live_bits() {
        assert_eq!(live_bit(b'a'), 1);
        assert_eq!(live_bit(b'A'), 1 << 26);
        assert_eq!(live_bit(b'1'), 0);
    }

    fn isup(tokens: &str) -> Isupport {
        let mut is = Isupport::default();
        for t in tokens.split(' ') {
            isupport_token(&mut is, t);
        }
        is
    }

    #[test]
    fn nicklen_default_parse_and_cap() {
        let mut is = Isupport::default();
        assert_eq!(is.nicklen(), 30);
        isupport_token(&mut is, "NICKLEN=9");
        assert_eq!(is.nicklen(), 9);
        isupport_token(&mut is, "NICKLEN=31");
        assert_eq!(is.nicklen(), 31);
        isupport_token(&mut is, "NICKLEN=200");
        assert_eq!(is.nicklen(), MAX_MEMBER_NICK - 1);
        isupport_token(&mut is, "NICKLEN=0");
        assert_eq!(is.nicklen(), MAX_MEMBER_NICK - 1); // 0 is not taken
        isupport_token(&mut is, "-NICKLEN");
        assert_eq!(is.nicklen(), 30);
        isupport_token(&mut is, "NICKLEN=abc");
        assert_eq!(is.nicklen(), 30);
    }

    #[test]
    fn chanmodes_fields_are_64_bytes_and_d_is_cut() {
        let is = isup("CHANMODES=beI,k,l,imnpst");
        assert_eq!((is.cm_a.as_str(), is.cm_d.as_str()), ("beI", "imnpst"));
        // A, B, C up to 63 bytes are taken (they were 24 before)
        let a63 = "a".repeat(63);
        let is = isup(&format!("CHANMODES={a63},k,l,imnpst"));
        assert_eq!(is.cm_a, a63);
        // an oversized A, B or C refuses the whole token
        let a64 = "a".repeat(64);
        let is = isup(&format!("CHANMODES={a64},k,l,x"));
        assert_eq!(is.cm_a, "beI");
        assert_eq!(is.cm_d, "imnpst");
        let is = isup(&format!("CHANMODES=b,{a64},l,x"));
        assert_eq!(is.cm_d, "imnpst");
        // an oversized D is cut to 63 bytes, the rest of the token is kept
        let d100 = "d".repeat(100);
        let is = isup(&format!("CHANMODES=beI,k,l,{d100}"));
        assert_eq!(is.cm_a, "beI");
        assert_eq!(is.cm_d, "d".repeat(63));
        let d64 = "d".repeat(64);
        assert_eq!(isup(&format!("CHANMODES=beI,k,l,{d64}")).cm_d.len(), 63);
        // malformed (too few fields) keeps what we had
        assert_eq!(isup("CHANMODES=beI,k").cm_d, "imnpst");
    }
}
