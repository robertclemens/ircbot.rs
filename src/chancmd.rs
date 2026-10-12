//! Bot commands for hubless networks (chancmd.c, irchub docs/modes.md
//! section 5.2):
//!
//!   chanmode <#c> [<modes> [args]|-]     = console `channel mode`
//!   chanset  <#c|default> [...]          = console `channel set`
//!   +ban <#c|*> <mask> [min|perm] [sticky] [reason] / -ban / bans
//!                                        = console `ban add/del/list`
//!
//! They write this bot's own C| / D| / B| (and the c| key) with LWW stamps,
//! through the same record codecs the hub's lines use (`chancfg::local_*`),
//! and apply at once: a connected hub gets the lines, the config is saved,
//! the channel sweeps run.  The dispatcher refuses them under opt 'h' like
//! chkey; this file asks `admin_change_refused` again, so nothing here runs
//! gated off.  Replies go out as PRIVMSG to the asker, which a ~A2S command
//! seals.  Every ban is checked against bots and authorised users first
//! (section 6.2).

use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::{Tok, eq_ic, now, trunc_string};
use crate::state::{BotState, CS_COUNT, CsetId, FL_COUNT, FloodKind, lww_next_ts};
use crate::{chancfg, chanenf, chanlive, channel, hub_client, ircf};

fn say(state: &mut BotState, nick: &str, text: &str) {
    ircf!(state, "PRIVMSG {} :{}\r\n", nick, text);
}

fn refused(state: &mut BotState, nick: &str, cmd: &str) -> bool {
    if !chancfg::admin_change_refused(state) {
        return false;
    }
    ircf!(
        state,
        "PRIVMSG {} :Error: '{}' is disabled -- network is in hub-only-mutation mode (opt 'h'). Use the hub console.\r\n",
        nick,
        cmd
    );
    true
}

/// A managed channel by name (its index), or None (reply sent).
fn find_chan(state: &mut BotState, nick: &str, name: Option<&str>) -> Option<usize> {
    let Some(name) = name.filter(|n| n.starts_with(['#', '&']) && n.len() < MAX_CHAN) else {
        say(state, nick, "Error: give a channel name (#channel).");
        return None;
    };
    match channel::find(state, name).filter(|&ci| state.chans[ci].is_managed) {
        Some(ci) => Some(ci),
        None => {
            ircf!(
                state,
                "PRIVMSG {} :Error: {} is not in my channel list.\r\n",
                nick,
                name
            );
            None
        }
    }
}

// ---- chanmode ---------------------------------------------------------------------

fn key_ok(k: &str) -> bool {
    !k.is_empty()
        && k.len() < MAX_KEY
        && k.bytes()
            .all(|c| c > 0x20 && c != 0x7f && c != b',' && c != b'|')
}

/// The result of parsing a mode string (section 3.2): `stored` is the C|
/// modes field ("+stnkl 20"), plus the key change.
#[derive(Debug, PartialEq, Eq)]
struct ParsedModes {
    stored: String,
    key: Option<String>,
    key_clear: bool,
}

/// `modes` = the letters token; `args` = the rest, consumed left to right by
/// +k and +l.
fn parse_modes(modes: &str, args: &[&str]) -> Result<ParsedModes, String> {
    let mut seen = [false; 128];
    let mut letters = String::new();
    let mut sign: Option<char> = None;
    let mut ai = 0usize;
    let mut limit = 0i64;
    let (mut plus_s, mut plus_p) = (false, false);
    let mut key: Option<String> = None;
    let mut key_clear = false;
    let mut adding = true;
    for m in modes.chars() {
        if m == '+' || m == '-' {
            adding = m == '+';
            continue;
        }
        if !"imnpstkl".contains(m) {
            return Err(format!(
                "'{m}' is not a channel mode I manage (i m n p s t k l)"
            ));
        }
        if seen[m as usize & 0x7f] {
            return Err(format!("'{m}' given twice"));
        }
        seen[m as usize & 0x7f] = true;
        if letters.len() + 3 >= 40 {
            return Err("mode string too long".into());
        }
        let want = if adding { '+' } else { '-' };
        if sign != Some(want) {
            letters.push(want);
            sign = Some(want);
        }
        letters.push(m);
        if adding && m == 's' {
            plus_s = true;
        }
        if adding && m == 'p' {
            plus_p = true;
        }
        if m == 'k' {
            if adding {
                match args.get(ai).filter(|a| key_ok(a)) {
                    Some(k) => {
                        key = Some((*k).to_string());
                        ai += 1;
                    }
                    None => {
                        return Err(format!(
                            "+k needs a key (1..{} bytes, no space, comma or control character)",
                            MAX_KEY - 1
                        ));
                    }
                }
            } else {
                key_clear = true;
            }
        } else if m == 'l' && adding {
            let Some(a) = args.get(ai) else {
                return Err("+l needs a limit (1..99999)".into());
            };
            ai += 1;
            // strtol: an optional sign, then digits and nothing else
            let digits = a.strip_prefix(['+', '-']).unwrap_or(a);
            let v =
                (a.len() <= 5 && !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()))
                    .then(|| a.parse::<i64>().ok())
                    .flatten()
                    .filter(|v| (1..=99999).contains(v));
            match v {
                Some(v) => limit = v,
                None => return Err("the limit must be 1..99999".into()),
            }
        }
    }
    if letters.is_empty() {
        return Err("no modes given".into());
    }
    if ai != args.len() {
        return Err("wrong number of arguments for the modes".into());
    }
    if plus_s && plus_p {
        return Err("+s and +p together are refused".into());
    }
    let stored = if limit > 0 {
        format!("{letters} {limit}")
    } else {
        letters
    };
    if stored.len() > C_MODES_MAX {
        return Err("mode string too long".into());
    }
    Ok(ParsedModes {
        stored,
        key,
        key_clear,
    })
}

fn show_modes(state: &mut BotState, nick: &str, ci: usize) {
    let c = &state.chans[ci];
    let line = format!(
        "{}: stored modes {}{}, key {}, {}",
        c.name,
        chancfg::get_modes(state, Some(c)),
        if c.cfg_active && c.cfg_ts > 0 && !c.cfg_modes.is_empty() {
            ""
        } else {
            " (default)"
        },
        if c.key.is_empty() { "none" } else { "set" },
        if chancfg::get(state, Some(c), CsetId::EnforceModes) != 0 {
            "+enforcemodes"
        } else {
            "-enforcemodes"
        }
    );
    say(state, nick, crate::cstr::trunc(&line, 256));
}

/// `chanmode <#channel> [<modes> [args]|-]`; `args` is the argument line.
pub fn chanmode(state: &mut BotState, nick: &str, args: Option<&str>) {
    if refused(state, nick, "chanmode") {
        return;
    }
    let mut t = Tok::new(args.unwrap_or(""));
    let Some(name) = t.next(" ") else {
        say(
            state,
            nick,
            "Syntax: chanmode <#channel> [<modes> [args]|-]",
        );
        return;
    };
    let Some(ci) = find_chan(state, nick, Some(name)) else {
        return;
    };
    let Some(modes) = t.next(" ") else {
        show_modes(state, nick, ci);
        return;
    };
    let mut av: Vec<&str> = Vec::new();
    while let Some(tk) = t.next(" ") {
        if av.len() >= 8 {
            say(state, nick, "Error: too many arguments.");
            return;
        }
        av.push(tk);
    }

    let parsed = if modes == "-" && av.is_empty() {
        // back to the network default
        ParsedModes {
            stored: String::new(),
            key: None,
            key_clear: false,
        }
    } else {
        match parse_modes(modes, &av) {
            Ok(p) => p,
            Err(e) => {
                ircf!(state, "PRIVMSG {} :Error: bad mode: {}.\r\n", nick, e);
                return;
            }
        }
    };
    let stored = parsed.stored;

    let mut key_changed = false;
    let old_key = Zeroizing::new(state.chans[ci].key.clone());
    let c = &mut state.chans[ci];
    if let Some(k) = parsed.key.as_deref().filter(|k| c.key != *k) {
        c.key = k.to_string();
        key_changed = true;
    } else if parsed.key_clear && !c.key.is_empty() {
        c.key.clear();
        key_changed = true;
    }
    let settings = state.chans[ci].cfg_settings.clone();
    if !chancfg::local_c(state, ci, &stored, &settings) {
        state.chans[ci].key = old_key.to_string();
        say(state, nick, "Error: could not store the modes.");
        return;
    }
    if key_changed {
        let c = &mut state.chans[ci];
        c.timestamp = lww_next_ts(c.timestamp);
        hub_client::push_config(state);
    }
    drop(old_key);

    let shown = if stored.is_empty() {
        "network default"
    } else {
        &stored
    };
    let name = state.chans[ci].name.clone();
    if state.chans[ci].status == crate::state::ChanStatus::In && state.chans[ci].i_am_opped {
        let (r, sum) = chanlive::apply_stored(state, ci);
        let sum = if r < 0 {
            "could not apply".to_string()
        } else {
            trunc_string(&sum, 64)
        };
        ircf!(
            state,
            "PRIVMSG {} :{}: modes stored ({}) and applied: {}.\r\n",
            nick,
            name,
            shown,
            sum
        );
    } else {
        ircf!(
            state,
            "PRIVMSG {} :{}: modes stored ({}); not applied, I am not opped there.\r\n",
            nick,
            name,
            shown
        );
    }
    if stored.contains('l') && chancfg::get(state, state.chans.get(ci), CsetId::DynamicLimit) != 0 {
        say(
            state,
            nick,
            "Warning: +dynamiclimit is on and overrides the fixed limit.",
        );
    }
}

// ---- chanset ----------------------------------------------------------------------

/// The `chanset` listing as rows; `ci` None = the network default.
fn settings_rows(state: &BotState, ci: Option<usize>) -> Vec<String> {
    let net = ci.is_none();
    let c = ci.map(|i| &state.chans[i]);
    let mut rows = Vec::new();
    let mut row = String::new();
    for i in 0..CS_COUNT + FL_COUNT {
        let Some(name) = chancfg::item_name(i, net) else {
            continue;
        };
        let val = if i < CS_COUNT {
            chancfg::get(state, c, CsetId::ALL[i]).to_string()
        } else {
            match chancfg::get_flood(state, c, FloodKind::ALL[i - CS_COUNT]) {
                Some((n, s)) => format!("{n}:{s}"),
                None => "off".to_string(),
            }
        };
        let src = ['b', 'n', 'c'][usize::from(chancfg::item_source(state, c, i))];
        let item = format!("{name}={val}({src})  ");
        if row.len() + item.len() >= 360 {
            rows.push(std::mem::take(&mut row));
        }
        row.push_str(&item);
    }
    if !row.is_empty() {
        rows.push(row);
    }
    rows
}

fn show_settings(state: &mut BotState, nick: &str, ci: Option<usize>) {
    let rows = settings_rows(state, ci);
    let what = ci.map_or("default".to_string(), |i| state.chans[i].name.clone());
    ircf!(
        state,
        "PRIVMSG {} :Settings for {} (c = channel, n = network default, b = built-in):\r\n",
        nick,
        what
    );
    for r in rows {
        say(state, nick, &r);
    }
}

/// `chanset <#channel|default> [+opt -opt ...] [<name> <value|default>]
/// [flood <type> <N:S|off|default>]`.
pub fn chanset(state: &mut BotState, nick: &str, args: Option<&str>) {
    if refused(state, nick, "chanset") {
        return;
    }
    let mut t = Tok::new(args.unwrap_or(""));
    let Some(name) = t.next(" ") else {
        say(
            state,
            nick,
            "Syntax: chanset <#channel|default> [+opt -opt ...] [<name> <value|default>] [flood <type> <N:S|off|default>]",
        );
        return;
    };
    let net = eq_ic(name, "default");
    let ci = if net {
        None
    } else {
        match find_chan(state, nick, Some(name)) {
            Some(ci) => Some(ci),
            None => return,
        }
    };
    let Some(first) = t.next(" ") else {
        show_settings(state, nick, ci);
        return;
    };

    let mut sets = match ci {
        Some(ci) => state.chans[ci].cfg_settings.clone(),
        None => state.net_settings.clone(),
    };
    let mut edits = 0;
    let mut tok = Some(first);
    while let Some(tk) = tok {
        let item: String;
        let val: &str;
        if tk.starts_with(['+', '-']) && tk.len() > 1 {
            item = tk[1..].to_string();
            val = if tk.starts_with('+') { "1" } else { "0" };
            if !chancfg::setting_is_flag(&item) {
                ircf!(
                    state,
                    "PRIVMSG {} :Error: '{}' is not an on/off option; give it a value.\r\n",
                    nick,
                    item
                );
                return;
            }
        } else if eq_ic(tk, "key") {
            say(
                state,
                nick,
                "Error: the key moved: use chanmode <#channel> +k <key>.",
            );
            return;
        } else if tk == "flood" {
            let typ = t.next(" ");
            let v = t.next(" ");
            let Some((typ, v)) = typ.zip(v).filter(|(a, _)| a.len() <= 8) else {
                say(state, nick, "Syntax: flood <type> <N:S|off|default>");
                return;
            };
            let bot = matches!(typ, "cmd" | "msg" | "ctcp");
            // "ctcp" is both a channel and a bot flood: on `default` the
            // channel one is `flood ctcp`, the bot one `flood bot ctcp` is
            // not offered -- cmd and msg are unambiguous, ctcp picks the
            // channel flood.
            let pre = if net && bot && typ != "ctcp" {
                "bflood"
            } else {
                "flood"
            };
            item = format!("{pre} {typ}");
            val = v;
        } else if tk == "bflood" && net {
            let typ = t.next(" ");
            let v = t.next(" ");
            let Some((typ, v)) = typ.zip(v).filter(|(a, _)| a.len() <= 8) else {
                say(
                    state,
                    nick,
                    "Syntax: bflood <cmd|msg|ctcp> <N:S|off|default>",
                );
                return;
            };
            item = format!("bflood {typ}");
            val = v;
        } else {
            item = tk.to_string();
            let Some(v) = t.next(" ") else {
                ircf!(
                    state,
                    "PRIVMSG {} :Error: '{}' needs a value.\r\n",
                    nick,
                    item
                );
                return;
            };
            val = v;
        }
        if let Err(why) = chancfg::settings_edit(&mut sets, D_SETTINGS_MAX + 1, net, &item, val) {
            ircf!(state, "PRIVMSG {} :Error: {}.\r\n", nick, why);
            return;
        }
        edits += 1;
        tok = t.next(" ");
    }
    if edits == 0 {
        return;
    }
    let ok = match ci {
        None => {
            let modes = state.net_modes.clone();
            chancfg::local_d(state, &modes, &sets)
        }
        Some(ci) => {
            let modes = state.chans[ci].cfg_modes.clone();
            chancfg::local_c(state, ci, &modes, &sets)
        }
    };
    if !ok {
        say(state, nick, "Error: could not store the settings.");
        return;
    }
    let what = ci.map_or("default".to_string(), |i| state.chans[i].name.clone());
    ircf!(
        state,
        "PRIVMSG {} :{}: {} setting{} changed (now: {}).\r\n",
        nick,
        what,
        edits,
        if edits == 1 { "" } else { "s" },
        if sets.is_empty() {
            "all built-in"
        } else {
            &sets
        }
    );
}

// ---- bans ---------------------------------------------------------------------------

fn mask_ok(m: &str) -> bool {
    m.len() >= 5
        && m.len() <= BAN_MASK_MAX
        && !m.contains('|')
        && m.find('!').is_some_and(|b| m[b..].contains('@'))
}

/// Chan "*" (Some(None)) or a managed channel (Some(Some(ci))); None = a
/// reply was sent.
fn ban_target(state: &mut BotState, nick: &str, name: &str) -> Option<Option<usize>> {
    if name == "*" {
        return Some(None);
    }
    find_chan(state, nick, Some(name)).map(Some)
}

fn user_name(state: &BotState, who: usize) -> String {
    state
        .user_records
        .get(who)
        .map_or_else(|| "admin".to_string(), |u| u.name.clone())
}

/// `+ban <#channel|*> <nick!user@host> [<minutes>|perm] [sticky] [reason]`.
pub fn ban_add(state: &mut BotState, nick: &str, who: usize, args: Option<&str>) {
    if refused(state, nick, "+ban") {
        return;
    }
    let mut t = Tok::new(args.unwrap_or(""));
    let chan = t.next(" ");
    let mask = chan.and_then(|_| t.next(" "));
    let (Some(chan), Some(mask)) = (chan, mask) else {
        say(
            state,
            nick,
            "Syntax: +ban <#channel|*> <nick!user@host> [<minutes>|perm] [sticky] [reason]",
        );
        return;
    };
    let Some(target) = ban_target(state, nick, chan) else {
        return;
    };
    if !mask_ok(mask) {
        say(
            state,
            nick,
            "Error: the mask must look like nick!user@host (wildcards allowed).",
        );
        return;
    }

    // optional: minutes|perm, then sticky, then the reason is the rest
    let mut expires = 0i64;
    let mut sticky = false;
    let mut p = t.remaining().trim_start_matches(' ');
    let wl = p.find(' ').unwrap_or(p.len());
    if wl > 0 && wl < 16 {
        let w = &p[..wl];
        if w == "perm" {
            p = &p[wl..];
        } else if w.bytes().all(|c| c.is_ascii_digit()) && wl <= 6 {
            let mins: i64 = w.parse().unwrap_or(0);
            if !(1..=525_600).contains(&mins) {
                say(state, nick, "Error: minutes must be 1..525600 (or perm).");
                return;
            }
            expires = now() + mins * 60;
            p = &p[wl..];
        }
    }
    p = p.trim_start_matches(' ');
    let wl = p.find(' ').unwrap_or(p.len());
    if wl == 6 && &p[..6] == "sticky" {
        sticky = true;
        p = &p[wl..];
    }
    let reason = p.trim_start_matches(' ');

    // section 6.2: never a bot or an authorised user
    let verdict = match target {
        Some(ci) => chanenf::ban_allowed_why(state, Some(ci), mask),
        None => (0..state.chans.len())
            .filter(|&k| state.chans[k].is_managed)
            .try_for_each(|k| chanenf::ban_allowed_why(state, Some(k), mask))
            .and_then(|()| chanenf::ban_allowed_why(state, None, mask)),
    };
    if let Err(hit) = verdict {
        ircf!(
            state,
            "PRIVMSG {} :Refused: {} would hit {} -- a bot or an authorised user is never banned.\r\n",
            nick,
            mask,
            trunc_string(&hit, 128)
        );
        return;
    }
    let cn = target.map_or("*".to_string(), |ci| state.chans[ci].name.clone());
    let setter = user_name(state, who);
    if !chancfg::local_ban(
        state,
        &cn,
        mask,
        expires,
        if sticky { "s" } else { "" },
        &setter,
        reason,
        false,
    ) {
        say(
            state,
            nick,
            "Error: ban not stored (list full or bad value).",
        );
        return;
    }
    ircf!(
        state,
        "PRIVMSG {} :Ban added: {} {} ({}{}).\r\n",
        nick,
        cn,
        mask,
        if expires != 0 { "timed" } else { "permanent" },
        if sticky { ", sticky" } else { "" }
    );
}

/// `-ban <#channel|*> <nick!user@host>`.
pub fn ban_del(state: &mut BotState, nick: &str, who: usize, args: Option<&str>) {
    if refused(state, nick, "-ban") {
        return;
    }
    let mut t = Tok::new(args.unwrap_or(""));
    let chan = t.next(" ");
    let mask = chan.and_then(|_| t.next(" "));
    let (Some(chan), Some(mask)) = (chan, mask) else {
        say(state, nick, "Syntax: -ban <#channel|*> <nick!user@host>");
        return;
    };
    let Some(target) = ban_target(state, nick, chan) else {
        return;
    };
    let cn = target.map_or("*".to_string(), |ci| state.chans[ci].name.clone());
    let setter = user_name(state, who);
    if chancfg::ban_get(state, &cn, mask).is_none()
        || !chancfg::local_ban(state, &cn, mask, 0, "", &setter, "", true)
    {
        ircf!(
            state,
            "PRIVMSG {} :Error: no ban {} on {}.\r\n",
            nick,
            mask,
            cn
        );
        return;
    }
    ircf!(state, "PRIVMSG {} :Ban removed: {} {}.\r\n", nick, cn, mask);
}

const BANS_ROWS: usize = 30;

/// `bans [#channel]`.
pub fn bans(state: &mut BotState, nick: &str, args: Option<&str>) {
    let chan = Tok::new(args.unwrap_or("")).next(" ");
    let t = now();
    let mut rows: Vec<String> = Vec::new();
    let mut total = 0usize;
    for b in &state.cfg_bans {
        if !b.active {
            continue;
        }
        if chan.is_some_and(|c| !eq_ic(&b.chan, c) && b.chan != "*") {
            continue;
        }
        if b.expires != 0 && b.expires <= t {
            continue;
        }
        total += 1;
        if rows.len() >= BANS_ROWS {
            continue;
        }
        let left = if b.expires != 0 {
            format!("{}m", (b.expires - t + 59) / 60)
        } else {
            "perm".to_string()
        };
        rows.push(format!(
            "{} {} {}{} by {}{}{}",
            b.chan,
            b.mask,
            left,
            if b.flags.contains('s') { " sticky" } else { "" },
            b.setter,
            if b.reason.is_empty() { "" } else { ": " },
            b.reason
        ));
    }
    let shown = rows.len();
    for r in rows {
        say(state, nick, &r);
    }
    if total == 0 {
        say(state, nick, "No network bans.");
    } else if total > shown {
        ircf!(
            state,
            "PRIVMSG {} :... and {} more.\r\n",
            nick,
            total - shown
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(modes: &str, args: &[&str]) -> Result<ParsedModes, String> {
        parse_modes(modes, args)
    }

    #[test]
    fn modes_plain() {
        assert_eq!(pm("+nt", &[]).unwrap().stored, "+nt");
        assert_eq!(pm("+nt-s", &[]).unwrap().stored, "+nt-s");
        assert_eq!(pm("-i+m", &[]).unwrap().stored, "-i+m");
    }

    #[test]
    fn modes_key_and_limit_left_to_right() {
        let p = pm("+ntkl", &["sekrit", "20"]).unwrap();
        assert_eq!(p.stored, "+ntkl 20");
        assert_eq!(p.key.as_deref(), Some("sekrit"));
        assert!(!p.key_clear);
        let p = pm("+nt-k", &[]).unwrap();
        assert!(p.key_clear);
        assert_eq!(p.stored, "+nt-k");
    }

    #[test]
    fn modes_errors() {
        assert!(pm("+x", &[]).unwrap_err().contains("not a channel mode"));
        assert_eq!(pm("+nn", &[]).unwrap_err(), "'n' given twice");
        assert_eq!(pm("+", &[]).unwrap_err(), "no modes given");
        assert!(pm("+k", &[]).unwrap_err().starts_with("+k needs a key"));
        assert!(pm("+k", &["a,b"]).is_err());
        assert_eq!(pm("+l", &[]).unwrap_err(), "+l needs a limit (1..99999)");
        assert_eq!(pm("+l", &["0"]).unwrap_err(), "the limit must be 1..99999");
        assert_eq!(
            pm("+l", &["100000"]).unwrap_err(),
            "the limit must be 1..99999"
        );
        assert_eq!(pm("+l", &["5x"]).unwrap_err(), "the limit must be 1..99999");
        assert_eq!(pm("+l", &["+5"]).unwrap().stored, "+l 5");
        assert_eq!(
            pm("+n", &["extra"]).unwrap_err(),
            "wrong number of arguments for the modes"
        );
        assert_eq!(
            pm("+sp", &[]).unwrap_err(),
            "+s and +p together are refused"
        );
        assert!(pm("+s-p", &[]).is_ok());
    }

    #[test]
    fn ban_mask_shape() {
        assert!(mask_ok("a!b@c.d"));
        assert!(mask_ok("*!*@*.example.com"));
        assert!(!mask_ok("a!b"));
        assert!(!mask_ok("a@b!c"));
        assert!(!mask_ok("a!b@c|d"));
        assert!(!mask_ok("!@"));
    }

    #[test]
    fn key_rules() {
        assert!(key_ok("sekrit"));
        assert!(!key_ok(""));
        assert!(!key_ok("a b"));
        assert!(!key_ok("a|b"));
        assert!(!key_ok(&"k".repeat(MAX_KEY)));
        assert!(key_ok(&"k".repeat(MAX_KEY - 1)));
    }
}
