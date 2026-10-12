//! One line from the IRC server (irc_parser.c).

use crate::botflood::{self, Bf};
use crate::consts::*;
use crate::cstr::{Tok, eq_ic, now, starts_with_ic, trunc, trunc_string};
use crate::state::{BotState, ChanReq, ChanStatus, M_I, M_K, RosterEntry, S_AUTHED, lww_next_ts};
use crate::{
    auth, bot_comms, chanenf, chanflood, chanlive, channel, commands, crypto, dcc, hub_client,
    irc_client, ircf, logm,
};

/// Hub UUID for a roster entry whose nick may carry collision '_'s: exact
/// hostmask, then "nick!" prefix, then base nick with trailing '_' stripped
/// on both sides.
fn find_uuid_for_helper(state: &BotState, helper: &RosterEntry) -> Option<String> {
    let base = |s: &str| s.trim_end_matches('_').to_string();
    for tb in &state.trusted_bots {
        if tb.uuid.is_empty() {
            continue;
        }
        if eq_ic(&tb.mask, &helper.hostmask) {
            return Some(tb.uuid.clone());
        }
        let pfx = format!("{}!", helper.nick);
        if starts_with_ic(&tb.mask, &pfx) {
            return Some(tb.uuid.clone());
        }
        let stored_nick = match tb.mask.find('!') {
            Some(b) => trunc(&tb.mask[..b], MAX_NICK),
            None => "",
        };
        let bs = base(stored_nick);
        if !bs.is_empty() && eq_ic(&bs, &base(&helper.nick)) {
            return Some(tb.uuid.clone());
        }
    }
    None
}

/// MODE on a channel: our own op state (with immediate re-read on deop),
/// roster op flags, the key and +i.
fn handle_mode_change(state: &mut BotState, channel: &str, modes: &str, args: &str) {
    let Some(ci) = channel::find(state, channel) else {
        return;
    };
    // Live modes, key, limit, ban list and halfop/voice flags (chanlive.rs).
    // The C copy of the arguments exists because its tokeniser works in
    // place; here a copy is not needed, but the same 1024-byte bound holds.
    if args.len() < 1024 {
        chanlive::apply(state, ci, modes, args, false);
    }
    // modes.md section 3.3: under +enforcemodes with a k in the stored modes
    // the key is the bots', so a key someone sets or clears is not learned.
    let key_managed = chanenf::key_managed(state, ci);
    let mut adding = true;
    let mut toks = Tok::new(args);
    let mut current_arg = toks.next(" ");

    for mode in modes.chars() {
        match mode {
            '+' => adding = true,
            '-' => adding = false,
            'o' | 'v' | 'b' | 'e' | 'I' => {
                let Some(arg) = current_arg else { continue };
                if mode == 'o' {
                    if eq_ic(arg, &state.current_nick) {
                        let me = state.current_nick.clone();
                        let c = &mut state.chans[ci];
                        c.i_am_opped = adding;
                        if let Some(r) = c.roster.iter_mut().find(|r| eq_ic(&r.nick, &me)) {
                            r.is_op = adding;
                        }
                        if adding {
                            c.enf_dirty = true; // chanenf.rs sweep
                            c.enf_ops_check = true;
                            c.op_request_pending = false;
                            c.op_request_retry_count = 0;
                            logm!(state, L_INFO, "[INFO] I am now OP in {}\n", channel);
                            hub_client::grant_held_ops(state, ci);
                        } else {
                            // Deopped: re-read the channel before choosing a
                            // helper (the roster was not refreshed while we
                            // held ops); the 315 handler sends the request.
                            logm!(
                                state,
                                L_INFO,
                                "[INFO] I was DEOPPED in {}. Refreshing roster to find a trusted op.\n",
                                channel
                            );
                            if !state.chans[ci].op_request_pending {
                                state.chans[ci].roster.clear();
                                let name = state.chans[ci].name.clone();
                                ircf!(state, "WHO {}\r\n", name);
                                if let Some(c) = state.chans.get_mut(ci) {
                                    c.last_who_request = now();
                                }
                            }
                        }
                    } else if let Some(r) = state.chans[ci]
                        .roster
                        .iter_mut()
                        .find(|r| eq_ic(&r.nick, arg))
                    {
                        r.is_op = adding;
                        logm!(
                            state,
                            L_DEBUG,
                            "[DEBUG] Roster update: {} is_op={} in {}\n",
                            arg,
                            adding as i32,
                            channel
                        );
                    }
                }
                current_arg = toks.next(" ");
            }
            'k' => {
                let c = &mut state.chans[ci];
                if key_managed {
                    // the mode job puts the stored key back; learn nothing
                } else if adding {
                    if let Some(arg) = current_arg {
                        c.key = trunc_string(arg, MAX_KEY);
                        c.modes |= M_K;
                    }
                } else {
                    // -k clears the key regardless of its argument.
                    c.key.clear();
                    c.modes &= !M_K;
                }
                if current_arg.is_some() {
                    current_arg = toks.next(" ");
                }
            }
            'l' => {
                // +l takes an argument (the limit); -l does not.
                if adding && current_arg.is_some() {
                    current_arg = toks.next(" ");
                }
            }
            'i' => {
                let c = &mut state.chans[ci];
                if adding {
                    c.modes |= M_I;
                } else {
                    c.modes &= !M_I;
                }
            }
            _ => {}
        }
    }
}

/// Record our own hostmask -- only ever from our 352 entry or our JOIN
/// echo, both strings the server shows OTHER clients verbatim.  Pushes to
/// the hub only when the value actually changes.
fn update_own_hostmask(state: &mut BotState, mask: &str) {
    if mask.is_empty() || state.actual_hostname == mask {
        return;
    }
    state.actual_hostname = trunc_string(mask, MAX_MASK_LEN);
    state.actual_hostname_ts = now();
    logm!(
        state,
        L_INFO,
        "[INFO] My hostmask is now: {}\n",
        state.actual_hostname
    );
    if state.hub_connected && state.hub_authenticated {
        hub_client::sync_hostmask(state);
    }
}

/// `WHO <nick>`: answered by a 352 carrying the nick!ident@host other
/// clients are shown.
fn request_own_hostmask(state: &mut BotState) {
    if !state.current_nick.is_empty() {
        let n = state.current_nick.clone();
        ircf!(state, "WHO {}\r\n", n);
    }
}

/// The trailing parameter ("... :text"), or all of params if there is none.
fn irc_trailing(params: &str) -> &str {
    if let Some(rest) = params.strip_prefix(':') {
        return rest;
    }
    match params.find(" :") {
        Some(i) => &params[i + 2..],
        None => params,
    }
}

/// Second whitespace token of params (the channel of most numerics).
fn second_tok(params: &str) -> Option<&str> {
    let mut t = Tok::new(params);
    t.next(" ");
    t.next(" ")
}

pub fn handle_line(state: &mut BotState, line: &str) {
    if let Some(rest) = line.strip_prefix("PING :") {
        ircf!(state, "PONG :{}\r\n", rest);
        state.last_pong_time = now();
        state.pong_pending = false;
        return;
    }
    let line = trunc(line, MAX_BUFFER);

    let (prefix, rest) = match line.strip_prefix(':') {
        Some(r) => match r.find(' ') {
            Some(i) => (Some(&r[..i]), &r[i + 1..]),
            None => return,
        },
        None => (None, line),
    };
    let Some(sp) = rest.find(' ') else { return };
    let command = &rest[..sp];
    let params = &rest[sp + 1..];

    if command == "PONG" {
        state.last_pong_time = now();
        state.pong_pending = false;
        return;
    }
    if command == "004"
        && let Some(server_name) = second_tok(params)
    {
        state.actual_server_name = trunc_string(server_name, 256);
    }

    match command {
        "001" => on_welcome(state, params),
        "433" | "432" | "437" => on_nick_refused(state, command, params),
        // ERR_YOUREBANNEDCREEP / ERR_NOPERMFORHOST: recorded; classified
        // when the link drops.
        "465" | "463" => irc_client::note_refusal(state, irc_trailing(params), true),
        "ERROR" => irc_client::note_refusal(state, irc_trailing(params), false),
        "474" => on_lockout(state, params, ChanReq::Unban),
        "475" => on_lockout(state, params, ChanReq::Key),
        // RPL_ISUPPORT: MODES, MAXLIST, PREFIX, CHANMODES for the send queue
        // and the mode parser.
        "005" => {
            if params.len() < 1024 {
                chanlive::isupport_parse(state, params);
            }
        }
        // RPL_CHANNELMODEIS / RPL_CREATIONTIME: live state only.
        "324" | "329" => chanlive::numeric(state, command, params),
        "367" => {
            chanlive::numeric(state, command, params); // our own ban list copy
            let mut t = Tok::new(params);
            t.next(" ");
            if let (Some(ch), Some(mask)) = (t.next(" "), t.next(" ")) {
                channel::unban_note_ban(state, ch, mask);
            }
        }
        "368" => {
            chanlive::numeric(state, command, params);
            if let Some(ch) = second_tok(params) {
                channel::unban_finish(state, ch);
            }
        }
        "405" => {
            // ERR_TOOMANYCHANNELS: stop retrying this channel.
            if let Some(ch) = second_tok(params)
                && let Some(ci) = channel::find(state, ch)
            {
                state.chans[ci].join_disabled = true;
                logm!(
                    state,
                    L_INFO,
                    "[405] Channel limit reached, disabling join retry: {}\n",
                    ch
                );
            }
        }
        "473" => {
            if let Some(ch) = second_tok(params)
                && let Some(ci) = channel::find(state, ch).filter(|&ci| state.chans[ci].is_managed)
            {
                logm!(
                    state,
                    L_INFO,
                    "[473] Channel {} is invite-only, requesting invite\n",
                    ch
                );
                channel::access_request(state, ci, ChanReq::Invite);
            }
        }
        "MODE" => on_mode(state, prefix, params),
        "352" => on_who_reply(state, params),
        "396" => {
            if let Some(host) = second_tok(params) {
                // Only a signal that our mask moved: re-ask, never splice.
                logm!(
                    state,
                    L_INFO,
                    "[INFO] Displayed host changed to {}; re-checking my mask\n",
                    host
                );
                request_own_hostmask(state);
            }
        }
        "315" => on_end_of_who(state, params),
        "PRIVMSG" => {
            if let Some(p) = prefix {
                on_privmsg(state, p, params);
            }
        }
        "NOTICE" => {
            if let Some(p) = prefix {
                on_notice(state, p, params);
            }
        }
        "JOIN" => {
            if let Some(p) = prefix {
                on_join(state, p, params);
            }
        }
        "PART" => {
            if let Some(p) = prefix {
                let nick = Tok::new(p).next("!");
                if let Some(n) =
                    nick.filter(|n| !eq_ic(n, &state.current_nick) && !eq_ic(n, &state.target_nick))
                {
                    let pc = params.strip_prefix(':').unwrap_or(params);
                    let pc = pc.split(' ').next().unwrap_or("");
                    if !pc.is_empty() && pc.len() < MAX_CHAN {
                        chanenf::on_part(state, pc, n);
                    }
                }
                if nick
                    .is_some_and(|n| eq_ic(n, &state.current_nick) || eq_ic(n, &state.target_nick))
                {
                    let chan_name = params.strip_prefix(':').unwrap_or(params);
                    let chan_name = chan_name.split(' ').next().unwrap_or("");
                    if let Some(ci) = channel::find(state, chan_name) {
                        let c = &mut state.chans[ci];
                        c.status = ChanStatus::Out;
                        c.roster.clear();
                        c.i_am_opped = false;
                        chanlive::live_reset(c);
                        logm!(state, L_DEBUG, "[IRC] Parted channel {}\n", chan_name);
                    }
                }
            }
        }
        "KICK" => {
            let mut t = Tok::new(params);
            let (ch, kicked) = (t.next(" "), t.next(" "));
            if let (Some(ch), Some(kicked)) = (ch, kicked) {
                chanenf::on_kick(state, ch, prefix, kicked);
            }
            if let (Some(ch), Some(kicked)) = (ch, kicked)
                && eq_ic(kicked, &state.current_nick)
                && let Some(ci) = channel::find(state, ch)
            {
                state.chans[ci].status = ChanStatus::Out;
                state.chans[ci].i_am_opped = false;
                chanlive::live_reset(&mut state.chans[ci]);
            }
        }
        "QUIT" => {
            if let Some(qnick) = prefix.and_then(|p| Tok::new(p).next("!")) {
                chanenf::on_quit(state, qnick);
            }
        }
        "NICK" => {
            if let Some(p) = prefix {
                on_nick(state, p, params);
            }
        }
        _ => {}
    }
}

fn on_welcome(state: &mut BotState, params: &str) {
    state.status |= S_AUTHED;
    irc_client::note_registered(state);
    // 001's first parameter is the nick the server actually registered.
    let srv_nick = params.split(' ').next().unwrap_or("");
    // Registered under anything but the target nick is news for the hub even
    // when current_nick already says so: a 433 during registration switches
    // current_nick to the fallback without a push, and a hub link that came
    // up before that has only the target.
    let renamed = state.current_nick != srv_nick;
    if !srv_nick.is_empty()
        && srv_nick.len() < MAX_NICK
        && (renamed || !eq_ic(srv_nick, &state.target_nick))
    {
        if renamed {
            logm!(
                state,
                L_INFO,
                "[INFO] Server registered me as {} (was {})\n",
                srv_nick,
                if state.current_nick.is_empty() {
                    "unset"
                } else {
                    state.current_nick.as_str()
                }
            );
        }
        state.current_nick = srv_nick.to_string();
        state.current_nick_ts = now();
        if state.hub_connected && state.hub_authenticated {
            let (n, ts) = (state.current_nick.clone(), state.current_nick_ts);
            hub_client::push_delta(state, "n", &n, ts);
        }
    }
    // The mask in the 001 text is a self-directed greeting: ask instead.
    request_own_hostmask(state);
}

fn on_nick_refused(state: &mut BotState, command: &str, params: &str) {
    // "<me> <nick> :<reason>"; a 437 can name a channel instead.
    let mut t = Tok::new(params);
    t.next(" ");
    let refused = t.next(" ");
    if refused.is_some_and(|r| r.starts_with('#') || r.starts_with('&')) {
        return;
    }
    state.nick_change_pending = false;
    // 432 is final for that nick on this server: stop re-sending it.
    if let Some(r) = refused
        && command == "432"
        && eq_ic(r, &state.target_nick)
        && !eq_ic(&state.nick_refused, r)
    {
        state.nick_refused = state.target_nick.clone();
        logm!(
            state,
            L_INFO,
            "[INFO] Server refuses nick '{}' (432: {}); not retrying it here. Pick another with chnick.\n",
            state.target_nick,
            irc_trailing(t.remaining())
        );
    }
    // Not registered yet: without an accepted nick there is no 001.
    if state.status & S_AUTHED == 0 {
        irc_client::generate_new_nick(state);
    }
}

/// 474 / 475: ask the mesh to lift the ban or hand us the current key.
fn on_lockout(state: &mut BotState, params: &str, kind: ChanReq) {
    let Some(ch) = second_tok(params) else { return };
    let Some(ci) = channel::find(state, ch) else {
        return;
    };
    state.chans[ci].status = ChanStatus::Out;
    if state.chans[ci].is_managed {
        match kind {
            ChanReq::Unban => logm!(
                state,
                L_INFO,
                "[474] Banned from {}, requesting unban\n",
                ch
            ),
            _ => logm!(
                state,
                L_INFO,
                "[475] Bad key for {}, requesting current key\n",
                ch
            ),
        }
        channel::access_request(state, ci, kind);
    }
}

fn on_mode(state: &mut BotState, prefix: Option<&str>, params: &str) {
    let mut t = Tok::new(params);
    let target = t.next(" ");
    let modes = t.next(" ");
    let args = t.rest().unwrap_or("");
    let (Some(target), Some(modes)) = (target, modes) else {
        return;
    };
    if !(target.starts_with('#') || target.starts_with('&')) {
        return;
    }
    handle_mode_change(state, target, modes, args);
    // The enforcement pass sees the same arguments; an oversized set is
    // skipped (fail closed).
    if args.len() < 1024 {
        chanenf::on_mode(state, target, prefix, modes, args);
    }
    // Key / invite-only changes go to the hub, and to our own config: with no
    // hub to echo them back, a key we learned and saved must not outlive a -k.
    if (modes.contains('k') || modes.contains('i'))
        && let Some(ci) = channel::find(state, target).filter(|&ci| {
            state.chans[ci].is_managed && (modes.contains('i') || !chanenf::key_managed(state, ci))
        })
    {
        state.chans[ci].timestamp = lww_next_ts(state.chans[ci].timestamp);
        state.chans[ci].enf_pending = true; // cleared once a hub has it (D43)
        hub_client::push_channel(state, ci);
        crate::config::write_with_state_pass(state);
    }
}

fn on_who_reply(state: &mut BotState, params: &str) {
    let mut t = Tok::new(params);
    t.next(" ");
    let chan_name = t.next(" ");
    let ident = t.next(" ");
    let host = t.next(" ");
    t.next(" ");
    let nick = t.next(" ");
    let modes = t.next(" ");
    let (Some(chan_name), Some(ident), Some(host), Some(nick), Some(modes)) =
        (chan_name, ident, host, nick, modes)
    else {
        return;
    };
    let is_op = modes.contains('@');
    // PREFIX (005) names the halfop / voice symbols this server uses.
    let prefix_sym = |letter: char| {
        let is = &state.isup;
        is.prefix_modes
            .find(letter)
            .and_then(|i| is.prefix_syms.as_bytes().get(i).copied())
            .is_some_and(|sym| modes.as_bytes().contains(&sym))
    };
    let (is_halfop, is_voice) = (prefix_sym('h'), prefix_sym('v'));
    let is_me = eq_ic(nick, &state.current_nick);

    // Self-mask capture first: the reply to `WHO <nick>` has "*" as channel.
    if is_me {
        let self_mask = trunc_string(&format!("{nick}!{ident}@{host}"), MAX_MASK_LEN);
        update_own_hostmask(state, &self_mask);
    }
    let Some(ci) = channel::find(state, chan_name) else {
        return;
    };
    let c = &mut state.chans[ci];
    // Own op status even when the roster is full.
    if is_me {
        c.i_am_opped = is_op;
    }
    // add, or replace the entry a JOIN already made (chanenf.rs keeps the
    // roster current between WHOs)
    let who = format!("{nick}!{ident}@{host}");
    if who.len() < MAX_MASK_LEN {
        chanenf::roster_set(c, nick, &who, is_op, is_halfop, is_voice);
    }
}

/// 315 (end of WHO): if we are not opped, pick a random trusted op from the
/// fresh roster and ask it -- via the hub when it has a UUID, else ~B2.
fn on_end_of_who(state: &mut BotState, params: &str) {
    let Some(ch) = second_tok(params) else { return };
    let Some(ci) = channel::find(state, ch) else {
        return;
    };
    let (name, roster_len) = (state.chans[ci].name.clone(), state.chans[ci].roster.len());
    logm!(
        state,
        L_INFO,
        "[INFO] Roster for {} updated with {} users.\n",
        name,
        roster_len
    );
    state.chans[ci].enf_dirty = true; // chanenf.rs sweep
    state.chans[ci].enf_ops_check = true;
    state.chans[ci].who_done = true; // the member list is complete

    if state.chans[ci].i_am_opped {
        state.chans[ci].op_request_pending = false;
        state.chans[ci].op_request_retry_count = 0;
        return;
    }

    logm!(
        state,
        L_DEBUG,
        "[OP-REQ] trusted_bot_count={}\n",
        state.trusted_bots.len()
    );
    for (i, tb) in state.trusted_bots.iter().enumerate() {
        logm!(
            state,
            L_DEBUG,
            "[OP-REQ] trusted_bots[{}]: {}|{}{}\n",
            i,
            tb.mask,
            tb.uuid,
            if tb.has_pub { "" } else { " (no key)" }
        );
    }

    let now = now();
    let c = &state.chans[ci];
    if c.op_request_pending && now - c.last_op_request_time < 60 {
        return;
    }
    // Reset the retry counter after 5 minutes of no attempts.
    if c.op_request_retry_count >= 5 && now - c.last_op_request_time > 300 {
        logm!(
            state,
            L_INFO,
            "[INFO] Resetting retry counter for {} after timeout.\n",
            name
        );
        state.chans[ci].op_request_retry_count = 0;
    }
    if state.chans[ci].op_request_retry_count >= 5 {
        logm!(
            state,
            L_INFO,
            "[INFO] Gave up requesting ops in {} after {} attempts.\n",
            name,
            state.chans[ci].op_request_retry_count
        );
        return;
    }

    logm!(
        state,
        L_DEBUG,
        "[OP-REQ] Scanning {} roster entries for trusted ops\n",
        roster_len
    );
    let mut helpers: Vec<RosterEntry> = Vec::new();
    for (i, entry) in state.chans[ci].roster.iter().enumerate() {
        let trusted = auth::is_trusted_bot(state, &entry.hostmask);
        logm!(
            state,
            L_DEBUG,
            "[OP-REQ] Roster[{}]: nick={} hostmask={} is_op={} is_trusted={}\n",
            i,
            entry.nick,
            entry.hostmask,
            entry.is_op as i32,
            trusted as i32
        );
        if entry.is_op && trusted {
            helpers.push(entry.clone());
        }
    }

    if helpers.is_empty() {
        logm!(
            state,
            L_DEBUG,
            "[OP-REQ] No trusted ops in roster. trusted_bot_count={}, roster_count={}\n",
            state.trusted_bots.len(),
            roster_len
        );
        // Not a failed attempt: back-date so the WHO retry comes in ~30 s.
        let c = &mut state.chans[ci];
        c.op_request_pending = true;
        c.last_op_request_time = now - 30;
        return;
    }

    let chosen = helpers[crypto::random_index(helpers.len())].clone();
    logm!(
        state,
        L_INFO,
        "[INFO] Found {} trusted ops. Randomly selected: {}. Sending OPME request (attempt {}).\n",
        helpers.len(),
        chosen.nick,
        state.chans[ci].op_request_retry_count + 1
    );
    state.chans[ci].last_op_request_time = now;
    state.chans[ci].op_request_pending = true;

    if now - state.last_op_request_sent >= OP_REQUEST_MIN_INTERVAL {
        let mut sent_via_hub = false;
        logm!(
            state,
            L_DEBUG,
            "[OP-REQ] Looking up UUID for helper: nick={} hostmask={}\n",
            chosen.nick,
            chosen.hostmask
        );
        if let Some(uuid) = find_uuid_for_helper(state, &chosen) {
            logm!(state, L_DEBUG, "[OP-REQ] Found UUID, trying hub request\n");
            sent_via_hub = hub_client::request_op(state, &uuid, &name);
            logm!(
                state,
                L_DEBUG,
                "[OP-REQ] hub_client_request_op returned: {}\n",
                sent_via_hub as i32
            );
        }
        if !sent_via_hub {
            logm!(
                state,
                L_DEBUG,
                "[OP-REQ] Hub unavailable or no UUID match, falling back to PRIVMSG\n"
            );
            bot_comms::send_to_host(
                state,
                &chosen.hostmask,
                &chosen.nick,
                &format!("OPME {name}"),
            );
        }
        state.last_op_request_sent = now;
        if let Some(c) = state.chans.get_mut(ci) {
            c.op_request_retry_count += 1;
        }
    } else {
        logm!(
            state,
            L_DEBUG,
            "[OP-REQ] Rate limited in {}; will retry (attempt {} pending)\n",
            name,
            state.chans[ci].op_request_retry_count + 1
        );
    }
}

fn on_privmsg(state: &mut BotState, prefix: &str, params: &str) {
    let mut pt = Tok::new(prefix);
    let nick = pt.next("!");
    let user = pt.next("@");
    let host = pt.rest();
    let mut t = Tok::new(params);
    let dest = t.next(" ");
    let message = t.rest().map(|m| m.strip_prefix(':').unwrap_or(m));
    let (Some(nick), Some(dest), Some(message)) = (nick, dest, message) else {
        return;
    };

    if dest.starts_with(['#', '&']) {
        // text to a channel: only the flood counters look at it
        if let (Some(u), Some(h)) = (user, host) {
            chanflood::on_text(state, dest, nick, u, h, message);
        }
        return;
    }
    let src_nuh = match (user, host) {
        (Some(u), Some(h)) => Some(format!("{nick}!{u}@{h}")).filter(|n| n.len() < MAX_MASK_LEN),
        _ => None,
    };
    let mb = message.as_bytes();
    if mb.len() >= 2 && mb[0] == 0x01 && mb[mb.len() - 1] == 0x01 {
        logm!(state, L_CTCP, "[CTCP] ({}) {}\n", nick, message);
        // ctcp flood (section 9.1): an ignored host, or quiet mode, gets no answer
        if let Some(n) = &src_nuh
            && botflood::ctcp(state, n) != Bf::Ok
        {
            return;
        }
        let ctcp = &message[1..message.len() - 1];
        if starts_with_ic(ctcp, "DCC ") {
            // Only ever the reply to this bot's own passive offer.
            if user.is_some() && host.is_some() && eq_ic(dest, &state.current_nick) {
                dcc::handle_ctcp(state, src_nuh.as_deref().unwrap_or(""), ctcp);
            }
        } else if eq_ic(ctcp, "VERSION") {
            ircf!(
                state,
                "NOTICE {} :\x01VERSION {}\x01\r\n",
                nick,
                VERSION_RESPONSE
            );
        } else if starts_with_ic(ctcp, "PING ") {
            ircf!(state, "NOTICE {} :\x01{}\x01\r\n", nick, ctcp);
        }
    } else {
        commands::handle_private_message(
            state,
            nick,
            user.unwrap_or("(null)"),
            host.unwrap_or("(null)"),
            dest,
            message,
        );
    }
}

/// NOTICEs were never read; now they only feed the flood counters.
fn on_notice(state: &mut BotState, prefix: &str, params: &str) {
    if !prefix.contains('!') {
        return;
    }
    let mut pt = Tok::new(prefix);
    let nick = pt.next("!");
    let user = pt.next("@");
    let host = pt.rest();
    let mut t = Tok::new(params);
    let dest = t.next(" ");
    let message = t.rest().map(|m| m.strip_prefix(':').unwrap_or(m));
    let (Some(nick), Some(user), Some(host), Some(dest), Some(message)) =
        (nick, user, host, dest, message)
    else {
        return;
    };
    if dest.starts_with(['#', '&']) {
        chanflood::on_text(state, dest, nick, user, host, message);
    } else if eq_ic(dest, &state.current_nick) && !message.starts_with('\x01') {
        // services (NickServ, ChanServ, ...) answer every command with a
        // NOTICE: that is not a flood from a host (servers carry no '!')
        let nb = nick.as_bytes();
        let services = nb.len() >= 4 && nb[nb.len() - 4..].eq_ignore_ascii_case(b"Serv");
        let src_nuh = format!("{nick}!{user}@{host}");
        if !services && src_nuh.len() < MAX_MASK_LEN {
            botflood::msg(state, &src_nuh);
        }
    }
}

fn on_join(state: &mut BotState, prefix: &str, params: &str) {
    // Our own JOIN echo's prefix is the mask the channel was shown -- the
    // earliest exact value.  A prefix that does not fit is not stored.
    let join_mask_ok = !prefix.is_empty() && prefix.len() < MAX_MASK_LEN;
    let nick = Tok::new(prefix).next("!");
    let Some(nick) = nick else { return };
    if join_mask_ok
        && eq_ic(nick, &state.current_nick)
        && prefix.contains('!')
        && prefix.contains('@')
    {
        update_own_hostmask(state, prefix);
    }
    if !(eq_ic(nick, &state.current_nick) || eq_ic(nick, &state.target_nick)) {
        // someone else joined: keep the roster (and the enforcement) current
        if join_mask_ok {
            let jc = params.strip_prefix(':').unwrap_or(params);
            let jc = jc.split(' ').next().unwrap_or("");
            if !jc.is_empty() && jc.len() < MAX_CHAN {
                chanenf::on_join(state, jc, prefix);
            }
        }
        return;
    }
    let chan_name = params.strip_prefix(':').unwrap_or(params);
    let Some(ci) = channel::find(state, chan_name) else {
        return;
    };
    if !state.chans[ci].is_managed {
        // Removed while this JOIN was on its way: the newest command wins.
        let name = state.chans[ci].name.clone();
        logm!(
            state,
            L_INFO,
            "[INFO] {} was removed while joining; parting\n",
            name
        );
        ircf!(state, "PART {} :Channel removed\r\n", name);
        if let Some(c) = state.chans.get_mut(ci) {
            c.status = ChanStatus::Out;
        }
    } else {
        let c = &mut state.chans[ci];
        c.status = ChanStatus::In;
        c.roster.clear();
        c.i_am_opped = false;
        chanlive::live_reset(c);
        c.last_who_request = now();
        let name = c.name.clone();
        ircf!(state, "WHO {}\r\n", name);
        chanlive::request(state, ci); // 324 modes and the 367 ban list
    }
}

fn on_nick(state: &mut BotState, prefix: &str, params: &str) {
    let old = Tok::new(prefix).next("!");
    let new_nick = params.strip_prefix(':').unwrap_or(params);
    let Some(old) = old else { return };
    chanenf::on_nick(state, old, new_nick);
    if !eq_ic(old, &state.current_nick) {
        return;
    }
    state.current_nick = trunc_string(new_nick, MAX_NICK);
    state.current_nick_ts = now();
    if state.hub_connected && state.hub_authenticated {
        let (n, ts) = (state.current_nick.clone(), state.current_nick_ts);
        hub_client::push_delta(state, "n", &n, ts);
    }
    // Our mask changed in its nick half: ask, let the 352 supply it.
    request_own_hostmask(state);
    state.nick_change_pending = false;
    if eq_ic(&state.current_nick, &state.target_nick) {
        state.nick_generation_attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::TrustedBot;

    #[test]
    fn helper_uuid_matches_a_long_nick() {
        let mut st = BotState::for_test();
        let long = "h".repeat(30);
        st.trusted_bots.push(TrustedBot {
            mask: format!("{long}!u@other.host"),
            uuid: "44444444-4444-4444-8444-444444444444".into(),
            ..TrustedBot::default()
        });
        let helper = RosterEntry {
            nick: long.clone(),
            hostmask: format!("{long}!v@new.host"),
            ..RosterEntry::default()
        };
        assert_eq!(
            find_uuid_for_helper(&st, &helper).as_deref(),
            Some("44444444-4444-4444-8444-444444444444")
        );
    }
}
