//! Channel list, join/roster upkeep, and channel-access requests (channel.c).
//!
//! Getting back into a managed channel we are locked out of: 474 (banned),
//! 473 (invite-only) and 475 (bad key) each raise a request that the hub
//! mesh fans out to the other bots.  With no hub up we fall back to a sealed
//! ~B2 PRIVMSG aimed at one trusted bot per attempt -- round-robin rather
//! than a broadcast.  Nothing trusts the requester for anything that
//! matters: the hub fills in the nick and hostmask from its own records, and
//! a bot servicing an unban removes only ban masks that match that hostmask.

use crate::auth::wildcard_match;
use crate::consts::*;
use crate::cstr::{eq_ic, now, trunc_string};
use crate::state::{
    BotState, Chan, ChanReq, ChanStatus, M_I, M_K, OWN_REQ_OP, OWN_REQ_SLOTS, OWN_REQ_WAIT_CHAN,
    OWN_REQ_WAIT_OP, S_AUTHED, UnbanJob,
};
use crate::{bot_comms, config, hub_client, ircf, logm};

/// channel_add(): None if the channel is already listed.
pub fn add(state: &mut BotState, name: &str) -> Option<usize> {
    if find(state, name).is_some() {
        return None;
    }
    // A name that is not one channel ("#a,0" -- 0 parts every channel on most
    // servers -- or one with a blank) never reaches a JOIN line.
    if !crate::chancfg::valid_chan_name(name) {
        logm!(state, L_INFO, "[CHAN] Not a channel name, not added\n");
        return None;
    }
    // The hub holds at most this many channel rows (tombstones included); an
    // uncapped list let one config frame use up memory.
    if state.chans.len() >= CFG_MAX_CHANNELS {
        logm!(
            state,
            L_INFO,
            "[CHAN] Channel table full ({}): {} not added\n",
            CFG_MAX_CHANNELS,
            name
        );
        return None;
    }
    state.chans.push(Chan {
        name: trunc_string(name, MAX_CHAN),
        status: ChanStatus::Out,
        is_managed: true,
        timestamp: now(),
        ..Chan::default()
    });
    Some(state.chans.len() - 1)
}

pub fn find(state: &BotState, name: &str) -> Option<usize> {
    state.chans.iter().position(|c| eq_ic(&c.name, name))
}

/// After a disconnect: every channel is out, and every lockout gets a fresh
/// set of attempts (a reconnect may well have brought a new hostmask).
pub fn reset_status(state: &mut BotState) {
    for c in &mut state.chans {
        c.status = ChanStatus::Out;
        c.last_join_attempt = 0;
        c.join_disabled = false;
        c.i_am_opped = false;
        crate::chanlive::live_reset(c);
        c.op_request_pending = false;
        c.op_request_retry_count = 0;
        c.last_access_request = [0; 3];
        c.access_retry_count = [0; 3];
    }
    for j in &mut state.unban_jobs {
        j.active = false;
    }
}

/// JOIN what we should be in, keep rosters fresh while seeking ops.
pub fn check_joins(state: &mut BotState) {
    if state.status & S_AUTHED == 0 {
        return;
    }
    // No channel before the NETWORK= check says this is the right network.
    if !crate::pool::netcheck_passed(state) {
        return;
    }
    let now = now();
    unban_expire(state);

    for i in 0..state.chans.len() {
        let Some(c) = state.chans.get(i) else { break };
        if !c.is_managed || c.join_disabled {
            continue;
        }
        if c.status != ChanStatus::In && now - c.last_join_attempt > JOIN_RETRY_TIME {
            let line = if c.key.is_empty() {
                format!("JOIN {}\r\n", c.name)
            } else {
                format!("JOIN {} {}\r\n", c.name, c.key)
            };
            if let Some(c) = state.chans.get_mut(i) {
                c.last_join_attempt = now;
            }
            crate::irc_client::irc_printf(state, &line);
            continue;
        }
        if c.status != ChanStatus::In {
            continue;
        }
        if c.i_am_opped {
            // No periodic WHO while opped: the MODE -o handler re-reads then.
            let c = &mut state.chans[i];
            c.op_request_pending = false;
            c.op_request_retry_count = 0;
            continue;
        }
        let name = c.name.clone();
        let mut should_refresh = false;
        if c.roster.is_empty() && now - c.last_who_request > 30 {
            logm!(
                state,
                L_DEBUG,
                "[DEBUG] No roster for {}. Requesting WHO.\n",
                name
            );
            should_refresh = true;
        } else if now - c.last_who_request > ROSTER_REFRESH_INTERVAL {
            logm!(
                state,
                L_DEBUG,
                "[DEBUG] Periodic roster refresh for {} (not opped).\n",
                name
            );
            should_refresh = true;
        } else if c.op_request_pending
            && now - c.last_op_request_time > 60
            && c.op_request_retry_count < 5
        {
            logm!(
                state,
                L_DEBUG,
                "[DEBUG] Op request timeout in {}. Refreshing to retry.\n",
                name
            );
            should_refresh = true;
            state.chans[i].op_request_pending = false;
        }
        if should_refresh {
            state.chans[i].roster.clear();
            ircf!(state, "WHO {}\r\n", name);
            if let Some(c) = state.chans.get_mut(i) {
                c.last_who_request = now;
            }
        }
    }
}

/// One trusted bot per attempt, advancing each time so a bot that is
/// offline or unhelpful does not absorb every retry.  why: logged; irc_only:
/// PRIVMSG even with a hub link (a failback because the hub did not get it
/// done).
fn access_fallback(
    state: &mut BotState,
    kind: ChanReq,
    channel: &str,
    why: &str,
    irc_only: bool,
) -> bool {
    let n = state.trusted_bots.len();
    if n == 0 {
        return false;
    }
    for _ in 0..n {
        let idx = state.chan_req_fallback_idx % n;
        state.chan_req_fallback_idx = (idx + 1) % n;
        let tb_nick = state.trusted_bots[idx].nick().to_string();
        if tb_nick.is_empty() {
            continue;
        }
        // Our own record may be in the roster; asking ourselves achieves nothing.
        if !state.current_nick.is_empty() && eq_ic(&tb_nick, &state.current_nick) {
            continue;
        }
        let cmd = match kind {
            ChanReq::Unban => format!("UNBAN {channel}"),
            ChanReq::Invite => {
                // Nothing to invite without a nick the server has accepted.
                if state.current_nick.is_empty() {
                    return false;
                }
                format!("INVITE {} {}", channel, state.current_nick)
            }
            ChanReq::Key => format!("KEY {channel}"),
        };
        if irc_only {
            bot_comms::send_command_irc(state, &tb_nick, &cmd);
        } else {
            bot_comms::send_command(state, &tb_nick, &cmd);
        }
        logm!(
            state,
            L_INFO,
            "[B2-FAILBACK] {} for {} via {} ({})\n",
            kind.token(),
            channel,
            tb_nick,
            why
        );
        return true;
    }
    false
}

/// Ask the mesh to let us into channel `ci`: CMD_CHAN_REQUEST when a hub is
/// up, else a sealed ~B2 to one trusted bot.  Rate-limited per chan+kind and
/// globally; true when a request actually left the bot.
pub fn access_request(state: &mut BotState, ci: usize, kind: ChanReq) -> bool {
    let k = kind as usize;
    let Some(c) = state.chans.get(ci) else {
        return false;
    };
    if !c.is_managed || c.join_disabled || state.status & S_AUTHED == 0 {
        return false;
    }
    let now = now();
    // A long quiet spell clears the retry count.
    if c.access_retry_count[k] >= CHAN_REQUEST_MAX_RETRIES {
        if now - c.last_access_request[k] > CHAN_REQUEST_COOLOFF {
            state.chans[ci].access_retry_count[k] = 0;
        } else {
            return false;
        }
    }
    let c = &state.chans[ci];
    if c.last_access_request[k] != 0 && now - c.last_access_request[k] < CHAN_REQUEST_RETRY_TIME {
        return false;
    }
    // Global spacing: a rejoin after a netsplit can trip many channels at once.
    if now - state.last_chan_request_sent < CHAN_REQUEST_MIN_INTERVAL {
        return false;
    }
    let name = c.name.clone();
    // A 2.5.4 hub (it sent an N|) answers; an older one gets no third field.
    let rid = if state.pool_hub_seen {
        hub_client::new_rid().unwrap_or_default()
    } else {
        String::new()
    };
    let mut sent = hub_client::send_chan_request(state, kind.token(), &name, &rid);
    if sent {
        if let Some(c) = state.chans.get_mut(ci) {
            c.own_rid[k] = rid;
            c.own_sent[k] = now;
        }
    } else {
        sent = access_fallback(state, kind, &name, "no hub", false);
    }
    if !sent {
        return false;
    }
    if let Some(c) = state.chans.get_mut(ci) {
        c.last_access_request[k] = now;
        c.access_retry_count[k] += 1;
    }
    state.last_chan_request_sent = now;
    true
}

// ---- Our own requests: the hub's answer, or ~B2 when there is none ------

fn own_slot_kind(slot: usize) -> Option<ChanReq> {
    match slot {
        0 => Some(ChanReq::Unban),
        1 => Some(ChanReq::Invite),
        2 => Some(ChanReq::Key),
        _ => None,
    }
}

fn own_slot_word(slot: usize) -> &'static str {
    own_slot_kind(slot).map_or("op", |k| k.token())
}

/// op over IRC: a trusted bot this bot sees opped in the channel.
fn own_op_b2(state: &mut BotState, ci: usize, why: &str) -> bool {
    let name = state.chans[ci].name.clone();
    let helpers: Vec<(String, String)> = state.chans[ci]
        .roster
        .iter()
        .filter(|r| r.is_op && crate::auth::is_trusted_bot(state, &r.hostmask))
        .map(|r| (r.nick.clone(), r.hostmask.clone()))
        .collect();
    if helpers.is_empty() {
        logm!(
            state,
            L_INFO,
            "[B2-FAILBACK] op for {}: no trusted bot opped here ({})\n",
            name,
            why
        );
        return false;
    }
    let (nick, hostmask) = &helpers[crate::crypto::random_index(helpers.len())];
    logm!(
        state,
        L_INFO,
        "[B2-FAILBACK] op for {} via {} ({})\n",
        name,
        nick,
        why
    );
    bot_comms::send_to_host_irc(state, hostmask, nick, &format!("OPME {name}"));
    true
}

/// The hub did not get it done (none / silent / failed): ask over IRC now.
/// Nothing if it already worked.
pub fn own_failback(state: &mut BotState, ci: usize, slot: usize, why: &str) {
    if ci >= state.chans.len() || slot >= OWN_REQ_SLOTS {
        return;
    }
    let c = &mut state.chans[ci];
    c.own_sent[slot] = 0;
    c.own_rid[slot].clear();
    let (inside, opped, name) = (c.status == ChanStatus::In, c.i_am_opped, c.name.clone());
    match own_slot_kind(slot) {
        None => {
            if inside && !opped {
                own_op_b2(state, ci, why);
            }
        }
        Some(kind) => {
            if !inside {
                access_fallback(state, kind, &name, why, true);
            }
        }
    }
}

/// CMD_USER_CHAN_RESULT for a rid of ours: ok -- done; denied -- policy, no
/// ~B2 around it; none (anything else) -- nobody on a hub could: ~B2.
pub fn own_result(state: &mut BotState, rid: &str, status: &str, detail: &str) -> bool {
    if rid.is_empty() {
        return false;
    }
    for ci in 0..state.chans.len() {
        for s in 0..OWN_REQ_SLOTS {
            let c = &state.chans[ci];
            if c.own_sent[s] == 0 || c.own_rid[s] != rid {
                continue;
            }
            let d: String = trunc_string(detail, 200)
                .chars()
                .map(|ch| {
                    if (ch as u32) < 0x20 || ch == '\x7f' {
                        ' '
                    } else {
                        ch
                    }
                })
                .collect();
            if status == "ok" || status == "denied" {
                let name = c.name.clone();
                logm!(
                    state,
                    L_INFO,
                    "[CHANREQ] {} for {}: {}{}{}\n",
                    own_slot_word(s),
                    name,
                    if status == "ok" {
                        "done"
                    } else {
                        "denied, not asking over IRC"
                    },
                    if d.is_empty() { "" } else { " - " },
                    d
                );
                let c = &mut state.chans[ci];
                c.own_sent[s] = 0;
                c.own_rid[s].clear();
            } else {
                let why = format!(
                    "hub: {}",
                    crate::cstr::trunc(if d.is_empty() { status } else { &d }, 201)
                );
                own_failback(state, ci, s, &why);
            }
            return true;
        }
    }
    false
}

/// Each second: a request that worked is dropped quietly; one the hub left
/// unanswered past its wait goes over IRC.
pub fn own_tick(state: &mut BotState) {
    let now = now();
    for ci in 0..state.chans.len() {
        for s in 0..OWN_REQ_SLOTS {
            let c = &state.chans[ci];
            if c.own_sent[s] == 0 {
                continue;
            }
            let inside = c.status == ChanStatus::In;
            let done = if s == OWN_REQ_OP {
                inside && c.i_am_opped
            } else {
                inside
            };
            if done {
                let c = &mut state.chans[ci];
                c.own_sent[s] = 0;
                c.own_rid[s].clear();
                continue;
            }
            let wait = if s == OWN_REQ_OP {
                OWN_REQ_WAIT_OP
            } else {
                OWN_REQ_WAIT_CHAN
            };
            if now - c.own_sent[s] < wait {
                continue;
            }
            let why = if c.own_rid[s].is_empty() {
                "no result through an older hub"
            } else {
                "no answer from the hub"
            };
            own_failback(state, ci, s, why);
        }
    }
}

/// Our own op through the hub's election (a 2.5.4 hub).  False: not sent
/// (no such hub link) -- the caller takes the older path.
pub fn own_op_request(state: &mut BotState, ci: usize) -> bool {
    if !state.pool_hub_seen {
        return false;
    }
    let Some(rid) = hub_client::new_rid() else {
        return false;
    };
    let name = state.chans[ci].name.clone();
    if !hub_client::send_chan_request(state, "op", &name, &rid) {
        return false;
    }
    let c = &mut state.chans[ci];
    c.own_rid[OWN_REQ_OP] = rid;
    c.own_sent[OWN_REQ_OP] = now();
    true
}

// ---- An invite only for the mask the request was for -------------------

/// The nick is outside the channel, so its mask comes from `WHO <nick>`: the
/// 352 carries the nick!ident@host every client is shown (request_own_hostmask
/// explains why not USERHOST).  id "" = a ~B2 invite.  C `invite_check_start`.
pub fn invite_check_start(
    state: &mut BotState,
    id: &str,
    chan: &str,
    nick: &str,
    mask: &str,
    user: &str,
) {
    if state.invite_checks.len() >= crate::state::INVITE_CHECKS {
        logm!(
            state,
            L_INFO,
            "[INVITE] Too many invite checks in flight; not inviting {}\n",
            nick
        );
        if !id.is_empty() {
            hub_client::chan_done_send(state, id, false, "busy");
        }
        return;
    }
    state.invite_checks.push(crate::state::InviteCheck {
        id: trunc_string(id, 64),
        chan: trunc_string(chan, MAX_CHAN),
        nick: trunc_string(nick, MAX_MEMBER_NICK),
        mask: trunc_string(mask, MAX_MASK_LEN),
        user: trunc_string(user, 37),
        seen: false,
        sent: now(),
    });
    ircf!(state, "WHO {}\r\n", nick);
}

fn invite_check_close(state: &mut BotState, k: crate::state::InviteCheck, ok: bool, why: &str) {
    if ok {
        logm!(
            state,
            L_INFO,
            "[INVITE] Inviting {} into {} ({} checked)\n",
            k.nick,
            k.chan,
            k.mask
        );
        ircf!(state, "INVITE {} {}\r\n", k.nick, k.chan);
    } else {
        logm!(
            state,
            L_INFO,
            "[INVITE] Not inviting {} into {}: {}\n",
            k.nick,
            k.chan,
            why
        );
    }
    if !k.id.is_empty() {
        hub_client::chan_done_send(state, &k.id, ok, if ok { "INVITE sent" } else { why });
    }
}

/// A 352: the live mask of a nick we may be about to invite.
pub fn invite_check_who(state: &mut BotState, nick: &str, ident: &str, host: &str) {
    let live = format!("{nick}!{ident}@{host}");
    if live.len() >= MAX_MASK_LEN {
        return;
    }
    let mut i = 0;
    while i < state.invite_checks.len() {
        if !eq_ic(&state.invite_checks[i].nick, nick) {
            i += 1;
            continue;
        }
        let k = state.invite_checks.remove(i);
        let opped = find(state, &k.chan).is_some_and(|ci| {
            state.chans[ci].status == ChanStatus::In && state.chans[ci].i_am_opped
        });
        let why = if !opped {
            Some("not opped there")
        } else if if k.user.is_empty() {
            !crate::auth::bot_mask_ok(state, &k.mask, &live)
        } else {
            !crate::auth::mask_equal(&live, &k.mask)
        } {
            Some("the nick is not the requester now")
        } else if !k.user.is_empty() && !crate::auth::user_live_ok(state, &k.user, &live, &k.chan) {
            Some("the user's masks do not cover it")
        } else {
            None
        };
        invite_check_close(state, k, why.is_none(), why.unwrap_or(""));
    }
}

/// The 315 after it: a nick no 352 answered for is not on IRC.
pub fn invite_check_end(state: &mut BotState, nick: &str) {
    let mut i = 0;
    while i < state.invite_checks.len() {
        let k = &state.invite_checks[i];
        if !k.seen && eq_ic(&k.nick, nick) {
            let k = state.invite_checks.remove(i);
            invite_check_close(state, k, false, "the nick is not on IRC");
        } else {
            i += 1;
        }
    }
}

pub fn invite_check_tick(state: &mut BotState) {
    let now = now();
    let mut i = 0;
    while i < state.invite_checks.len() {
        if now - state.invite_checks[i].sent >= crate::state::INVITE_CHECK_WAIT {
            let k = state.invite_checks.remove(i);
            invite_check_close(state, k, false, "no WHO answer");
        } else {
            i += 1;
        }
    }
}

fn unban_job_find(state: &BotState, channel: &str) -> Option<usize> {
    state
        .unban_jobs
        .iter()
        .position(|j| j.active && eq_ic(&j.channel, channel))
}

/// Close out ban-list walks whose 368 never arrived.
pub fn unban_expire(state: &mut BotState) {
    let now = now();
    for i in 0..state.unban_jobs.len() {
        let j = &state.unban_jobs[i];
        if j.active && now - j.started > UNBAN_JOB_TTL {
            let ch = j.channel.clone();
            state.unban_jobs[i].active = false;
            logm!(
                state,
                L_DEBUG,
                "[DEBUG] [UNBAN] Ban list for {} never closed; job dropped\n",
                ch
            );
        }
    }
}

/// Raise a job and ask for the ban list; a burst of requests for one channel
/// collapses onto one walk.
fn unban_job_start(state: &mut BotState, channel: &str, hostmask: &str) -> bool {
    unban_expire(state);
    if unban_job_find(state, channel).is_some() {
        return false;
    }
    let Some(slot) = state.unban_jobs.iter().position(|j| !j.active) else {
        logm!(state, L_INFO, "[UNBAN] No free job slot for {}\n", channel);
        return false;
    };
    state.unban_jobs[slot] = UnbanJob {
        channel: trunc_string(channel, MAX_CHAN),
        hostmask: trunc_string(hostmask, MAX_MASK_LEN),
        started: now(),
        removed: 0,
        active: true,
    };
    ircf!(state, "MODE {} +b\r\n", channel);
    logm!(
        state,
        L_INFO,
        "[UNBAN] Walking ban list of {} for {}\n",
        channel,
        hostmask
    );
    true
}

/// One 367 entry.  Only masks that match the requester come off, and never
/// more than UNBAN_MAX_REMOVALS of them.
pub fn unban_note_ban(state: &mut BotState, channel: &str, ban_mask: &str) {
    let Some(ji) = unban_job_find(state, channel) else {
        return;
    };
    if ban_mask.is_empty() {
        return;
    }
    let j = &state.unban_jobs[ji];
    if j.removed >= UNBAN_MAX_REMOVALS || !wildcard_match(ban_mask, &j.hostmask) {
        return;
    }
    let hostmask = j.hostmask.clone();
    match find(state, channel) {
        Some(ci) if state.chans[ci].status == ChanStatus::In && state.chans[ci].i_am_opped => {}
        _ => return,
    }
    ircf!(state, "MODE {} -b {}\r\n", channel, ban_mask);
    if let Some(j) = state.unban_jobs.get_mut(ji) {
        j.removed += 1;
    }
    logm!(
        state,
        L_INFO,
        "[UNBAN] Removed {} from {} (matched {})\n",
        ban_mask,
        channel,
        hostmask
    );
}

pub fn unban_finish(state: &mut BotState, channel: &str) {
    let Some(ji) = unban_job_find(state, channel) else {
        return;
    };
    if state.unban_jobs[ji].removed == 0 {
        let hm = state.unban_jobs[ji].hostmask.clone();
        logm!(
            state,
            L_INFO,
            "[UNBAN] No ban in {} matched {}\n",
            channel,
            hm
        );
    }
    state.unban_jobs[ji].active = false;
}

/// Service a request another bot made of us.  `hostmask` and `nick` are the
/// requester's as the hub resolved them.  Replies (key) go back via
/// `reply_to` (the ~B2 fallback's requester nick) or the hub.
pub fn access_service(
    state: &mut BotState,
    request_id: &str,
    kind: ChanReq,
    channel: &str,
    nick: Option<&str>,
    hostmask: Option<&str>,
    reply_to: Option<&str>,
) {
    if channel.is_empty() {
        return;
    }
    let ci = match find(state, channel) {
        Some(ci) if state.chans[ci].status == ChanStatus::In => ci,
        _ => {
            logm!(
                state,
                L_DEBUG,
                "[DEBUG] [CHANREQ] {} for {} ignored: not in channel\n",
                kind.token(),
                channel
            );
            return;
        }
    };
    let opped = state.chans[ci].i_am_opped;
    match kind {
        ChanReq::Unban => {
            let Some(hm) = hostmask.filter(|h| !h.is_empty()) else {
                return;
            };
            if !opped {
                logm!(
                    state,
                    L_DEBUG,
                    "[DEBUG] [UNBAN] Not opped in {}; cannot help\n",
                    channel
                );
                return;
            }
            unban_job_start(state, channel, hm);
        }
        ChanReq::Invite => {
            let Some(n) = nick.filter(|n| !n.is_empty()) else {
                return;
            };
            if !opped {
                logm!(
                    state,
                    L_DEBUG,
                    "[DEBUG] [INVITE] Not opped in {}; cannot help\n",
                    channel
                );
                return;
            }
            logm!(
                state,
                L_INFO,
                "[INVITE] Inviting {} into {} (mesh request)\n",
                n,
                channel
            );
            ircf!(state, "INVITE {} {}\r\n", n, channel);
        }
        ChanReq::Key => {
            // Being in the channel is enough: only a bot sitting in it has
            // the current key.
            let key = state.chans[ci].key.clone();
            if key.is_empty() {
                logm!(
                    state,
                    L_DEBUG,
                    "[DEBUG] [CHANREQ] No key held for {}; staying quiet\n",
                    channel
                );
                return;
            }
            if let Some(to) = reply_to.filter(|r| !r.is_empty()) {
                bot_comms::send_command(state, to, &format!("KEYIS {channel} {key}"));
                logm!(
                    state,
                    L_INFO,
                    "[CHANREQ] Sent key for {} to {} (~B2)\n",
                    channel,
                    to
                );
            } else if !request_id.is_empty() {
                hub_client::send_chan_reply(state, request_id, kind.token(), channel, "ok", &key);
                logm!(
                    state,
                    L_INFO,
                    "[CHANREQ] Sent key for {} via hub\n",
                    channel
                );
            }
        }
    }
}

/// A key handed to us by another bot.  Accepted only for a managed channel
/// we are locked out of and asked about recently, so a stray reply cannot
/// rewrite a good key.
pub fn access_accept_key(state: &mut BotState, channel: &str, key: &str) {
    if key.is_empty() {
        return;
    }
    if key.len() >= MAX_KEY {
        logm!(
            state,
            L_INFO,
            "[CHANREQ] Oversized key for {} ignored\n",
            channel
        );
        return;
    }
    let Some(ci) = find(state, channel) else {
        return;
    };
    let c = &state.chans[ci];
    if !c.is_managed || c.status == ChanStatus::In {
        return;
    }
    let asked = c.last_access_request[ChanReq::Key as usize];
    if asked == 0 || now() - asked > CHAN_REPLY_ACCEPT_WINDOW {
        logm!(
            state,
            L_INFO,
            "[CHANREQ] Unsolicited key for {} ignored\n",
            channel
        );
        return;
    }
    if c.key == key {
        return;
    }
    // learned, never existence (K|): the c| stamp stays, so a delete this
    // races is not undone
    let c = &mut state.chans[ci];
    let modes = c.modes | M_K;
    if !learn(c, key, modes) {
        logm!(
            state,
            L_INFO,
            "[CHANREQ] Malformed key for {} ignored\n",
            channel
        );
        return;
    }
    logm!(
        state,
        L_INFO,
        "[CHANREQ] Learned key for {}; retrying join\n",
        channel
    );
    hub_client::push_channel(state, ci);
    config::write_with_state_pass(state);
    // Go straight back in rather than waiting out JOIN_RETRY_TIME.
    if let Some(c) = state.chans.get_mut(ci) {
        c.last_join_attempt = 0;
    }
}

// ---- K|: learned channel state ----------------------------------------------

/// chan_key_refresh(): key = the newer of ckey@timestamp and lkey@l_ts (a tie
/// keeps ckey).
pub fn key_refresh(c: &mut Chan) {
    c.key = if c.l_ts > c.timestamp {
        c.lkey.clone()
    } else {
        c.ckey.clone()
    };
}

fn learned_key_ok(k: &str) -> bool {
    k.len() < MAX_KEY
        && k.bytes()
            .all(|c| c > 0x20 && c != b',' && c != b'|' && c < 0x7f)
}

/// chan_learn(): a key / +k+i this bot saw, stamped past both stamps; false
/// when nothing changed or the key is malformed.
pub fn learn(c: &mut Chan, key: &str, modes: u32) -> bool {
    if !learned_key_ok(key) {
        return false;
    }
    let modes = modes & (M_K | M_I);
    if c.l_ts > 0 && c.key == key && c.modes == modes {
        return false;
    }
    // past the c| stamp as well: what was just seen is the key in use
    c.l_ts = crate::state::lww_next_ts(c.l_ts.max(c.timestamp));
    c.lkey = key.to_string();
    c.modes = modes;
    key_refresh(c);
    true
}

/// chan_learned_forget(): the channel went.
pub fn learned_forget(c: &mut Chan) {
    zeroize::Zeroize::zeroize(&mut c.lkey);
    c.l_ts = 0;
    c.modes = 0;
    key_refresh(c);
}

/// chan_learned_ingest(): one "chan|key|modes|ts" body from a hub or the
/// config (managed channels only).
pub fn learned_ingest(state: &mut BotState, body: &str) -> bool {
    if body.len() >= MAX_CHAN + MAX_KEY + 48 {
        return false;
    }
    let f: Vec<&str> = body.split('|').collect();
    if f.len() != 4 || !learned_key_ok(f[1]) {
        return false;
    }
    let (Ok(modes), Ok(ts)) = (f[2].parse::<i64>(), f[3].parse::<i64>()) else {
        return false;
    };
    if modes < 0 || modes & !i64::from(M_K | M_I) != 0 || ts <= 0 {
        return false;
    }
    // never existence: only for a channel managed here
    let Some(ci) = find(state, f[0]) else {
        return false;
    };
    let c = &mut state.chans[ci];
    if !c.is_managed
        || ts < c.l_ts
        || (ts == c.l_ts && format!("{}|{modes}", f[1]) <= format!("{}|{}", c.lkey, c.modes))
    {
        return false;
    }
    c.lkey = f[1].to_string();
    c.modes = modes as u32;
    c.l_ts = ts;
    key_refresh(c);
    true
}

/// chan_format_l(): the K| line.
pub fn format_k(c: &Chan) -> String {
    format!("K|{}|{}|{}|{}\n", c.name, c.lkey, c.modes, c.l_ts)
}
