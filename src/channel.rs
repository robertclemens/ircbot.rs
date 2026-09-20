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
use crate::state::{BotState, Chan, ChanReq, ChanStatus, S_AUTHED, UnbanJob};
use crate::{bot_comms, config, hub_client, ircf, logm};

/// channel_add(): None if the channel is already listed.
pub fn add(state: &mut BotState, name: &str) -> Option<usize> {
    if find(state, name).is_some() {
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
/// offline or unhelpful does not absorb every retry.
fn access_fallback(state: &mut BotState, kind: ChanReq, channel: &str) -> bool {
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
        bot_comms::send_command(state, &tb_nick, &cmd);
        logm!(
            state,
            L_INFO,
            "[CHANREQ] {} for {} via {} (no hub)\n",
            kind.token(),
            channel,
            tb_nick
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
    let mut sent = hub_client::send_chan_request(state, kind.token(), &name);
    if !sent {
        sent = access_fallback(state, kind, &name);
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
    let c = &mut state.chans[ci];
    c.key = key.to_string();
    c.timestamp = crate::state::lww_next_ts(c.timestamp);
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
