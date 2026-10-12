//! Channel floods (chanflood.c, irchub docs/modes.md section 8).
//!
//! Every opped or not bot counts the same channel events and so agrees when a
//! flood trips; only the holder of the matching election job acts (the
//! `chanenf::request_*` hooks queue the work in the section 7 deal), and a
//! bot that is not opped only logs.  There are no timers: a window is opened
//! by the first event from a source and judged when the next one arrives, so
//! more than N events within S seconds of the window's start trip it (N+1,
//! not N).  After a trip the window starts afresh, so one burst is one trip.
//!
//! Sources are keyed by host (a nick change does not reset a window).  The
//! tracker holds MAX_FLOOD_TRACK sources per channel; when it is full the
//! source idle longest is replaced.  Authorised members, this bot and server
//! sources are never counted; with +dontkickops neither are ops for the
//! chan / ctcp / join / nick floods.  A halfop's kicks and bans count in the
//! op floods (D41).

use crate::chancfg;
use crate::consts::*;
use crate::cstr::{eq_ic, starts_with_ic, trunc};
use crate::sendq::mono_ms;
use crate::state::{BotState, ChanStatus, CsetId, FL_CHAN_COUNT, FloodKind, FloodSrc, FloodWindow};
use crate::{chanenf, channel, hub_client, logm};

/// flood_now_ms(): monotonic milliseconds.
pub fn now_ms() -> i64 {
    mono_ms()
}

/// Pure window step: true when this event is the N+1th inside the window
/// (the window is then reset, so one trip is reported once).  n / s come from
/// the setting.
pub fn window_hit(w: &mut FloodWindow, n: i32, s: i32, now_ms: i64) -> bool {
    if w.count <= 0 || now_ms - w.start_ms >= i64::from(s) * 1000 {
        w.start_ms = now_ms;
        w.count = 0;
    }
    w.count += 1;
    if w.count > n {
        w.start_ms = 0;
        w.count = 0;
        return true;
    }
    false
}

/// Lower-cased host of nick!user@host, cut to FLOOD_HOST_MAX; None when
/// there is no '!' and '@' (a server source) or the host is empty.
pub fn src_host(nuh: &str) -> Option<String> {
    let bang = nuh.find('!')?;
    let at = bang + nuh[bang..].find('@')?;
    let host = &nuh[at + 1..];
    (!host.is_empty()).then(|| trunc(host, FLOOD_HOST_MAX).to_ascii_lowercase())
}

fn src_nick(nuh: &str) -> Option<&str> {
    let bang = nuh.find('!')?;
    (bang != 0 && bang < MAX_MEMBER_NICK).then(|| &nuh[..bang])
}

/// The tracker step: find or make the slot for `host` (a full tracker gives
/// up the source idle longest), note the victim, step the window of `kind`.
/// Some(a) when it tripped; `a` = an authorised victim was seen since the
/// last trip of this kind.
#[allow(clippy::too_many_arguments)]
pub fn track(
    flood: &mut [FloodSrc],
    host: &str,
    kind: usize,
    victim_auth: bool,
    n: i32,
    s: i32,
    now_ms: i64,
) -> Option<bool> {
    let (mut slot, mut free, mut oldest): (Option<usize>, Option<usize>, Option<usize>) =
        (None, None, None);
    for (i, f) in flood.iter().enumerate() {
        if f.host.is_empty() {
            free.get_or_insert(i);
        } else if f.host == host {
            slot = Some(i);
            break;
        } else if oldest.is_none_or(|o| f.last_ms < flood[o].last_ms) {
            oldest = Some(i);
        }
    }
    let i = match slot {
        Some(i) => i,
        None => {
            // full: the longest idle goes
            let i = free.or(oldest)?;
            flood[i] = FloodSrc {
                host: host.to_string(),
                ..FloodSrc::default()
            };
            i
        }
    };
    let f = &mut flood[i];
    f.last_ms = now_ms;
    if victim_auth {
        f.victim_auth |= 1u8 << kind;
    }
    if !window_hit(&mut f.w[kind], n, s, now_ms) {
        return None;
    }
    let a = f.victim_auth & (1u8 << kind) != 0;
    f.victim_auth &= !(1u8 << kind);
    Some(a)
}

/// Testable core (chanflood_count_at): Some(auth_victim) when the event
/// tripped its flood (the ladder is not run).
pub fn count_at(
    state: &mut BotState,
    ci: usize,
    nuh: &str,
    kind: FloodKind,
    victim_auth: bool,
    now_ms: i64,
) -> Option<bool> {
    let k = kind as usize;
    if k >= FL_CHAN_COUNT {
        return None;
    }
    let c = state.chans.get(ci)?;
    let (n, s) = chancfg::get_flood(state, Some(c), kind)?; // off
    let host = src_host(nuh)?;
    let nick = src_nick(nuh)?;
    if chanenf::chan_nuh_authorised(state, ci, nuh) {
        return None;
    }
    let text_kind = matches!(
        kind,
        FloodKind::Chan | FloodKind::Ctcp | FloodKind::Join | FloodKind::Nick
    );
    if text_kind
        && chancfg::get(state, Some(c), CsetId::DontKickOps) != 0
        && c.roster.iter().any(|e| eq_ic(&e.nick, nick) && e.is_op)
    {
        return None;
    }
    let c = &mut state.chans[ci];
    if c.flood.is_empty() {
        c.flood = vec![FloodSrc::default(); MAX_FLOOD_TRACK];
    }
    track(&mut c.flood, &host, k, victim_auth, n, s, now_ms)
}

const KIND_NAME: [&str; FL_CHAN_COUNT] = ["chan", "ctcp", "join", "nick", "deop", "kick", "ban"];

/// Section 8.3: what a trip does.
fn trip(state: &mut BotState, ci: usize, nuh: &str, kind: FloodKind, auth_victim: bool) {
    let Some(nick) = src_nick(nuh) else { return };
    let name = state.chans[ci].name.clone();
    let (n, s) = chancfg::get_flood(state, state.chans.get(ci), kind).unwrap_or((0, 0));
    let off = chanenf::offence(state, &name, nuh);
    let op_flood = matches!(kind, FloodKind::Deop | FloodKind::Kick | FloodKind::Ban);
    let revenge = chancfg::get(state, state.chans.get(ci), CsetId::Revenge) != 0;
    let ban_step = if kind == FloodKind::Join {
        true // a join flood is returning: ban + kick at once
    } else if op_flood {
        off >= 2 || (revenge && auth_victim)
    } else {
        off >= 2
    };
    let job = if ban_step {
        JOB_BAN
    } else if op_flood {
        JOB_OP
    } else {
        JOB_KICK
    };
    let act = if ban_step {
        "kick+ban"
    } else if op_flood {
        "deop"
    } else {
        "kick"
    };
    let kname = KIND_NAME[kind as usize];
    let reason = format!("{kname} flood");

    let rank = chanenf::deal_rank(state, ci, job);
    logm!(
        state,
        L_INFO,
        "[FLOOD] {} flood ({}:{}) in {} by {}, offence {} -> {}{}\n",
        kname,
        n,
        s,
        name,
        nuh,
        off,
        act,
        if rank < 0 {
            " (not opped or not in the deal: logged only)"
        } else {
            ""
        }
    );
    let queued = if ban_step {
        chanenf::request_ban(state, &name, nuh, &reason, true)
    } else if op_flood {
        chanenf::request_deop(state, &name, nick, &reason)
    } else {
        chanenf::request_kick(state, &name, nick, &reason)
    };
    // One chan event per trip: from the bot that holds the job.
    if queued && rank == 0 {
        let detail = format!("{kname} flood {n}:{s}, offence {off}: {act}");
        hub_client::chan_event(state, &name, "floodtrip", nick, &detail);
    }
}

/// Count one event of `kind` from nick!user@host in `chan`; trips run the
/// section 8.3 ladder.  `victim_auth`: the event hurt an authorised member
/// (+revenge).
pub fn event(state: &mut BotState, chan: &str, nuh: &str, kind: FloodKind, victim_auth: bool) {
    let Some(ci) = channel::find(state, chan) else {
        return;
    };
    if state.chans[ci].status != ChanStatus::In {
        return;
    }
    if let Some(auth_victim) = count_at(state, ci, nuh, kind, victim_auth, now_ms()) {
        trip(state, ci, nuh, kind, auth_victim);
    }
}

/// Text sent to a channel (PRIVMSG or NOTICE): CTCP other than ACTION counts
/// as ctcp, everything else as chan.
pub fn on_text(state: &mut BotState, chan: &str, nick: &str, user: &str, host: &str, msg: &str) {
    let nuh = format!("{nick}!{user}@{host}");
    if nuh.len() >= MAX_MASK_LEN {
        return;
    }
    let ctcp = msg.as_bytes().first() == Some(&1) && !starts_with_ic(&msg[1..], "ACTION");
    let kind = if ctcp {
        FloodKind::Ctcp
    } else {
        FloodKind::Chan
    };
    event(state, chan, &nuh, kind, false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(w: &mut FloodWindow, n: i32, s: i32, t: i64) -> bool {
        window_hit(w, n, s, t)
    }

    #[test]
    fn trips_at_n_plus_one() {
        let mut w = FloodWindow::default();
        // 3:10 -- three events are fine, the fourth trips
        assert!(!win(&mut w, 3, 10, 1000));
        assert!(!win(&mut w, 3, 10, 1100));
        assert!(!win(&mut w, 3, 10, 1200));
        assert!(win(&mut w, 3, 10, 1300));
        // the trip reset the window: one burst is one trip
        assert!(!win(&mut w, 3, 10, 1400));
        assert_eq!(w.count, 1);
    }

    #[test]
    fn window_resets_after_s_seconds() {
        let mut w = FloodWindow::default();
        assert!(!win(&mut w, 2, 10, 5000));
        assert!(!win(&mut w, 2, 10, 5100));
        // exactly s seconds after the start: a new window opens
        assert!(!win(&mut w, 2, 10, 15000));
        assert_eq!((w.start_ms, w.count), (15000, 1));
        // one ms short of s: still the same window
        let mut w = FloodWindow::default();
        assert!(!win(&mut w, 2, 10, 5000));
        assert!(!win(&mut w, 2, 10, 5100));
        assert!(win(&mut w, 2, 10, 14999));
    }

    #[test]
    fn host_is_lowercased_and_nick_bounded() {
        assert_eq!(
            src_host("N!u@Host.EXAMPLE.com").as_deref(),
            Some("host.example.com")
        );
        assert_eq!(src_host("irc.server.net"), None);
        assert_eq!(src_host("n!u@"), None);
        assert_eq!(src_nick("nick!u@h"), Some("nick"));
        assert_eq!(src_nick("!u@h"), None);
        assert_eq!(src_nick("tenletters!u@h"), Some("tenletters"));
        assert_eq!(
            src_nick(&format!("{}!u@h", "n".repeat(31))).map(str::len),
            Some(31)
        );
        assert_eq!(src_nick(&format!("{}!u@h", "n".repeat(32))), None);
    }

    #[test]
    fn tracker_counts_per_host_and_kind() {
        let mut t = vec![FloodSrc::default(); 4];
        let kc = FloodKind::Chan as usize;
        let kj = FloodKind::Join as usize;
        for i in 0..3 {
            assert_eq!(track(&mut t, "a.example", kc, false, 3, 10, 1000 + i), None);
        }
        // another kind and another host have their own windows
        assert_eq!(track(&mut t, "a.example", kj, false, 3, 10, 1010), None);
        assert_eq!(track(&mut t, "b.example", kc, false, 3, 10, 1020), None);
        assert_eq!(
            track(&mut t, "a.example", kc, false, 3, 10, 1030),
            Some(false)
        );
    }

    #[test]
    fn tracker_replaces_the_longest_idle_source() {
        let mut t = vec![FloodSrc::default(); 3];
        let k = FloodKind::Kick as usize;
        track(&mut t, "a", k, false, 5, 60, 100);
        track(&mut t, "b", k, false, 5, 60, 200);
        track(&mut t, "c", k, false, 5, 60, 300);
        track(&mut t, "a", k, false, 5, 60, 400); // a is fresh again, b is idle longest
        track(&mut t, "d", k, false, 5, 60, 500);
        let hosts: Vec<&str> = t.iter().map(|f| f.host.as_str()).collect();
        assert_eq!(hosts, ["a", "d", "c"]);
        // d starts a fresh window
        assert_eq!(t[1].w[k].count, 1);
    }

    #[test]
    fn authorised_victim_is_remembered_until_the_trip() {
        let mut t = vec![FloodSrc::default(); 2];
        let k = FloodKind::Deop as usize;
        assert_eq!(track(&mut t, "h", k, false, 2, 10, 0), None);
        assert_eq!(track(&mut t, "h", k, true, 2, 10, 1), None);
        assert_eq!(track(&mut t, "h", k, false, 2, 10, 2), Some(true));
        // consumed: the next burst starts clean
        for i in 0..2 {
            assert_eq!(track(&mut t, "h", k, false, 2, 10, 10 + i), None);
        }
        assert_eq!(track(&mut t, "h", k, false, 2, 10, 13), Some(false));
    }
}
