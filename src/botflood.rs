//! Bot floods, the ignore table and quiet mode (botflood.c, irchub
//! docs/modes.md section 9.1).
//!
//!   cmd   per user record: sealed ~A2/~A2S commands about to run, PRIVMSG and
//!         DCC together.  Over N in the window: drop, with one "slow down"
//!         notice per window.  Over 3N: the user is ignored for ignoretime.
//!   msg   per host: PRIVMSG / NOTICE to the bot that are not commands --
//!         failed or malformed ~A2..., ~A2A, plain text.  Over N: host ignored.
//!   ctcp  per host: CTCP to the bot.  Over N: host ignored (no replies).
//!
//! Limits come from the D| record (`bflood cmd|msg|ctcp`, `ignoretime`) or the
//! built-ins 10:30, 5:60, 3:60 and 10 minutes (`chancfg::get_flood` / `get`).
//! Authorised sources (trusted bots, hosts matching an active usermask) are
//! never counted or ignored by host.  The ignore table holds MAX_IGNORES
//! entries and is never persisted or shared (D34).  When it is full and its
//! oldest entry is under a minute old -- many hosts at once, a botnet -- the
//! bot goes quiet for ignoretime: it answers no unauthorised source at all,
//! logged once per episode.  Windows are judged on arrival, no timers.
//!
//! The tables are plain data in [`BotFlood`] (`BotState.flood`); everything
//! that needs no clock or setting from the state is a method of it, so the
//! counters can be tested on their own.

use crate::chancfg;
use crate::chanflood::{now_ms, src_host, window_hit};
use crate::consts::*;
use crate::state::{
    BotFlood, BotState, ChanStatus, CmdFlood, CsetId, FloodKind, FloodWindow, HostFlood,
};
use crate::{auth, hub_client, ircf, logm};

/// BF_OK / BF_DROP / BF_IGNORE / BF_IGNORE_NEW.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bf {
    /// Carry on.
    Ok,
    /// Drop this one (a command over its limit).
    Drop,
    /// Source ignored: drop silently.
    Ignore,
    /// cmd: ignored from now on (also an ignore).
    IgnoreNew,
}

/// What one command counted as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CmdStep {
    Ok,
    /// Over N; `notice` = the "slow down" notice is due (once per window).
    Drop {
        notice: bool,
    },
    /// Over 3N: the user is to be ignored (the window was reset).
    Flood3x,
}

impl BotFlood {
    /// Quiet mode over?  Clears an expired episode.
    pub fn quiet_at(&mut self, now_ms: i64) -> bool {
        if self.quiet_until_ms != 0 && now_ms >= self.quiet_until_ms {
            self.quiet_until_ms = 0;
            self.quiet_logged = false;
        }
        self.quiet_until_ms != 0
    }

    /// Is `key` in the table and unexpired?
    pub fn ignore_find(&self, key: &str, now_ms: i64) -> bool {
        self.ignores
            .iter()
            .any(|e| !e.key.is_empty() && e.until_ms > now_ms && e.key == key)
    }

    /// Put `key` in the table for `ignore_ms`.  Err when it did not fit and
    /// quiet mode began; the bool says whether this is the episode's first
    /// (the one log line is due).
    pub fn ignore_add(&mut self, key: &str, now_ms: i64, ignore_ms: i64) -> Result<(), bool> {
        let (mut slot, mut oldest): (Option<usize>, Option<usize>) = (None, None);
        for i in 0..self.ignores.len() {
            if !self.ignores[i].key.is_empty() && self.ignores[i].until_ms <= now_ms {
                self.ignores[i].key.clear(); // expired
            }
            if !self.ignores[i].key.is_empty() && self.ignores[i].key == key {
                slot = Some(i); // already there: extend
                break;
            }
            if self.ignores[i].key.is_empty() {
                slot.get_or_insert(i);
            } else if oldest.is_none_or(|o| self.ignores[i].since_ms < self.ignores[o].since_ms) {
                oldest = Some(i);
            }
        }
        let i = match slot {
            Some(i) => i,
            None => {
                let Some(o) = oldest else { return Err(false) };
                if now_ms - self.ignores[o].since_ms <= QUIET_FILL_MS {
                    self.quiet_until_ms = now_ms + ignore_ms;
                    let first = !self.quiet_logged;
                    self.quiet_logged = true;
                    return Err(first);
                }
                o // full, but the oldest has had its time: replace it
            }
        };
        let e = &mut self.ignores[i];
        if e.key != key {
            e.key = key.to_string();
            e.since_ms = now_ms;
        }
        e.until_ms = now_ms + ignore_ms;
        Ok(())
    }

    /// The tracker slot of `host` (made if new: a free slot, else the host
    /// idle longest).
    fn host_slot(&mut self, host: &str, now_ms: i64) -> usize {
        let (mut free, mut oldest): (Option<usize>, Option<usize>) = (None, None);
        for i in 0..self.host_flood.len() {
            if self.host_flood[i].host.is_empty() {
                free.get_or_insert(i);
            } else if self.host_flood[i].host == host {
                self.host_flood[i].last_ms = now_ms;
                return i;
            } else if oldest.is_none_or(|o| self.host_flood[i].last_ms < self.host_flood[o].last_ms)
            {
                oldest = Some(i);
            }
        }
        let i = free.or(oldest).unwrap_or(0);
        self.host_flood[i] = HostFlood {
            host: host.to_string(),
            last_ms: now_ms,
            ..HostFlood::default()
        };
        i
    }

    /// Count one msg (or ctcp) event from `host`: true when it tripped.
    pub fn host_hit(&mut self, host: &str, ctcp: bool, n: i32, s: i32, now_ms: i64) -> bool {
        let i = self.host_slot(host, now_ms);
        let h = &mut self.host_flood[i];
        let w: &mut FloodWindow = if ctcp { &mut h.ctcp } else { &mut h.msg };
        window_hit(w, n, s, now_ms)
    }

    /// Count one command of the user record `uuid` against its n:s limit.
    pub fn cmd_count(&mut self, uuid: &str, n: i32, s: i32, now_ms: i64) -> CmdStep {
        let (mut slot, mut free, mut oldest): (Option<usize>, Option<usize>, Option<usize>) =
            (None, None, None);
        for (i, f) in self.cmd_flood.iter().enumerate() {
            if f.uuid.is_empty() {
                free.get_or_insert(i);
            } else if f.uuid == uuid {
                slot = Some(i);
                break;
            } else if oldest.is_none_or(|o| f.last_ms < self.cmd_flood[o].last_ms) {
                oldest = Some(i);
            }
        }
        let i = match slot.or(free).or(oldest) {
            Some(i) => i,
            None => return CmdStep::Ok,
        };
        if slot.is_none() {
            self.cmd_flood[i] = CmdFlood {
                uuid: uuid.to_string(),
                ..CmdFlood::default()
            };
        }
        let f = &mut self.cmd_flood[i];
        f.last_ms = now_ms;
        if f.w.count <= 0 || now_ms - f.w.start_ms >= i64::from(s) * 1000 {
            f.w.start_ms = now_ms;
            f.w.count = 0;
            f.notified = false;
        }
        f.w.count += 1;
        if f.w.count > 3 * n {
            f.w.count = 0;
            f.notified = false;
            return CmdStep::Flood3x;
        }
        if f.w.count > n {
            let notice = !f.notified;
            f.notified = true;
            return CmdStep::Drop { notice };
        }
        CmdStep::Ok
    }
}

fn ignore_ms(state: &BotState) -> i64 {
    chancfg::get(state, None, CsetId::IgnoreTime) * 60000
}

/// A first managed channel we are in, to hang a console event on.
fn emit_ignore(state: &mut BotState, target: &str, detail: &str) {
    let name = state
        .chans
        .iter()
        .find(|c| c.is_managed && c.status == ChanStatus::In)
        .map(|c| c.name.clone());
    if let Some(name) = name {
        hub_client::chan_event(state, &name, "ignore", target, detail);
    }
}

/// Add `key` to the ignore table; the one-per-episode log line when the
/// table was full.  False when it did not fit (quiet mode began).
fn ignore_add(state: &mut BotState, key: &str, now: i64) -> bool {
    let ms = ignore_ms(state);
    match state.flood.ignore_add(key, now, ms) {
        Ok(()) => true,
        Err(first) => {
            if first {
                logm!(
                    state,
                    L_INFO,
                    "[FLOOD] Ignore table full within a minute: quiet mode for {} min, no replies to unauthorised sources\n",
                    chancfg::get(state, None, CsetId::IgnoreTime)
                );
            }
            false
        }
    }
}

/// Quiet mode: unauthorised sources get no reply at all.
#[allow(dead_code)] // declared in C as well, with no caller there either
pub fn quiet(state: &mut BotState) -> bool {
    state.flood.quiet_at(now_ms())
}

/// Shared body of msg / ctcp.
fn host_flood_at(
    state: &mut BotState,
    nuh: &str,
    authorised: bool,
    kind: FloodKind,
    now: i64,
) -> Bf {
    let host = match src_host(nuh) {
        Some(h) if !authorised => h,
        _ => return Bf::Ok,
    };
    if state.flood.quiet_at(now) || state.flood.ignore_find(&host, now) {
        return Bf::Ignore;
    }
    let Some((n, s)) = chancfg::get_flood(state, None, kind) else {
        return Bf::Ok; // off
    };
    let ctcp = kind == FloodKind::BotCtcp;
    if !state.flood.host_hit(&host, ctcp, n, s, now) {
        return Bf::Ok;
    }
    let what = if ctcp { "ctcp" } else { "msg" };
    let mins = chancfg::get(state, None, CsetId::IgnoreTime);
    logm!(
        state,
        L_INFO,
        "[FLOOD] {} flood ({}:{}) from {}: ignoring it for {} min\n",
        what,
        n,
        s,
        host,
        mins
    );
    if ignore_add(state, &host, now) {
        emit_ignore(
            state,
            &host,
            &format!("{what} flood {n}:{s}, ignored {mins} min"),
        );
    }
    Bf::Ignore
}

/// Testable core of [`msg`] (now injected).
pub fn msg_at(state: &mut BotState, nuh: &str, authorised: bool, now: i64) -> Bf {
    host_flood_at(state, nuh, authorised, FloodKind::BotMsg, now)
}

/// Testable core of [`ctcp`].
pub fn ctcp_at(state: &mut BotState, nuh: &str, authorised: bool, now: i64) -> Bf {
    host_flood_at(state, nuh, authorised, FloodKind::BotCtcp, now)
}

/// Per-host flood for non-command PRIVMSG / NOTICE to the bot.  Authorised
/// sources are never counted.  `Bf::Ignore` = answer nothing.
pub fn msg(state: &mut BotState, nuh: &str) -> Bf {
    let a = auth::is_authorised(state, nuh);
    msg_at(state, nuh, a, now_ms())
}

/// Per-host flood for CTCP to the bot.
pub fn ctcp(state: &mut BotState, nuh: &str) -> Bf {
    let a = auth::is_authorised(state, nuh);
    ctcp_at(state, nuh, a, now_ms())
}

/// Is this source host ignored right now (no count)?
pub fn host_ignored(state: &mut BotState, nuh: &str) -> bool {
    let Some(host) = src_host(nuh) else {
        return false;
    };
    if auth::is_authorised(state, nuh) {
        return false;
    }
    let now = now_ms();
    state.flood.quiet_at(now) || state.flood.ignore_find(&host, now)
}

/// Testable core of [`cmd`]: the verdict and whether the "slow down" notice
/// is due.
pub fn cmd_at(state: &mut BotState, uuid: &str, name: &str, now: i64) -> (Bf, bool) {
    if uuid.is_empty() {
        return (Bf::Ok, false);
    }
    let key = format!("u:{uuid}");
    if state.flood.ignore_find(&key, now) {
        return (Bf::Ignore, false);
    }
    let Some((n, s)) = chancfg::get_flood(state, None, FloodKind::BotCmd) else {
        return (Bf::Ok, false);
    };
    match state.flood.cmd_count(uuid, n, s, now) {
        CmdStep::Ok => (Bf::Ok, false),
        CmdStep::Drop { notice } => (Bf::Drop, notice),
        CmdStep::Flood3x => {
            logm!(
                state,
                L_INFO,
                "[FLOOD] WARNING: user {} is sending commands at over 3x the limit ({}:{}): ignored for {} min\n",
                name,
                n,
                s,
                chancfg::get(state, None, CsetId::IgnoreTime)
            );
            ignore_add(state, &key, now);
            (Bf::IgnoreNew, false)
        }
    }
}

/// `flood cmd` for user record `who`, called for every sealed command about
/// to run.  `Bf::Drop` also sends the one "slow down" notice per window to
/// `nick`.
pub fn cmd(state: &mut BotState, who: usize, nick: &str) -> Bf {
    let Some(u) = state.user_records.get(who) else {
        return Bf::Ok;
    };
    let (uuid, name) = (u.uuid.clone(), u.name.clone());
    let (r, notice) = cmd_at(state, &uuid, &name, now_ms());
    if r == Bf::Drop && notice {
        ircf!(
            state,
            "PRIVMSG {} :Slow down: too many commands, some were dropped.\r\n",
            nick
        );
    }
    if r == Bf::IgnoreNew {
        let mins = chancfg::get(state, None, CsetId::IgnoreTime);
        emit_ignore(state, &name, &format!("command flood, ignored {mins} min"));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60000;

    #[test]
    fn host_msg_trips_at_n_plus_one() {
        let mut f = BotFlood::default();
        // 5:60 -- five are fine, the sixth trips; the next window starts fresh
        for i in 0..5 {
            assert!(!f.host_hit("h.example", false, 5, 60, 1000 + i));
        }
        assert!(f.host_hit("h.example", false, 5, 60, 1005));
        assert!(!f.host_hit("h.example", false, 5, 60, 1006));
    }

    #[test]
    fn msg_and_ctcp_windows_are_separate() {
        let mut f = BotFlood::default();
        for i in 0..3 {
            assert!(!f.host_hit("h", false, 3, 60, i));
        }
        assert!(!f.host_hit("h", true, 3, 60, 10));
        assert!(f.host_hit("h", false, 3, 60, 11));
    }

    #[test]
    fn host_window_resets() {
        let mut f = BotFlood::default();
        for i in 0..3 {
            assert!(!f.host_hit("h", true, 3, 60, i));
        }
        // s seconds after the window opened: counting starts again
        assert!(!f.host_hit("h", true, 3, 60, 60000));
        for i in 1..3 {
            assert!(!f.host_hit("h", true, 3, 60, 60000 + i));
        }
        assert!(f.host_hit("h", true, 3, 60, 60003));
    }

    #[test]
    fn host_tracker_replaces_the_longest_idle_host() {
        let mut f = BotFlood::default();
        for i in 0..MAX_HOST_TRACK {
            f.host_hit(&format!("h{i}"), false, 5, 60, 100 + i as i64);
        }
        // h0 is touched again, so h1 is the idle one
        f.host_hit("h0", false, 5, 60, 1000);
        f.host_hit("new", false, 5, 60, 1001);
        assert!(f.host_flood.iter().any(|h| h.host == "h0"));
        assert!(f.host_flood.iter().any(|h| h.host == "new"));
        assert!(!f.host_flood.iter().any(|h| h.host == "h1"));
        // a replaced host comes back with a fresh window
        let i = f.host_flood.iter().position(|h| h.host == "new").unwrap();
        assert_eq!(f.host_flood[i].msg.count, 1);
    }

    #[test]
    fn cmd_drop_notice_and_3x_ignore() {
        let mut f = BotFlood::default();
        // 2:30 -- two pass, 3..6 are dropped (one notice), the 7th is 3x+1
        assert_eq!(f.cmd_count("u1", 2, 30, 0), CmdStep::Ok);
        assert_eq!(f.cmd_count("u1", 2, 30, 1), CmdStep::Ok);
        assert_eq!(f.cmd_count("u1", 2, 30, 2), CmdStep::Drop { notice: true });
        for t in 3..6 {
            assert_eq!(f.cmd_count("u1", 2, 30, t), CmdStep::Drop { notice: false });
        }
        assert_eq!(f.cmd_count("u1", 2, 30, 6), CmdStep::Flood3x);
        // the window was reset by the trip
        assert_eq!(f.cmd_count("u1", 2, 30, 7), CmdStep::Ok);
    }

    #[test]
    fn cmd_window_reset_rearms_the_notice() {
        let mut f = BotFlood::default();
        assert_eq!(f.cmd_count("u", 1, 10, 0), CmdStep::Ok);
        assert_eq!(f.cmd_count("u", 1, 10, 1), CmdStep::Drop { notice: true });
        assert_eq!(f.cmd_count("u", 1, 10, 10000), CmdStep::Ok);
        assert_eq!(
            f.cmd_count("u", 1, 10, 10001),
            CmdStep::Drop { notice: true }
        );
    }

    #[test]
    fn cmd_tracker_replaces_the_longest_idle_user() {
        let mut f = BotFlood::default();
        for i in 0..MAX_USER_RECORDS {
            f.cmd_count(&format!("u{i}"), 5, 30, 10 + i as i64);
        }
        f.cmd_count("u0", 5, 30, 500);
        f.cmd_count("fresh", 5, 30, 501);
        assert!(f.cmd_flood.iter().any(|c| c.uuid == "u0"));
        assert!(f.cmd_flood.iter().any(|c| c.uuid == "fresh"));
        assert!(!f.cmd_flood.iter().any(|c| c.uuid == "u1"));
    }

    #[test]
    fn ignore_expires_and_extends() {
        let mut f = BotFlood::default();
        assert_eq!(f.ignore_add("h", 1000, 10 * MIN), Ok(()));
        assert!(f.ignore_find("h", 1000 + 10 * MIN - 1));
        assert!(!f.ignore_find("h", 1000 + 10 * MIN));
        assert!(!f.ignore_find("other", 1000));
        // adding again extends the same entry, keeping its first-seen time
        assert_eq!(f.ignore_add("h", 5000, 10 * MIN), Ok(()));
        assert!(f.ignore_find("h", 1000 + 10 * MIN));
        assert_eq!(f.ignores.iter().filter(|e| e.key == "h").count(), 1);
        assert_eq!(
            f.ignores.iter().find(|e| e.key == "h").unwrap().since_ms,
            1000
        );
    }

    #[test]
    fn full_table_within_a_minute_goes_quiet_once() {
        let mut f = BotFlood::default();
        for i in 0..MAX_IGNORES {
            assert_eq!(
                f.ignore_add(&format!("h{i}"), 1000 + i as i64, 10 * MIN),
                Ok(())
            );
        }
        assert!(!f.quiet_at(5000));
        // the 65th host while the oldest entry is under a minute old
        assert_eq!(f.ignore_add("late", 5000, 10 * MIN), Err(true));
        assert!(f.quiet_at(5001));
        assert!(f.quiet_at(5000 + 10 * MIN - 1));
        // the episode logs once
        assert_eq!(f.ignore_add("later", 6000, 10 * MIN), Err(false));
        // quiet mode ends by the clock and re-arms the log line
        assert!(!f.quiet_at(6000 + 10 * MIN));
        assert!(!f.quiet_logged);
    }

    #[test]
    fn full_table_replaces_an_old_entry() {
        let mut f = BotFlood::default();
        for i in 0..MAX_IGNORES {
            assert_eq!(
                f.ignore_add(&format!("h{i}"), 1000 + i as i64, 60 * MIN),
                Ok(())
            );
        }
        // the oldest entry is over a minute old: replaced, no quiet mode
        let t = 1000 + QUIET_FILL_MS + 1;
        assert_eq!(f.ignore_add("late", t, 60 * MIN), Ok(()));
        assert!(!f.quiet_at(t));
        assert!(f.ignore_find("late", t));
        assert!(!f.ignore_find("h0", t));
        assert!(f.ignore_find("h1", t));
    }

    #[test]
    fn expired_entries_make_room() {
        let mut f = BotFlood::default();
        for i in 0..MAX_IGNORES {
            assert_eq!(f.ignore_add(&format!("h{i}"), 100, MIN), Ok(()));
        }
        // a minute later every entry has expired: no quiet mode
        assert_eq!(f.ignore_add("x", 100 + MIN + 1, MIN), Ok(()));
        assert!(!f.quiet_at(100 + MIN + 1));
    }
}
