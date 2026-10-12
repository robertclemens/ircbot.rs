//! Output send queue and pacing (sendq.c, modes.md section 10).
//!
//! Every line the bot sends to the IRC server goes through here
//! (`irc_printf` -> `send_line` -> [`enqueue`]).  A token bucket lets
//! `burst` lines out back to back and then one per `interval_ms` (both live in
//! `state.sendq`, from the D| setting `sendq` B:I, default SENDQ_DEF_BURST :
//! SENDQ_DEF_INTERVAL_MS) -- a bot answering a flood with a pile of KICK /
//! MODE lines is otherwise disconnected for "Excess Flood".  Interval 0 means
//! unpaced: every queued line is sent at once, with no credit gating; the
//! lanes, the protection dedupe and the MODE packing below still apply.
//!
//! Three lanes, always drained in this order:
//!   0 protocol    PONG, PING, registration (NICK USER PASS CAP), QUIT
//!   1 protection  MODE changes and KICK
//!   2 other       everything else (PRIVMSG, JOIN, WHO, ...)
//! Consecutive single-change MODE lines for one channel in lane 1 are packed
//! into one line, up to the server's 005 MODES= changes (default 3); KICKs go
//! one per line.  The queue holds at most MAX_SENDQ lines; when it is full
//! the oldest line of lane 2 is dropped (and, with lane 2 empty, the oldest
//! of lane 1 for a protocol or protection line, otherwise the new line
//! itself).  A protection line identical to one already queued is not queued
//! twice.
//!
//! No timer or thread of its own: [`drain`] runs from `enqueue` (credit is
//! usually there), from the main loop after every poll round, and the poll
//! timeout is shortened to the moment the next line may go ([`next_ms`]).

use std::sync::OnceLock;
use std::time::Instant;

use crate::consts::*;
use crate::state::{BotState, S_CONNECTED, SendQ};
use crate::{irc_client, logm};

/// Monotonic milliseconds since the first call.
pub fn mono_ms() -> i64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Drop everything and refill the burst.  Called when the link goes away, so
/// a new connection starts with a full bucket and an empty queue.
pub fn clear(state: &mut BotState) {
    let q = &mut state.sendq;
    for lane in &mut q.q {
        lane.clear();
    }
    q.total = 0;
    q.credit_ms = q.burst * q.interval_ms;
    q.last_ms = mono_ms();
}

/// New live limits (D| sendq changed).  Out-of-range values are clamped; the
/// stored credit is cut to the new cap, never raised.
pub fn set_limits(state: &mut BotState, burst: i64, interval_ms: i64) {
    let q = &mut state.sendq;
    q.burst = burst.clamp(SENDQ_MIN_BURST, SENDQ_MAX_BURST);
    q.interval_ms = interval_ms.clamp(SENDQ_MIN_INTERVAL_MS, SENDQ_MAX_INTERVAL_MS);
    let cap = q.burst * q.interval_ms;
    if q.credit_ms > cap {
        q.credit_ms = cap;
    }
}

fn refill(q: &mut SendQ) {
    let now = mono_ms();
    let cap = q.burst * q.interval_ms;
    if now > q.last_ms {
        q.credit_ms += now - q.last_ms;
    }
    q.last_ms = now;
    if q.credit_ms > cap {
        q.credit_ms = cap;
    }
}

/// sendq_next_ms(): -1 when nothing is queued, 0 when a line may go now,
/// else the milliseconds until credit allows the next one.  The main loop
/// uses it to shorten the poll timeout.
pub fn next_ms(state: &mut BotState) -> i64 {
    let q = &mut state.sendq;
    if q.total == 0 {
        return -1;
    }
    refill(q);
    if q.credit_ms >= q.interval_ms {
        return 0;
    }
    q.interval_ms - q.credit_ms
}

/// Is the line a MODE query (list or mode fetch) rather than a change?
fn mode_is_query(line: &[u8]) -> bool {
    let p = line.get(5..).unwrap_or(&[]); // after "MODE "
    let Some(sp) = p.iter().position(|&c| c == b' ') else {
        return true; // "MODE #chan"
    };
    let p = &p[sp + 1..];
    // "MODE #chan +b" with no argument lists the bans
    let sp2 = p.iter().position(|&c| c == b' ');
    let mlen = sp2.unwrap_or_else(|| p.iter().take_while(|&&c| c != b'\r' && c != b'\n').count());
    let no_arg = match sp2 {
        None => true,
        Some(i) => matches!(p.get(i + 1), None | Some(b'\r') | Some(b'\n')),
    };
    if no_arg {
        if mlen == 2 && matches!(p[1], b'b' | b'e' | b'I') {
            return true;
        }
        if mlen == 1 && matches!(p[0], b'b' | b'e' | b'I') {
            return true;
        }
    }
    false
}

/// SENDQ_LANE_* for a finished line.
pub fn lane_of(line: &[u8]) -> usize {
    let vl = line
        .iter()
        .take_while(|&&c| c != b' ' && c != b'\r' && c != b'\n')
        .count();
    let verb = &line[..vl];
    let is = |w: &str| verb.eq_ignore_ascii_case(w.as_bytes());
    if is("PONG") || is("PING") || is("NICK") || is("USER") || is("PASS") || is("QUIT") || is("CAP")
    {
        return SENDQ_LANE_PROTO;
    }
    if is("KICK") {
        return SENDQ_LANE_PROT;
    }
    if is("MODE") && line.get(4) == Some(&b' ') && !mode_is_query(line) {
        return SENDQ_LANE_PROT;
    }
    SENDQ_LANE_REST
}

fn lane_pop(q: &mut SendQ, lane: usize) -> Option<Vec<u8>> {
    let s = q.q[lane].pop_front()?;
    q.total -= 1;
    Some(s)
}

/// Make room for one more line of `lane`.  False: the new line is the one to
/// drop.
fn make_room(state: &mut BotState, lane: usize) -> bool {
    let q = &mut state.sendq;
    if q.total < MAX_SENDQ {
        return true;
    }
    let victim = if !q.q[SENDQ_LANE_REST].is_empty() {
        SENDQ_LANE_REST
    } else if lane != SENDQ_LANE_REST && !q.q[SENDQ_LANE_PROT].is_empty() {
        SENDQ_LANE_PROT // the oldest protection line is the stale one
    } else {
        return false;
    };
    lane_pop(q, victim);
    q.dropped += 1;
    true
}

/// Queue one finished line (ends in CRLF).  Lane by verb: PONG / registration
/// -> proto, MODE changes / KICK -> protection, the rest -> other.  Drains at
/// once while credit lasts.  Returns len, or -1 when it had to be dropped.
pub fn enqueue(state: &mut BotState, line: &[u8]) -> i32 {
    let len = line.len();
    if len < 2 {
        return -1;
    }
    let lane = lane_of(line);

    // An IRC line is at most 512 bytes with CRLF; the server would cut it
    // there anyway.  Cutting here bounds what the queue can hold.
    let body = (len - 2).min(SENDQ_LINE_MAX);
    // The sweep asks for the same KICK / MODE again while the first is still
    // waiting for its turn: one copy in the queue is enough.
    if lane == SENDQ_LANE_PROT
        && state.sendq.q[lane]
            .iter()
            .any(|w| w.len() == body + 2 && w[..body] == line[..body])
    {
        return len as i32;
    }
    if !make_room(state, lane) {
        state.sendq.dropped += 1;
        let vl = line
            .iter()
            .take_while(|&&c| c != b' ' && c != b'\r' && c != b'\n')
            .count()
            .min(16);
        let verb = String::from_utf8_lossy(&line[..vl]).into_owned();
        logm!(
            state,
            L_INFO,
            "[SENDQ] Queue full; dropped a {} line\n",
            verb
        );
        return -1;
    }
    let mut copy = Vec::with_capacity(body + 2);
    copy.extend_from_slice(&line[..body]);
    copy.extend_from_slice(b"\r\n");
    state.sendq.q[lane].push_back(copy);
    state.sendq.total += 1;
    drain(state);
    len as i32
}

// ---- MODE packing -------------------------------------------------------------

struct ModeItem {
    chan: String,
    sign: u8,
    letter: u8,
    arg: String,
    has_arg: bool,
}

/// "MODE <chan> <+|-><letter> [arg]\r\n" for a letter we know the argument
/// rule of.  Anything else is sent as it stands.
fn mode_item_parse(line: &[u8]) -> Option<ModeItem> {
    if line.len() < 5 || !line[..5].eq_ignore_ascii_case(b"MODE ") {
        return None;
    }
    let p = &line[5..];
    let cl = p
        .iter()
        .take_while(|&&c| c != b' ' && c != b'\r' && c != b'\n')
        .count();
    if cl == 0 || cl >= MAX_CHAN || p.get(cl) != Some(&b' ') {
        return None;
    }
    let chan = std::str::from_utf8(&p[..cl]).ok()?.to_string();
    let p = &p[cl + 1..];
    let at = |i: usize| p.get(i).copied().unwrap_or(0);
    if (at(0) != b'+' && at(0) != b'-')
        || matches!(at(1), 0 | b'\r' | b'\n')
        || (at(2) != b' ' && at(2) != b'\r')
    {
        return None; // exactly one signed letter
    }
    let (sign, letter) = (at(0), at(1));
    let mut a = &p[2..];
    if a.first() == Some(&b' ') {
        a = &a[1..];
    }
    let al = a
        .iter()
        .take_while(|&&c| c != b' ' && c != b'\r' && c != b'\n')
        .count();
    if a.get(al) == Some(&b' ') {
        return None; // more than one argument
    }
    let needs = match letter {
        b'o' | b'v' | b'h' | b'b' | b'e' | b'I' | b'k' => true,
        b'l' => sign == b'+',
        b'i' | b'm' | b'n' | b'p' | b's' | b't' => false,
        _ => return None,
    };
    if needs != (al > 0) || al >= 300 {
        return None;
    }
    let arg = std::str::from_utf8(&a[..al]).ok()?.to_string();
    Some(ModeItem {
        chan,
        sign,
        letter,
        arg,
        has_arg: needs,
    })
}

/// Build the line to send from lane 1's head, packing following
/// single-change MODEs for the same channel.  Pops what it uses.  The result
/// ends in CRLF.
fn take_protection(state: &mut BotState) -> Option<Vec<u8>> {
    let lane = SENDQ_LANE_PROT;
    let limit = if state.isup.modes < 1 {
        ISUPPORT_MODES_DEFAULT
    } else {
        state.isup.modes.min(ISUPPORT_MODES_MAX)
    } as usize;
    let q = &mut state.sendq;
    let Some(first) = q.q[lane].front().and_then(|h| mode_item_parse(h)) else {
        return lane_pop(q, lane);
    };
    let mut est = 5 + first.chan.len() + 3 + first.arg.len() + 1;
    let mut items = vec![first];
    while items.len() < limit && items.len() < q.q[lane].len() {
        let Some(it) = mode_item_parse(&q.q[lane][items.len()]) else {
            break;
        };
        if !it.chan.eq_ignore_ascii_case(&items[0].chan) {
            break;
        }
        let add = 2 + it.arg.len() + 1;
        if est + add > 400 {
            break;
        }
        est += add;
        items.push(it);
    }
    let mut out = format!("MODE {} ", items[0].chan).into_bytes();
    let mut cur = 0u8;
    for it in &items {
        if it.sign != cur {
            out.push(it.sign);
            cur = it.sign;
        }
        out.push(it.letter);
    }
    for it in items.iter().filter(|it| it.has_arg) {
        out.push(b' ');
        out.extend_from_slice(it.arg.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    for _ in &items {
        lane_pop(q, lane);
    }
    Some(out)
}

/// Write what credit allows; returns lines written now.
pub fn drain(state: &mut BotState) -> i32 {
    if state.sendq.total == 0 {
        return 0;
    }
    refill(&mut state.sendq);
    let mut sent = 0;
    while state.sendq.total > 0 && state.sendq.credit_ms >= state.sendq.interval_ms {
        if state.status & S_CONNECTED == 0 {
            clear(state);
            return sent;
        }
        let line = if !state.sendq.q[SENDQ_LANE_PROTO].is_empty() {
            lane_pop(&mut state.sendq, SENDQ_LANE_PROTO)
        } else if !state.sendq.q[SENDQ_LANE_PROT].is_empty() {
            take_protection(state)
        } else {
            lane_pop(&mut state.sendq, SENDQ_LANE_REST)
        };
        let Some(line) = line else { break };
        state.sendq.credit_ms -= state.sendq.interval_ms;
        if irc_client::write_raw(state, &line) < 0 {
            return sent; // write_raw disconnected and cleared the queue
        }
        sent += 1;
    }
    sent
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lanes() {
        assert_eq!(lane_of(b"PONG :x\r\n"), SENDQ_LANE_PROTO);
        assert_eq!(lane_of(b"cap LS\r\n"), SENDQ_LANE_PROTO);
        assert_eq!(lane_of(b"KICK #c n :r\r\n"), SENDQ_LANE_PROT);
        assert_eq!(lane_of(b"MODE #c +o n\r\n"), SENDQ_LANE_PROT);
        assert_eq!(lane_of(b"MODE #c\r\n"), SENDQ_LANE_REST);
        assert_eq!(lane_of(b"MODE #c +b\r\n"), SENDQ_LANE_REST);
        assert_eq!(lane_of(b"MODE #c b\r\n"), SENDQ_LANE_REST);
        assert_eq!(lane_of(b"PRIVMSG #c :hi\r\n"), SENDQ_LANE_REST);
    }

    #[test]
    fn mode_items() {
        let it = mode_item_parse(b"MODE #c +o nick\r\n").unwrap();
        assert_eq!((it.sign, it.letter, it.arg.as_str()), (b'+', b'o', "nick"));
        assert!(mode_item_parse(b"MODE #c +ov a b\r\n").is_none());
        assert!(mode_item_parse(b"MODE #c +o\r\n").is_none());
        assert!(mode_item_parse(b"MODE #c -l\r\n").is_some());
        assert!(mode_item_parse(b"MODE #c +l\r\n").is_none());
        assert!(mode_item_parse(b"MODE #c +t\r\n").is_some());
    }

    fn kick(n: usize) -> Vec<u8> {
        format!("KICK #c nick{n} :r\r\n").into_bytes()
    }

    #[test]
    fn identical_protection_line_is_refused() {
        let mut st = BotState::for_test();
        enqueue(&mut st, &kick(1));
        enqueue(&mut st, &kick(1));
        assert_eq!(st.sendq.total, 1);
        enqueue(&mut st, &kick(2));
        assert_eq!(st.sendq.total, 2);
        // a prefix of a queued line is not the same line
        enqueue(&mut st, b"KICK #c nick1 :\r\n");
        assert_eq!(st.sendq.total, 3);
        // only the protection lane dedupes
        enqueue(&mut st, b"PRIVMSG #c :hi\r\n");
        enqueue(&mut st, b"PRIVMSG #c :hi\r\n");
        assert_eq!(st.sendq.total, 5);
    }

    #[test]
    fn full_queue_drops_protection_only_when_lane_2_is_empty() {
        let mut st = BotState::for_test();
        for i in 0..MAX_SENDQ - 1 {
            enqueue(&mut st, &kick(i));
        }
        enqueue(&mut st, b"PRIVMSG #c :other\r\n");
        assert_eq!(st.sendq.total, MAX_SENDQ);
        // lane 2 has a line: it goes first
        enqueue(&mut st, &kick(1000));
        assert_eq!(st.sendq.q[SENDQ_LANE_REST].len(), 0);
        assert_eq!(st.sendq.q[SENDQ_LANE_PROT].len(), MAX_SENDQ);
        // lane 2 empty: the oldest protection line goes, for a protection line
        enqueue(&mut st, &kick(1001));
        assert_eq!(st.sendq.total, MAX_SENDQ);
        assert_eq!(st.sendq.q[SENDQ_LANE_PROT].front().unwrap(), &kick(1));
        assert_eq!(st.sendq.q[SENDQ_LANE_PROT].back().unwrap(), &kick(1001));
        // ... and for a protocol line
        enqueue(&mut st, b"PONG :x\r\n");
        assert_eq!(st.sendq.q[SENDQ_LANE_PROTO].len(), 1);
        assert_eq!(st.sendq.total, MAX_SENDQ);
        // a line for lane 2 is the one dropped when lane 2 is empty
        assert_eq!(enqueue(&mut st, b"PRIVMSG #c :late\r\n"), -1);
        assert_eq!(st.sendq.q[SENDQ_LANE_REST].len(), 0);
    }

    fn queue_privmsgs(st: &mut BotState, n: usize) {
        for i in 0..n {
            st.sendq.q[SENDQ_LANE_REST].push_back(format!("PRIVMSG #c :{i}\r\n").into_bytes());
            st.sendq.total += 1;
        }
    }

    #[test]
    fn set_limits_clamps_and_cuts_credit() {
        let mut st = BotState::for_test();
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (10, 100));
        st.sendq.credit_ms = 1000;
        set_limits(&mut st, 0, -5);
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (1, 0));
        assert_eq!(st.sendq.credit_ms, 0);
        set_limits(&mut st, 500, 99999);
        assert_eq!((st.sendq.burst, st.sendq.interval_ms), (100, 10000));
        assert_eq!(st.sendq.credit_ms, 0); // never raised
        st.sendq.credit_ms = 5_000_000;
        set_limits(&mut st, 2, 300);
        assert_eq!(st.sendq.credit_ms, 600);
    }

    #[test]
    fn clear_refills_to_cap() {
        let mut st = BotState::for_test();
        set_limits(&mut st, 4, 250);
        clear(&mut st);
        assert_eq!(st.sendq.credit_ms, 1000);
    }

    #[test]
    fn next_ms_values() {
        let mut st = BotState::for_test();
        assert_eq!(next_ms(&mut st), -1);
        queue_privmsgs(&mut st, 2);
        set_limits(&mut st, 10, 100);
        st.sendq.credit_ms = 100;
        st.sendq.last_ms = i64::MAX;
        assert_eq!(next_ms(&mut st), 0);
        st.sendq.credit_ms = 30;
        assert_eq!(next_ms(&mut st), 70);
        set_limits(&mut st, 10, 0);
        st.sendq.credit_ms = 0;
        assert_eq!(next_ms(&mut st), 0);
    }

    #[test]
    fn interval_zero_is_ungated() {
        // No socket here: the first write fails and stops the drain, so one
        // line leaving at zero credit is the signal that nothing gates it.
        let mut st = BotState::for_test();
        queue_privmsgs(&mut st, 3);
        drain(&mut st);
        assert_eq!(st.sendq.total, 3); // interval 100, no credit: held
        set_limits(&mut st, 10, 0);
        drain(&mut st);
        assert_eq!(st.sendq.total, 2); // interval 0: popped without credit
    }
}
