//! In-channel elections and set-option enforcement (chanenf.c, irchub
//! docs/modes.md sections 4, 6, 7).
//!
//! Nobody tells the bots who acts.  Every opped trusted bot in a channel sees
//! the same member list, so each computes the same deal ([`deal_rank`]): the
//! five jobs (kick, ban, op, mode, limit) are dealt over those bots in
//! SHA-256(lower(chan) || uuid) order, job j to position j mod n, backups
//! following.  A bot that is the job's holder acts at once; a backup queues
//! the work and acts after backup-index x JOB_STEP_MS if it is still needed.
//! Whoever acts, the action is re-checked against the current roster / live
//! modes / ban list first, so a duplicate costs at most a MODE the server
//! ignores.
//!
//! Two kinds of trigger feed the jobs: events (a MODE with a source, a KICK,
//! a JOIN -- needed where *who did it* matters: protectops, revenge,
//! stopnethack, bitch on a receiver) and the state sweep ([`tick`], per
//! channel on the dirty flag and every ENF_SWEEP_SECS: enforcemodes, the ban
//! list, dynamic limit, cycle).  All MODE / KICK lines leave through
//! `ircf!`, i.e. the paced queue's protection lane.  Every action goes
//! through the `act_*` primitives: opped, target unauthorised (or, for a
//! re-op, authorised), event to the hub (D42).
//!
//! The roster is kept current here from JOIN / PART / QUIT / KICK / NICK, so
//! an opped bot (which no longer polls WHO) still sees who is there.

use std::cell::Cell;
use std::cmp::Ordering;

use sha2::{Digest, Sha256};

use crate::consts::*;
use crate::cstr::{Tok, eq_ic, now, trunc, trunc_string};
use crate::sendq::mono_ms;
use crate::state::FloodKind;
use crate::state::{BotState, Chan, ChanStatus, CsetId, JobAct, RosterEntry, S_CONNECTED};
use crate::{auth, chancfg, chanflood, chanlive, channel, hub_client, ircf, logm, updater};

// same kick / deop / reop again: pending until its MODE / KICK echo
// (recent_ack) or this long
const RECENT_ACT_MS: i64 = 30000;
const RECENT_BAN_MS: i64 = 30000;
const RECENT_MODE_MS: i64 = 10000; // mode revert / limit change

// ---- small helpers ----------------------------------------------------------------

fn valid_nick(state: &BotState, n: &str) -> bool {
    if n.is_empty() || n.len() > state.isup.nicklen() {
        return false;
    }
    n.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"[]\\`_^{|}-".contains(&c))
}

/// A token we may put on an IRC line: no space, no control byte.
fn safe_token(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c > 0x20 && c != 0x7f)
}

/// snprintf(dst, dsz, lower(src)).
fn lower_copy(src: &str, dsz: usize) -> String {
    trunc(src, dsz).to_ascii_lowercase()
}

/// Nick part of a "nick!user@host" (or bare nick).
fn nuh_nick(nuh: &str) -> Option<&str> {
    let n = nuh.find('!').map_or(nuh, |b| &nuh[..b]);
    (!n.is_empty() && n.len() < MAX_MEMBER_NICK).then_some(n)
}

fn is_me(state: &BotState, nick: &str) -> bool {
    eq_ic(nick, &state.current_nick)
}

fn rfind(c: &Chan, nick: &str) -> Option<usize> {
    c.roster.iter().position(|r| eq_ic(&r.nick, nick))
}

fn rremove(c: &mut Chan, nick: &str) {
    if let Some(i) = rfind(c, nick) {
        c.roster.remove(i);
    }
}

/// What "authorised" depends on: the trusted bots, the user and mask records
/// (none of which has one change hook) and cfg_gen.  The records are hashed
/// at most every 200 ms; a change bumps state.auth_gen, which retires every
/// roster entry's cached verdict at once.
fn fp_str(h: u64, s: &str) -> u64 {
    let h = s
        .bytes()
        .fold(h, |h, b| (h ^ u64::from(b)).wrapping_mul(1099511628211));
    (h ^ 0xff).wrapping_mul(1099511628211)
}

fn auth_epoch(state: &BotState) -> u32 {
    let ms = mono_ms();
    if state.auth_gen.get() != 0
        && state.auth_seen_cfg_gen.get() == state.cfg_gen
        && ms - state.auth_fp_ms.get() < 200
    {
        return state.auth_gen.get();
    }
    let mut h: u64 = 14695981039346656037;
    for tb in &state.trusted_bots {
        h = fp_str(h, &tb.mask);
        h = fp_str(h, &tb.uuid);
    }
    for m in &state.mask_records {
        h = fp_str(fp_str(h, &m.mask), &m.uuid).wrapping_add(u64::from(m.is_active));
    }
    for u in &state.user_records {
        h = fp_str(h, &u.uuid).wrapping_add(u64::from(u.is_active));
    }
    h = h
        .wrapping_mul(1099511628211)
        .wrapping_add(state.trusted_bots.len() as u64 * 3)
        .wrapping_add(state.mask_records.len() as u64 * 5)
        .wrapping_add(state.user_records.len() as u64);
    if state.auth_gen.get() == 0
        || h != state.auth_fp.get()
        || state.auth_seen_cfg_gen.get() != state.cfg_gen
    {
        state.auth_fp.set(h);
        state.auth_seen_cfg_gen.set(state.cfg_gen);
        let g = state.auth_gen.get().wrapping_add(1);
        state.auth_gen.set(if g == 0 { 1 } else { g });
    }
    state.auth_fp_ms.set(ms);
    state.auth_gen.get()
}

/// The verdict is cached in the entry (only its cache cells change), so every
/// wildcard match against the bots / masks is paid once per entry per
/// auth_gen instead of once per ban x entry.
fn entry_authorised(state: &BotState, e: &RosterEntry) -> bool {
    if is_me(state, &e.nick) {
        return true;
    }
    let gen_now = auth_epoch(state);
    if e.auth_gen.get() != gen_now {
        e.authorised.set(auth::is_authorised(state, &e.hostmask));
        e.auth_gen.set(gen_now);
    }
    e.authorised.get()
}

/// True for this bot itself or an authorised user/bot (nick!user@host), using
/// the roster's cached verdict when `nuh` is a member of channel `ci`.
pub fn chan_nuh_authorised(state: &BotState, ci: usize, nuh: &str) -> bool {
    let Some(nick) = nuh_nick(nuh) else {
        return false;
    };
    if is_me(state, nick) {
        return true;
    }
    if let Some(c) = state.chans.get(ci)
        && let Some(i) = rfind(c, nick)
        && eq_ic(&c.roster[i].hostmask, nuh)
    {
        return entry_authorised(state, &c.roster[i]);
    }
    auth::is_authorised(state, nuh)
}

/// Add or replace a roster entry (WHO reply, JOIN); false when full.
pub fn roster_set(
    c: &mut Chan,
    nick: &str,
    hostmask: &str,
    op: bool,
    halfop: bool,
    voice: bool,
) -> bool {
    if nick.len() >= MAX_MEMBER_NICK || hostmask.len() >= MAX_MASK_LEN {
        return false;
    }
    let i = match rfind(c, nick) {
        Some(i) => i,
        None => {
            if c.roster.len() >= MAX_ROSTER_SIZE {
                return false;
            }
            c.roster.push(RosterEntry::default());
            c.roster.len() - 1
        }
    };
    c.roster[i] = RosterEntry {
        nick: nick.to_string(),
        hostmask: hostmask.to_string(),
        is_op: op,
        is_halfop: halfop,
        is_voice: voice,
        // the cached verdict was for the old hostmask
        authorised: Cell::new(false),
        auth_gen: Cell::new(0),
    };
    true
}

fn live_has_ban(c: &Chan, mask: &str) -> bool {
    c.bans.iter().any(|b| eq_ic(&b.mask, mask))
}

fn cset(state: &BotState, ci: usize, id: CsetId) -> i64 {
    chancfg::get(state, state.chans.get(ci), id)
}

/// enforcemodes with a k in the stored modes: the key is the bots', so a key
/// someone else sets or clears is not learned (section 3.3).
pub fn key_managed(state: &BotState, ci: usize) -> bool {
    if cset(state, ci, CsetId::EnforceModes) == 0 {
        return false;
    }
    chancfg::get_modes(state, state.chans.get(ci))
        .split(' ')
        .next()
        .is_some_and(|m| m.contains('k'))
}

// ---- the deal (section 7.1) -------------------------------------------------------

struct Elig {
    h: u64,
    id: String,
}

fn bot_too_old(state: &BotState, id: &str) -> bool {
    state.bot_tree.iter().any(|r| {
        r.kind != 'h'
            && r.uuid == id
            // version unknown (empty) = keep it in the deal
            && !r.version.is_empty()
            && updater::version_cmp(&r.version, JOB_MIN_VERSION) == Ordering::Less
    })
}

/// First 8 bytes (big endian) of SHA-256(lc_chan || id).
fn deal_hash(lc_chan: &str, id: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(lc_chan.as_bytes());
    h.update(id.as_bytes());
    let md = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&md[..8]);
    u64::from_be_bytes(b)
}

fn elig_add(el: &mut Vec<Elig>, lc_chan: &str, id: &str) -> bool {
    if el.iter().any(|e| e.id == id) {
        return false;
    }
    // C hashes out of a MAX_CHAN + 64 byte buffer
    if lc_chan.len() + id.len() > MAX_CHAN + 64 {
        return false;
    }
    el.push(Elig {
        h: deal_hash(lc_chan, id),
        id: trunc_string(id, 64),
    });
    true
}

fn elig_cmp(a: &Elig, b: &Elig) -> Ordering {
    a.h.cmp(&b.h).then_with(|| a.id.cmp(&b.id))
}

/// The deal: this bot's backup index (0 = holds the job now) for job JOB_* in
/// channel `ci`, or -1 when it takes no part (not opped, not in the deal).
pub fn deal_rank(state: &BotState, ci: usize, job: usize) -> i32 {
    let Some(c) = state.chans.get(ci) else {
        return -1;
    };
    if !c.i_am_opped || job >= JOB_COUNT {
        return -1;
    }
    let mut el: Vec<Elig> = Vec::new();
    let lc = lower_copy(&c.name, MAX_CHAN);
    let me = trunc_string(
        if state.bot_uuid.is_empty() {
            &state.current_nick
        } else {
            &state.bot_uuid
        },
        64,
    );
    if !elig_add(&mut el, &lc, &me) {
        return -1;
    }
    for e in &c.roster {
        if el.len() > MAX_ROSTER_SIZE {
            break;
        }
        if !e.is_op || is_me(state, &e.nick) {
            continue;
        }
        let Some(ti) = auth::trusted_bot_by_host(state, &e.hostmask) else {
            continue;
        };
        let tb = &state.trusted_bots[ti];
        let id = if tb.uuid.is_empty() {
            &tb.mask
        } else {
            &tb.uuid
        };
        if bot_too_old(state, id) {
            continue;
        }
        elig_add(&mut el, &lc, id);
    }
    el.sort_by(elig_cmp);
    let Some(pos) = el.iter().rposition(|e| e.id == me) else {
        return -1;
    };
    let n = el.len();
    let primary = job % n;
    ((pos + n - primary) % n) as i32
}

// ---- ban masks (section 6.1) ------------------------------------------------------

fn all_in(s: &str, set: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| set.as_bytes().contains(&c))
}

/// The host widened one step; cloaks and short names stay as they are.
fn widen_host(host: &str) -> String {
    let hl = host.len();
    let b = host.as_bytes();
    if host.contains('/') {
        return host.to_string(); // cloak: never widened
    }
    if host.contains(':') {
        // IPv6: the /64 = the first four groups, when they are spelled out.
        if !all_in(host, "0123456789abcdefABCDEF:.") {
            return host.to_string();
        }
        let mut colons = 0;
        for i in 0..hl {
            if b[i] == b':' {
                colons += 1;
                if colons < 4 && i + 1 < hl && b[i + 1] == b':' {
                    return host.to_string(); // "::" inside the first four groups
                }
                if colons == 4 {
                    if i + 2 > MAX_MASK_LEN - 1 {
                        return host.to_string();
                    }
                    return format!("{}*", &host[..=i]);
                }
            }
        }
        return host.to_string();
    }
    if all_in(host, "0123456789.") {
        // IPv4 a.b.c.d -> a.b.c.*
        let (mut dots, mut last, mut seg) = (0, 0usize, 0usize);
        for (i, &ch) in b.iter().enumerate() {
            if ch == b'.' {
                if seg == 0 || seg > 3 {
                    return host.to_string();
                }
                dots += 1;
                last = i;
                seg = 0;
            } else {
                seg += 1;
            }
        }
        if dots != 3 || seg == 0 || seg > 3 || last + 2 > MAX_MASK_LEN - 1 {
            return host.to_string();
        }
        return format!("{}*", &host[..=last]);
    }
    // name: 3 or more labels -> *.<all but the first>
    let mut labels = 1;
    for i in 0..hl {
        if b[i] == b'.' {
            if i == 0 || i + 1 == hl || b[i + 1] == b'.' {
                return host.to_string(); // empty label: leave it
            }
            labels += 1;
        }
    }
    if labels < 3 {
        return host.to_string();
    }
    match host.find('.') {
        Some(d) => format!("*{}", &host[d..]),
        None => host.to_string(),
    }
}

/// Ban mask of `nuh` for ban type 0-9 (section 6.1); None when the pieces
/// are not safe literal text or the result is too long.
pub fn ban_mask(typ: i64, nuh: &str) -> Option<String> {
    if !(0..=9).contains(&typ) {
        return None;
    }
    let bang = nuh.find('!')?;
    let at = bang + nuh[bang..].find('@')?;
    if at < bang + 2 {
        return None;
    }
    let (nick, user, host) = (&nuh[..bang], &nuh[bang + 1..at], &nuh[at + 1..]);
    if nick.is_empty()
        || nick.len() >= MAX_MEMBER_NICK
        || user.is_empty()
        || user.len() >= 64
        || host.is_empty()
        || host.len() >= MAX_MASK_LEN
    {
        return None;
    }
    // components are literal text: no wildcard, separator or control byte
    for p in [nick, user, host] {
        if !safe_token(p, MAX_MASK_LEN) || p.contains(['*', '?', '!', '@', ',']) {
            return None;
        }
    }
    let widen = matches!(typ, 3 | 4 | 8 | 9);
    let whost;
    let h = if widen {
        whost = widen_host(host);
        whost.as_str()
    } else {
        host
    };
    let nk = if typ >= 5 { nick } else { "*" };
    let ubuf = match typ % 5 {
        0 => user.to_string(),
        1 | 3 => format!("*{}", user.strip_prefix('~').unwrap_or(user)),
        _ => "*".to_string(),
    };
    let out = format!("{nk}!{ubuf}@{h}");
    (out.len() <= BAN_MASK_MAX).then_some(out)
}

/// Section 6.2 step 1: Some("member <nick>") when `mask` would hit an
/// authorised member who is in the channel now.
fn allowed_members(state: &BotState, ci: usize, mask: &str) -> Option<String> {
    let c = state.chans.get(ci)?;
    c.roster
        .iter()
        .find(|e| entry_authorised(state, e) && auth::wildcard_match(mask, &e.hostmask))
        .map(|e| format!("member {}", e.nick))
}

/// Section 6.2 steps 1 + 2 for a ban that has not been set yet: Err(who) names
/// what the mask would hit ("bad mask", "member <nick>", "bot <mask>" or
/// "user <name>").  `ci` None = no channel, so only the overlap half runs
/// (a `*` ban).
pub fn ban_allowed_why(state: &BotState, ci: Option<usize>, mask: &str) -> Result<(), String> {
    if !safe_token(mask, BAN_MASK_MAX) {
        return Err("bad mask".into());
    }
    if let Some(ci) = ci
        && let Some(who) = allowed_members(state, ci, mask)
    {
        return Err(who);
    }
    match auth::mask_overlaps_authorised(state, mask) {
        Some(who) => Err(who),
        None => Ok(()),
    }
}

/// Section 6.2 steps 1 + 2 for a ban that has not been set yet.
pub fn ban_allowed(state: &BotState, ci: usize, mask: &str) -> bool {
    ban_allowed_why(state, Some(ci), mask).is_ok()
}

/// The configured ban type for `nuh`, then the narrowing retry 2 -> 0 -> 7 -> 5.
pub fn auto_ban_mask(state: &BotState, ci: usize, nuh: &str) -> Option<String> {
    let first = cset(state, ci, CsetId::BanType);
    let order = [first, 2, 0, 7, 5];
    for i in 0..order.len() {
        if order[..i].contains(&order[i]) {
            continue;
        }
        if let Some(m) = ban_mask(order[i], nuh)
            && ban_allowed(state, ci, &m)
        {
            return Some(m);
        }
    }
    None
}

// ---- per-ban runtime clocks -------------------------------------------------------

/// The table grows to MAX_BAN_TRACK, enough for every channel's bans and every
/// global ban in every channel, so no clock is evicted (and no banidle clock
/// restarted) in practice.
fn track_get(state: &mut BotState, chan: &str, mask: &str, t: i64) -> usize {
    let mut free_slot: Option<usize> = None;
    let mut oldest: Option<usize> = None;
    for (i, tr) in state.ban_track.iter().enumerate() {
        if tr.chan.is_empty() {
            free_slot.get_or_insert(i);
            continue;
        }
        if eq_ic(&tr.chan, chan) && eq_ic(&tr.mask, mask) {
            return i;
        }
        if oldest.is_none_or(|o| tr.last_match < state.ban_track[o].last_match) {
            oldest = Some(i);
        }
    }
    let fresh = crate::state::BanTrack {
        chan: trunc_string(chan, MAX_CHAN),
        mask: trunc_string(mask, BAN_MASK_MAX + 1),
        last_match: t, // the idle clock starts the first time we see it
        ..Default::default()
    };
    let i = match free_slot {
        Some(i) => i,
        None if state.ban_track.len() < MAX_BAN_TRACK => {
            state.ban_track.push(Default::default());
            state.ban_track.len() - 1
        }
        None => oldest.unwrap_or(0), // full
    };
    state.ban_track[i] = fresh;
    i
}

/// Repeat-offence memory keyed by channel + host: counts this one, forgets
/// after bantime; returns the count (1 = first offence).
pub fn offence(state: &mut BotState, chan: &str, nuh: &str) -> u32 {
    let host = nuh.find('@').map_or(nuh, |a| &nuh[a + 1..]);
    let lc = lower_copy(chan, MAX_CHAN);
    let lh = lower_copy(host, 120);
    let key = trunc_string(&format!("{lc}|{lh}"), MAX_CHAN + 128);
    let ci = channel::find(state, chan);
    let bt = chancfg::get(state, ci.and_then(|i| state.chans.get(i)), CsetId::BanTime);
    let t = now();
    let span = if bt > 0 { bt * 60 } else { 86400 };
    let mut slot: Option<usize> = None;
    let mut oldest = 0usize;
    for i in 0..MAX_OFFENCES {
        if !state.offences[i].key.is_empty() && t - state.offences[i].when >= span {
            state.offences[i].key.clear(); // forgotten
        }
        let o = &mut state.offences[i];
        if !o.key.is_empty() && o.key == key {
            o.count += 1;
            o.when = t;
            return o.count;
        }
        if o.key.is_empty() {
            slot.get_or_insert(i);
        } else if o.when < state.offences[oldest].when {
            oldest = i;
        }
    }
    let i = slot.unwrap_or(oldest);
    state.offences[i] = crate::state::Offence {
        key,
        when: t,
        count: 1,
    };
    1
}

// ---- action primitives ------------------------------------------------------------

/// Same key again inside window_ms: skip (an echo has not arrived yet).
/// `record` false only looks.
fn recent_check(state: &mut BotState, key: &str, window_ms: i64, record: bool) -> bool {
    let t = mono_ms();
    let lk = lower_copy(key, MAX_CHAN + 8 + MAX_MASK_LEN);
    if state
        .enf_recent
        .iter()
        .any(|r| r.when_ms != 0 && r.key == lk && t - r.when_ms < window_ms)
    {
        return true;
    }
    if !record {
        return false;
    }
    let idx = state.enf_recent_idx;
    state.enf_recent[idx].key = lk;
    state.enf_recent[idx].when_ms = t;
    state.enf_recent_idx = (idx + 1) % ENF_RECENT;
    false
}

fn recent_key_of(name: &str, act: &str, target: &str) -> String {
    trunc_string(
        &format!("{name}|{act}|{target}"),
        MAX_CHAN + 8 + MAX_MASK_LEN,
    )
}

fn recent_key(state: &mut BotState, name: &str, act: &str, target: &str, window_ms: i64) -> bool {
    recent_check(state, &recent_key_of(name, act, target), window_ms, true)
}

fn recent_peek(state: &mut BotState, name: &str, act: &str, target: &str, window_ms: i64) -> bool {
    recent_check(state, &recent_key_of(name, act, target), window_ms, false)
}

/// The echo of an act (our KICK / MODE coming back) ends its pending window.
fn recent_ack(state: &mut BotState, name: &str, act: &str, target: &str) {
    let lk = lower_copy(
        &recent_key_of(name, act, target),
        MAX_CHAN + 8 + MAX_MASK_LEN,
    );
    for r in &mut state.enf_recent {
        if r.when_ms != 0 && r.key == lk {
            r.when_ms = 0;
        }
    }
}

fn clean_reason(src: &str, dsz: usize) -> String {
    let s: String = src
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' {
                ' '
            } else {
                c
            }
        })
        .collect();
    trunc_string(&s, dsz)
}

fn act_deop(state: &mut BotState, ci: usize, nick: &str, why: &str, half: bool) {
    let c = &state.chans[ci];
    if !c.i_am_opped || !valid_nick(state, nick) {
        return;
    }
    let Some(e) = rfind(c, nick).map(|i| &c.roster[i]) else {
        return;
    };
    if !(if half { e.is_halfop } else { e.is_op }) || entry_authorised(state, e) {
        return;
    }
    let (name, enick) = (c.name.clone(), e.nick.clone());
    let act = if half { "dehalf" } else { "deop" };
    if recent_key(state, &name, act, &enick, RECENT_ACT_MS) {
        return;
    }
    ircf!(
        state,
        "MODE {} -{} {}\r\n",
        name,
        if half { 'h' } else { 'o' },
        enick
    );
    hub_client::chan_event(state, &name, "deop", &enick, why);
}

fn act_reop(state: &mut BotState, ci: usize, nick: &str, why: &str) {
    let c = &state.chans[ci];
    if !c.i_am_opped || !valid_nick(state, nick) {
        return;
    }
    let Some(e) = rfind(c, nick).map(|i| &c.roster[i]) else {
        return;
    };
    if e.is_op || is_me(state, &e.nick) || !entry_authorised(state, e) {
        return;
    }
    let (name, enick) = (c.name.clone(), e.nick.clone());
    if recent_key(state, &name, "reop", &enick, RECENT_ACT_MS) {
        return;
    }
    ircf!(state, "MODE {} +o {}\r\n", name, enick);
    hub_client::chan_event(state, &name, "reop", &enick, why);
}

fn act_kick(state: &mut BotState, ci: usize, nick: &str, reason: &str) {
    let c = &state.chans[ci];
    if !c.i_am_opped || !valid_nick(state, nick) {
        return;
    }
    let Some(e) = rfind(c, nick).map(|i| &c.roster[i]) else {
        return;
    };
    if entry_authorised(state, e) {
        return;
    }
    let (name, enick) = (c.name.clone(), e.nick.clone());
    if recent_key(state, &name, "kick", &enick, RECENT_ACT_MS) {
        return;
    }
    let why = clean_reason(
        if reason.is_empty() { "kicked" } else { reason },
        BAN_REASON_MAX + 1,
    );
    ircf!(state, "KICK {} {} :{}\r\n", name, enick, why);
    hub_client::chan_event(state, &name, "kick", &enick, &why);
}

fn act_ban(state: &mut BotState, ci: usize, mask: &str, why: &str) {
    let c = &state.chans[ci];
    if !c.i_am_opped || !safe_token(mask, BAN_MASK_MAX) || live_has_ban(c, mask) {
        return;
    }
    if c.ban_list_known && c.bans.len() >= state.isup.ban_cap() {
        return; // the server's list is full
    }
    let name = c.name.clone();
    let t = now();
    let ti = track_get(state, &name, mask, t);
    if t - state.ban_track[ti].set_at < RECENT_BAN_MS / 1000 {
        return;
    }
    // section 6.2: step 1 every time (who is in the channel), step 2 cached 60 s
    if let Some(who) = allowed_members(state, ci, mask) {
        logm!(
            state,
            L_INFO,
            "[BAN] Not setting {} in {}: it would hit {}\n",
            mask,
            name,
            trunc(&who, 80)
        );
        return;
    }
    if t - state.ban_track[ti].checked_at >= 60 {
        let ov = auth::mask_overlaps_authorised(state, mask);
        state.ban_track[ti].overlap_ok = ov.is_none();
        state.ban_track[ti].checked_at = t;
        if let Some(who) = ov {
            logm!(
                state,
                L_INFO,
                "[BAN] Not setting {} in {}: it overlaps {}\n",
                mask,
                name,
                trunc(&who, 80)
            );
        }
    }
    if !state.ban_track[ti].overlap_ok {
        return;
    }
    state.ban_track[ti].set_at = t;
    ircf!(state, "MODE {} +b {}\r\n", name, mask);
    hub_client::chan_event(state, &name, "ban", mask, why);
}

fn act_unban(state: &mut BotState, ci: usize, mask: &str, why: &str) {
    let c = &state.chans[ci];
    if !c.i_am_opped || !safe_token(mask, BAN_MASK_MAX) || !live_has_ban(c, mask) {
        return;
    }
    let name = c.name.clone();
    if recent_key(state, &name, "unban", mask, RECENT_ACT_MS) {
        return;
    }
    ircf!(state, "MODE {} -b {}\r\n", name, mask);
    hub_client::chan_event(state, &name, "unban", mask, why);
}

// ---- jobs -------------------------------------------------------------------------

fn act_job(a: JobAct) -> usize {
    match a {
        JobAct::Deop | JobAct::Dehalf | JobAct::Reop => JOB_OP,
        JobAct::Kick => JOB_KICK,
        JobAct::BanNuh | JobAct::BanMask | JobAct::Unban => JOB_BAN,
        JobAct::Mode => JOB_MODE,
        JobAct::Limit => JOB_LIMIT,
    }
}

fn exec_ban_nuh(state: &mut BotState, ci: usize, nuh: &str, reason: &str) {
    let Some(nick) = nuh_nick(nuh) else { return };
    if !state.chans[ci].i_am_opped {
        return;
    }
    let c = &state.chans[ci];
    if rfind(c, nick).is_some_and(|i| entry_authorised(state, &c.roster[i]))
        || chan_nuh_authorised(state, ci, nuh)
    {
        return;
    }
    let name = c.name.clone();
    let Some(mask) = auto_ban_mask(state, ci, nuh) else {
        logm!(
            state,
            L_INFO,
            "[BAN] No ban type is safe for {} in {}; kick only\n",
            nuh,
            name
        );
        return;
    };
    let bt = cset(state, ci, CsetId::BanTime);
    if bt > 0 {
        // the record is how every bot (and a later joiner) learns of the ban
        // and who lifts it; the hub takes bot-written bans only when timed
        chancfg::bot_ban(
            state,
            &name,
            &mask,
            now() + bt * 60,
            Some(""),
            Some(reason),
            false,
        );
    }
    act_ban(
        state,
        ci,
        &mask,
        if reason.is_empty() {
            "auto ban"
        } else {
            reason
        },
    );
}

fn exec_mode(state: &mut BotState, ci: usize) {
    let c = &state.chans[ci];
    if cset(state, ci, CsetId::EnforceModes) == 0 || !c.live_known || !c.i_am_opped {
        return;
    }
    let name = c.name.clone();
    let skip_limit = cset(state, ci, CsetId::DynamicLimit) != 0;
    let (n, _) = chanlive::sync(state, ci, skip_limit, true, true);
    if n <= 0 || recent_key(state, &name, "moderevert", "", RECENT_MODE_MS) {
        return;
    }
    let (n, sum) = chanlive::sync(state, ci, skip_limit, false, true);
    if n > 0 {
        hub_client::chan_event(state, &name, "moderevert", &name, trunc(&sum, 64));
    }
}

/// The +l the dynamic limit wants now, or 0 when the live one is close enough
/// (or cannot be judged).  The sweep queues the limit job only on a nonzero
/// answer, so a backup's delay counts from when it saw the need.
fn limit_due(state: &BotState, ci: usize) -> i64 {
    let c = &state.chans[ci];
    if cset(state, ci, CsetId::DynamicLimit) == 0
        || !c.i_am_opped
        || !c.who_done // the count is only right once the whole WHO has been read
        || c.roster.len() >= MAX_ROSTER_SIZE // cannot count a big channel
        || !c.live_known
    {
        return 0;
    }
    let want = (c.roster.len() as i64 + cset(state, ci, CsetId::LimitGap)).clamp(1, 99999);
    if chanlive::live_has(c, b'l') && (c.live_limit - want).abs() < 2 {
        return 0; // off by less than 2: no MODE every time someone joins
    }
    want
}

fn exec_limit(state: &mut BotState, ci: usize) {
    let want = limit_due(state, ci);
    let name = state.chans[ci].name.clone();
    if want == 0 || recent_key(state, &name, "limit", "", RECENT_MODE_MS) {
        return;
    }
    ircf!(state, "MODE {} +l {}\r\n", name, want);
    hub_client::chan_event(state, &name, "limit", &name, &format!("+l {want}"));
}

fn job_exec(state: &mut BotState, ci: usize, act: JobAct, target: &str, reason: &str) {
    match act {
        JobAct::Deop => act_deop(state, ci, target, reason, false),
        JobAct::Dehalf => act_deop(state, ci, target, reason, true),
        JobAct::Reop => act_reop(state, ci, target, reason),
        JobAct::Kick => act_kick(state, ci, target, reason),
        JobAct::BanNuh => exec_ban_nuh(state, ci, target, reason),
        JobAct::BanMask => act_ban(state, ci, target, reason),
        JobAct::Unban => act_unban(state, ci, target, reason),
        JobAct::Mode => exec_mode(state, ci),
        JobAct::Limit => exec_limit(state, ci),
    }
}

/// Hand a piece of work to the election: run it now when this bot holds the
/// job, otherwise queue it for backup-index x JOB_STEP_MS.  false = this bot
/// takes no part (not opped / not in the deal) or the queue is full.
fn job_submit(state: &mut BotState, ci: usize, act: JobAct, target: &str, reason: &str) -> bool {
    let rank = deal_rank(state, ci, act_job(act));
    if rank < 0 {
        return false;
    }
    if rank == 0 {
        job_exec(state, ci, act, target, reason);
        return true;
    }
    let name = state.chans[ci].name.clone();
    let mut slot: Option<usize> = None;
    for (i, j) in state.jobs.iter().enumerate() {
        if !j.used {
            slot.get_or_insert(i);
            continue;
        }
        if j.act == act && eq_ic(&j.chan, &name) && eq_ic(&j.target, target) {
            return true; // already waiting
        }
    }
    let Some(i) = slot else {
        logm!(
            state,
            L_DEBUG,
            "[JOB] Pending queue full; dropping a job in {}\n",
            name
        );
        return false;
    };
    state.jobs[i] = crate::state::PendingJob {
        used: true,
        act,
        chan: name,
        target: trunc_string(target, MAX_MASK_LEN),
        reason: trunc_string(reason, BAN_REASON_MAX + 1),
        created_ms: mono_ms(),
    };
    true
}

/// Forget this channel's queued (backup) work of one kind.
fn jobs_drop(state: &mut BotState, ci: usize, act: JobAct) {
    let name = state.chans[ci].name.clone();
    for j in state.jobs.iter_mut() {
        if j.used && j.act == act && eq_ic(&j.chan, &name) {
            j.used = false;
        }
    }
}

fn jobs_tick(state: &mut BotState) {
    let t = mono_ms();
    for i in 0..MAX_PENDING_JOBS {
        if !state.jobs[i].used {
            continue;
        }
        let ci = channel::find(state, &state.jobs[i].chan)
            .filter(|&ci| state.chans[ci].status == ChanStatus::In);
        let Some(ci) = ci.filter(|_| t - state.jobs[i].created_ms <= JOB_MAX_AGE_MS) else {
            state.jobs[i].used = false;
            continue;
        };
        // re-dealt every tick: a roster change moves the rank
        let rank = deal_rank(state, ci, act_job(state.jobs[i].act));
        if rank < 0 {
            state.jobs[i].used = false;
            continue;
        }
        // the limit job comes from each bot's own sweep, up to a sweep apart:
        // its backups give the holder one whole sweep first
        let mut wait = i64::from(rank) * JOB_STEP_MS;
        if state.jobs[i].act == JobAct::Limit {
            wait += ENF_SWEEP_SECS * 1000;
        }
        if t - state.jobs[i].created_ms < wait {
            continue;
        }
        let copy = state.jobs[i].clone();
        state.jobs[i].used = false;
        // queued under +bitch, which may be gone by now: a member given +o/+h
        // again after -bitch keeps it
        if copy.reason == "bitch" && cset(state, ci, CsetId::Bitch) == 0 {
            continue;
        }
        job_exec(state, ci, copy.act, &copy.target, &copy.reason);
    }
}

// ---- hooks for the flood lane -----------------------------------------------------

fn in_chan(state: &BotState, chan: &str) -> Option<usize> {
    channel::find(state, chan).filter(|&ci| state.chans[ci].status == ChanStatus::In)
}

/// Queue a kick in the channel election (executed at once by the job holder,
/// after backup delay by the others, re-checked first).  true = queued/ran.
pub fn request_kick(state: &mut BotState, chan: &str, nick: &str, reason: &str) -> bool {
    match in_chan(state, chan) {
        Some(ci) if valid_nick(state, nick) => job_submit(state, ci, JobAct::Kick, nick, reason),
        _ => false,
    }
}

/// Queue a deop in the channel election.
pub fn request_deop(state: &mut BotState, chan: &str, nick: &str, reason: &str) -> bool {
    match in_chan(state, chan) {
        Some(ci) if valid_nick(state, nick) => job_submit(state, ci, JobAct::Deop, nick, reason),
        _ => false,
    }
}

/// Automatic ban of the host in `nuh` (bantype, bantime, section 6.2
/// narrowing retry, bot-written B|); `kick_too` also requests the kick for
/// that nick.
pub fn request_ban(
    state: &mut BotState,
    chan: &str,
    nuh: &str,
    reason: &str,
    kick_too: bool,
) -> bool {
    let Some(ci) = in_chan(state, chan) else {
        return false;
    };
    if nuh.len() >= MAX_MASK_LEN {
        return false;
    }
    let Some(nick) = nuh_nick(nuh).filter(|n| valid_nick(state, n)) else {
        return false;
    };
    let ok = job_submit(state, ci, JobAct::BanNuh, nuh, reason);
    if kick_too {
        job_submit(state, ci, JobAct::Kick, nick, reason);
    }
    ok
}

/// +revenge: the unauthorised `prefix` hurt an authorised member.  First time
/// within bantime: deop; again: kick + ban.
fn revenge(state: &mut BotState, ci: usize, prefix: &str) {
    let Some(nick) = nuh_nick(prefix) else { return };
    let name = state.chans[ci].name.clone();
    if offence(state, &name, prefix) <= 1 {
        job_submit(state, ci, JobAct::Deop, nick, "revenge");
    } else {
        request_ban(state, &name, prefix, "revenge", true);
    }
}

// ---- roster events ----------------------------------------------------------------

pub fn on_join(state: &mut BotState, chan: &str, nuh: &str) {
    let Some(ci) = in_chan(state, chan) else {
        return;
    };
    let Some(nick) = nuh_nick(nuh) else { return };
    if !nuh.contains('@') || is_me(state, nick) {
        return;
    }
    let c = &mut state.chans[ci];
    roster_set(c, nick, nuh, false, false, false);
    c.enf_dirty = true;
    let name = c.name.clone();
    chanflood::event(state, &name, nuh, FloodKind::Join, false);
}

pub fn on_part(state: &mut BotState, chan: &str, nick: &str) {
    if is_me(state, nick) {
        return;
    }
    let Some(ci) = channel::find(state, chan) else {
        return;
    };
    let c = &mut state.chans[ci];
    rremove(c, nick);
    c.enf_dirty = true;
}

pub fn on_quit(state: &mut BotState, nick: &str) {
    if is_me(state, nick) {
        return;
    }
    for c in &mut state.chans {
        if c.status == ChanStatus::In && rfind(c, nick).is_some() {
            rremove(c, nick);
            c.enf_dirty = true;
        }
    }
}

/// `prefix` is the message source ("nick!user@host", or a server name with
/// no '!').
pub fn on_kick(state: &mut BotState, chan: &str, prefix: Option<&str>, victim: &str) {
    let Some(ci) = in_chan(state, chan) else {
        return;
    };
    if is_me(state, victim) {
        return;
    }
    let c = &state.chans[ci];
    let victim_auth = rfind(c, victim).is_some_and(|i| entry_authorised(state, &c.roster[i]));
    let name = c.name.clone();
    recent_ack(state, &name, "kick", victim);
    let c = &mut state.chans[ci];
    rremove(c, victim);
    c.enf_dirty = true;
    if let Some(p) = prefix.filter(|p| p.contains('!')) {
        let name = state.chans[ci].name.clone();
        chanflood::event(state, &name, p, FloodKind::Kick, victim_auth);
    }
    if let Some(p) = prefix
        && victim_auth
        && p.contains('!')
        && cset(state, ci, CsetId::Revenge) != 0
        && !chan_nuh_authorised(state, ci, p)
    {
        revenge(state, ci, p);
    }
}

pub fn on_nick(state: &mut BotState, old_nick: &str, new_nick: &str) {
    let new_ok = valid_nick(state, new_nick);
    for ci in 0..state.chans.len() {
        let c = &mut state.chans[ci];
        let Some(e) = (c.status == ChanStatus::In)
            .then(|| rfind(c, old_nick))
            .flatten()
        else {
            continue;
        };
        if !new_ok {
            // a nick we cannot track: forget the member rather than keep the
            // old name, which no longer exists
            rremove(c, old_nick);
            c.enf_dirty = true;
            continue;
        }
        let hm = &c.roster[e].hostmask;
        let mask = hm.find('!').map(|b| format!("{new_nick}{}", &hm[b..]));
        let mut renamed = None;
        match mask.filter(|m| m.len() < MAX_MASK_LEN) {
            Some(mask) => {
                // a stale entry under the new name -- but a case-only change
                // (Bob -> bob) names the same entry, which is renamed in place
                if !eq_ic(old_nick, new_nick) {
                    rremove(c, new_nick);
                }
                if let Some(e) = rfind(c, old_nick) {
                    c.roster[e].nick = new_nick.to_string();
                    c.roster[e].hostmask = mask.clone();
                    c.roster[e].auth_gen.set(0);
                    renamed = Some(mask);
                }
            }
            None => rremove(c, old_nick),
        }
        if let Some(mask) = renamed {
            let name = state.chans[ci].name.clone();
            chanflood::event(state, &name, &mask, FloodKind::Nick, false);
        }
        state.chans[ci].enf_dirty = true;
    }
}

// ---- MODE events (who did what) ---------------------------------------------------

fn ban_hits_authorised(state: &BotState, ci: usize, mask: &str) -> bool {
    state.chans[ci]
        .roster
        .iter()
        .any(|e| entry_authorised(state, e) && auth::wildcard_match(mask, &e.hostmask))
}

/// A MODE line on a channel, after the live state was updated.  `prefix` is
/// the message source; `args` the mode parameters.
pub fn on_mode(state: &mut BotState, chan: &str, prefix: Option<&str>, modes: &str, args: &str) {
    let Some(ci) = in_chan(state, chan) else {
        return;
    };
    let user_src = prefix.is_some_and(|p| p.contains('!'));
    let server_src = prefix.is_some() && !user_src;
    let pfx = prefix.unwrap_or("");
    let src_unauth = user_src && !chan_nuh_authorised(state, ci, pfx);
    let src_me = user_src && nuh_nick(pfx).is_some_and(|n| is_me(state, n));
    let bitch = cset(state, ci, CsetId::Bitch) != 0;
    let protect = cset(state, ci, CsetId::ProtectOps) != 0;
    let rev = cset(state, ci, CsetId::Revenge) != 0;
    let nethack = cset(state, ci, CsetId::StopNetHack) != 0;
    let has_h = state.isup.prefix_modes.contains('h');
    let (mut mode_changed, mut bans_changed, mut revenged) = (false, false, false);

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
            continue;
        }
        // our own acts coming back end their pending window (recent_ack)
        let cname = state.chans[ci].name.clone();
        if let Some(a) = a.filter(|a| valid_nick(state, a)).filter(|_| ch == b'o') {
            recent_ack(state, &cname, if adding { "reop" } else { "deop" }, a);
        } else if let Some(a) = a
            .filter(|a| valid_nick(state, a))
            .filter(|_| ch == b'h' && !adding)
        {
            recent_ack(state, &cname, "dehalf", a);
        } else if let Some(a) = a.filter(|a| ch == b'b' && !adding && safe_token(a, BAN_MASK_MAX)) {
            recent_ack(state, &cname, "unban", a);
        } else if src_me && ch == b'l' {
            recent_ack(state, &cname, "limit", "");
        }
        let valid_a = a.filter(|a| valid_nick(state, a));
        // op floods (section 8): a user source only, never the server (netjoin)
        if user_src && !adding && ch == b'o' && valid_a.is_some() {
            let va = valid_a.unwrap_or("");
            let c = &state.chans[ci];
            let victim_auth = rfind(c, va)
                .map(|i| &c.roster[i])
                .is_some_and(|ve| is_me(state, &ve.nick) || entry_authorised(state, ve));
            let name = c.name.clone();
            chanflood::event(state, &name, pfx, FloodKind::Deop, victim_auth);
        } else if user_src
            && adding
            && ch == b'b'
            && let Some(ba) = a.filter(|a| safe_token(a, BAN_MASK_MAX))
        {
            let victim_auth = ban_hits_authorised(state, ci, ba);
            let name = state.chans[ci].name.clone();
            chanflood::event(state, &name, pfx, FloodKind::Ban, victim_auth);
        }
        if ch == b'o' && valid_a.is_some() {
            let a = valid_a.unwrap_or("");
            let c = &state.chans[ci];
            let Some(e) = rfind(c, a).map(|i| &c.roster[i]) else {
                continue;
            };
            if is_me(state, &e.nick) {
                continue;
            }
            let (enick, auth) = (e.nick.clone(), entry_authorised(state, e));
            if adding && !auth {
                if bitch {
                    job_submit(state, ci, JobAct::Deop, &enick, "bitch");
                } else if nethack && server_src {
                    job_submit(state, ci, JobAct::Deop, &enick, "stopnethack");
                }
            } else if !adding && auth && user_src && src_unauth && !src_me {
                if protect {
                    job_submit(state, ci, JobAct::Reop, &enick, "protectops");
                }
                if rev && !revenged {
                    revenged = true;
                    revenge(state, ci, pfx);
                }
            }
        } else if ch == b'h' && adding && has_h && valid_a.is_some() {
            let a = valid_a.unwrap_or("");
            let c = &state.chans[ci];
            if bitch
                && let Some(e) = rfind(c, a).map(|i| &c.roster[i])
                && !is_me(state, &e.nick)
                && !entry_authorised(state, e)
            {
                let enick = e.nick.clone();
                job_submit(state, ci, JobAct::Dehalf, &enick, "bitch");
            }
        } else if ch == b'b' {
            bans_changed = true;
            if adding
                && let Some(a) = a
                && rev
                && !revenged
                && src_unauth
                && !src_me
                && safe_token(a, BAN_MASK_MAX)
                && ban_hits_authorised(state, ci, a)
            {
                revenged = true;
                revenge(state, ci, pfx);
            }
        } else if b"imnpstkl".contains(&ch) {
            mode_changed = true;
            if ch == b'l' && adding && (server_src || !src_unauth) {
                state.chans[ci].enf_last_limit = now(); // limitdelay counts from here
            }
        }
    }
    if mode_changed {
        let skip_limit = cset(state, ci, CsetId::DynamicLimit) != 0;
        let clean = state.chans[ci].live_known
            && chanlive::sync(state, ci, skip_limit, true, true).0 <= 0;
        // a line that leaves the channel as stored (the holder's revert echoed)
        // ends a backup's wait: a revert job left pending would keep its first
        // timer and fire on the next operator change just as the holder answers
        // it, so a backup's delay always counts from the newest need
        if clean {
            jobs_drop(state, ci, JobAct::Mode);
        } else if !src_me && cset(state, ci, CsetId::EnforceModes) != 0 {
            job_submit(state, ci, JobAct::Mode, "", "enforcemodes");
        }
        // our own revert coming back ends its window once nothing is left to move
        // (a second MODE line may still be in flight): the holder must not leave
        // the next change to a backup for RECENT_MODE_MS
        if clean && src_me {
            let cname = state.chans[ci].name.clone();
            recent_ack(state, &cname, "moderevert", "");
        }
    }
    if bans_changed {
        state.chans[ci].enf_dirty = true;
    }
}

// ---- the state sweep --------------------------------------------------------------

/// The unauthorised members `mask` matches: their nicks (the count is of
/// all), and whether an authorised member matches it too.  Authorisation is
/// the roster's cached bit, so this is one wildcard match per member.
fn unauth_match(state: &BotState, ci: usize, mask: &str) -> (Vec<String>, bool) {
    let mut hits = Vec::new();
    let mut auth_hit = false;
    for e in &state.chans[ci].roster {
        if entry_authorised(state, e) {
            if !auth_hit && auth::wildcard_match(mask, &e.hostmask) {
                auth_hit = true;
            }
            continue;
        }
        if auth::wildcard_match(mask, &e.hostmask) {
            hits.push(e.nick.clone());
        }
    }
    (hits, auth_hit)
}

/// Queue kicks for the matched members, at most ENF_KICKS_PER_SWEEP per
/// channel per ban sweep; one whose KICK is still pending does not count.
fn sweep_kicks(state: &mut BotState, ci: usize, hits: &[String], reason: &str, kicks: &mut usize) {
    for nk in hits.iter().take(MAX_ROSTER_SIZE) {
        if *kicks >= ENF_KICKS_PER_SWEEP {
            break;
        }
        let name = state.chans[ci].name.clone();
        if recent_peek(state, &name, "kick", nk, RECENT_ACT_MS) {
            continue;
        }
        *kicks += 1;
        job_submit(state, ci, JobAct::Kick, nk, reason);
    }
}

fn ban_sweep(state: &mut BotState, ci: usize, t: i64) {
    if !state.chans[ci].ban_list_known {
        return;
    }
    let name = state.chans[ci].name.clone();
    let protect = cset(state, ci, CsetId::ProtectOps) != 0;
    let enforce = cset(state, ci, CsetId::EnforceBans) != 0;
    let dyn_bans = cset(state, ci, CsetId::DynamicBans) != 0;
    let idle = cset(state, ci, CsetId::BanIdle) * 60;
    let mut kicks = 0usize;

    // (a) bans on the channel that match an authorised member (section 6.2 step 5)
    if protect {
        let masks: Vec<String> = state.chans[ci]
            .bans
            .iter()
            .map(|b| b.mask.clone())
            .collect();
        for m in masks {
            if m.len() > BAN_MASK_MAX {
                continue;
            }
            if ban_hits_authorised(state, ci, &m) {
                job_submit(state, ci, JobAct::Unban, &m, "protectops");
            }
        }
    }

    // (b) the network list for this channel; permanent first, oldest first:
    // they win the room when the list is full
    let mut recs: Vec<crate::state::CfgBan> =
        chancfg::bans_for(state, &name, MAX_BANS_PER_CHAN + MAX_GLOBAL_BANS)
            .into_iter()
            .cloned()
            .collect();
    recs.sort_by_key(|r| (r.expires != 0, r.ts));
    let mut room = state.isup.ban_cap() as i64 - state.chans[ci].bans.len() as i64;
    for r in &recs {
        if !safe_token(&r.mask, BAN_MASK_MAX) {
            continue;
        }
        let sticky = r.flags.contains('s');
        // act_ban can grow the table: read what is needed before any job
        let ti = track_get(state, &name, &r.mask, t);
        let tr = &state.ban_track[ti];
        if tr.checked_at != 0 && t - tr.checked_at < 60 && !tr.overlap_ok {
            continue; // known to hit a bot / operator: neither set nor kick
        }
        let last_match = tr.last_match;
        let live = live_has_ban(&state.chans[ci], &r.mask);
        let (hits, _) = unauth_match(state, ci, &r.mask);
        let matched = !hits.is_empty();
        if matched {
            state.ban_track[ti].last_match = t;
        }
        let mut keep = sticky || !dyn_bans;
        if keep && !live {
            if sticky || room > 0 {
                room -= 1;
                job_submit(state, ci, JobAct::BanMask, &r.mask, &r.reason);
            } else {
                keep = false; // no room: this one stays dynamic
                if !state.chans[ci].ban_cap_warned {
                    state.chans[ci].ban_cap_warned = true;
                    logm!(
                        state,
                        L_INFO,
                        "[BAN] {}: the server ban list ({}) is full; the rest of the listed bans stay dynamic\n",
                        name,
                        state.isup.ban_cap()
                    );
                }
            }
        }
        if !keep {
            if matched && !live {
                job_submit(state, ci, JobAct::BanMask, &r.mask, &r.reason);
            } else if live && !matched && idle > 0 && t - last_match >= idle {
                job_submit(state, ci, JobAct::Unban, &r.mask, "banidle");
            }
        }
        if matched {
            let why = if r.reason.is_empty() {
                "banned"
            } else {
                &r.reason
            };
            sweep_kicks(state, ci, &hits, why, &mut kicks);
        }
    }

    // (c) records that expired or were deleted: lift them from the channel
    let lifts: Vec<(String, bool)> = state
        .cfg_bans
        .iter()
        .filter(|b| !(b.active && !(b.expires > 0 && b.expires <= t)))
        .filter(|b| b.chan == "*" || eq_ic(&b.chan, &name))
        .filter(|b| live_has_ban(&state.chans[ci], &b.mask))
        .map(|b| (b.mask.clone(), b.active))
        .collect();
    for (mask, active) in lifts {
        job_submit(
            state,
            ci,
            JobAct::Unban,
            &mask,
            if active { "expired" } else { "removed" },
        );
    }

    // (d) +enforcebans: anyone's ban kicks the unauthorised members it matches,
    // except a ban that also hits an authorised member: step (a) takes that one
    // off, and it must not be used to kick in the meantime
    if enforce {
        let masks: Vec<String> = state.chans[ci]
            .bans
            .iter()
            .map(|b| b.mask.clone())
            .collect();
        for m in masks {
            if !safe_token(&m, BAN_MASK_MAX) {
                continue;
            }
            let (hits, auth_hit) = unauth_match(state, ci, &m);
            if hits.is_empty() || auth_hit {
                continue;
            }
            sweep_kicks(state, ci, &hits, "banned", &mut kicks);
        }
    }
}

fn cycle_check(state: &mut BotState, ci: usize, t: i64) {
    let c = &state.chans[ci];
    if cset(state, ci, CsetId::Cycle) == 0
        || c.i_am_opped
        || c.roster.len() != 1
        || !is_me(state, &c.roster[0].nick)
        || c.last_who_request == 0
        || t - c.last_who_request < 30
        || t - c.enf_last_cycle < ENF_CYCLE_MIN_SECS
    {
        return;
    }
    let name = c.name.clone();
    state.chans[ci].enf_last_cycle = t;
    logm!(
        state,
        L_INFO,
        "[CYCLE] Alone and opless in {}; cycling\n",
        name
    );
    ircf!(state, "PART {} :cycling\r\n", name);
}

fn chan_sweep(state: &mut BotState, ci: usize, t: i64) {
    if !state.chans[ci].i_am_opped {
        cycle_check(state, ci, t);
        return;
    }
    // +bitch: unauthorised ops already there when we got ops / settings changed
    if state.chans[ci].enf_ops_check {
        state.chans[ci].enf_ops_check = false;
        if cset(state, ci, CsetId::Bitch) != 0 {
            let has_h = state.isup.prefix_modes.contains('h');
            let todo: Vec<(String, bool, bool)> = state.chans[ci]
                .roster
                .iter()
                .filter(|e| !entry_authorised(state, e))
                .map(|e| (e.nick.clone(), e.is_op, e.is_halfop))
                .collect();
            for (nk, op, half) in todo {
                if op {
                    job_submit(state, ci, JobAct::Deop, &nk, "bitch");
                }
                if has_h && half {
                    job_submit(state, ci, JobAct::Dehalf, &nk, "bitch");
                }
            }
        }
    }
    if cset(state, ci, CsetId::EnforceModes) != 0 && state.chans[ci].live_known {
        let skip = cset(state, ci, CsetId::DynamicLimit) != 0;
        if chanlive::sync(state, ci, skip, true, true).0 > 0 {
            job_submit(state, ci, JobAct::Mode, "", "enforcemodes");
        }
    }
    if cset(state, ci, CsetId::DynamicLimit) != 0 {
        let delay = cset(state, ci, CsetId::LimitDelay);
        // enf_last_limit is the channel's last +l from an authorised source
        // (on_mode): one clock for every bot, so the holder is never still
        // inside its own throttle while a backup's has run out
        if t - state.chans[ci].enf_last_limit >= delay && limit_due(state, ci) != 0 {
            job_submit(state, ci, JobAct::Limit, "", "dynamiclimit");
        }
    }
    ban_sweep(state, ci, t);
}

fn minute_sweep(state: &mut BotState, t: i64) {
    // bans this bot wrote and that ran out: write the del (the hub's own
    // sweep does the same; last write wins)
    let mut i = 0;
    while i < state.cfg_bans.len() {
        let b = state.cfg_bans[i].clone();
        if b.active
            && b.expires > 0
            && b.expires <= t
            && !state.bot_uuid.is_empty()
            && b.setter == state.bot_uuid
        {
            chancfg::bot_ban(state, &b.chan, &b.mask, 0, None, None, true);
        }
        i += 1;
    }
    // idle clocks of bans that are gone from every list
    let mut i = 0;
    while i < state.ban_track.len() {
        let tr = &state.ban_track[i];
        if tr.chan.is_empty() || (t - tr.last_match > 86400 && t - tr.set_at > 86400) {
            state.ban_track.swap_remove(i); // compact
        } else {
            i += 1;
        }
    }
}

/// Main-loop tick (<= 1 s): sweeps, pending jobs, 60 s ban expiry.
pub fn tick(state: &mut BotState) {
    if state.status & S_CONNECTED == 0 {
        return;
    }
    let t = now();
    let ms = mono_ms();
    let all = state.cfg_gen != state.enf_seen_gen;
    state.enf_seen_gen = state.cfg_gen;
    for ci in 0..state.chans.len() {
        let c = &mut state.chans[ci];
        if !c.is_managed || c.status != ChanStatus::In {
            continue;
        }
        if all {
            c.enf_dirty = true;
            c.enf_ops_check = true;
        }
        let due = ms - c.enf_last_sweep_ms >= ENF_SWEEP_SECS * 1000;
        if (c.enf_dirty && ms - c.enf_last_sweep_ms >= ENF_RESWEEP_MS) || due {
            c.enf_dirty = false;
            c.enf_last_sweep_ms = ms;
            chan_sweep(state, ci, t);
        }
    }
    jobs_tick(state);
    if t - state.enf_last_minute >= 60 {
        state.enf_last_minute = t;
        minute_sweep(state, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deal order of `ids` in `chan` as C's chanenf_deal_rank sorts it.
    fn order(chan: &str, ids: &[&str]) -> Vec<(u64, String)> {
        let lc = lower_copy(chan, MAX_CHAN);
        let mut el = Vec::new();
        for id in ids {
            elig_add(&mut el, &lc, id);
        }
        el.sort_by(elig_cmp);
        el.into_iter().map(|e| (e.h, e.id)).collect()
    }

    const UUIDS: [&str; 5] = [
        "0a1b2c3d-0000-4000-8000-000000000001",
        "9f8e7d6c-1111-4111-9111-000000000002",
        "5b5b5b5b-2222-4222-a222-000000000003",
        "c0ffee00-3333-4333-b333-000000000004",
        "deadbeef-4444-4444-8444-000000000005",
    ];

    #[test]
    fn deal_order_fixed_uuids() {
        let got: Vec<String> = order("#Test", &UUIDS)
            .iter()
            .map(|(h, id)| format!("{h:016x} {id}"))
            .collect();
        // Printed by the C harness (chanenf.c elig_add / elig_cmp, OpenSSL
        // SHA-256) for the same inputs: the order every bot must agree on.
        assert_eq!(
            got,
            [
                "18f23ebe2149a380 0a1b2c3d-0000-4000-8000-000000000001",
                "48d639906167aa71 9f8e7d6c-1111-4111-9111-000000000002",
                "4c11f3865b7d83b4 5b5b5b5b-2222-4222-a222-000000000003",
                "b07db53dd444b4e8 c0ffee00-3333-4333-b333-000000000004",
                "f17d17f495542dfd deadbeef-4444-4444-8444-000000000005",
            ]
        );
        // case-insensitive channel name, duplicates dropped
        let want = order("#Test", &UUIDS);
        assert_eq!(want, order("#TEST", &UUIDS));
        let mut dup = UUIDS.to_vec();
        dup.push(UUIDS[0]);
        assert_eq!(want, order("#test", &dup));
    }

    #[test]
    fn ban_masks() {
        let n = "nick!~user@192.168.7.9";
        assert_eq!(ban_mask(0, n).as_deref(), Some("*!~user@192.168.7.9"));
        assert_eq!(ban_mask(1, n).as_deref(), Some("*!*user@192.168.7.9"));
        assert_eq!(ban_mask(2, n).as_deref(), Some("*!*@192.168.7.9"));
        assert_eq!(ban_mask(3, n).as_deref(), Some("*!*user@192.168.7.*"));
        assert_eq!(ban_mask(4, n).as_deref(), Some("*!*@192.168.7.*"));
        assert_eq!(ban_mask(6, n).as_deref(), Some("nick!*user@192.168.7.9"));
        assert_eq!(ban_mask(7, n).as_deref(), Some("nick!*@192.168.7.9"));
        assert_eq!(ban_mask(10, n), None);
        assert_eq!(
            ban_mask(4, "a!b@x.y.example.org").as_deref(),
            Some("*!*@*.y.example.org")
        );
        assert_eq!(
            ban_mask(4, "a!b@y.example.org").as_deref(),
            Some("*!*@*.example.org")
        );
        assert_eq!(
            ban_mask(4, "a!b@example.org").as_deref(),
            Some("*!*@example.org")
        );
        assert_eq!(
            ban_mask(4, "a!b@2001:db8:1:2:3:4:5:6").as_deref(),
            Some("*!*@2001:db8:1:2:*")
        );
        assert_eq!(ban_mask(4, "a!b@user/abc").as_deref(), Some("*!*@user/abc"));
        assert_eq!(ban_mask(0, "a*!b@h"), None);
        assert_eq!(ban_mask(0, "nobang"), None);
    }

    use crate::state::{LiveBan, MaskRecord, TrustedBot, UserRecord};

    fn set_cset(c: &mut Chan, id: CsetId, v: i64) {
        c.cfg_active = true;
        c.cfg_ts = 1;
        c.cfg_set.present |= 1 << id as usize;
        c.cfg_set.val[id as usize] = v;
    }

    /// A channel "#c" with us opped, a known ban list and `members`
    /// (nick, hostmask); alice's host is a trusted bot.
    fn chan_state(members: &[(String, String)]) -> BotState {
        let mut st = BotState::for_test();
        st.trusted_bots.push(TrustedBot {
            mask: "alice!*@good.host".into(),
            uuid: "33333333-3333-4333-8333-333333333333".into(),
            ..TrustedBot::default()
        });
        let ci = channel::add(&mut st, "#c").unwrap();
        let c = &mut st.chans[ci];
        c.status = ChanStatus::In;
        c.i_am_opped = true;
        c.ban_list_known = true;
        set_cset(c, CsetId::EnforceBans, 1);
        for (n, h) in members {
            assert!(roster_set(c, n, h, false, false, false));
        }
        st
    }

    fn members() -> Vec<(String, String)> {
        vec![
            ("alice".into(), "alice!u@good.host".into()),
            ("mallory".into(), "mallory!u@evil.host".into()),
        ]
    }

    fn add_live_ban(st: &mut BotState, mask: &str) {
        st.chans[0].bans.push(LiveBan {
            mask: mask.into(),
            setter: "x".into(),
            when: 0,
        });
    }

    fn queued_kicks(st: &BotState) -> Vec<String> {
        st.sendq.q[SENDQ_LANE_PROT]
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .filter(|l| l.starts_with("KICK "))
            .collect()
    }

    #[test]
    fn enforcebans_skips_bans_that_hit_authorised_members() {
        // a ban on the evil host alone kicks mallory
        let mut st = chan_state(&members());
        add_live_ban(&mut st, "*!*@evil.host");
        ban_sweep(&mut st, 0, now());
        assert_eq!(queued_kicks(&st), ["KICK #c mallory :banned\r\n"]);
        // a ban that also matches alice (authorised) is not used to kick
        let mut st = chan_state(&members());
        add_live_ban(&mut st, "*!*@*.host");
        ban_sweep(&mut st, 0, now());
        assert!(queued_kicks(&st).is_empty());
    }

    #[test]
    fn at_most_four_kicks_per_channel_per_sweep() {
        let mut m = members();
        for i in 0..10 {
            m.push((format!("bad{i}"), format!("bad{i}!u@evil.host")));
        }
        let mut st = chan_state(&m);
        add_live_ban(&mut st, "*!*@evil.host");
        add_live_ban(&mut st, "*!bad*@evil.host");
        ban_sweep(&mut st, 0, now());
        assert_eq!(queued_kicks(&st).len(), ENF_KICKS_PER_SWEEP);
    }

    #[test]
    fn pending_kick_is_not_repeated_until_echoed() {
        let mut st = chan_state(&members());
        add_live_ban(&mut st, "*!*@evil.host");
        let t = now();
        ban_sweep(&mut st, 0, t);
        // the same KICK is neither re-queued nor does it use up a slot
        ban_sweep(&mut st, 0, t);
        assert_eq!(st.sendq.total, 1);
        // its echo ends the pending window; the member is gone from the roster
        recent_ack(&mut st, "#c", "kick", "Mallory");
        assert!(!recent_peek(
            &mut st,
            "#c",
            "kick",
            "mallory",
            RECENT_ACT_MS
        ));
    }

    #[test]
    fn long_member_nicks_follow_nicklen() {
        let mut st = BotState::for_test();
        let n30 = "n".repeat(30);
        assert!(valid_nick(&st, &n30));
        assert!(!valid_nick(&st, &"n".repeat(31)));
        isupport_nicklen_for_test(&mut st, 9);
        assert!(valid_nick(&st, "ninechars"));
        assert!(!valid_nick(&st, "tencharsss"));
        isupport_nicklen_for_test(&mut st, 100);
        assert!(valid_nick(&st, &"n".repeat(31)));
        assert!(!valid_nick(&st, &"n".repeat(32)));
        assert!(!valid_nick(&st, "bad nick"));
        // a roster takes 31-byte nicks, not 32
        let mut c = Chan::default();
        assert!(roster_set(
            &mut c,
            &"n".repeat(31),
            "n!u@h",
            false,
            false,
            false
        ));
        assert!(!roster_set(
            &mut c,
            &"n".repeat(32),
            "n!u@h",
            false,
            false,
            false
        ));
        assert_eq!(
            nuh_nick(&format!("{}!u@h", "n".repeat(31))).map(str::len),
            Some(31)
        );
        assert_eq!(nuh_nick(&format!("{}!u@h", "n".repeat(32))), None);
    }

    fn isupport_nicklen_for_test(st: &mut BotState, n: i32) {
        st.isup.nicklen = n;
    }

    #[test]
    fn invalid_new_nick_removes_the_member() {
        let mut st = chan_state(&members());
        on_nick(&mut st, "mallory", "bad nick");
        assert!(rfind(&st.chans[0], "mallory").is_none());
        assert!(rfind(&st.chans[0], "bad nick").is_none());
        assert!(st.chans[0].enf_dirty);
        // a valid rename keeps the member under the new name
        on_nick(&mut st, "alice", "alice2");
        let i = rfind(&st.chans[0], "alice2").unwrap();
        assert_eq!(st.chans[0].roster[i].hostmask, "alice2!u@good.host");
        // a long but valid one too
        let long = "l".repeat(30);
        on_nick(&mut st, "alice2", &long);
        assert!(rfind(&st.chans[0], &long).is_some());
        assert_eq!(rfind(&st.chans[0], "alice2"), None);
    }

    #[test]
    fn authorised_verdict_is_cached_until_the_records_change() {
        let mut st = chan_state(&members());
        let e = st.chans[0].roster[1].clone();
        assert!(!entry_authorised(&st, &e));
        assert_eq!(e.auth_gen.get(), st.auth_gen.get());
        // a new record is seen once the fingerprint is retaken (<= 200 ms)
        st.trusted_bots.push(TrustedBot {
            mask: "mallory!*@evil.host".into(),
            uuid: "55555555-5555-4555-8555-555555555555".into(),
            ..TrustedBot::default()
        });
        st.auth_fp_ms.set(st.auth_fp_ms.get() - 201);
        assert!(entry_authorised(&st, &e));
        // a config generation change retires the cache at once
        st.trusted_bots.clear();
        st.cfg_gen += 1;
        assert!(!entry_authorised(&st, &e));
        // a hostmask change (roster_set) forgets the verdict
        assert_eq!(st.chans[0].roster[0].auth_gen.get(), 0);
    }

    /// The sweep on a big channel: 300 members, 200 listed bans, 100 network
    /// bans, 70 masks on the authorised side.  Run with
    /// `cargo test --release sweep_timing -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn sweep_timing() {
        let m: Vec<(String, String)> = (0..300)
            .map(|i| {
                (
                    format!("m{i}"),
                    format!("m{i}!u{i}@h{}.example.net", i % 50),
                )
            })
            .collect();
        let mut st = chan_state(&m);
        for i in 0..40 {
            st.trusted_bots.push(TrustedBot {
                mask: format!("bot{i}!*@bots{i}.example.org"),
                uuid: format!("bot-{i}"),
                ..TrustedBot::default()
            });
        }
        st.user_records.push(UserRecord {
            uuid: "u1".into(),
            name: "op".into(),
            is_active: true,
            typ: 'a',
            ..UserRecord::default()
        });
        for i in 0..30 {
            st.mask_records.push(MaskRecord {
                uuid: "u1".into(),
                mask: format!("*!op{i}@ops{i}.example.org"),
                is_active: true,
                ..MaskRecord::default()
            });
        }
        for i in 0..200 {
            add_live_ban(&mut st, &format!("*!*@ban{i}.example.com"));
        }
        let t = now();
        for i in 0..100 {
            st.cfg_bans.push(crate::state::CfgBan {
                chan: "*".into(),
                mask: format!("*!*@net{i}.example.com"),
                setter: "hub".into(),
                ts: t,
                active: true,
                ..crate::state::CfgBan::default()
            });
        }
        let t0 = std::time::Instant::now();
        ban_sweep(&mut st, 0, t);
        let cold = t0.elapsed();
        let t1 = std::time::Instant::now();
        ban_sweep(&mut st, 0, t);
        println!("ban_sweep: cold {cold:?}, warm {:?}", t1.elapsed());
    }
}
