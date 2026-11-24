//! The bot side of the hub's IRC server pool (2.5.4): pool.c, rule for rule.
//!
//! Plan: irchub/docs/plans/2026-10-29_server_pool_plan.md §5.  A hub-managed
//! bot (hubs non-empty) dials only from the pool the hub sends (N|/S| lines,
//! cached in the .cnf); its local s| lines are dormant.  A standalone bot
//! dials its local s| list.  Either way irc_client::connect works over
//! server_list, which [`servers_rebuild`] fills from the right source.

use sha2::{Digest, Sha256};

use crate::consts::*;
use crate::cstr::{eq_ic, now, strtoll, trunc};
use crate::pool_rec::{
    self, POOL_DEFAULT_NET, POOL_N_LINE_MAX, POOL_S_LINE_MAX, POOL_UUID_LEN, PoolNet, PoolSrv,
    PoolState,
};
use crate::state::{BotState, PoolEntry, S_CONNECTED, ServerBlock, ServerBlockKind, lww_next_ts};
use crate::{config, hub_client, irc_client, ircf, logm};

// ---- records -------------------------------------------------------------

fn find(state: &BotState, uuid: &str) -> Option<usize> {
    state.pool.iter().position(|e| e.s.uuid == uuid)
}

/// The hub's config carried N|/S| lines: drop the cached pool first.
pub fn clear(state: &mut BotState) {
    state.pool.clear();
    state.pool_net = PoolNet::default();
    state.pool_net_ts = 0;
    state.pool_known = false;
}

/// "<value>|<ts>": the value and the stamp; None without a stamp.
fn split_ts(data: &str, cap: usize) -> Option<(&str, i64)> {
    let bar = data.rfind('|')?;
    if bar >= cap {
        return None;
    }
    let tail = &data[bar + 1..];
    let (v, used) = strtoll(tail);
    if used == 0 || used != tail.len() || v < 0 {
        return None;
    }
    Some((&data[..bar], v))
}

/// Store one N| or S| line's data ("<value>|<ts>"); false if malformed.
pub fn ingest_line(state: &mut BotState, tag: u8, data: &str) -> bool {
    let Some((value, ts)) = split_ts(data, POOL_S_LINE_MAX.max(POOL_N_LINE_MAX)) else {
        return false;
    };
    if tag == b'N' {
        let Some(n) = pool_rec::net_parse(value) else {
            return false;
        };
        if n.net_id != POOL_DEFAULT_NET {
            return true; // v1: one network
        }
        if state.pool_known && ts < state.pool_net_ts {
            return true;
        }
        state.pool_net = n;
        state.pool_net_ts = ts;
        state.pool_known = true;
        return true;
    }
    if tag != b'S' {
        return false;
    }
    let Some(s) = pool_rec::srv_parse(value) else {
        return false;
    };
    let i = match find(state, &s.uuid) {
        Some(i) => {
            if ts < state.pool[i].ts {
                return true;
            }
            i
        }
        None => {
            if state.pool.len() >= MAX_POOL_SERVERS + MAX_POOL_TOMBS {
                return false;
            }
            state.pool.push(PoolEntry::default());
            state.pool.len() - 1
        }
    };
    let e = &mut state.pool[i];
    e.s = s;
    e.ts = ts;
    true
}

/// The pool as .cnf lines (N|, then S|); None if it did not fit
/// POOL_RECORDS_MAX (the C buffer) or a record would not format.
pub fn format_lines(state: &BotState) -> Option<String> {
    let mut out = String::new();
    if state.pool_known {
        let v = pool_rec::net_format(&state.pool_net)?;
        out.push_str(&format!("N|{}|{}\n", v, state.pool_net_ts));
    }
    for e in &state.pool {
        let v = pool_rec::srv_format(&e.s)?;
        out.push_str(&format!("S|{}|{}\n", v, e.ts));
    }
    (out.len() < POOL_RECORDS_MAX).then_some(out)
}

fn entry_eligible(e: &PoolEntry) -> bool {
    !e.s.deleted && e.s.state == PoolState::Ok && e.s.net_id == POOL_DEFAULT_NET
}

/// Usable pool entries: live, state ok, in POOL_DEFAULT_NET.
pub fn eligible_count(state: &BotState) -> usize {
    state.pool.iter().filter(|e| entry_eligible(e)).count()
}

// ---- dial list -----------------------------------------------------------

/// The dial string of an entry: always "host:port" (every entry has one).
fn entry_dial(s: &PoolSrv) -> String {
    format!("{}:{}", s.host, s.port)
}

/// Rendezvous score of (this bot, entry): every bot orders the pool its own
/// way, so bots that see no load view yet still spread out.
fn hrw(bot_uuid: &str, entry_uuid: &str) -> u64 {
    let d = Sha256::digest(format!("{bot_uuid}|{entry_uuid}").as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_be_bytes(b)
}

/// Eligible entries (pool indexes) in this bot's HRW order.
fn ranked(state: &BotState) -> Vec<usize> {
    let mut r: Vec<(usize, u64)> = state
        .pool
        .iter()
        .enumerate()
        .filter(|(_, e)| entry_eligible(e))
        .map(|(i, e)| (i, hrw(&state.bot_uuid, &e.s.uuid)))
        .collect();
    r.sort_by(|x, y| {
        y.1.cmp(&x.1)
            .then_with(|| state.pool[x.0].s.uuid.cmp(&state.pool[y.0].s.uuid))
    });
    r.into_iter().map(|(i, _)| i).collect()
}

/// Slot i's identity across rebuilds: its pool uuid, else its dial string.
fn slot_same(uuid_a: &str, dial_a: &str, uuid_b: &str, dial_b: &str) -> bool {
    if !uuid_a.is_empty() || !uuid_b.is_empty() {
        return uuid_a == uuid_b;
    }
    eq_ic(dial_a, dial_b)
}

fn idle_text(state: &BotState) -> String {
    if state.pool_known {
        format!("[POOL] Network {POOL_DEFAULT_NET}: no usable server, waiting for one\n")
    } else {
        "[POOL] Waiting for the hub's server pool before connecting to IRC\n".to_string()
    }
}

/// Rebuild server_list from the pool or the local list, keeping holds and
/// the live slot; logs once when a hub-managed bot has nothing to dial.
/// A 2.5.3 bot's first start on 2.5.4 (and any hub-managed bot that has
/// never held a pool entry): it dials its own s| list until a hub sends S|
/// lines, so a hub it cannot reach never keeps it off IRC.  Any S| at all, a
/// tombstone included (an admin's server del ... force), ends it for good.
/// Legacy: 2.5.5 drops it with the s| purge.
pub fn local_fallback(state: &BotState) -> bool {
    !state.hubs.is_empty() && state.pool.is_empty() && !state.local_servers.is_empty()
}

pub fn servers_rebuild(state: &mut BotState) {
    // Old slots, to carry holds and the live link over.
    let old_dial = std::mem::take(&mut state.server_list);
    let old_uuid = std::mem::take(&mut state.dial_uuid);
    let old_n = old_dial.len();
    let old_block: Vec<ServerBlock> = state.server_blocks.iter().take(old_n).cloned().collect();
    let live_old = if state.status & S_CONNECTED != 0 {
        state.irc_server_idx
    } else {
        None
    };

    let mut list = Vec::new();
    let mut uuids = Vec::new();
    let local = local_fallback(state);
    if local != state.pool_using_local {
        if local {
            let n = state.local_servers.len();
            logm!(
                state,
                L_INFO,
                "[POOL] No server pool from a hub yet: dialing the {} local server{} (s|) until one arrives\n",
                n,
                if n == 1 { "" } else { "s" }
            );
        } else if !state.hubs.is_empty() {
            logm!(
                state,
                L_INFO,
                "[POOL] Server pool received from the hub: dialing it, local s| now dormant\n"
            );
        }
        state.pool_using_local = local;
    }
    if !state.hubs.is_empty() && !local {
        for i in ranked(state) {
            if list.len() >= MAX_SERVERS {
                break;
            }
            let s = &state.pool[i].s;
            list.push(entry_dial(s));
            uuids.push(s.uuid.clone());
        }
    } else {
        for d in state.local_servers.iter().take(MAX_SERVERS) {
            list.push(d.clone());
            uuids.push(String::new());
        }
    }
    let n = list.len();
    state.server_list = list;
    state.dial_uuid = uuids;

    let mut live_new = None;
    state.server_blocks = vec![ServerBlock::default(); MAX_SERVERS];
    for i in 0..n {
        for (j, od) in old_dial.iter().enumerate() {
            if !slot_same(
                &state.dial_uuid[i],
                &state.server_list[i],
                old_uuid.get(j).map_or("", |s| s.as_str()),
                od,
            ) {
                continue;
            }
            if let Some(b) = old_block.get(j) {
                state.server_blocks[i] = b.clone();
            }
            if Some(j) == live_old {
                live_new = Some(i);
            }
            break;
        }
    }

    // A connected bot stays connected (plan D13); a link whose entry is gone
    // just has no slot for a refusal to land on.
    state.irc_server_idx = live_new;
    state.current_server_index = live_new.map_or(0, |i| i + 1);
    state.jump_slot1 = 0; // slots moved: a pending jump by index is void

    let connected = state.status & S_CONNECTED != 0;
    let idle = !state.hubs.is_empty() && n == 0;
    if idle && !state.pool_idle {
        state.pool_idle_warned = 0;
        if !connected {
            let t = idle_text(state);
            logm!(state, L_INFO, "{}", t);
            state.pool_idle_warned = now();
        }
    } else if !idle && state.pool_idle {
        logm!(
            state,
            L_INFO,
            "[POOL] Network {}: {} usable server{} again\n",
            POOL_DEFAULT_NET,
            n,
            if n == 1 { "" } else { "s" }
        );
    }
    state.pool_idle = idle;
    if idle && !connected {
        link_note(state, "idle", Some(""));
    }
}

/// The hourly repeat of the idle line (irc_client::connect).
pub fn idle_warn(state: &mut BotState) {
    let t = idle_text(state);
    logm!(state, L_INFO, "{}", t);
}

/// The pool entry (index into state.pool) a dial slot came from.
pub fn entry_of_slot(state: &BotState, slot: Option<usize>) -> Option<usize> {
    let slot = slot?;
    if slot >= state.server_list.len() {
        return None;
    }
    let u = state.dial_uuid.get(slot)?;
    if u.is_empty() {
        return None;
    }
    find(state, u)
}

/// Pool entries the dial list leaves out (deleted excluded), for `servers`.
pub fn unlisted(state: &BotState, max: usize) -> Vec<usize> {
    state
        .pool
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.s.deleted && !entry_eligible(e))
        .map(|(i, _)| i)
        .take(max)
        .collect()
}

// ---- migration and going hubless -----------------------------------------

/// After a hub config: the one-time migration of local s| into the pool.
pub fn after_hub_config(state: &mut BotState) {
    // pool_hub_seen, not pool_known: the cached pool proves nothing about this
    // link, and a 2.5.3 hub would read an S| push as a phantom bot.
    if !state.pool_hub_seen || state.pool_migrated || !state.hub_authenticated {
        return;
    }
    state.pool_migrated = true;
    if state.local_servers.is_empty() {
        config::write_local_with_state_pass(state);
        return;
    }
    // Every local s| as an S| add stamped 0: it loses to anything a hub holds,
    // a deleted server above all (plan D15); the hub stamps an unknown one.
    // Offered under opt 'h' too: the hub takes a bot's migration once, for
    // POOL_MIGRATE_WINDOW (irchub hub.h), so an opt-h net does not roll onto
    // an empty pool.  The local s| lines stay (dormant) for a 2.5.3 failback;
    // 2.5.5 purges them and ends the opt 'h' exception.
    let cap = MAX_SERVERS * POOL_S_LINE_MAX;
    let mut lines = String::new();
    let mut sent = 0;
    for ls in state.local_servers.clone() {
        let parsed = pool_rec::hostport_parse(&ls).and_then(|(host, port)| {
            pool_rec::srv_uuid(POOL_DEFAULT_NET, &host, port).map(|u| (host, port, u))
        });
        let Some((host, port, uuid)) = parsed else {
            logm!(
                state,
                L_INFO,
                "[POOL] Local server '{}' is not a valid host[:port]; not migrated\n",
                ls
            );
            continue;
        };
        let s = PoolSrv {
            uuid,
            net_id: POOL_DEFAULT_NET.to_string(),
            host,
            port,
            weight: 1,
            max: 0,
            state: PoolState::Ok,
            seen: String::new(),
            deleted: false,
        };
        let Some(v) = pool_rec::srv_format(&s) else {
            continue;
        };
        let line = format!("S|{v}|0\n");
        if lines.len() + line.len() >= cap {
            break;
        }
        lines.push_str(&line);
        sent += 1;
    }
    // In frames of at most POOL_PUSH_CHUNK, split at line boundaries: the hub
    // reads one push into a MAX_BUFFER work buffer, and nothing may be cut.
    let b = lines.as_bytes();
    let mut at = 0;
    while at < b.len() {
        let mut n = b.len() - at;
        if n > POOL_PUSH_CHUNK {
            n = POOL_PUSH_CHUNK;
            while n > 0 && b[at + n - 1] != b'\n' {
                n -= 1;
            }
        }
        // a cut after '\n' is on a char boundary (ASCII byte)
        if n == 0 || !hub_client::push_lines(state, &lines[at..at + n]) {
            state.pool_migrated = false; // the next config tries again
            return;
        }
        at += n;
    }
    logm!(
        state,
        L_INFO,
        "[POOL] Offered {} local server{} to the hub's pool\n",
        sent,
        if sent == 1 { "" } else { "s" }
    );
    config::write_local_with_state_pass(state);
}

/// The last hub was removed: the usable pool becomes the local s| list.
pub fn go_hubless(state: &mut BotState) {
    let r = ranked(state);
    if state.pool.is_empty() {
        // Never got a pool (an emptied one keeps its tombstones): the local
        // list is all it has.
        state.pool_migrated = false;
        servers_rebuild(state);
        return;
    }
    state.local_servers.clear();
    // The server it is on first, then this bot's HRW order.
    let live = match state.irc_server_idx {
        Some(i) if state.status & S_CONNECTED != 0 && i < state.server_list.len() => {
            state.dial_uuid.get(i).cloned().unwrap_or_default()
        }
        _ => String::new(),
    };
    for pass in 0..2 {
        for &i in &r {
            if state.local_servers.len() >= MAX_SERVERS {
                break;
            }
            let is_live = !live.is_empty() && state.pool[i].s.uuid == live;
            if (pass == 0) != is_live {
                continue;
            }
            let d = entry_dial(&state.pool[i].s);
            state.local_servers.push(d);
        }
    }
    // The pool is the hub's; without one it has nothing to keep it current.
    // N| stays: it is the network check standalone too.
    state.pool.clear();
    state.pool_migrated = false;
    let n = state.local_servers.len();
    logm!(
        state,
        L_INFO,
        "[POOL] Hubless: pool -> {} local server{}\n",
        n,
        if n == 1 { "" } else { "s" }
    );
    servers_rebuild(state);
}

// ---- +server / -server ---------------------------------------------------

fn local_find(state: &BotState, hostport: &str) -> bool {
    state.local_servers.iter().any(|s| eq_ic(s, hostport))
}

/// A pool push from this bot: refused under opt h (the hub refuses it too).
fn push_ok(state: &BotState) -> Result<(), String> {
    if state.is_opt_set(OPT_HUB_ONLY_MUTATIONS) {
        return Err(
            "the server pool is managed on the hub (opt h); use the hub console 'server add/del'"
                .into(),
        );
    }
    if !state.pool_hub_seen || !state.hub_authenticated {
        return Err("no hub link with a server pool yet".into());
    }
    Ok(())
}

fn push_entry(state: &mut BotState, e: &PoolEntry) -> bool {
    let Some(v) = pool_rec::srv_format(&e.s) else {
        return false;
    };
    let line = format!("S|{}|{}\n", v, e.ts);
    hub_client::push_lines(state, &line)
}

/// +server: the local list (standalone) or an S| add pushed to the hub's
/// pool (hub-managed).  Err holds the reason for the admin.
pub fn servers_add(state: &mut BotState, hostport: &str) -> Result<(), String> {
    let Some((host, port)) = pool_rec::hostport_parse(hostport) else {
        return Err(format!("'{hostport}' is not host[:port]"));
    };
    if state.hubs.is_empty() {
        if local_find(state, hostport) {
            return Err(format!("'{hostport}' is already listed"));
        }
        if state.local_servers.len() >= MAX_SERVERS {
            return Err(format!("the server list is full ({MAX_SERVERS})"));
        }
        state.local_servers.push(hostport.to_string());
        servers_rebuild(state);
        config::write_with_state_pass(state);
        return Ok(());
    }
    push_ok(state)?;
    let Some(uuid) = pool_rec::srv_uuid(POOL_DEFAULT_NET, &host, port) else {
        return Err(format!("'{hostport}' is not host[:port]"));
    };
    let ei = find(state, &uuid);
    if let Some(i) = ei
        && !state.pool[i].s.deleted
    {
        return Err(format!("'{hostport}' is already in the pool"));
    }
    if ei.is_none() && state.pool.len() >= MAX_POOL_SERVERS + MAX_POOL_TOMBS {
        return Err("the pool is full".into());
    }
    let old = ei.map(|i| state.pool[i].clone());
    let next = PoolEntry {
        s: PoolSrv {
            uuid,
            net_id: POOL_DEFAULT_NET.to_string(),
            host,
            port,
            weight: old.as_ref().map_or(1, |e| e.s.weight),
            max: old.as_ref().map_or(0, |e| e.s.max),
            state: PoolState::Ok,
            seen: String::new(),
            deleted: false,
        },
        ts: lww_next_ts(old.as_ref().map_or(0, |e| e.ts)),
        load_up: old.as_ref().map_or(0, |e| e.load_up),
        load_conn: old.as_ref().map_or(0, |e| e.load_conn),
    };
    if !push_entry(state, &next) {
        return Err("could not send it to the hub".into());
    }
    match ei {
        Some(i) => state.pool[i] = next,
        None => state.pool.push(next),
    }
    servers_rebuild(state);
    config::write_local_with_state_pass(state);
    Ok(())
}

/// -server: off the local list (standalone) or an S| delete pushed to the
/// hub's pool (hub-managed).
pub fn servers_del(state: &mut BotState, what: &str) -> Result<(), String> {
    if state.hubs.is_empty() {
        let Some(i) = state.local_servers.iter().position(|s| eq_ic(s, what)) else {
            return Err(format!("server '{what}' not found"));
        };
        state.local_servers.remove(i);
        servers_rebuild(state);
        config::write_with_state_pass(state);
        return Ok(());
    }
    push_ok(state)?;
    let mut ei = None;
    if what.len() == POOL_UUID_LEN {
        ei = find(state, what);
    }
    if ei.is_none()
        && let Some((host, port)) = pool_rec::hostport_parse(what)
        && let Some(u) = pool_rec::srv_uuid(POOL_DEFAULT_NET, &host, port)
    {
        ei = find(state, &u);
    }
    let Some(i) = ei.filter(|&i| !state.pool[i].s.deleted) else {
        return Err(format!("server '{what}' is not in the pool"));
    };
    if entry_eligible(&state.pool[i]) && eligible_count(state) <= 1 {
        let h = &state.pool[i].s.host;
        return Err(format!(
            "{h} is the last usable server of network {POOL_DEFAULT_NET} -- removing it could take all \
bots off IRC; add another first, or use the hub console 'server del {h} force'"
        ));
    }
    let mut next = state.pool[i].clone();
    next.s.deleted = true;
    next.ts = lww_next_ts(state.pool[i].ts);
    if !push_entry(state, &next) {
        return Err("could not send it to the hub".into());
    }
    state.pool[i] = next;
    servers_rebuild(state);
    config::write_local_with_state_pass(state);
    Ok(())
}

/// The pool changed (hub config): wrong-network holds go, list rebuilt.
pub fn changed(state: &mut BotState) {
    // A new N| or a cleared entry may make a wrong-network server right: the
    // next connect checks it again.
    let n = state.server_list.len().min(state.server_blocks.len());
    for b in &mut state.server_blocks[..n] {
        if b.kind == ServerBlockKind::WrongNet {
            *b = ServerBlock::default();
        }
    }
    servers_rebuild(state);
}

// ---- the NETWORK= check (plan §5.4) --------------------------------------

/// Armed at 001, decided at 376/422 or after NETCHECK_WAIT; channel joins
/// wait for it to pass.
pub fn netcheck_arm(state: &mut BotState) {
    state.net_check = 1;
    state.net_check_deadline = now() + NETCHECK_WAIT;
}

pub fn netcheck_passed(state: &BotState) -> bool {
    state.net_check == 2
}

fn netcheck_report(state: &mut BotState, kind: &str) {
    // a local server or a jump: no pool entry to report on
    let Some(i) = entry_of_slot(state, state.irc_server_idx) else {
        return;
    };
    let payload = format!(
        "{}|{}|{}|{}",
        state.pool[i].s.uuid,
        kind,
        state.isup.network,
        trunc(&state.actual_server_name, 256)
    );
    hub_client::send_server_report(state, &payload);
}

fn netcheck_decide(state: &mut BotState) {
    let net = state.isup.network.clone();
    let learned = state.pool_known && !state.pool_net.name.is_empty();
    if !learned || (!net.is_empty() && pool_rec::net_matches(&state.pool_net, &net)) {
        state.net_check = 2;
        if !learned && !net.is_empty() && state.hubs.is_empty() {
            // Standalone: learn the network locally, then lock it (plan D6).
            state.pool_net = PoolNet {
                net_id: POOL_DEFAULT_NET.to_string(),
                label: POOL_DEFAULT_NET.to_string(),
                name: net.clone(),
                ..PoolNet::default()
            };
            state.pool_net_ts = now();
            state.pool_known = true;
            logm!(state, L_INFO, "[POOL] Network learned: {}\n", net);
            config::write_local_with_state_pass(state);
        }
        // ok, with the name the hub learns it from; no token while nothing is
        // learned is fine and says nothing (the hub would count "unverified"
        // as a strike against the entry).
        if !net.is_empty() {
            netcheck_report(state, "ok");
        }
        return;
    }
    // The wrong network, or none named once one is known: off at once.
    let idx = state.irc_server_idx;
    let srv = if state.actual_server_name.is_empty() {
        "server".to_string()
    } else {
        state.actual_server_name.clone()
    };
    let expected = state.pool_net.name.clone();
    logm!(
        state,
        L_INFO,
        "[POOL] {} says NETWORK={}, expected {}: wrong network, disconnecting\n",
        srv,
        if net.is_empty() {
            "(none)"
        } else {
            net.as_str()
        },
        expected
    );
    netcheck_report(
        state,
        if net.is_empty() {
            "unverified"
        } else {
            "wrongnet"
        },
    );
    if let Some(i) = idx
        && i < state.server_list.len()
        && i < state.server_blocks.len()
    {
        let b = &mut state.server_blocks[i];
        b.kind = ServerBlockKind::WrongNet;
        b.until = now() + WRONGNET_HOLD;
        b.reason = if net.is_empty() {
            "(no NETWORK=)".to_string()
        } else {
            net
        };
    }
    ircf!(state, "QUIT :wrong network\r\n");
    irc_client::disconnect(state);
}

pub fn netcheck_end_of_motd(state: &mut BotState) {
    if state.net_check == 1 {
        netcheck_decide(state);
    }
}

pub fn netcheck_tick(state: &mut BotState) {
    if state.net_check == 1 && now() >= state.net_check_deadline {
        netcheck_decide(state);
    }
}

// ---- the IRC link state to the hub (CMD_BOT_IRC_LINK) --------------------

fn link_send(state: &mut BotState) {
    if state.irc_link.is_empty() {
        return;
    }
    let payload = format!(
        "{}|{}|{}|",
        POOL_DEFAULT_NET,
        if state.irc_link_entry.is_empty() {
            "-"
        } else {
            state.irc_link_entry.as_str()
        },
        state.irc_link
    );
    if payload == state.irc_link_sent {
        return;
    }
    if hub_client::send_irc_link(state, &payload) {
        state.irc_link_sent = payload;
    }
}

/// The IRC link changed (connecting with the entry, up, down, idle); sent to
/// the hub when it takes it.  `entry` None keeps the last one.
pub fn link_note(state: &mut BotState, link: &str, entry: Option<&str>) {
    state.irc_link = trunc(link, 12).to_string();
    if let Some(e) = entry {
        state.irc_link_entry = trunc(e, POOL_UUID_LEN + 1).to_string();
    }
    link_send(state);
}

/// After a fresh hub link (its config): the link state again.
pub fn link_resend(state: &mut BotState) {
    link_send(state);
}

// ---- load-aware pick (plan §5.3) -----------------------------------------

/// One "%d" of sscanf: optional C whitespace and sign, then digits; the
/// value and the rest.  Values past i64 saturate (rejected by the caller's
/// range check).
fn scan_int(s: &str) -> Option<(i64, &str)> {
    let (v, used) = strtoll(s);
    (used > 0).then(|| (v, &s[used..]))
}

/// "E|<uuid>|<up>|<conn>" as sscanf("%36[0-9a-f-]|%d|%d%c") == 3 reads it.
fn view_line(line: &str) -> Option<(&str, i64, i64)> {
    let rest = line.strip_prefix("E|")?;
    let ul = rest
        .bytes()
        .take(POOL_UUID_LEN)
        .take_while(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c) || c == b'-')
        .count();
    if ul == 0 {
        return None;
    }
    let uuid = &rest[..ul];
    let rest = rest[ul..].strip_prefix('|')?;
    let (up, rest) = scan_int(rest)?;
    let rest = rest.strip_prefix('|')?;
    let (conn, rest) = scan_int(rest)?;
    rest.is_empty().then_some((uuid, up, conn))
}

/// CMD_POOL_VIEW: the hub's per-entry load, whole each time.
pub fn view_apply(state: &mut BotState, payload: &str) {
    for e in &mut state.pool {
        e.load_up = 0;
        e.load_conn = 0;
    }
    for line in payload.split('\n') {
        let ll = line.len();
        if ll >= POOL_UUID_LEN + 48 || ll <= 2 {
            continue;
        }
        let Some((uuid, up, conn)) = view_line(line) else {
            continue;
        };
        if !(0..=100_000).contains(&up) || !(0..=100_000).contains(&conn) {
            continue;
        }
        if let Some(i) = find(state, uuid) {
            state.pool[i].load_up = up as i32;
            state.pool[i].load_conn = conn as i32;
        }
    }
    state.pool_view_at = now();
}

/// Hub-managed pick: the eligible slot with the lowest load per weight (its
/// HRW order breaks ties), skipping slots at their max unless all are; None
/// if every slot is held.  The second value is the earliest hold to end.
pub fn pick_slot(state: &BotState, now: i64) -> (Option<usize>, i64) {
    let mut best: Option<(usize, i64)> = None;
    let mut best_over: Option<(usize, i64)> = None;
    let mut soonest = 0i64;
    for i in 0..state.server_list.len().min(state.server_blocks.len()) {
        let b = &state.server_blocks[i];
        if b.kind == ServerBlockKind::BannedPerm {
            continue;
        }
        if b.kind != ServerBlockKind::None && b.until > now {
            if soonest == 0 || b.until < soonest {
                soonest = b.until;
            }
            continue;
        }
        let e = entry_of_slot(state, Some(i)).map(|k| &state.pool[k]);
        let load = e.map_or(0, |e| i64::from(e.load_up) + i64::from(e.load_conn));
        let w = e.map_or(1, |e| {
            if e.s.weight > 0 {
                i64::from(e.s.weight)
            } else {
                1
            }
        });
        // slots are in HRW order: first wins a tie
        let mut cost = load * 1000 / w;
        // a slot whose last attempt failed lately goes behind every other one
        if b.last_fail != 0 && now - b.last_fail < POOL_FAIL_AVOID {
            cost += 1_000_000_000;
        }
        let over = e.is_some_and(|e| e.s.max > 0 && load >= i64::from(e.s.max));
        if !over && best.is_none_or(|(_, c)| cost < c) {
            best = Some((i, cost));
        }
        if over && best_over.is_none_or(|(_, c)| cost < c) {
            best_over = Some((i, cost));
        }
    }
    (best.or(best_over).map(|(i, _)| i), soonest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_line_caps_match_pool_rec() {
        assert_eq!(
            crate::consts::POOL_N_LINE_MAX_CFG,
            crate::pool_rec::POOL_N_LINE_MAX
        );
        assert_eq!(
            crate::consts::POOL_S_LINE_MAX_CFG,
            crate::pool_rec::POOL_S_LINE_MAX
        );
    }

    #[test]
    fn view_lines() {
        let u = "60be3bd3-8d40-8411-81ac-96a777cd8710";
        assert_eq!(view_line(&format!("E|{u}|3|1")), Some((u, 3, 1)));
        assert_eq!(view_line(&format!("E|{u}| 3|+1")), Some((u, 3, 1)));
        assert!(view_line(&format!("E|{u}|3|1 ")).is_none());
        assert!(view_line(&format!("E|{u}|3")).is_none());
        assert!(view_line("E||3|1").is_none());
    }

    #[test]
    fn stamps() {
        assert_eq!(split_ts("a|b|12", 100), Some(("a|b", 12)));
        assert!(split_ts("a|b|", 100).is_none());
        assert!(split_ts("a|b|-1", 100).is_none());
        assert!(split_ts("a|b|1x", 100).is_none());
        assert!(split_ts("ab", 100).is_none());
    }
}
