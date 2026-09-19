//! Bot-to-bot commands sealed with the peers' public keys (~B2,
//! irchub/docs/passwordless.md 5):
//!
//!   ~B2 <b64( eph_pub(32) || iv(12) || ct || tag(16) )>
//!   pt  = "<ts>:<nonce16hex>:<OPME|SETNICK|INVITE|UNBAN|KEY|KEYIS ...>"
//!   ikm = X25519(eph, R_x) || X25519(S_x, R_x)
//!   AAD = B2_LABEL "\0" sender_uuid "\0" recipient_uuid
//!
//! Carried by the hub relay (opaque to the hub) when connected, else by
//! direct PRIVMSG.  Only the holder of the sender's private key can produce a
//! frame that opens, so the b| pubkey is the whole trust anchor.

use crate::consts::*;
use crate::cstr::{eq_ic, now, Tok};
use crate::state::{has_control_bytes, is_rfc_nick, BotState, ChanReq, ChanStatus};
use crate::{auth, channel, config, crypto, hub_client, ircf, logm};

/// Strict "<ts>:<nonce>:<command>" parser shared by ~A2 and ~B2: ts 1..19
/// digits, nonce exactly 16 lower-case hex, a non-empty command.
pub fn envelope_parse(pt: &str) -> Option<(i64, u64, &str)> {
    let b = pt.as_bytes();
    let nd = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if nd == 0 || nd > 19 || b.get(nd) != Some(&b':') {
        return None;
    }
    let q = &b[nd + 1..];
    if q.len() < 18 || !q[..16].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) || q[16] != b':' {
        return None;
    }
    let ts: i64 = pt[..nd].parse().ok()?;
    let nonce = u64::from_str_radix(&pt[nd + 1..nd + 17], 16).ok()?;
    Some((ts, nonce, &pt[nd + 18..]))
}

fn b2_aad(sender_uuid: &str, recipient_uuid: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(B2_LABEL.len() + sender_uuid.len() + recipient_uuid.len() + 2);
    aad.extend_from_slice(B2_LABEL.as_bytes());
    aad.push(0);
    aad.extend_from_slice(sender_uuid.as_bytes());
    aad.push(0);
    aad.extend_from_slice(recipient_uuid.as_bytes());
    aad
}

/// Open a ~B2 frame from trusted bot `ti` and run it.  `sender_nick` is the
/// PRIVMSG source (None on the relay path): OPME ops that nick, so it only
/// works over PRIVMSG.
fn open_and_dispatch(state: &mut BotState, ti: usize, b64: &str, sender_nick: Option<&str>) {
    let sender = state.trusted_bots[ti].clone();
    if !sender.has_pub || sender.uuid.is_empty() {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 from {} dropped: no public key on file yet\n", sender.mask);
        return;
    }
    if !state.self_pub_set || state.bot_uuid.is_empty() {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 dropped: no identity key\n");
        return;
    }
    if b64.len() > A2_B64_MAX {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 from {} oversized; dropped\n", sender.mask);
        return;
    }
    let frame = match crypto::b64_decode(b64) {
        Some(f) if f.len() >= SEAL_OVERHEAD => f,
        _ => {
            logm!(state, L_CMD, "[BOT-COMM] ~B2 from {} malformed; dropped\n", sender.mask);
            return;
        }
    };
    let aad = b2_aad(&sender.uuid, &state.bot_uuid);
    let (_, self_x) = crypto::pub_halves(&state.self_pub);
    let (_, sender_x) = crypto::pub_halves(&sender.pub_key);
    let pt = hub_client::bot_key_decode(state)
        .and_then(|(_ed, x)| crypto::open(&x, &self_x, Some(&sender_x), B2_LABEL, &aad, &frame));
    let Some(pt) = pt else {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 from {} did not open; dropped\n", sender.mask);
        return;
    };
    if has_control_bytes(&pt) {
        logm!(state, L_CMD, "[BOT-COMM] Control character in command from {}; dropped\n", sender.mask);
        return;
    }
    let pt = zeroize::Zeroizing::new(String::from_utf8_lossy(&pt).into_owned());
    let Some((ts, nonce, cmd)) = envelope_parse(&pt) else {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 from {}: bad envelope\n", sender.mask);
        return;
    };
    let now = now();
    if (now - ts).abs() > B2_TS_SKEW {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 from {}: stale timestamp\n", sender.mask);
        return;
    }
    if state.recent_nonces.seen(nonce, now) {
        logm!(state, L_CMD, "[BOT-COMM] ~B2 replay from {}; dropped\n", sender.mask);
        return;
    }
    state.recent_nonces.record(nonce, now);
    logm!(
        state,
        L_DEBUG,
        "[BOT-COMM] ~B2 verified from {} ({})\n",
        sender.uuid,
        if sender_nick.is_some() { "privmsg" } else { "hub relay" }
    );

    let mut t = Tok::new(cmd);
    let (Some(verb), Some(arg1)) = (t.next(" "), t.next(" ")) else { return };
    if eq_ic(verb, "OPME") {
        if let Some(n) = sender_nick {
            ircf!(state, "MODE {} +o {}\r\n", arg1, n);
        }
    } else if eq_ic(verb, "SETNICK") {
        if is_rfc_nick(arg1) {
            state.target_nick = arg1.to_string();
            state.current_nick_ts = crate::cstr::now();
            let ts = state.current_nick_ts;
            hub_client::push_delta(state, "n", arg1, ts);
            config::write_with_state_pass(state);
        } else {
            logm!(state, L_INFO, "[BOT-COMM] SETNICK from {} refused: '{}' is not a valid IRC nick\n", sender.uuid, arg1);
        }
    } else if eq_ic(verb, "INVITE") {
        if let Some(arg2) = t.next(" ") {
            if let Some(ci) = channel::find(state, arg1) {
                if state.chans[ci].status == ChanStatus::In && state.chans[ci].i_am_opped {
                    logm!(state, L_INFO, "[BOT-COMMS] Inviting {} to {} (bot req)\n", arg2, arg1);
                    ircf!(state, "INVITE {} {}\r\n", arg2, arg1);
                }
            }
        }
    } else if eq_ic(verb, "UNBAN") {
        // The mask matched against the ban list is the sender's own b|
        // record, never anything in the message.
        channel::access_service(state, "", ChanReq::Unban, arg1, None, Some(&sender.mask), None);
    } else if eq_ic(verb, "KEY") {
        match sender_nick {
            Some(n) => channel::access_service(state, "", ChanReq::Key, arg1, None, None, Some(n)),
            None => logm!(
                state,
                L_DEBUG,
                "[DEBUG] [BOT-COMM] KEY over hub relay has no reply nick; the hub path answers these\n"
            ),
        }
    } else if eq_ic(verb, "KEYIS") {
        if let Some(arg2) = t.next(" ") {
            channel::access_accept_key(state, arg1, arg2);
        }
    }
}

/// Hub-relayed CMD_BOT_MSG: "<sender_uuid>|~B2 <b64>".  The UUID is the one
/// the hub authenticated; it only selects which b| key must open the frame.
pub fn process_payload(state: &mut BotState, payload: &str) {
    let Some(bar) = payload.find('|') else { return };
    let uuid = &payload[..bar];
    if uuid.is_empty() || uuid.len() >= UUID_BUF {
        return;
    }
    let Some(b64) = payload[bar + 1..].strip_prefix("~B2 ") else {
        logm!(state, L_CMD, "[BOT-COMM] Relayed frame from {} is not ~B2 (pre-passwordless sender?); dropped\n", uuid);
        return;
    };
    match auth::trusted_bot_by_uuid(state, uuid) {
        Some(ti) => open_and_dispatch(state, ti, b64, None),
        None => logm!(state, L_CMD, "[BOT-COMM] Relayed ~B2 from unknown bot {}\n", uuid),
    }
}

/// Direct PRIVMSG: true if it was a ~B2 frame (handled or dropped), so the
/// caller stops processing it.
pub fn handle_privmsg(state: &mut BotState, nick: &str, user_host: &str, message: &str) -> bool {
    let Some(b64) = message.strip_prefix("~B2 ") else { return false };
    match auth::trusted_bot_by_host(state, user_host) {
        Some(ti) => open_and_dispatch(state, ti, b64, Some(nick)),
        None => logm!(state, L_CMD, "[BOT-COMM] ~B2 from untrusted {} dropped\n", user_host),
    }
    true
}

/// Seal `command` to trusted bot `ti` and deliver it to IRC nick
/// `target_nick` (hub relay when connected, else PRIVMSG).
fn b2_send(state: &mut BotState, ti: Option<usize>, target_nick: &str, command: &str) {
    let tb = match ti.map(|i| state.trusted_bots[i].clone()) {
        Some(tb) if tb.has_pub && !tb.uuid.is_empty() => tb,
        _ => {
            logm!(state, L_DEBUG, "[BOT-COMM] Cannot send to {}: no public key on file\n", target_nick);
            return;
        }
    };
    if !state.self_pub_set || state.bot_uuid.is_empty() {
        logm!(state, L_DEBUG, "[BOT-COMM] Cannot send: no identity key\n");
        return;
    }
    if command.len() >= 256 {
        return;
    }
    let mut rnd = [0u8; 8];
    if !crypto::random_bytes(&mut rnd) {
        return;
    }
    let nonce: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let pt = zeroize::Zeroizing::new(format!("{}:{}:{}", now(), nonce, command));
    if pt.len() >= 512 {
        return;
    }
    let aad = b2_aad(&state.bot_uuid, &tb.uuid);
    let (_, self_x) = crypto::pub_halves(&state.self_pub);
    let (_, peer_x) = crypto::pub_halves(&tb.pub_key);
    let frame = hub_client::bot_key_decode(state)
        .and_then(|(_ed, x)| crypto::seal(Some((&x, &self_x)), &peer_x, B2_LABEL, &aad, pt.as_bytes()));
    drop(pt);
    let Some(frame) = frame else {
        logm!(state, L_INFO, "[BOT-COMM] Sealing to {} failed\n", target_nick);
        return;
    };
    let line = format!("~B2 {}", crypto::b64_encode(&frame));
    if line.len() >= 1024 {
        return;
    }
    let mut sent_via_hub = false;
    if state.hub_connected && state.hub_authenticated && state.hub.is_some() {
        logm!(state, L_DEBUG, "[BOT-COMM] Relaying {} to {} via hub\n", command, target_nick);
        sent_via_hub = hub_client::relay_bot_command(state, &tb.uuid, &line);
    }
    if !sent_via_hub {
        logm!(state, L_DEBUG, "[BOT-COMM] Sending ~B2 PRIVMSG to {}: {}\n", target_nick, command);
        ircf!(state, "PRIVMSG {} :{}\r\n", target_nick, line);
    }
}

/// To a trusted bot addressed by nick (its mask's nick part).
pub fn send_command(state: &mut BotState, target_nick: &str, command: &str) {
    let ti = auth::trusted_bot_by_nick(state, target_nick);
    b2_send(state, ti, target_nick, command);
}

/// To the trusted bot whose mask matches `hostmask`, at IRC nick
/// `target_nick` (a roster nick may carry a collision suffix).
pub fn send_to_host(state: &mut BotState, hostmask: &str, target_nick: &str, command: &str) {
    let ti = auth::trusted_bot_by_host(state, hostmask);
    b2_send(state, ti, target_nick, command);
}

#[cfg(test)]
mod tests {
    use super::envelope_parse;

    #[test]
    fn envelope_shapes() {
        assert_eq!(envelope_parse("123:0123456789abcdef:OPME #x"), Some((123, 0x0123456789abcdef, "OPME #x")));
        assert!(envelope_parse("123:0123456789ABCDEF:x").is_none());
        assert!(envelope_parse("123:0123456789abcdef:").is_none());
        assert!(envelope_parse(":0123456789abcdef:x").is_none());
        assert!(envelope_parse("12345678901234567890:0123456789abcdef:x").is_none());
    }
}
