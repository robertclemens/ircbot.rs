//! Outbound-only DCC CHAT for admins (dcc.c, irchub/docs/passwordless.md
//! 4.6).
//!
//! The bot never listens.  An admin sends the sealed command `dcc`; the bot
//! answers with a passive offer
//!     PRIVMSG <nick> :\1DCC CHAT chat <our ip> 0 <token>\1
//! the admin's client listens on a port from its own range and replies from
//! the same nick!user@host with
//!     PRIVMSG <bot> :\1DCC CHAT chat <its ip> <port> <token>\1
//! (or a plain offer with no token while ours is open), and the bot connects
//! out.  The chat is only a transport: every line must be a sealed ~A2 frame
//! from the admin who asked, or the chat closes.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use zeroize::Zeroize;

use crate::consts::*;
use crate::cstr::{eq_ic, now, trunc_string, Tok};
use crate::net;
use crate::state::BotState;
use crate::{commands, crypto, ircf, logm};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DccPhase {
    #[default]
    Free,
    /// Passive offer sent; waiting for the client's address.
    Offered,
    /// Non-blocking connect in progress.
    Connecting,
    Open,
}

/// One chat.  Everything is fixed when the admin asks: the reply must come
/// from user_host, and only uuid's key opens a frame, with nick and botnick
/// as the ~A2 context.
#[derive(Default)]
pub struct DccSession {
    pub phase: DccPhase,
    pub sock: Option<mio::net::TcpStream>,
    pub token: Option<mio::Token>,
    pub dcc_token: u32,
    pub phase_since: i64,
    pub last_active: i64,
    /// Write error or overflow: close at the next check.
    pub failed: bool,
    pub nick: String,
    pub botnick: String,
    pub user_host: String,
    pub uuid: String,
    pub name: String,
    pub peer: String,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
}

impl DccSession {
    fn wipe(&mut self) {
        self.inbuf.zeroize();
        self.outbuf.zeroize();
        *self = DccSession::default();
    }
}

/// Release a slot: close the socket and wipe everything it held.
fn free(state: &mut BotState, i: usize) {
    if let Some(mut s) = state.dcc[i].sock.take() {
        let _ = state.registry.deregister(&mut s);
    }
    if state.dcc_reply == Some(i) {
        state.dcc_reply = None;
    }
    state.dcc[i].wipe();
}

/// Queue one line (text + "\n") and try to send it.  Past DCC_OUTBUF_MAX
/// the chat is marked failed (a client that stopped reading).
fn queue(s: &mut DccSession, text: &[u8]) {
    if s.phase != DccPhase::Open || s.failed {
        return;
    }
    if s.outbuf.len() + text.len() + 1 > DCC_OUTBUF_MAX {
        s.failed = true;
        return;
    }
    s.outbuf.extend_from_slice(text);
    s.outbuf.push(b'\n');
    flush(s);
}

fn flush(s: &mut DccSession) {
    if let Some(sock) = s.sock.as_mut() {
        if net::flush(sock, &mut s.outbuf).is_err() {
            s.failed = true;
        }
    }
}

/// Close a chat; an open one is told why first (one send attempt).
fn close(state: &mut BotState, i: usize, reason: Option<&str>) {
    if let Some(r) = reason {
        queue(&mut state.dcc[i], r.as_bytes());
    }
    let s = &state.dcc[i];
    logm!(
        state,
        L_INFO,
        "[DCC] Closed chat with {} ({}){}{}\n",
        s.name,
        s.user_host,
        if reason.is_some() { ": " } else { "" },
        reason.unwrap_or("")
    );
    free(state, i);
}

/// The one reply channel a chat that never opened has: PRIVMSG on IRC.
fn give_up(state: &mut BotState, i: usize, why: &str) {
    let (name, uh, nick) = (state.dcc[i].name.clone(), state.dcc[i].user_host.clone(), state.dcc[i].nick.clone());
    logm!(state, L_INFO, "[DCC] Chat for {} ({}) abandoned: {}\n", name, uh, why);
    ircf!(state, "PRIVMSG {} :DCC chat not opened: {}\r\n", nick, why);
    free(state, i);
}

pub fn close_all(state: &mut BotState, reason: &str) {
    for i in 0..state.dcc.len() {
        match state.dcc[i].phase {
            DccPhase::Open => close(state, i, Some(reason)),
            DccPhase::Free => {}
            _ => free(state, i),
        }
    }
}

/// `dcc` from an admin (user record `who`): make a passive offer.
pub fn offer(state: &mut BotState, nick: &str, user_host: &str, who: usize) {
    if nick.len() >= A2_NICK_MAX || user_host.len() >= MAX_MASK_LEN {
        ircf!(state, "PRIVMSG {} :Error: your nick or mask is too long for a DCC chat.\r\n", nick);
        return;
    }
    // Our address, only because clients reject a zero one: the receiver of
    // a passive offer never connects to it.
    let ip = match state.irc.as_ref().and_then(|c| c.sock.local_addr().ok()).map(|a| a.ip()) {
        Some(IpAddr::V4(v4)) => u32::from(v4).to_string(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => u32::from(v4).to_string(),
            None => v6.to_string(),
        },
        None => String::new(),
    };
    if ip.is_empty() {
        ircf!(state, "PRIVMSG {} :Error: cannot offer a DCC chat right now (no IRC connection).\r\n", nick);
        return;
    }
    let mut rnd = [0u8; 4];
    if !crypto::random_bytes(&mut rnd) {
        ircf!(state, "PRIVMSG {} :Error: RNG failure.\r\n", nick);
        return;
    }
    // Clients read the passive id as a positive int; 0 means "none".
    let mut token = u32::from_be_bytes(rnd) & 0x7fff_ffff;
    if token == 0 {
        token = 1;
    }
    let (who_uuid, who_name) = (state.user_records[who].uuid.clone(), state.user_records[who].name.clone());

    // One chat per user: a new request replaces any earlier one.
    for i in 0..state.dcc.len() {
        if state.dcc[i].phase != DccPhase::Free && state.dcc[i].uuid == who_uuid {
            if state.dcc[i].phase == DccPhase::Open {
                close(state, i, Some("Replaced by a new DCC request."));
            } else {
                free(state, i);
            }
        }
    }
    let Some(i) = state.dcc.iter().position(|s| s.phase == DccPhase::Free) else {
        ircf!(
            state,
            "PRIVMSG {} :Error: all {} DCC chat slots are in use; try again later.\r\n",
            nick,
            DCC_MAX_SESSIONS
        );
        return;
    };
    let botnick = trunc_string(&state.current_nick, MAX_NICK);
    let s = &mut state.dcc[i];
    s.phase = DccPhase::Offered;
    s.sock = None;
    s.dcc_token = token;
    s.phase_since = now();
    s.nick = nick.to_string();
    s.botnick = botnick.clone();
    s.user_host = user_host.to_string();
    s.uuid = who_uuid;
    s.name = who_name.clone();

    ircf!(state, "PRIVMSG {} :\x01DCC CHAT chat {} 0 {}\x01\r\n", nick, ip, token);
    ircf!(
        state,
        "PRIVMSG {} :DCC chat offered; accept it within {} s (irssi: /dcc chat {}). I connect out to your client, so open its DCC port range in your firewall and set its DCC address to your public IP. A client without passive DCC can /dcc chat {} instead while this offer is open.\r\n",
        nick,
        DCC_OFFER_TIMEOUT,
        botnick,
        botnick
    );
    logm!(state, L_INFO, "[DCC] Offered a chat to {} ({})\n", who_name, user_host);
}

/// The address field of an offer: classic decimal IPv4, or a literal IPv6
/// or dotted IPv4 -- never a hostname.  IPv4-mapped IPv6 becomes IPv4.
fn parse_addr(a: &str, port: u16) -> Option<SocketAddr> {
    if a.is_empty() || a.len() >= 46 {
        return None;
    }
    let ip = if a.bytes().all(|c| c.is_ascii_digit()) {
        if a.len() > 10 {
            return None;
        }
        let v: u64 = a.parse().ok()?;
        IpAddr::V4(Ipv4Addr::from(u32::try_from(v).ok()?))
    } else if a.contains(':') {
        let v6: Ipv6Addr = a.parse().ok()?;
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        }
    } else {
        IpAddr::V4(a.parse::<Ipv4Addr>().ok()?)
    };
    Some(SocketAddr::new(ip, port))
}

/// Never unspecified, link-local (169.254/16: cloud metadata), multicast,
/// broadcast or reserved.  Loopback and private ranges stay allowed.
fn addr_allowed(sa: &SocketAddr) -> bool {
    match sa.ip() {
        IpAddr::V4(v4) => {
            let a = u32::from(v4);
            !((a >> 24) == 0 || (a >> 16) == 0xA9FE || (a >> 28) >= 0xE)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            !(v6.is_unspecified() || (seg[0] & 0xffc0) == 0xfe80 || v6.is_multicast() || v6.to_ipv4_mapped().is_some())
        }
    }
}

fn all_digits(s: &str, maxlen: usize) -> bool {
    !s.is_empty() && s.len() <= maxlen && s.bytes().all(|c| c.is_ascii_digit())
}

/// Start a non-blocking connect (from the VHOST when it is the same family).
fn start_connect(state: &mut BotState, sa: &SocketAddr) -> io::Result<mio::net::TcpStream> {
    let bind = match net::vhost_addr(&state.vhost) {
        Some(Ok(ip)) if ip.is_ipv4() == sa.is_ipv4() => Some(ip),
        _ => None,
    };
    let sock = match net::new_socket(sa, bind) {
        Ok(s) => s,
        Err(e) if bind.is_some() => {
            logm!(state, L_INFO, "[DCC] Could not bind VHOST {}: {}\n", state.vhost, e);
            net::new_socket(sa, None)?
        }
        Err(e) => return Err(e),
    };
    sock.set_nonblocking(true)?;
    match sock.connect(&(*sa).into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(nix::libc::EINPROGRESS) || e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    Ok(mio::net::TcpStream::from_std(std::net::TcpStream::from(sock)))
}

/// "DCC ..." CTCP to us: completes this bot's own pending offer when it is
/// the reply to one; everything else is ignored.
pub fn handle_ctcp(state: &mut BotState, user_host: &str, ctcp: &str) {
    // "DCC CHAT chat <addr> <port> [<token>]"
    let mut f: Vec<&str> = Vec::new();
    let mut shape_ok = ctcp.len() < 256;
    if shape_ok {
        let mut t = Tok::new(ctcp);
        while let Some(x) = t.next(" ") {
            if f.len() == 6 {
                shape_ok = false;
                break;
            }
            f.push(x);
        }
    }
    shape_ok = shape_ok && f.len() >= 5 && eq_ic(f[0], "DCC") && eq_ic(f[1], "CHAT") && eq_ic(f[2], "chat");
    let si = state
        .dcc
        .iter()
        .position(|s| s.phase == DccPhase::Offered && eq_ic(&s.user_host, user_host));
    let Some(i) = si.filter(|_| shape_ok) else {
        logm!(state, L_CTCP, "[DCC] Ignored DCC request from {}: the bot only connects out, after its own offer\n", user_host);
        return;
    };
    if f.len() == 6 && (!all_digits(f[5], 10) || f[5].parse::<u64>().ok() != Some(u64::from(state.dcc[i].dcc_token))) {
        logm!(state, L_CTCP, "[DCC] Reply from {} carries another offer's token; ignored\n", user_host);
        return;
    }
    // From here the reply belongs to this offer: a bad value ends it.
    let port_digits = all_digits(f[4], 5);
    let port: u64 = if port_digits { f[4].parse().unwrap_or(0) } else { 0 };
    if port_digits && port == 0 {
        give_up(
            state,
            i,
            "your client answered with a passive offer of its own; it has to listen on a port for me to connect to.",
        );
        return;
    }
    if !port_digits || port < u64::from(DCC_MIN_PORT) || port > 65535 {
        let why = if port_digits {
            format!("port {port} is not allowed (use {DCC_MIN_PORT}-65535).")
        } else {
            "your client's reply has no valid port.".to_string()
        };
        give_up(state, i, &why);
        return;
    }
    let Some(sa) = parse_addr(f[3], port as u16).filter(addr_allowed) else {
        give_up(state, i, "your client sent an address I will not connect to; set its DCC address to your public IP.");
        return;
    };
    state.dcc[i].peer = format!("{} port {}", sa.ip(), port);
    match start_connect(state, &sa) {
        Ok(mut sock) => {
            let token = state.new_token(net::SLOT_DCC0 + i);
            if let Err(e) = state.registry.register(&mut sock, token, net::INTEREST) {
                let why = format!("connecting to {} failed: {}.", state.dcc[i].peer, e);
                give_up(state, i, &why);
                return;
            }
            let s = &mut state.dcc[i];
            s.sock = Some(sock);
            s.token = Some(token);
            s.phase = DccPhase::Connecting;
            s.phase_since = now();
            let (peer, name) = (s.peer.clone(), s.name.clone());
            logm!(state, L_INFO, "[DCC] Connecting to {} for {} ({})\n", peer, name, user_host);
        }
        Err(e) => {
            let why = format!("connecting to {} failed: {}.", state.dcc[i].peer, e);
            give_up(state, i, &why);
        }
    }
}

/// A connecting socket turned writable: open, or report why not.
fn on_connect(state: &mut BotState, i: usize) {
    let Some(sock) = state.dcc[i].sock.as_ref() else { return };
    let err = match sock.take_error() {
        Ok(Some(e)) => Some(e),
        Err(e) => Some(e),
        Ok(None) => match sock.peer_addr() {
            Ok(_) => None,
            Err(e) if e.kind() == io::ErrorKind::NotConnected => return, // not finished yet
            Err(e) => Some(e),
        },
    };
    if let Some(e) = err {
        let why = format!(
            "connecting to {} failed: {}. Check that your firewall lets that port in.",
            state.dcc[i].peer, e
        );
        give_up(state, i, &why);
        return;
    }
    let t = now();
    let s = &mut state.dcc[i];
    s.phase = DccPhase::Open;
    s.phase_since = t;
    s.last_active = t;
    let line = format!(
        "{}: DCC chat open for {}. Type commands here or use /botcmd {} <command> (the client script seals both); the replies come back here. Anything that is not a sealed command closes this chat. Idle limit: {} min.",
        s.botnick,
        s.name,
        s.botnick,
        DCC_IDLE_TIMEOUT / 60
    );
    let (name, uh, peer) = (s.name.clone(), s.user_host.clone(), s.peer.clone());
    logm!(state, L_INFO, "[DCC] Chat open with {} ({}) at {}\n", name, uh, peer);
    queue(&mut state.dcc[i], line.as_bytes());
}

/// Read what arrived and run each complete line.
fn read(state: &mut BotState, i: usize, token: mio::Token) {
    let mut buf = [0u8; 2048];
    loop {
        let r = match state.dcc[i].sock.as_mut() {
            Some(s) => s.read(&mut buf),
            None => return,
        };
        let n = match r {
            Ok(0) => {
                let (name, uh) = (state.dcc[i].name.clone(), state.dcc[i].user_host.clone());
                logm!(state, L_INFO, "[DCC] {} ({}) closed the chat\n", name, uh);
                free(state, i);
                return;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(_) => {
                let (name, uh) = (state.dcc[i].name.clone(), state.dcc[i].user_host.clone());
                logm!(state, L_INFO, "[DCC] {} ({}) closed the chat\n", name, uh);
                free(state, i);
                return;
            }
        };
        for &c in &buf[..n] {
            let s = &mut state.dcc[i];
            if c == b'\n' {
                let mut line = std::mem::take(&mut s.inbuf);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() {
                    continue; // blank line: nothing to run
                }
                let text = zeroize::Zeroizing::new(String::from_utf8_lossy(&line).into_owned());
                line.zeroize();
                let uh = s.user_host.clone();
                logm!(state, L_RAW, "[DCC_RECV] ({}) {}\n", uh, text.as_str());
                let ok = commands::handle_dcc_line(state, i, &text);
                if !ok {
                    if state.dcc[i].token == Some(token) {
                        close(state, i, Some("That was not a valid sealed command from your key; closing."));
                    }
                    return;
                }
                if state.dcc[i].token != Some(token) || state.dcc[i].phase != DccPhase::Open {
                    return;
                }
                continue;
            }
            // A frame is base64: a control byte (other than the CR before
            // LF) or an over-long line is not one.
            let bad = (c < 0x20 && c != b'\r') || c == 0x7f || s.inbuf.last() == Some(&b'\r');
            if bad || s.inbuf.len() > A2_LINE_MAX {
                close(state, i, Some(if bad { "Unexpected control byte; closing." } else { "Line too long; closing." }));
                return;
            }
            s.inbuf.push(c);
        }
    }
}

/// A poll event for DCC slot `i`.
pub fn handle_event(state: &mut BotState, i: usize, token: mio::Token, readable: bool, writable: bool) {
    let Some(s) = state.dcc.get(i) else { return };
    if s.token != Some(token) || s.sock.is_none() {
        return;
    }
    match s.phase {
        DccPhase::Connecting => {
            if writable {
                on_connect(state, i);
            }
            // Data can arrive together with the connect completion.
            if readable && state.dcc[i].phase == DccPhase::Open {
                read(state, i, token);
            }
        }
        DccPhase::Open => {
            if writable {
                flush(&mut state.dcc[i]);
            }
            if !state.dcc[i].failed && readable {
                read(state, i, token);
            }
            if state.dcc[i].token == Some(token) && state.dcc[i].phase == DccPhase::Open && state.dcc[i].failed {
                close(state, i, None);
            }
        }
        _ => {}
    }
}

pub fn check_timeouts(state: &mut BotState) {
    let now = now();
    for i in 0..state.dcc.len() {
        let s = &state.dcc[i];
        if s.phase == DccPhase::Open && s.failed {
            close(state, i, None);
        } else if s.phase == DccPhase::Offered && now - s.phase_since > DCC_OFFER_TIMEOUT {
            give_up(state, i, "your client did not answer the offer in time.");
        } else if s.phase == DccPhase::Connecting && now - s.phase_since > DCC_CONNECT_TIMEOUT {
            let why = format!("connecting to {} timed out. Check that your firewall lets that port in.", s.peer);
            give_up(state, i, &why);
        } else if s.phase == DccPhase::Open && now - s.last_active > DCC_IDLE_TIMEOUT {
            close(state, i, Some("Idle limit reached; closing."));
        }
    }
}

/// irc_printf hook: while a command from a chat runs, its replies ("PRIVMSG
/// <that nick> :<text>") go down the chat.  Lines to anyone else still go
/// to IRC.
pub fn divert_reply(state: &mut BotState, line: &str) -> bool {
    let Some(i) = state.dcc_reply else { return false };
    let nick = state.dcc[i].nick.clone();
    let lb = line.as_bytes();
    let head = 8 + nick.len() + 2;
    if lb.len() < head + 2
        || !line.starts_with("PRIVMSG ")
        || &lb[8..8 + nick.len()] != nick.as_bytes()
        || &lb[8 + nick.len()..head] != b" :"
    {
        return false;
    }
    let text = &lb[head..lb.len() - 2];
    let uh = state.dcc[i].user_host.clone();
    logm!(state, L_RAW, "[DCC_SEND] ({}) {}\n", uh, String::from_utf8_lossy(text));
    queue(&mut state.dcc[i], text);
    true
}
