//! The IRC server link (irc_client.c): connect (plain or TLS on 6697),
//! buffered non-blocking I/O on the poll loop, keepalive, nick reclaim, and
//! the server ban/throttle holds.
//!
//! A server that refuses the bot says why in a 465 / 463 numeric and/or the
//! ERROR line before it closes the link.  The parser hands that text to
//! [`note_refusal`]; when the link drops, [`disconnect`] classifies it once
//! and puts a hold on that server_list slot, which [`connect`] then skips:
//!
//!   ban wording + stated length -> held that long (+IRC_BAN_GRACE), never
//!                                  less than the throttle backoff
//!   ban wording + "permanent"   -> never retried automatically
//!   ban wording alone           -> IRC_BAN_BACKOFF doubling to _MAX
//!   "throttled", "too fast", "too many" -> IRC_THROTTLE_BACKOFF doubling
//!
//! The text is server-controlled: sanitized, bounded, parsed without
//! overflow.  Holds are runtime-only.

use std::io::{self, Read, Write};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

use crate::consts::*;
use crate::cstr::{eq_ic, now, trunc, trunc_string};
use crate::net::{self, ReadOutcome};
use crate::state::{BotState, S_AUTHED, S_CONNECTED, ServerBlock, ServerBlockKind, is_rfc_nick};
use crate::{chanlive, channel, crypto, dcc, hub_client, irc_parser, logm, sendq};

/// Unsent bytes past which a server that stopped reading is dropped.
const IRC_WBUF_MAX: usize = 1024 * 1024;
/// Receive buffer (C: MAX_BUFFER * 2); a line longer than this is dropped.
const IRC_RBUF_CAP: usize = MAX_BUFFER * 2 - 1;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct IrcConn {
    pub sock: mio::net::TcpStream,
    pub token: mio::Token,
    pub tls: Option<Box<ClientConnection>>,
    rbuf: Vec<u8>,
    wbuf: Vec<u8>,
}

impl IrcConn {
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    fn queue(&mut self, data: &[u8]) -> io::Result<()> {
        if self.wbuf.len() + data.len() > IRC_WBUF_MAX {
            return Err(io::Error::other("send queue overflow"));
        }
        self.wbuf.extend_from_slice(data);
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        let IrcConn {
            sock, tls, wbuf, ..
        } = self;
        let Some(tls) = tls else {
            return net::flush(sock, wbuf);
        };
        loop {
            if !wbuf.is_empty() {
                let n = tls.writer().write(wbuf)?;
                wbuf.drain(..n);
            }
            while tls.wants_write() {
                match tls.write_tls(sock) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            if wbuf.is_empty() {
                return Ok(());
            }
        }
    }

    /// Pull whatever arrived into rbuf.
    fn read(&mut self) -> io::Result<ReadOutcome> {
        let IrcConn {
            sock, tls, rbuf, ..
        } = self;
        let Some(tls) = tls else {
            return net::read_available(sock, rbuf, IRC_RBUF_CAP);
        };
        let mut chunk = [0u8; 8192];
        loop {
            // Decrypted data first: rustls refuses more ciphertext while its
            // plaintext buffer is full.
            loop {
                if rbuf.len() >= IRC_RBUF_CAP {
                    return Ok(ReadOutcome::Full);
                }
                let want = chunk.len().min(IRC_RBUF_CAP - rbuf.len());
                match tls.reader().read(&mut chunk[..want]) {
                    Ok(0) => return Ok(ReadOutcome::Eof), // close_notify
                    Ok(n) => rbuf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        return Ok(ReadOutcome::Eof);
                    }
                    Err(e) => return Err(e),
                }
            }
            match tls.read_tls(sock) {
                // EOF is reported by the reader above on the next pass.
                Ok(_) => {
                    tls.process_new_packets().map_err(io::Error::other)?;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ReadOutcome::Drained),
                Err(e) => return Err(e),
            }
        }
    }
}

// ---- TLS -------------------------------------------------------------------

/// Review 9: the server's certificate is checked (Mozilla's roots, the name
/// it was dialled by) but never enforced: IRC networks run self-signed
/// certificates, and a bot must not lose its server over one.  The outcome
/// is recorded in LAST_VERIFY for dial_event, which logs it and keeps it for
/// `status`.  The bot is single-threaded and runs one IRC handshake at a
/// time, so one slot is enough.  The handshake signatures are still checked
/// against the presented certificate.
#[derive(Debug)]
struct SoftVerify {
    provider: Arc<CryptoProvider>,
    inner: Option<Arc<rustls::client::WebPkiServerVerifier>>,
}

/// The last handshake's certificate check: Ok, or why it failed.
static LAST_VERIFY: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);

impl ServerCertVerifier for SoftVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let r = match &self.inner {
            Some(v) => v
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            None => Err("no CA certificates".to_string()),
        };
        if let Ok(mut slot) = LAST_VERIFY.lock() {
            *slot = Some(r);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_config() -> Option<Arc<ClientConfig>> {
    static CFG: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();
    CFG.get_or_init(|| {
        // graviola asserts its CPU features on the first handshake; on a CPU
        // that lacks one, refuse TLS here (the connect fails and is logged)
        // instead of letting that assert take the whole bot down.
        if crate::updater::tls_cpu_missing().is_some() {
            return None;
        }
        // Also the process default, which is what ureq's rustls-no-provider
        // build reads for the updater's HTTPS fetches.
        let _ = rustls_graviola::default_provider().install_default();
        let provider = Arc::new(rustls_graviola::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SoftVerify {
                inner: {
                    let roots = rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                    );
                    rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(roots),
                        provider.clone(),
                    )
                    .build()
                    .ok()
                },
                provider,
            }))
            .with_no_client_auth();
        Some(Arc::new(cfg))
    })
    .clone()
}

// ---- Server refusals ---------------------------------------------------------

/// Server text with control bytes (a lone CR or LF too) replaced by '?'.
fn refusal_sanitize(src: &str, cap: usize) -> String {
    let s: String = src
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                '?'
            } else {
                c
            }
        })
        .collect();
    trunc_string(&s, cap)
}

/// Lower-cased, '-' dropped: "K-Lined", "k-line" and "KLINE" all read "kline".
fn refusal_fold(src: &str) -> Vec<u8> {
    src.bytes()
        .filter(|&b| b != b'-')
        .map(|b| b.to_ascii_lowercase())
        .take(IRC_REFUSAL_LEN - 1)
        .collect()
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// `needle` at a word start (not preceded by a letter), so "unbanned" does
/// not read as "banned".  Returns the position just past the match.
fn refusal_find(hay: &[u8], needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    let mut at = find_from(hay, n, 0);
    while let Some(p) = at {
        if p == 0 || !hay[p - 1].is_ascii_alphabetic() {
            return Some(p + n.len());
        }
        at = find_from(hay, n, p + 1);
    }
    None
}

/// A length such as "60 min", "2 hours", "1h30m" starting at the first digit
/// within 48 bytes.  Only a known unit counts; capped at IRC_BAN_STATED_MAX.
fn refusal_parse_duration(s: &[u8]) -> i64 {
    const UNITS: &[(&str, i64)] = &[
        ("s", 1),
        ("sec", 1),
        ("secs", 1),
        ("second", 1),
        ("seconds", 1),
        ("m", 60),
        ("min", 60),
        ("mins", 60),
        ("minute", 60),
        ("minutes", 60),
        ("h", 3600),
        ("hr", 3600),
        ("hrs", 3600),
        ("hour", 3600),
        ("hours", 3600),
        ("d", 86400),
        ("day", 86400),
        ("days", 86400),
        ("w", 604800),
        ("wk", 604800),
        ("week", 604800),
        ("weeks", 604800),
        ("mo", 2592000),
        ("month", 2592000),
        ("months", 2592000),
        ("y", 31536000),
        ("yr", 31536000),
        ("year", 31536000),
        ("years", 31536000),
    ];
    let mut p = 0usize;
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut skipped = 0;
    while at(p) != 0 && !at(p).is_ascii_digit() {
        skipped += 1;
        if skipped > 48 {
            return 0;
        }
        p += 1;
    }
    let mut total: i64 = 0;
    let mut pairs = 0;
    while pairs < 4 && at(p).is_ascii_digit() {
        pairs += 1;
        let mut n: i64 = 0;
        while at(p).is_ascii_digit() {
            if n < 1_000_000_000 {
                n = n * 10 + i64::from(at(p) - b'0');
            }
            p += 1;
        }
        while at(p) == b' ' {
            p += 1;
        }
        let mut word = Vec::new();
        while at(p).is_ascii_alphabetic() {
            if word.len() < 11 {
                word.push(at(p));
            }
            p += 1;
        }
        let unit = UNITS
            .iter()
            .find(|(w, _)| w.as_bytes() == word.as_slice())
            .map_or(0, |u| u.1);
        if unit == 0 {
            break;
        }
        total += n * unit;
        if total >= IRC_BAN_STATED_MAX {
            return IRC_BAN_STATED_MAX;
        }
        while at(p) == b' ' || at(p) == b',' {
            p += 1;
        }
    }
    total
}

fn refusal_classify(text: &str, ban_numeric: bool) -> (ServerBlockKind, i64) {
    const BAN_WORDS: &[&str] = &[
        "kline",
        "gline",
        "zline",
        "dline",
        "akill",
        "autokill",
        "banned",
        "not welcome",
    ];
    const THROTTLE_WORDS: &[&str] = &["throttl", "too fast", "too many"];
    let t = refusal_fold(text);
    // An oper KILL or the echo of our own QUIT is not a ban.
    if !ban_numeric
        && (find_from(&t, b"killed (", 0).is_some() || find_from(&t, b"(quit:", 0).is_some())
    {
        return (ServerBlockKind::None, 0);
    }
    let ban = ban_numeric || BAN_WORDS.iter().any(|w| refusal_find(&t, w).is_some());
    if ban {
        if let Some(after) = refusal_find(&t, "temporar").or_else(|| refusal_find(&t, "expire")) {
            let secs = refusal_parse_duration(&t[after..]);
            return if secs > 0 {
                (ServerBlockKind::BannedTemp, secs)
            } else {
                (ServerBlockKind::Banned, 0)
            };
        }
        return if refusal_find(&t, "permanent").is_some() {
            (ServerBlockKind::BannedPerm, 0)
        } else {
            (ServerBlockKind::Banned, 0)
        };
    }
    if THROTTLE_WORDS.iter().any(|w| refusal_find(&t, w).is_some()) {
        return (ServerBlockKind::Throttled, 0);
    }
    (ServerBlockKind::None, 0)
}

fn refusal_backoff(base: i64, strikes: i32, cap: i64) -> i64 {
    let mut s = base;
    let mut i = 1;
    while i < strikes && s < cap {
        s *= 2;
        i += 1;
    }
    s.min(cap)
}

pub fn fmt_secs(s: i64) -> String {
    if s >= 86400 {
        format!("{}d{}h", s / 86400, (s % 86400) / 3600)
    } else if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 && s % 60 != 0 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// Record what the server said (465/463 numeric or ERROR); classified when
/// the link drops.
pub fn note_refusal(state: &mut BotState, text: &str, ban_numeric: bool) {
    let clean = refusal_sanitize(text, IRC_REFUSAL_LEN);
    if ban_numeric {
        state.irc_refusal_ban = true;
    }
    logm!(
        state,
        L_INFO,
        "[IRC] Server {}: {}\n",
        if ban_numeric {
            "refused registration"
        } else {
            "ERROR"
        },
        clean
    );
    // A 465 is usually followed by an ERROR; keep both for the classifier.
    let cap = IRC_REFUSAL_LEN;
    if !state.irc_refusal.is_empty() && state.irc_refusal.len() + 3 + 1 < cap {
        state.irc_refusal.push_str(" | ");
    }
    let room = cap - 1 - state.irc_refusal.len().min(cap - 1);
    let add = trunc(&clean, room + 1).to_string();
    state.irc_refusal.push_str(&add);
}

/// Classify what this link was told, once, as it goes down.
fn apply_refusal(state: &mut BotState) {
    if state.irc_refusal.is_empty() && !state.irc_refusal_ban {
        return;
    }
    let (kind, stated) = refusal_classify(&state.irc_refusal, state.irc_refusal_ban);
    if let Some(idx) = state
        .irc_server_idx
        .filter(|&i| i < state.server_list.len())
        && kind != ServerBlockKind::None
    {
        let now = now();
        let b = &mut state.server_blocks[idx];
        if b.strikes < 32 {
            b.strikes += 1;
        }
        let hold = match kind {
            ServerBlockKind::Throttled => {
                refusal_backoff(IRC_THROTTLE_BACKOFF, b.strikes, IRC_THROTTLE_BACKOFF_MAX)
            }
            ServerBlockKind::Banned => {
                refusal_backoff(IRC_BAN_BACKOFF, b.strikes, IRC_BAN_BACKOFF_MAX)
            }
            ServerBlockKind::BannedTemp => {
                // Honour the stated length, but never redial faster than
                // a throttle would.
                let floor = refusal_backoff(IRC_THROTTLE_BACKOFF, b.strikes, IRC_BAN_BACKOFF_MAX);
                (stated + IRC_BAN_GRACE).max(floor)
            }
            _ => 0,
        };
        b.kind = kind;
        b.until = if kind == ServerBlockKind::BannedPerm {
            0
        } else {
            now + hold
        };
        b.reason = state.irc_refusal.clone();
        let strikes = b.strikes;
        let srv = state.server_list[idx].clone();
        match kind {
            ServerBlockKind::BannedPerm => logm!(
                state,
                L_INFO,
                "[BAN] {}: PERMANENT ban - will not reconnect to it until restart, 'jump {}', or re-adding it.\n",
                srv,
                srv
            ),
            ServerBlockKind::BannedTemp => logm!(
                state,
                L_INFO,
                "[BAN] {}: temporary ban, server says {} - holding {} (strike {}).\n",
                srv,
                fmt_secs(stated),
                fmt_secs(hold),
                strikes
            ),
            _ => logm!(
                state,
                L_INFO,
                "[BAN] {}: {} - holding {} (strike {}).\n",
                srv,
                if kind == ServerBlockKind::Throttled {
                    "throttled"
                } else {
                    "banned, no length given"
                },
                fmt_secs(hold),
                strikes
            ),
        }
    }
    state.irc_refusal.clear();
    state.irc_refusal_ban = false;
}

/// 001: this server took us; forget any hold and strike count it had.
pub fn note_registered(state: &mut BotState) {
    let Some(idx) = state
        .irc_server_idx
        .filter(|&i| i < state.server_list.len())
    else {
        return;
    };
    if state.server_blocks[idx].strikes > 0 {
        let srv = state.server_list[idx].clone();
        logm!(state, L_INFO, "[BAN] {} accepted us; hold cleared.\n", srv);
    }
    state.server_blocks[idx] = ServerBlock::default();
}

pub fn server_block_clear(state: &mut BotState, idx: usize) {
    if idx < MAX_SERVERS {
        state.server_blocks[idx] = ServerBlock::default();
        state.irc_blocked_logged = false;
    }
}

/// -server: call BEFORE server_list is compacted.
pub fn server_block_remove(state: &mut BotState, idx: usize) {
    let n = state.server_list.len();
    if idx >= n {
        return;
    }
    state.server_blocks.remove(idx);
    state.server_blocks.push(ServerBlock::default());
    match state.irc_server_idx {
        Some(i) if i == idx => state.irc_server_idx = None,
        Some(i) if i > idx => state.irc_server_idx = Some(i - 1),
        _ => {}
    }
}

/// "banned 42m", "throttled 55s", "banned, permanent", or "" if eligible.
pub fn server_block_desc(state: &BotState, idx: usize) -> String {
    let Some(b) = state.server_blocks.get(idx) else {
        return String::new();
    };
    if b.kind == ServerBlockKind::BannedPerm {
        return "banned, permanent".into();
    }
    let now = now();
    if b.kind == ServerBlockKind::None || b.until <= now {
        return String::new();
    }
    format!(
        "{} {}",
        if b.kind == ServerBlockKind::Throttled {
            "throttled"
        } else {
            "banned"
        },
        fmt_secs(b.until - now)
    )
}

/// First slot at or after current_server_index (wrapping) that is not held.
fn pick_server(state: &mut BotState, now: i64) -> Option<usize> {
    let n = state.server_list.len();
    if n == 0 {
        return None;
    }
    let start = if state.current_server_index < n {
        state.current_server_index
    } else {
        0
    };
    let mut soonest = 0i64;
    for k in 0..n {
        let i = (start + k) % n;
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
        state.irc_blocked_logged = false;
        return Some(i);
    }
    if !state.irc_blocked_logged {
        state.irc_blocked_logged = true;
        if soonest != 0 {
            logm!(
                state,
                L_INFO,
                "[BAN] Every configured server is refusing this bot; next attempt in {}.\n",
                fmt_secs(soonest - now)
            );
        } else {
            logm!(
                state,
                L_INFO,
                "[BAN] Every configured server has permanently banned this bot; not reconnecting to IRC until restarted.\n"
            );
        }
    }
    None
}

// ---- Link lifecycle ------------------------------------------------------------

pub fn disconnect(state: &mut BotState) {
    dial_abort(state); // a dial in flight goes with it
    state.overlong_nick.clear();
    state.overlong_since = 0;
    // Last chance for queued lines (a parting PRIVMSG, a restart notice) to
    // go out on whatever credit is left; a write error here already
    // disconnected.
    if state.status & S_CONNECTED != 0 && state.irc.is_some() {
        sendq::drain(state);
        if state.status & S_CONNECTED == 0 && state.irc.is_none() {
            return;
        }
    }
    apply_refusal(state);
    if let Some(mut conn) = state.irc.take() {
        // QUIT first so the server drops the nick now rather than at
        // ping-timeout.
        if state.status & S_CONNECTED != 0 {
            let _ = conn.queue(b"QUIT :bye\r\n");
        }
        if let Some(tls) = conn.tls.as_mut() {
            tls.send_close_notify();
            let _ = conn.flush();
        }
        let _ = state.registry.deregister(&mut conn.sock);
        let _ = conn.sock.shutdown(std::net::Shutdown::Both);
    }
    state.status = 0;
    sendq::clear(state);
    chanlive::isupport_reset(state);
    channel::reset_status(state);
}

/// True if `line` is exactly one IRC line: ends in "\r\n", no CR, LF or NUL
/// before that.
fn is_single_line(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 2
        && b[b.len() - 2] == b'\r'
        && b[b.len() - 1] == b'\n'
        && !b[..b.len() - 2]
            .iter()
            .any(|&c| c == b'\r' || c == b'\n' || c == 0)
}

/// irc_printf(): send one formatted line ("...\r\n").  One command per call,
/// always: a line with an embedded break or no terminator is refused.
pub fn irc_printf(state: &mut BotState, line: &str) -> i32 {
    if state.status & S_CONNECTED == 0 && state.dcc_reply.is_none() {
        return -1;
    }
    if line.len() >= MAX_BUFFER || !is_single_line(line) {
        let verb_len = line.find([' ', '\r', '\n']).unwrap_or(line.len()).min(16);
        logm!(
            state,
            L_INFO,
            "[IRC] Refused to send {} line: embedded line break or no terminator\n",
            trunc(line, verb_len + 1)
        );
        return -1;
    }
    if state.a2r.active
        && let Some(r) = a2r_seal_reply(state, line)
    {
        return r;
    }
    send_line(state, line)
}

/// `ircf!(state, "FMT\r\n", args...)` -- irc_printf with format!.
#[macro_export]
macro_rules! ircf {
    // Zeroizing: a ~A2S reply's plaintext is wiped once the line is sent
    // (sealed or not), as C wipes irc_printf's buffer (review 2026-10-25 L1).
    ($st:expr, $($arg:tt)*) => {
        $crate::irc_client::irc_printf($st, &zeroize::Zeroizing::new(format!($($arg)*)))
    };
}

/// While a ~A2S command runs, its replies to the asker leave as ~A2R frames
/// ("<seq>:<more>:<text>" sealed under the command's reply key, the text cut
/// into A2R_TEXT_MAX-byte pieces).  CTCP stays plain.  None for any other
/// line; else the last send's result.
fn a2r_seal_reply(state: &mut BotState, line: &str) -> Option<i32> {
    let verb = if line.starts_with("PRIVMSG ") {
        "PRIVMSG"
    } else if line.starts_with("NOTICE ") {
        "NOTICE"
    } else {
        return None;
    };
    let lb = line.as_bytes();
    let vl = verb.len() + 1;
    let nick = state.a2r.nick.clone();
    let nl = nick.len();
    let head = vl + nl + 2;
    if lb.len() < head + 2
        || &lb[vl..vl + nl] != nick.as_bytes()
        || &lb[vl + nl..vl + nl + 2] != b" :"
    {
        return None;
    }
    let text = &lb[head..lb.len() - 2];
    if text.first() == Some(&0x01) {
        return None;
    }
    let tlen = text.len();
    let mut ret;
    let mut off = 0usize;
    loop {
        let mut cut = tlen - off;
        if cut > A2R_TEXT_MAX {
            cut = A2R_TEXT_MAX;
            while cut > 1 && (text[off + cut] & 0xC0) == 0x80 {
                cut -= 1;
            }
        }
        let more = if off + cut < tlen { 1 } else { 0 };
        let mut pt = zeroize::Zeroizing::new(format!("{}:{}:", state.a2r.seq, more).into_bytes());
        let frame = if pt.len() + cut <= A2R_PT_MAX {
            pt.extend_from_slice(&text[off..off + cut]);
            crypto::reply_seal(&state.a2r.key, &state.a2r.aad, &pt)
        } else {
            None
        };
        drop(pt);
        let Some(frame) = frame else {
            logm!(
                state,
                L_INFO,
                "[CMD] Could not seal a reply to {}; the rest of it is dropped\n",
                nick
            );
            return Some(-1);
        };
        let out = format!("{} {} :~A2R {}\r\n", verb, nick, crypto::b64_encode(&frame));
        if out.len() >= 640 {
            return Some(-1);
        }
        ret = send_line(state, &out);
        if ret < 0 {
            return Some(ret);
        }
        state.a2r.seq += 1;
        off += cut;
        if off >= tlen {
            break;
        }
    }
    Some(ret)
}

/// PING or PONG as the command of a finished line (either direction), for
/// HIDEPINGPONG.  A CTCP PING rides inside PRIVMSG and never matches.
pub fn line_is_keepalive(line: &str) -> bool {
    let mut l = line.trim_start_matches(' ');
    if l.starts_with(':') {
        l = l.find(' ').map_or("", |i| &l[i..]).trim_start_matches(' ');
    }
    let b = l.as_bytes();
    if b.len() < 4
        || !(b[..4].eq_ignore_ascii_case(b"PING") || b[..4].eq_ignore_ascii_case(b"PONG"))
    {
        return false;
    }
    matches!(b.get(4), None | Some(b' ') | Some(b':') | Some(b'\r'))
}

/// One finished line to the server -- or down a DCC chat for a reply to a
/// command that came from one, even while the IRC link is down.  Lines for
/// the server go through the paced send queue (sendq.rs).
fn send_line(state: &mut BotState, line: &str) -> i32 {
    if dcc::divert_reply(state, line) {
        return line.len() as i32;
    }
    if state.status & S_CONNECTED == 0 {
        return -1;
    }
    sendq::enqueue(state, line.as_bytes())
}

/// The write itself, for a line the send queue has decided may go now.  A
/// write error drops the link (which also empties the queue).
pub fn write_raw(state: &mut BotState, line: &[u8]) -> i32 {
    if state.status & S_CONNECTED == 0 {
        return -1;
    }
    if !HIDEPINGPONG || !line_is_keepalive(&String::from_utf8_lossy(line)) {
        let s = zeroize::Zeroizing::new(String::from_utf8_lossy(line).into_owned());
        state.log.log_raw(&state.isup, "[RAW_SEND] ", &s);
    }
    let res = match state.irc.as_mut() {
        Some(c) => c.queue(line).map(|_| c.is_tls()),
        None => return -1,
    };
    match res {
        Ok(_) => line.len() as i32,
        Err(_) => {
            let tls = state.irc.as_ref().is_some_and(|c| c.is_tls());
            logm!(
                state,
                L_INFO,
                "[INFO] Lost connection to server ({}write error).\n",
                if tls { "SSL " } else { "" }
            );
            // Nothing queued can be written to a dead link: empty the queue
            // first so disconnect()'s last-chance drain does not retry.
            sendq::clear(state);
            disconnect(state);
            -1
        }
    }
}

/// Dial the next eligible server: its configured port, or 6667 then 6697.
/// Port 6697 is TLS.
pub fn connect(state: &mut BotState) {
    if state.irc.is_some() || state.irc_dial.is_some() {
        return;
    }
    let attempt_now = now();
    let Some(pick) = pick_server(state, attempt_now) else {
        return;
    };
    state.current_server_index = pick;
    state.irc_server_idx = Some(pick);
    state.last_irc_attempt = attempt_now;
    state.irc_refusal.clear();
    state.irc_refusal_ban = false;
    state.nick_refused.clear();

    let server_str = trunc_string(&state.server_list[pick], 256);
    let (host, ports): (&str, Vec<&str>) = match server_str.rfind(':') {
        Some(i) => (&server_str[..i], vec![&server_str[i + 1..]]),
        None => (server_str.as_str(), vec!["6667", "6697"]),
    };

    let vhost = match net::vhost_addr(&state.vhost) {
        Some(Ok(ip)) => Some(ip),
        Some(Err(())) => {
            logm!(
                state,
                L_INFO,
                "[WARN] Invalid VHOST IP '{}'. Ignoring.\n",
                state.vhost
            );
            None
        }
        None => None,
    };

    state.irc_dial = Some(IrcDial {
        host: host.to_string(),
        ports: ports.iter().map(|p| p.to_string()).collect(),
        port_idx: None,
        addrs: Vec::new(),
        next: 0,
        vhost,
        conn: None,
        tls: None,
        started: 0,
    });
    dial_next(state);
    state.current_server_index += 1;
}

/// Review 16: the IRC dial in flight (C irc_client.c `g_dial`).  connect()
/// picks the server and starts it: each address of each port (the configured
/// one, else 6667 then 6697 with TLS) gets a non-blocking connect, and a TLS
/// port then a non-blocking handshake, both driven by poll events on the
/// dial's token and bounded per step by dial_tick (CONNECT_TIMEOUT_SECS a
/// connect, TLS_HANDSHAKE_TIMEOUT the handshake).  The blocking connect froze
/// the bot up to 10 s per dead address.  state.irc stays None until the link
/// is up, so nothing else sees a half-open one.  (Name resolution still
/// blocks.)
pub struct IrcDial {
    host: String,
    ports: Vec<String>,
    /// ports[port_idx] is the port being tried.
    port_idx: Option<usize>,
    /// Its addresses; addrs[next..] still to try.
    addrs: Vec<std::net::SocketAddr>,
    next: usize,
    vhost: Option<std::net::IpAddr>,
    /// The address in flight: its socket (registered) and token.
    conn: Option<(mio::net::TcpStream, mio::Token, std::net::SocketAddr)>,
    /// Some: the connect is done and the TLS handshake is running.
    tls: Option<Box<ClientConnection>>,
    /// When the current step began.
    started: i64,
}

/// Close the address in flight (and its half-done TLS session).
fn dial_drop(state: &mut BotState) {
    let Some(d) = state.irc_dial.as_mut() else {
        return;
    };
    d.tls = None;
    if let Some((mut sock, _, _)) = d.conn.take() {
        let _ = state.registry.deregister(&mut sock);
    }
}

/// Start a connect to the next address that takes one, resolving the next
/// port when this one's run out; nothing left: the attempt is over.
fn dial_next(state: &mut BotState) {
    loop {
        let Some(d) = state.irc_dial.as_mut() else {
            return;
        };
        if d.next < d.addrs.len() {
            let addr = d.addrs[d.next];
            d.next += 1;
            let vhost = d.vhost;
            if let Some(v) = vhost
                && v.is_ipv4() != addr.is_ipv4()
            {
                continue;
            }
            let sock = match net::new_socket(&addr, vhost) {
                Ok(s) => s,
                Err(e) if vhost.is_some() => {
                    logm!(
                        state,
                        L_INFO,
                        "[WARN] Failed to bind VHOST {}: {}\n",
                        state.vhost,
                        e
                    );
                    continue;
                }
                Err(_) => continue,
            };
            let Ok(mut sock) = net::start_connect(sock, &addr) else {
                continue;
            };
            let token = state.new_token(net::SLOT_IRC);
            if state
                .registry
                .register(&mut sock, token, net::INTEREST)
                .is_err()
            {
                continue;
            }
            if let Some(d) = state.irc_dial.as_mut() {
                d.conn = Some((sock, token, addr));
                d.tls = None;
                d.started = now();
            }
            return;
        }
        let idx = d.port_idx.map_or(0, |i| i + 1);
        if idx >= d.ports.len() {
            state.irc_dial = None;
            return;
        }
        d.port_idx = Some(idx);
        d.addrs.clear();
        d.next = 0;
        let (host, port) = (d.host.clone(), d.ports[idx].clone());
        logm!(
            state,
            L_INFO,
            "[INFO] Attempting to connect to {}:{}...\n",
            host,
            port
        );
        let addrs = net::resolve(&host, &port).unwrap_or_default();
        if let Some(d) = state.irc_dial.as_mut() {
            d.addrs = addrs;
        }
    }
}

/// A failed TLS port is not tried further (as before: the rest of its
/// addresses are skipped).
fn dial_skip_port(state: &mut BotState) {
    if let Some(d) = state.irc_dial.as_mut() {
        d.next = d.addrs.len();
    }
}

/// A poll event on the dial's token.
fn dial_event(state: &mut BotState) {
    let Some(d) = state.irc_dial.as_mut() else {
        return;
    };
    if d.tls.is_none() {
        // The connect: done once the socket has a peer, failed on an error.
        let Some((sock, _, addr)) = d.conn.as_ref() else {
            return;
        };
        let addr = *addr;
        match sock.take_error() {
            Ok(None) => {}
            _ => {
                dial_drop(state);
                dial_next(state);
                return;
            }
        }
        if sock.peer_addr().is_err() {
            return; // still in flight
        }
        let port_is_tls = d.port_idx.is_some_and(|i| d.ports[i] == "6697");
        if !port_is_tls {
            logm!(state, L_INFO, "[INFO] Insecure connection established.\n");
            dial_up(state);
            return;
        }
        let host = d.host.clone();
        let conn = tls_config().and_then(|cfg| {
            let name = ServerName::try_from(host)
                .unwrap_or_else(|_| ServerName::IpAddress(addr.ip().into()));
            ClientConnection::new(cfg, name).ok()
        });
        let Some(conn) = conn else {
            dial_tls_failed(state);
            return;
        };
        if let Ok(mut slot) = LAST_VERIFY.lock() {
            *slot = None;
        }
        if let Some(d) = state.irc_dial.as_mut() {
            d.tls = Some(Box::new(conn));
            d.started = now();
        }
    }
    // The TLS handshake: as far as the socket lets it go.
    let Some(d) = state.irc_dial.as_mut() else {
        return;
    };
    let (Some((sock, _, _)), Some(tls)) = (d.conn.as_mut(), d.tls.as_mut()) else {
        return;
    };
    match tls_step(sock, tls) {
        Ok(true) => {
            logm!(state, L_INFO, "[INFO] Secure TLS connection established.\n");
            tls_check_result(state);
            dial_up(state);
        }
        Ok(false) => {}
        Err(()) => dial_tls_failed(state),
    }
}

/// Review 9: the handshake is done; was the certificate good?  Only
/// recorded: the link stays up, and the log and `status` say so.
fn tls_check_result(state: &mut BotState) {
    let r = LAST_VERIFY
        .lock()
        .ok()
        .and_then(|mut s| s.take())
        .unwrap_or_else(|| Err("no certificate".to_string()));
    let host = state
        .irc_dial
        .as_ref()
        .map(|d| d.host.clone())
        .unwrap_or_default();
    state.irc_tls_verified = r.is_ok();
    state.irc_tls_why = trunc_string(r.err().as_deref().unwrap_or(""), 96);
    if state.irc_tls_verified {
        logm!(
            state,
            L_INFO,
            "[INFO] TLS certificate of {} verified.\n",
            host
        );
    } else {
        logm!(
            state,
            L_INFO,
            "[WARN] TLS certificate of {} NOT verified ({}): the link is encrypted, but the server's identity is unchecked.\n",
            host,
            state.irc_tls_why
        );
    }
}

/// One pass of a non-blocking TLS handshake: Ok(true) done, Ok(false) the
/// socket would block, Err on a failure or EOF.
fn tls_step(sock: &mut mio::net::TcpStream, tls: &mut ClientConnection) -> Result<bool, ()> {
    loop {
        while tls.wants_write() {
            match tls.write_tls(sock) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(()),
            }
        }
        if !tls.is_handshaking() {
            return Ok(true);
        }
        match tls.read_tls(sock) {
            Ok(0) => return Err(()),
            Ok(_) => {
                tls.process_new_packets().map_err(|_| ())?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(()),
        }
    }
}

fn dial_tls_failed(state: &mut BotState) {
    match crate::updater::tls_unusable_reason() {
        Some(why) => logm!(state, L_INFO, "[INFO] No TLS: {}.\n", why),
        None => logm!(
            state,
            L_INFO,
            "[INFO] SSL handshake failed. Trying insecure.\n"
        ),
    }
    dial_drop(state);
    dial_skip_port(state);
    dial_next(state);
}

/// Up: the dial's socket becomes the IRC link and the registration goes out.
fn dial_up(state: &mut BotState) {
    let Some(mut d) = state.irc_dial.take() else {
        return;
    };
    let Some((sock, token, _)) = d.conn.take() else {
        return;
    };
    if d.tls.is_none() {
        state.irc_tls_verified = false;
        state.irc_tls_why.clear();
    }
    state.irc = Some(IrcConn {
        sock,
        token,
        tls: d.tls.take(),
        rbuf: Vec::new(),
        wbuf: Vec::new(),
    });
    sendq::clear(state); // new link: empty queue, full burst
    chanlive::isupport_reset(state);
    let t = now();
    state.status = S_CONNECTED;
    state.last_pong_time = t;
    state.pong_pending = false;
    state.connection_time = t;
    state.current_nick = state.target_nick.clone();
    let nick = state.current_nick.clone();
    let (user, gecos) = (state.user.clone(), state.gecos.clone());
    crate::ircf!(state, "NICK {}\r\n", nick);
    crate::ircf!(state, "USER {} 0 * :{}\r\n", user, gecos);
}

/// A step that has not finished in its bound: on to the next address (a TLS
/// port that stalls is given up like one that fails).
pub fn dial_tick(state: &mut BotState) {
    let Some(d) = state.irc_dial.as_ref() else {
        return;
    };
    if d.conn.is_none() {
        return;
    }
    let tls = d.tls.is_some();
    let bound = if tls {
        TLS_HANDSHAKE_TIMEOUT.as_secs() as i64
    } else {
        CONNECT_TIMEOUT_SECS as i64
    };
    if now() - d.started <= bound {
        return;
    }
    if tls {
        logm!(
            state,
            L_INFO,
            "[INFO] TLS handshake timeout after {} seconds.\n",
            bound
        );
        dial_drop(state);
        dial_skip_port(state);
    } else {
        logm!(
            state,
            L_INFO,
            "[INFO] Connection timeout after {} seconds.\n",
            bound
        );
        dial_drop(state);
    }
    dial_next(state);
}

pub fn dialing(state: &BotState) -> bool {
    state.irc_dial.is_some()
}

/// Give the dial up entirely (a disconnect, a server change, shutdown).
pub fn dial_abort(state: &mut BotState) {
    dial_drop(state);
    state.irc_dial = None;
}

/// A poll event for the IRC socket.
pub fn handle_event(state: &mut BotState, token: mio::Token, readable: bool, writable: bool) {
    if state
        .irc_dial
        .as_ref()
        .and_then(|d| d.conn.as_ref())
        .is_some_and(|c| c.1 == token)
    {
        dial_event(state);
        return;
    }
    if state.irc.as_ref().map(|c| c.token) != Some(token) {
        return;
    }
    if writable {
        let res = state.irc.as_mut().map(|c| c.flush());
        if let Some(Err(_)) = res {
            logm!(
                state,
                L_INFO,
                "[INFO] Lost connection to server (write error).\n"
            );
            disconnect(state);
            return;
        }
    }
    if readable {
        handle_read(state, token);
    }
}

fn handle_read(state: &mut BotState, token: mio::Token) {
    loop {
        let (outcome, lines) = {
            let Some(conn) = state.irc.as_mut().filter(|c| c.token == token) else {
                return;
            };
            let outcome = conn.read();
            let _ = conn.flush();
            let mut lines = Vec::new();
            let mut start = 0;
            let buf = &conn.rbuf;
            while let Some(p) = buf[start..].windows(2).position(|w| w == b"\r\n") {
                lines.push(String::from_utf8_lossy(&buf[start..start + p]).into_owned());
                start += p + 2;
            }
            conn.rbuf.drain(..start);
            (outcome, lines)
        };
        if !lines.is_empty() {
            state.last_pong_time = now();
        }
        for line in lines {
            if state.irc.as_ref().map(|c| c.token) != Some(token) {
                return;
            }
            let line = crate::cstr::until_nul(&line).to_string();
            if !HIDEPINGPONG || !line_is_keepalive(&line) {
                state.log.log_raw(&state.isup, "[RAW_RECV] ", &line);
            }
            irc_parser::handle_line(state, &line);
        }
        let Some(conn) = state.irc.as_mut().filter(|c| c.token == token) else {
            return;
        };
        if conn.rbuf.len() >= IRC_RBUF_CAP {
            conn.rbuf.clear();
            logm!(
                state,
                L_INFO,
                "[WARN] Receive buffer full (line too long). Flushing buffer.\n"
            );
        }
        match outcome {
            Ok(ReadOutcome::Full) => continue,
            Ok(ReadOutcome::Drained) => return,
            Ok(ReadOutcome::Eof) | Err(_) => {
                disconnect(state);
                return;
            }
        }
    }
}

/// Once per loop tick: hub watchdog, reconnect, keepalive, nick reclaim.
pub fn check_status(state: &mut BotState) {
    let now = now();

    // A hub link with no PONG or data for 120 s has zombied.
    if !state.hubs.is_empty()
        && state.hub.is_some()
        && state.hub_authenticated
        && now - state.last_hub_activity > 120
    {
        logm!(
            state,
            L_INFO,
            "[HUB] Connection timed out (Watchdog). Reconnecting...\n"
        );
        hub_client::drop_link(state);
    } else if !state.hubs.is_empty()
        && (state.hub.is_some() || hub_client::dialing(state))
        && !state.hub_authenticated
        && now - state.last_hub_connect_attempt > HUB_AUTH_TIMEOUT
        && !hub_client::data_waiting(state)
    {
        logm!(
            state,
            L_INFO,
            "[HUB] Handshake not finished in {} s — dropping the link\n",
            HUB_AUTH_TIMEOUT
        );
        hub_client::disconnect(state);
    }

    if state.status & S_CONNECTED == 0 {
        // Floor between attempts: a server that drops us before registration
        // must not be redialled every tick.
        dial_tick(state);
        if !dialing(state) && now - state.last_irc_attempt >= IRC_RECONNECT_MIN_INTERVAL {
            connect(state);
        }
        return;
    }

    // Registration watchdog.  Any received byte refreshes last_pong_time, and
    // a server answers an unregistered client's PING (451 or PONG), so without
    // this a link that never reaches 001 is held open forever, off IRC.
    if state.status & S_AUTHED == 0 && now - state.connection_time > IRC_REGISTER_TIMEOUT {
        logm!(
            state,
            L_INFO,
            "[INFO] No registration (001) after {} seconds. Disconnecting.\n",
            IRC_REGISTER_TIMEOUT
        );
        disconnect(state);
        return;
    }

    if now - state.last_pong_time > DEAD_SERVER_TIMEOUT {
        logm!(state, L_INFO, "[INFO] Server timed out. Disconnecting.\n");
        disconnect(state);
        return;
    }

    if !state.pong_pending && now - state.last_pong_time > CHECK_LAG_TIMEOUT {
        crate::ircf!(state, "PING :{}\r\n", now);
        state.pong_pending = true;
    }

    if state.status & S_AUTHED != 0
        && state.overlong_since != 0
        && now - state.overlong_since > NICK_OVERLONG_TIMEOUT
    {
        logm!(
            state,
            L_INFO,
            "[INFO] Still under {} (over {} characters) after {}s: reconnecting\n",
            state.overlong_nick,
            MAX_NICK - 1,
            NICK_OVERLONG_TIMEOUT
        );
        disconnect(state);
        return;
    }
    if state.status & S_AUTHED != 0 {
        channel::check_joins(state);
        if !state.nick_change_pending {
            if !eq_ic(&state.current_nick, &state.target_nick)
                && !eq_ic(&state.nick_refused, &state.target_nick)
            {
                if now - state.nick_release_time > NICK_TAKE_TIME {
                    if now - state.last_nick_attempt > NICK_RETRY_TIME {
                        let t = state.target_nick.clone();
                        logm!(
                            state,
                            L_INFO,
                            "[INFO] Attempting to reclaim primary nick '{}'.\n",
                            t
                        );
                        attempt_nick_change(state, &t);
                    }
                } else {
                    logm!(
                        state,
                        L_INFO,
                        "[INFO] Nick reclaim on hold. {} seconds remaining.\n",
                        NICK_TAKE_TIME - (now - state.nick_release_time)
                    );
                }
            }
        } else {
            logm!(
                state,
                L_INFO,
                "[INFO] Nick reclaim skipped: nick change pending.\n"
            );
        }
    }
}

pub fn attempt_nick_change(state: &mut BotState, new_nick: &str) {
    logm!(state, L_DEBUG, "[DEBUG] Attemping NICK to {}\n", new_nick);
    crate::ircf!(state, "NICK {}\r\n", new_nick);
    state.last_nick_attempt = now();
}

/// Review 10b: the server put us under `nick`, over the 9 bytes a bot nick
/// may be (a long 001, a services rename to Guest123456).  Nothing longer is
/// stored or sent to the hub: the bot renames itself back to its target now,
/// and with current_nick empty the reclaim in check_status keeps trying; a
/// refused target falls back to the 9-byte alternates (on_nick_refused).
/// Still over 9 after NICK_OVERLONG_TIMEOUT, it reconnects.
pub fn nick_overlong(state: &mut BotState, nick: &str) {
    if state.overlong_since == 0 {
        state.overlong_since = now();
    }
    state.overlong_nick = trunc_string(nick, MAX_MEMBER_NICK);
    state.current_nick.clear();
    logm!(
        state,
        L_INFO,
        "[INFO] Server put me under {}, over {} characters: renaming back to {}\n",
        state.overlong_nick,
        MAX_NICK - 1,
        state.target_nick
    );
    let target = state.target_nick.clone();
    attempt_nick_change(state, &target);
}

/// Next alternate nick: the target's RFC characters cut to 8 plus one
/// suffix ("_`^", then 0-9); wraps back to the start after that.
pub fn generate_new_nick(state: &mut BotState) {
    const SUFFIXES: &[u8] = b"_`^";
    let attempt = state.nick_generation_attempt;
    let mut base = String::new();
    for ch in state.target_nick.chars() {
        if base.len() >= 8 {
            break;
        }
        let one = ch.to_string();
        let probe = format!("a{ch}");
        if if base.is_empty() {
            is_rfc_nick(&one)
        } else {
            is_rfc_nick(&probe)
        } {
            base.push(ch);
        }
    }
    if base.is_empty() {
        base = "bot".into();
    }
    let new_nick = if attempt < SUFFIXES.len() {
        format!("{}{}", base, SUFFIXES[attempt] as char)
    } else {
        let n = attempt - SUFFIXES.len();
        if n < 10 {
            format!("{base}{n}")
        } else {
            state.nick_generation_attempt = 0;
            return;
        }
    };
    let new_nick = trunc_string(&new_nick, MAX_NICK);
    state.current_nick = new_nick.clone();
    state.nick_generation_attempt += 1;
    attempt_nick_change(state, &new_nick);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_refusals() {
        assert_eq!(
            refusal_classify("Closing Link: (K-Lined: go away)", false).0,
            ServerBlockKind::Banned
        );
        let (k, s) = refusal_classify("You are banned. Temporary K-line 60 min.", false);
        assert_eq!((k, s), (ServerBlockKind::BannedTemp, 3600));
        assert_eq!(
            refusal_classify("Permanently banned", true).0,
            ServerBlockKind::BannedPerm
        );
        assert_eq!(
            refusal_classify("Throttled: Reconnecting too fast", false).0,
            ServerBlockKind::Throttled
        );
        assert_eq!(
            refusal_classify("Closing Link: (Ping timeout)", false).0,
            ServerBlockKind::None
        );
        assert_eq!(
            refusal_classify("Killed (oper (banned))", false).0,
            ServerBlockKind::None
        );
        assert_eq!(
            refusal_classify("you were unbanned", false).0,
            ServerBlockKind::None
        );
        assert_eq!(refusal_parse_duration(b" in 1h30m"), 5400);
        assert_eq!(fmt_secs(5400), "1h30m");
        assert_eq!(fmt_secs(90), "1m30s");
    }

    #[test]
    fn keepalive_detection() {
        assert!(line_is_keepalive("PING :123\r\n"));
        assert!(line_is_keepalive(":irc.x PONG irc.x :1"));
        assert!(!line_is_keepalive("PINGX"));
        assert!(!line_is_keepalive(":a!b@c PRIVMSG x :\u{1}PING 1\u{1}"));
    }

    #[test]
    fn single_line_rule() {
        assert!(is_single_line("PRIVMSG a :b\r\n"));
        assert!(!is_single_line("PRIVMSG a :b\r\nQUIT\r\n"));
        assert!(!is_single_line("PRIVMSG a :b"));
    }
}
