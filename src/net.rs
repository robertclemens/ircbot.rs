//! Socket plumbing shared by the IRC, hub and DCC links: poll tokens,
//! blocking connect with a timeout (optionally from the VHOST address), and
//! non-blocking buffered reads and writes for the mio loop.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Low four bits of a poll token: which link it belongs to.  The rest is a
/// generation number (BotState::new_token).
pub const SLOT_IRC: usize = 0;
pub const SLOT_HUB: usize = 1;
pub const SLOT_DCC0: usize = 2;

pub fn slot_of(t: mio::Token) -> usize {
    t.0 & 0xf
}

/// The VHOST setting as an address; "" and "NULL" mean none.
pub fn vhost_addr(vhost: &str) -> Option<Result<IpAddr, ()>> {
    if vhost.is_empty() || vhost.eq_ignore_ascii_case("NULL") {
        return None;
    }
    Some(vhost.parse::<IpAddr>().map_err(|_| ()))
}

/// getaddrinfo(host, port): every address, in resolver order.
pub fn resolve(host: &str, port: &str) -> io::Result<Vec<SocketAddr>> {
    let p: u16 = port
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;
    Ok((host, p).to_socket_addrs()?.collect())
}

/// A TCP socket for `addr` (close-on-exec, as socket2 creates them),
/// bound to `bind` first when given.
pub fn new_socket(addr: &SocketAddr, bind: Option<IpAddr>) -> io::Result<Socket> {
    let sock = Socket::new(
        Domain::for_address(*addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if let Some(ip) = bind {
        sock.bind(&SockAddr::from(SocketAddr::new(ip, 0)))?;
    }
    Ok(sock)
}

/// Review 16: start a non-blocking connect; the caller registers the stream
/// with mio and waits for writability (in flight until then).
pub fn start_connect(sock: Socket, addr: &SocketAddr) -> io::Result<mio::net::TcpStream> {
    sock.set_nonblocking(true)?;
    match sock.connect(&SockAddr::from(*addr)) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(nix::libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    Ok(mio::net::TcpStream::from_std(TcpStream::from(sock)))
}

pub const INTEREST: mio::Interest = mio::Interest::READABLE.add(mio::Interest::WRITABLE);

/// Write out as much of `buf` as the socket takes; the rest stays queued.
/// Err only on a hard error.
pub fn flush<W: Write>(sock: &mut W, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut off = 0;
    let res = loop {
        if off >= buf.len() {
            break Ok(());
        }
        match sock.write(&buf[off..]) {
            Ok(0) => break Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0")),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    buf.drain(..off);
    res
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadOutcome {
    /// Drained: nothing more until the next readiness event.
    Drained,
    /// `into` reached `cap`; process it and read again (the socket may hold
    /// more, and an edge-triggered poll will not say so twice).
    Full,
    /// The peer closed the connection.
    Eof,
}

/// Read what is available (edge-triggered: until WouldBlock), stopping once
/// `into` holds `cap` bytes.
pub fn read_available<R: Read>(
    sock: &mut R,
    into: &mut Vec<u8>,
    cap: usize,
) -> io::Result<ReadOutcome> {
    let mut chunk = [0u8; 8192];
    loop {
        if into.len() >= cap {
            return Ok(ReadOutcome::Full);
        }
        let want = chunk.len().min(cap - into.len());
        match sock.read(&mut chunk[..want]) {
            Ok(0) => return Ok(ReadOutcome::Eof),
            Ok(n) => into.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ReadOutcome::Drained),
            Err(e) => return Err(e),
        }
    }
}
