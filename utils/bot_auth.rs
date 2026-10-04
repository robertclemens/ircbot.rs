//! bot-auth — command-line client for ircbot's key-based admin/oper protocol
//! (~A2A auth request, ~A2K lockbox, ~A2 / ~A2S sealed command, ~A2R sealed
//! reply).  Also the backend that bot-auth.mrc drives for mIRC (as
//! bot-auth.exe).  The Rust port of ircbot/utils/bot-auth.c, byte for byte
//! on the wire.  Protocol: irchub/docs/passwordless.md §4; the bot side is
//! src/commands.rs (a2_handle_auth / a2_open_command).
//!
//! Build:   `cargo build --release` (binary: `target/release/bot-auth`)
//!          (Windows: `cargo build --release --bin bot-auth --target x86_64-pc-windows-gnu`)
//!
//! Usage (keyfile = your `<ts>_<name>.private.b64`, chmod 600):
//!
//! ```text
//!   bot-auth auth <keyfile> <botnick> <yournick>
//!       -> prints "~A2A <sig> <ts>:<nonce>"; send it:  /msg <botnick> <line>
//!   bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply>
//!                 [--pin <pinfile>]
//!       -> the bot answers the auth with a NOTICE "~A2K <b64>"; pass it here
//!          with the <ts>:<nonce> of the ~A2A you sent.  Prints
//!          "<bot pubkey> <fingerprint>".  With --pin, the bot key is checked
//!          against / recorded in pinfile ("<lc botnick> <pubkey>" lines).
//!   bot-auth cmd <keyfile> <botnick> <yournick> <botpubkey|@file>
//!                [--sealed <replykeyfile>]
//!       -> reads ONE command line from stdin (never argv: ps(1) would show
//!          it) and prints "~A2 <b64>"; send it:  /quote PRIVMSG <bot> :<line>
//!          With --sealed it prints "~A2S <b64>" instead, which asks the bot
//!          to seal its replies, and writes that command's reply key to
//!          replykeyfile (created 0600; delete it when done).
//!   bot-auth reply <replykeyfile> <botnick> <yournick>
//!       -> reads the bot's reply lines (raw IRC lines or just "~A2R <b64>")
//!          from stdin and prints each reply in plaintext.
//!   bot-auth fp <pubkey|file>
//!       -> prints the key fingerprint (compare with the bot's 'status').
//!   bot-auth unlock <keyfile> [--expire <1h|30m|6h|1d|secs|never>]
//!                   [--passphrase-file <f>]
//!       -> asks for the passphrase of an irckey-v2 key and starts the key
//!          holder: a background process that keeps the decrypted key in
//!          locked memory until the expiry (default 1h) and signs / does the
//!          X25519 step for later auth/open/cmd calls over a 0600 UNIX socket
//!          in a 0700 directory (peer uid checked; Windows: see below).  The private key never
//!          leaves it.  On Windows the holder is a named pipe only the
//!          current user can open (DACL from the user's SID), as in the C
//!          bot-auth.exe; either one's holder serves both.
//!   bot-auth lock <keyfile>     -> ends the key holder (wipes the key).
//!   bot-auth status <keyfile>   -> "unlocked <secs|never>" or "locked".
//! ```
//!
//! A passphrase-protected key with no holder running: on a terminal the
//! passphrase is asked for that one call; otherwise bot-auth prints
//! "bot-auth: LOCKED: ..." and exits 4.  Keys: irchub/docs/console.md §9.
//!
//! Exit status: 0 ok, 1 usage/IO error, 2 crypto/verification failure,
//!              3 pinned key mismatch (possible MITM or a rekeyed bot),
//!              4 the key is locked (run bot-auth unlock).

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const A2A_LABEL: &str = "ircbot-A2A-v1";
const A2K_LABEL: &str = "ircbot-A2K-v1";
const A2_LABEL: &str = "ircbot-A2-v1";
const A2S_LABEL: &str = "ircbot-A2S-v1";
const A2R_LABEL: &str = "ircbot-A2R-v1";
const A2R_PT_MAX: usize = 264; // "<seq>:<more>:" + up to 240 bytes of text
const KEY_LEN: usize = 64; // ed25519(32) || x25519(32)
const KEY_B64: usize = 88;
const LOCKBOX_LEN: usize = 32 + 12 + KEY_LEN + 16;
const MAX_LINE: usize = 400; // IRC line budget for the ~A2 text
const MAX_CMD: usize = 300;

/// irckey-v2 reader bounds, as in keygen: at most 128 * r * N = 256 MB.
const IRCKEY_TAG: &str = "irckey-v2";
const IRCKEY_LOG2N: (u32, u32) = (14, 18);
const IRCKEY_R_MAX: u32 = 8;
const IRCKEY_P_MAX: u32 = 4;
const IRCKEY_LINE_MAX: usize = 512;
const PASS_MAX: usize = 1024;
const EXIT_LOCKED: i32 = 4;
const EXPIRE_MAX: i64 = 366 * 86400;
/// Largest holder request payload.
const HOLD_MAX: usize = 512;

/// die(): the exit status and message, carried up to main() so every secret
/// on the way is dropped (wiped) before the process exits.
struct Die(i32, &'static str);

type Res = Result<i32, Die>;

// ---- small helpers ---------------------------------------------------------

/// EVP_DecodeBlock: padded input, non-canonical trailing bits accepted.
const DECODE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

fn b64enc(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Strict-ish base64 decode into `out`: the decoded length, or None (also
/// when it would not fit in `out`).
fn b64dec(s: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = s.len();
    if n == 0 || !n.is_multiple_of(4) || n / 4 * 3 > out.len() + 2 {
        return None;
    }
    let v = Zeroizing::new(DECODE.decode(s).ok()?);
    if v.len() > out.len() {
        return None;
    }
    out[..v.len()].copy_from_slice(&v);
    Some(v.len())
}

/// ASCII lower-case, cut to cap-1 bytes.
fn lc_copy(s: &[u8], cap: usize) -> Vec<u8> {
    s.iter()
        .take(cap - 1)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn fingerprint(pub_key: &[u8; KEY_LEN]) -> String {
    let h = Sha256::digest(pub_key);
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// First line of a file (fgets(cap)), cut at the first of " \t\r\n"; None
/// when unreadable or empty.
fn read_first_line(path: &OsString, cap: usize) -> Option<Zeroizing<Vec<u8>>> {
    let f = std::fs::File::open(path).ok()?;
    let mut line = Zeroizing::new(Vec::with_capacity(cap));
    let mut r = std::io::BufReader::new(f).take(cap as u64 - 1);
    if r.read_until(b'\n', &mut line).ok()? == 0 {
        return None;
    }
    let end = line
        .iter()
        .position(|&c| matches!(c, b' ' | b'\t' | b'\r' | b'\n' | 0))
        .unwrap_or(line.len());
    line.truncate(end);
    (!line.is_empty()).then_some(line)
}

/// X25519 with all-zero-result rejection.
fn x25519(priv_key: &[u8], pub_key: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(priv_key);
    let mut p = [0u8; 32];
    p.copy_from_slice(pub_key);
    let shared = StaticSecret::from(*k).diffie_hellman(&PublicKey::from(p));
    if !shared.was_contributory() {
        return None;
    }
    Some(Zeroizing::new(*shared.as_bytes()))
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .ok()?;
    Some(out)
}

/// AES-256-GCM, detached tag: seal `buf` in place and return the tag.
fn gcm_seal(key: &[u8], iv: &[u8], aad: &[u8], buf: &mut [u8]) -> Option<[u8; 16]> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::try_from(iv).ok()?;
    let tag = c.encrypt_inout_detached(&nonce, aad, buf.into()).ok()?;
    let mut t = [0u8; 16];
    t.copy_from_slice(&tag);
    Some(t)
}

/// AES-256-GCM, detached tag: open `buf` in place; false (and `buf` wiped)
/// unless the tag verifies.
fn gcm_open(key: &[u8], iv: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> bool {
    let ok = (|| {
        let c = Aes256Gcm::new_from_slice(key).ok()?;
        let nonce = Nonce::try_from(iv).ok()?;
        let tag = Tag::try_from(tag).ok()?;
        c.decrypt_inout_detached(&nonce, aad, (&mut *buf).into(), &tag)
            .ok()
    })()
    .is_some();
    if !ok {
        buf.zeroize();
    }
    ok
}

/// `label "\0" lc(bot) "\0" lc(me) [ "\0" extra ]`, or None when it would
/// not fit in `cap` bytes (the C buffer, NUL included).
fn context(
    cap: usize,
    label: &str,
    bot: &[u8],
    me: &[u8],
    extra: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut v = Vec::with_capacity(cap);
    v.extend_from_slice(label.as_bytes());
    v.push(0);
    v.extend_from_slice(&lc_copy(bot, 64));
    v.push(0);
    v.extend_from_slice(&lc_copy(me, 64));
    if let Some(x) = extra {
        v.push(0);
        v.extend_from_slice(x);
    }
    (v.len() < cap).then_some(v)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---- passphrase-protected keys (irckey-v2) -----------------------------------

/// A parsed "irckey-v2 scrypt log2N r p salt nonce ct" line (bounds checked).
struct IrcKey {
    log2n: u32,
    r: u32,
    p: u32,
    salt: [u8; 16],
    nonce: [u8; 12],
    ct: Zeroizing<[u8; KEY_LEN + 16]>,
    aad: Vec<u8>,
}

fn is_irckey(line: &[u8]) -> bool {
    line.starts_with(format!("{IRCKEY_TAG} ").as_bytes())
}

fn small_uint(s: &[u8], lo: u32, hi: u32) -> Option<u32> {
    if s.is_empty() || s.len() > 3 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let x = s.iter().fold(0u32, |a, &c| a * 10 + u32::from(c - b'0'));
    (lo..=hi).contains(&x).then_some(x)
}

/// Exactly-n-bytes padded base64.
fn b64dec_n(s: &[u8], out: &mut [u8]) -> bool {
    s.len() == 4 * out.len().div_ceil(3) && b64dec(s, out) == Some(out.len())
}

fn irckey_parse(line: &[u8]) -> Option<IrcKey> {
    if line.len() >= IRCKEY_LINE_MAX
        || line.windows(2).any(|w| w == b"  ")
        || line.last() == Some(&b' ')
    {
        return None;
    }
    let f: Vec<&[u8]> = line.split(|&c| c == b' ').collect();
    if f.len() != 8 || f[0] != IRCKEY_TAG.as_bytes() || f[1] != b"scrypt" {
        return None;
    }
    let mut k = IrcKey {
        log2n: small_uint(f[2], IRCKEY_LOG2N.0, IRCKEY_LOG2N.1)?,
        r: small_uint(f[3], 1, IRCKEY_R_MAX)?,
        p: small_uint(f[4], 1, IRCKEY_P_MAX)?,
        salt: [0; 16],
        nonce: [0; 12],
        ct: Zeroizing::new([0; KEY_LEN + 16]),
        aad: line[..line.len() - f[7].len() - 1].to_vec(),
    };
    (b64dec_n(f[5], &mut k.salt) && b64dec_n(f[6], &mut k.nonce) && b64dec_n(f[7], &mut k.ct[..]))
        .then_some(k)
}

fn irckey_open(k: &IrcKey, pass: &[u8], priv_key: &mut [u8; KEY_LEN]) -> bool {
    let Ok(params) = scrypt::Params::new(k.log2n as u8, k.r, k.p) else {
        return false;
    };
    let mut key = Zeroizing::new([0u8; 32]);
    if scrypt::scrypt(pass, &k.salt, &params, key.as_mut()).is_err() {
        return false;
    }
    priv_key.copy_from_slice(&k.ct[..KEY_LEN]);
    gcm_open(key.as_ref(), &k.nonce, &k.aad, priv_key, &k.ct[KEY_LEN..])
}

/// One line from the terminal with echo off; None with no terminal, on EOF
/// or when longer than PASS_MAX.
#[cfg(unix)]
fn read_secret(prompt: &str) -> Option<Zeroizing<Vec<u8>>> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    use std::os::fd::AsFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let saved = tcgetattr(tty.as_fd()).ok()?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGQUIT,
    ] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }
    let mut t = saved.clone();
    t.local_flags.remove(LocalFlags::ECHO | LocalFlags::ECHONL);
    t.local_flags.insert(LocalFlags::ICANON);
    tcsetattr(tty.as_fd(), SetArg::TCSAFLUSH, &t).ok()?;
    let _ = tty.write_all(prompt.as_bytes());
    let mut buf = Zeroizing::new(Vec::with_capacity(PASS_MAX + 1));
    let (mut nl, mut too_long) = (false, false);
    let mut c = [0u8; 1];
    while !stop.load(Ordering::Relaxed) {
        match tty.read(&mut c) {
            Ok(0) => break,
            Ok(_) if c[0] == b'\n' => {
                nl = true;
                break;
            }
            Ok(_) if buf.len() < PASS_MAX => buf.push(c[0]),
            Ok(_) => too_long = true,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = tcsetattr(tty.as_fd(), SetArg::TCSAFLUSH, &saved);
    let _ = tty.write_all(b"\n");
    c.zeroize();
    if stop.load(Ordering::Relaxed) {
        drop(buf);
        std::process::exit(130);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    (nl && !too_long).then_some(buf)
}

/// The console, echo off (`bot-auth unlock` only: bot-auth.exe otherwise runs
/// in mIRC's hidden console, where a prompt would never be seen).
#[cfg(windows)]
fn read_secret(prompt: &str) -> Option<Zeroizing<Vec<u8>>> {
    let p = Zeroizing::new(rpassword::prompt_password(prompt).ok()?.into_bytes());
    (p.len() <= PASS_MAX).then_some(p)
}

#[cfg(not(any(unix, windows)))]
fn read_secret(_prompt: &str) -> Option<Zeroizing<Vec<u8>>> {
    None
}

/// A passphrase from the first line of a file only its owner can read.
fn file_secret(path: &OsString) -> Option<Zeroizing<Vec<u8>>> {
    let f = std::fs::File::open(path).ok()?;
    #[cfg(unix)]
    {
        let md = f.metadata().ok()?;
        if !md.is_file() || md.permissions().mode() & 0o077 != 0 {
            eprintln!(
                "bot-auth: {} must be a regular file with mode 0600",
                path.to_string_lossy()
            );
            return None;
        }
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(PASS_MAX + 1));
    let mut r = std::io::BufReader::new(f).take(PASS_MAX as u64 + 2);
    r.read_until(b'\n', &mut buf).ok()?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > PASS_MAX {
        return None;
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    (buf.len() <= PASS_MAX).then_some(buf)
}

/// "1h", "30m", "90s", "2d", "3600", "never" -> Some(seconds), -1 = never;
/// None = unreadable.
fn parse_expire(s: &[u8]) -> Option<i64> {
    if s == b"never" {
        return Some(-1);
    }
    let d = s.iter().take_while(|c| c.is_ascii_digit()).count();
    if d == 0 || d > 12 {
        return None;
    }
    let v: i64 = std::str::from_utf8(&s[..d]).ok()?.parse().ok()?;
    let mul = match &s[d..] {
        b"" | b"s" => 1,
        b"m" => 60,
        b"h" => 3600,
        b"d" => 86400,
        _ => return None,
    };
    (v <= EXPIRE_MAX / mul).then_some(v * mul)
}

// ---- key material ----------------------------------------------------------

struct UserKey {
    priv_key: Zeroizing<[u8; KEY_LEN]>, // ed || x (unused when held)
    pub_key: [u8; KEY_LEN],
    /// The key holder's socket when it does the private-key steps.
    held: Option<String>,
}

fn derive_pub(priv_key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut pub_key = [0u8; KEY_LEN];
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&priv_key[..32]);
    pub_key[..32].copy_from_slice(SigningKey::from_bytes(&seed).verifying_key().as_bytes());
    let mut x = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&priv_key[32..]);
    pub_key[32..].copy_from_slice(PublicKey::from(&StaticSecret::from(*x)).as_bytes());
    pub_key
}

/// The holder's socket for keyfile: a hash of its full path, in a private
/// 0700 directory ($XDG_RUNTIME_DIR/bot-auth or /tmp/bot-auth-<uid>).
#[cfg(unix)]
fn holder_name(keyfile: &OsString) -> Option<String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let full = std::fs::canonicalize(keyfile).ok()?;
    let h = Sha256::digest(full.as_os_str().as_encoded_bytes());
    let hex: String = h[..16].iter().map(|b| format!("{b:02x}")).collect();
    let uid = nix::unistd::getuid().as_raw();
    let dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(rt) if rt.starts_with('/') && rt.len() < 200 => format!("{rt}/bot-auth"),
        _ => format!("/tmp/bot-auth-{uid}"),
    };
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return None;
    }
    // ours, a real directory, and closed to everyone else
    let md = std::fs::symlink_metadata(&dir).ok()?;
    if !md.is_dir() || md.uid() != uid || md.mode() & 0o077 != 0 {
        eprintln!("bot-auth: {dir} is not a private directory of yours");
        return None;
    }
    let name = format!("{dir}/{hex}.sock");
    (name.len() < 108).then_some(name)
}

/// The holder's pipe for keyfile: a hash of its full path and the user name
/// (as the C bot-auth.exe names it, so either one's holder serves both).
#[cfg(windows)]
fn holder_name(keyfile: &OsString) -> Option<String> {
    let full = std::path::absolute(keyfile).ok()?;
    let user = std::env::var("USERNAME").unwrap_or_default();
    let id = format!("{}|{user}", full.to_string_lossy());
    let h = Sha256::digest(id.as_bytes());
    let hex: String = h[..16].iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(r"\\.\pipe\bot-auth-{hex}"))
}

#[cfg(not(any(unix, windows)))]
fn holder_name(_keyfile: &OsString) -> Option<String> {
    None
}

/// One holder request over an open connection.  Wire: op(1) len(2,
/// big-endian) payload; reply status(1: 0 ok) len(2) payload.
fn hold_request<S: Read + Write>(c: &mut S, op: u8, payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if payload.len() > HOLD_MAX {
        return None;
    }
    let mut req = vec![op];
    req.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    req.extend_from_slice(payload);
    c.write_all(&req).ok()?;
    let mut h = [0u8; 3];
    c.read_exact(&mut h).ok()?;
    let n = usize::from(u16::from_be_bytes([h[1], h[2]]));
    if h[0] != 0 || n > 64 {
        return None;
    }
    let mut out = Zeroizing::new(vec![0u8; n]);
    c.read_exact(&mut out).ok()?;
    Some(out)
}

/// One request to the holder (op, payload): the reply payload, or None (no
/// holder, refused, I/O error).
#[cfg(unix)]
fn holder_call(name: &str, op: u8, payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let mut c = UnixStream::connect(name).ok()?;
    let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = c.set_write_timeout(Some(Duration::from_secs(5)));
    hold_request(&mut c, op, payload)
}

#[cfg(windows)]
fn holder_call(name: &str, op: u8, payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    use interprocess::os::windows::named_pipe::{DuplexPipeStream, pipe_mode};
    let mut c = DuplexPipeStream::<pipe_mode::Bytes>::connect_by_path(name).ok()?;
    hold_request(&mut c, op, payload)
}

#[cfg(not(any(unix, windows)))]
fn holder_call(_name: &str, _op: u8, _payload: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    None
}

/// The whole first line of keyfile (CR/LF removed).
fn read_key_line(path: &OsString) -> Result<Zeroizing<Vec<u8>>, Die> {
    let f = std::fs::File::open(path).map_err(|_| Die(1, "cannot read the key file"))?;
    let mut line = Zeroizing::new(Vec::with_capacity(IRCKEY_LINE_MAX + 2));
    let mut r = std::io::BufReader::new(f).take(IRCKEY_LINE_MAX as u64 + 1);
    if r.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
        return Err(Die(1, "cannot read the key file"));
    }
    let end = line
        .iter()
        .position(|&c| matches!(c, b'\r' | b'\n'))
        .unwrap_or(line.len());
    line.truncate(end);
    Ok(line)
}

/// Loads keyfile.  A plain key is read directly.  An irckey-v2 key uses a
/// running holder, else (use_holder false, or none running) asks for the
/// passphrase on the terminal — or from passfile — and, failing that, exits
/// EXIT_LOCKED.
fn load_key_ex(
    path: &OsString,
    use_holder: bool,
    passfile: Option<&OsString>,
) -> Result<UserKey, Die> {
    let Ok(md) = std::fs::metadata(path) else {
        return Err(Die(1, "cannot read the key file"));
    };
    let line = read_key_line(path)?;
    let mut k = UserKey {
        priv_key: Zeroizing::new([0u8; KEY_LEN]),
        pub_key: [0u8; KEY_LEN],
        held: None,
    };
    let shown = path.to_string_lossy();
    if !is_irckey(&line) {
        #[cfg(unix)]
        {
            use std::io::IsTerminal;
            if md.permissions().mode() & 0o077 != 0 {
                eprintln!("bot-auth: warning: {shown} is readable by others — chmod 600 it");
            }
            if std::io::stderr().is_terminal() {
                eprintln!(
                    "bot-auth: warning: {shown} has no passphrase (add one: keygen --passwd {shown})"
                );
            }
        }
        #[cfg(not(unix))]
        let _ = md;
        let end = line
            .iter()
            .position(|&c| c == b' ' || c == b'\t')
            .unwrap_or(line.len());
        if b64dec(&line[..end], k.priv_key.as_mut()) != Some(KEY_LEN) {
            return Err(Die(
                1,
                "key file is not an 88-char private key (use the .private.b64)",
            ));
        }
        k.pub_key = derive_pub(&k.priv_key);
        return Ok(k);
    }
    let _ = md;
    let Some(ik) = irckey_parse(&line) else {
        return Err(Die(1, "unreadable or out-of-range irckey-v2 key file"));
    };
    drop(line);
    if use_holder
        && let Some(name) = holder_name(path)
        && let Some(p) = holder_call(&name, b'P', &[])
        && p.len() == KEY_LEN
    {
        k.pub_key.copy_from_slice(&p);
        k.held = Some(name);
        return Ok(k);
    }
    let mut ok = false;
    for _ in 0..if passfile.is_some() { 1 } else { 3 } {
        let pass = match passfile {
            Some(f) => file_secret(f),
            // bot-auth.exe runs in mIRC's hidden console: never prompt there
            None if cfg!(windows) && use_holder => None,
            None => read_secret("Passphrase: "),
        };
        let Some(pass) = pass else {
            break;
        };
        ok = irckey_open(&ik, &pass, &mut k.priv_key);
        if ok {
            break;
        }
        eprintln!("bot-auth: wrong passphrase (or a damaged key file)");
    }
    if !ok {
        eprintln!(
            "bot-auth: LOCKED: {shown} is passphrase-protected; run: bot-auth unlock {shown}"
        );
        return Err(Die(EXIT_LOCKED, ""));
    }
    k.pub_key = derive_pub(&k.priv_key);
    Ok(k)
}

fn load_key(path: &OsString) -> Result<UserKey, Die> {
    load_key_ex(path, true, None)
}

/// Ed25519 signature of an A2A context, locally or by the holder.
fn key_sign(k: &UserKey, msg: &[u8]) -> Option<[u8; 64]> {
    if let Some(name) = &k.held {
        let s = holder_call(name, b'S', msg)?;
        return <[u8; 64]>::try_from(&s[..]).ok();
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&k.priv_key[..32]);
    Some(SigningKey::from_bytes(&seed).sign(msg).to_bytes())
}

/// X25519(our x key, peer), locally or by the holder.
fn key_dh(k: &UserKey, peer: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if let Some(name) = &k.held {
        let s = holder_call(name, b'D', peer)?;
        let mut out = Zeroizing::new([0u8; 32]);
        if s.len() != 32 || s.iter().all(|&c| c == 0) {
            return None;
        }
        out.copy_from_slice(&s);
        return Some(out);
    }
    x25519(&k.priv_key[32..], peer)
}

/// The path in an "@file" argument.
fn after_at(arg: &OsString) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::OsStr::from_bytes(&arg.as_bytes()[1..]).to_os_string()
    }
    #[cfg(not(unix))]
    {
        arg.to_string_lossy()[1..].into()
    }
}

/// A bot public key given inline (88 chars) or as @file.
fn load_pub(arg: &OsString) -> Result<[u8; KEY_LEN], Die> {
    let a = arg.as_encoded_bytes();
    let line = if a.first() == Some(&b'@') {
        read_first_line(&after_at(arg), 256).ok_or(Die(1, "cannot read the pubkey file"))?
    } else {
        match read_first_line(arg, 256) {
            Some(l) => l,
            // snprintf(line, 256, "%s", arg)
            None => Zeroizing::new(a[..a.len().min(255)].to_vec()),
        }
    };
    let mut pub_key = [0u8; KEY_LEN];
    if line.len() != KEY_B64 || b64dec(&line, &mut pub_key) != Some(KEY_LEN) {
        return Err(Die(1, "not an 88-char public key"));
    }
    Ok(pub_key)
}

fn make_nonce() -> Result<String, Die> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| Die(2, "RNG failure"))?;
    Ok(r.iter().map(|b| format!("{b:02x}")).collect())
}

// ---- subcommands -----------------------------------------------------------

fn cmd_auth(keyfile: &OsString, bot: &[u8], me: &[u8]) -> Res {
    let k = load_key(keyfile)?;
    let nonce = make_nonce()?;
    let tsn = format!("{}:{nonce}", now());
    let Some(msg) = context(256, A2A_LABEL, bot, me, Some(tsn.as_bytes())) else {
        return Err(Die(2, "signing failed"));
    };
    let sig = key_sign(&k, &msg);
    drop(k);
    let Some(sig) = sig else {
        return Err(Die(2, "signing failed"));
    };
    println!("~A2A {} {tsn}", b64enc(&sig));
    Ok(0)
}

/// isspace(3) in the C locale.
fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// sscanf(line, "%63s %127s"): two whitespace-separated fields, each cut to
/// its width (a longer first field runs on into the second, as in C).
fn scan_two(line: &[u8]) -> Option<(&[u8], &[u8])> {
    fn field(s: &[u8], at: usize, width: usize) -> Option<(usize, usize)> {
        let start = at + s[at..].iter().take_while(|&&c| c_isspace(c)).count();
        let len = s[start..]
            .iter()
            .take(width)
            .take_while(|&&c| !c_isspace(c))
            .count();
        (len > 0).then_some((start, start + len))
    }
    let (a0, a1) = field(line, 0, 63)?;
    let (b0, b1) = field(line, a1, 127)?;
    Some((&line[a0..a1], &line[b0..b1]))
}

/// fgets(line, cap, f) chunks: each ends after '\n' or at cap-1 bytes.
fn fgets_chunks(data: &[u8], cap: usize) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let lim = rest.len().min(cap - 1);
        let end = rest[..lim]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(lim, |i| i + 1);
        let (chunk, r) = rest.split_at(end);
        rest = r;
        Some(chunk)
    })
}

/// Pin file: "<lc botnick> <pubkey b64>" per line.  0 ok/recorded, 3
/// mismatch.
fn pin_check(pinfile: &OsString, bot: &[u8], pub_key: &[u8; KEY_LEN]) -> Res {
    let want = b64enc(pub_key);
    let lbot = lc_copy(bot, 64);
    if let Ok(data) = std::fs::read(pinfile) {
        for line in fgets_chunks(&data, 256) {
            // %s stops at a NUL: sscanf sees the string up to it.
            let line = &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())];
            let Some((n, k)) = scan_two(line) else {
                continue;
            };
            if n != lbot.as_slice() {
                continue;
            }
            if k == want.as_bytes() {
                return Ok(0);
            }
            let mut old = [0u8; KEY_LEN];
            let ofp = if b64dec(k, &mut old) == Some(KEY_LEN) {
                fingerprint(&old)
            } else {
                "(unreadable)".to_string()
            };
            eprintln!(
                "bot-auth: *** KEY CHANGED for {}: pinned {ofp}, offered {} ***\n\
                 bot-auth: possible man-in-the-middle, or the bot was rekeyed.\n\
                 bot-auth: check the bot's 'status' / hub console 'bot list', then remove its line from {} to accept.",
                String::from_utf8_lossy(bot),
                fingerprint(pub_key),
                pinfile.to_string_lossy()
            );
            return Ok(3);
        }
    }
    // Created 0600 (the C tool's umask(077) around fopen "a").
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    o.mode(0o600);
    let Ok(mut f) = o.open(pinfile) else {
        return Err(Die(1, "cannot write the pin file"));
    };
    let mut rec = lbot;
    rec.push(b' ');
    rec.extend_from_slice(want.as_bytes());
    rec.push(b'\n');
    let _ = f.write_all(&rec);
    Ok(0)
}

fn cmd_open(
    keyfile: &OsString,
    bot: &[u8],
    me: &[u8],
    tsn: &[u8],
    reply: &[u8],
    pinfile: Option<&OsString>,
) -> Res {
    let b = reply.strip_prefix(b"~A2K ").unwrap_or(reply);
    let mut frame = [0u8; LOCKBOX_LEN + 4];
    if b64dec(b, &mut frame) != Some(LOCKBOX_LEN) {
        return Err(Die(2, "not a ~A2K lockbox"));
    }
    let k = load_key(keyfile)?;
    let mut info = A2K_LABEL.as_bytes().to_vec();
    info.extend_from_slice(&k.pub_key[32..]);
    let mut pub_key = [0u8; KEY_LEN];
    let ok = (|| {
        let aad = context(256, A2K_LABEL, bot, me, Some(tsn))?;
        let ss = key_dh(&k, &frame[..32])?;
        let key = hkdf(ss.as_ref(), &frame[..32], &info)?;
        pub_key.copy_from_slice(&frame[44..44 + KEY_LEN]);
        gcm_open(
            key.as_ref(),
            &frame[32..44],
            &aad,
            &mut pub_key,
            &frame[44 + KEY_LEN..LOCKBOX_LEN],
        )
        .then_some(())
    })()
    .is_some();
    drop(k);
    if !ok {
        return Err(Die(
            2,
            "lockbox did not verify (wrong key, bot nick, your nick, or ts:nonce)",
        ));
    }
    if let Some(pin) = pinfile {
        let rc = pin_check(pin, bot, &pub_key)?;
        if rc != 0 {
            return Ok(rc);
        }
    }
    println!("{} {}", b64enc(&pub_key), fingerprint(&pub_key));
    Ok(0)
}

/// fgets(line_in, MAX_CMD + 2, stdin) and feof(stdin) afterwards.
fn read_cmd_line() -> (Zeroizing<Vec<u8>>, bool) {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_CMD + 1));
    let mut stdin = std::io::stdin().lock();
    let mut eof = false;
    let mut c = [0u8; 1];
    while buf.len() < MAX_CMD + 1 {
        match stdin.read(&mut c) {
            Ok(0) | Err(_) => {
                eof = true;
                break;
            }
            Ok(_) => {
                buf.push(c[0]);
                if c[0] == b'\n' {
                    break;
                }
            }
        }
    }
    c.zeroize();
    (buf, eof)
}

/// With rkfile: a ~A2S frame, and its reply key HKDF(ikm, eph_pub, A2R_LABEL
/// || user_x || bot_x) written to rkfile (0600) for `bot-auth reply`.
fn cmd_cmd(
    keyfile: &OsString,
    bot: &[u8],
    me: &[u8],
    botpub: &OsString,
    rkfile: Option<&OsString>,
) -> Res {
    let label = if rkfile.is_some() {
        A2S_LABEL
    } else {
        A2_LABEL
    };
    let bpub = load_pub(botpub)?;
    let (line_in, eof) = read_cmd_line();
    if line_in.is_empty() && eof {
        return Err(Die(1, "no command on stdin"));
    }
    // The C string ends at a NUL; the command at the first '\r' or '\n'.
    let s = &line_in[..line_in
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(line_in.len())];
    let cl = s
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .unwrap_or(s.len());
    if cl == s.len() && !eof {
        return Err(Die(1, "command too long"));
    }
    let cmd = &s[..cl];
    if cmd.is_empty() {
        return Err(Die(1, "empty command"));
    }
    if cmd.iter().any(|&c| c < 0x20 || c == 0x7f) {
        return Err(Die(1, "control characters are not allowed in commands"));
    }

    let k = load_key(keyfile)?;
    let nonce = make_nonce()?;
    let mut pt = Zeroizing::new(format!("{}:{nonce}:", now()).into_bytes());
    pt.extend_from_slice(cmd);
    drop(line_in);
    let pl = pt.len();

    let mut info = label.as_bytes().to_vec();
    info.extend_from_slice(&k.pub_key[32..]);
    info.extend_from_slice(&bpub[32..]);
    let mut frame = vec![0u8; 44 + pl + 16];
    let mut rk = None;
    let ok = (|| {
        let mut eph = Zeroizing::new([0u8; 32]);
        getrandom::fill(eph.as_mut()).ok()?;
        let eph_pub = PublicKey::from(&StaticSecret::from(*eph)).to_bytes();
        let aad = context(160, label, bot, me, None)?;
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(x25519(eph.as_ref(), &bpub[32..])?.as_ref());
        ikm[32..].copy_from_slice(key_dh(&k, &bpub[32..])?.as_ref());
        let key = hkdf(ikm.as_ref(), &eph_pub, &info)?;
        frame[..32].copy_from_slice(&eph_pub);
        getrandom::fill(&mut frame[32..44]).ok()?;
        let (head, body) = frame.split_at_mut(44);
        body[..pl].copy_from_slice(&pt);
        let tag = gcm_seal(key.as_ref(), &head[32..44], &aad, &mut body[..pl])?;
        body[pl..].copy_from_slice(&tag);
        if rkfile.is_some() {
            // A2S_LABEL and A2R_LABEL are the same length.
            info[..A2R_LABEL.len()].copy_from_slice(A2R_LABEL.as_bytes());
            rk = Some(hkdf(ikm.as_ref(), &eph_pub, &info)?);
        }
        Some(())
    })()
    .is_some();
    drop(k);
    drop(pt);
    if !ok {
        return Err(Die(2, "sealing failed"));
    }
    let out = b64enc(&frame);
    if out.len() + if rkfile.is_some() { 5 } else { 4 } > MAX_LINE {
        return Err(Die(
            1,
            "command too long for one IRC line (keep it under ~200 chars)",
        ));
    }
    if let (Some(path), Some(rk)) = (rkfile, rk) {
        let rb = Zeroizing::new(format!("{}\n", b64enc(rk.as_ref())));
        drop(rk);
        let mut o = OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        o.mode(0o600);
        let wrote = match o.open(path) {
            Ok(mut f) => {
                #[cfg(unix)]
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                f.write_all(rb.as_bytes()).is_ok() && f.flush().is_ok()
            }
            Err(_) => false,
        };
        if !wrote {
            return Err(Die(1, "cannot write the reply key file"));
        }
    }
    println!("{} {out}", if rkfile.is_some() { "~A2S" } else { "~A2" });
    Ok(0)
}

/// strtoul(s, &e, 10) on a C string: leading space, an optional sign, digits
/// (ULONG_MAX on overflow, a '-' negates).  Returns (value, index of e).
fn strtoul(s: &[u8]) -> (u64, usize) {
    let mut i = s.iter().take_while(|&&c| c_isspace(c)).count();
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let d0 = i;
    let mut v: u64 = 0;
    let mut over = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add(u64::from(s[i] - b'0')))
        {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if i == d0 {
        return (0, 0);
    }
    if over {
        return (u64::MAX, i);
    }
    (if neg { v.wrapping_neg() } else { v }, i)
}

/// Open the bot's ~A2R replies to one ~A2S command (its reply key in
/// rkfile): "<seq>:<more>:<text>" pieces, seq rising (a repeat is dropped),
/// pieces with more = 1 joined to the next.  Control bytes are shown as '?'.
/// Exit 2 if any ~A2R line did not open.
fn cmd_reply(rkfile: &OsString, bot: &[u8], me: &[u8]) -> Res {
    let mut rk = Zeroizing::new([0u8; 32]);
    let Some(line) = read_first_line(rkfile, 2048) else {
        return Err(Die(1, "cannot read the reply key file"));
    };
    let kl = b64dec(&line, rk.as_mut());
    drop(line);
    if kl != Some(32) {
        return Err(Die(1, "not a reply key file (from bot-auth cmd --sealed)"));
    }
    let Some(aad) = context(160, A2R_LABEL, bot, me, None) else {
        return Err(Die(1, "bot nick or your nick too long"));
    };

    let mut stdin = std::io::stdin().lock();
    let mut line = Zeroizing::new(Vec::<u8>::with_capacity(2048));
    let mut out = std::io::stdout().lock();
    let mut joined = Zeroizing::new(Vec::<u8>::with_capacity(8192));
    let mut next: u64 = 0;
    let mut seen = false;
    let mut bad = 0;
    // while (fgets(line, 2048, stdin)): one line, or 2047 bytes of one
    loop {
        line.clear();
        match (&mut stdin).take(2047).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        // strstr and strcspn stop at a NUL
        let chunk = &line[..line.iter().position(|&c| c == 0).unwrap_or(line.len())];
        let Some(at) = chunk.windows(5).position(|w| w == b"~A2R ") else {
            continue;
        };
        let p = &chunk[at + 5..];
        let p = &p[..p
            .iter()
            .position(|&c| matches!(c, b'\r' | b'\n' | b' ' | b'\t'))
            .unwrap_or(p.len())];
        let mut fr = Zeroizing::new([0u8; A2R_PT_MAX + 28 + 4]);
        let fl = b64dec(p, fr.as_mut());
        let opened = match fl {
            Some(fl) if fl >= 28 && fl - 28 <= A2R_PT_MAX => {
                let n = fl - 28;
                let (iv, rest) = fr.split_at_mut(12);
                let (ct, tag) = rest.split_at_mut(n);
                gcm_open(rk.as_ref(), iv, &aad, ct, &tag[..16]).then_some(n)
            }
            _ => None,
        };
        let Some(n) = opened else {
            eprintln!(
                "bot-auth: an ~A2R line did not open (a reply to another command, or the wrong nicks)"
            );
            bad += 1;
            continue;
        };
        // pt[n] = '\0': the C string ends at the first NUL
        let pt = &fr[12..12 + n];
        let pt = &pt[..pt.iter().position(|&c| c == 0).unwrap_or(n)];
        let (seq, e) = strtoul(pt);
        let at = |i: usize| pt.get(i).copied().unwrap_or(0);
        if e == 0 || at(e) != b':' || (at(e + 1) != b'0' && at(e + 1) != b'1') || at(e + 2) != b':'
        {
            bad += 1;
            continue;
        }
        if seen && seq < next {
            // a repeat of a piece already shown
            continue;
        }
        if seen && seq != next && !joined.is_empty() {
            // a piece went missing
            let _ = out.write_all(&joined);
            let _ = out.write_all(b" [...]\n");
            joined.clear();
        }
        next = seq.wrapping_add(1);
        seen = true;
        for &t in &pt[e + 3..] {
            if joined.len() >= 8192 - 1 {
                break;
            }
            joined.push(if t < 0x20 || t == 0x7f { b'?' } else { t });
        }
        if at(e + 1) == b'0' {
            let _ = out.write_all(&joined);
            let _ = out.write_all(b"\n");
            joined.clear();
        }
    }
    if !joined.is_empty() {
        let _ = out.write_all(&joined);
        let _ = out.write_all(b" [...]\n");
    }
    let _ = out.flush();
    Ok(if bad > 0 { 2 } else { 0 })
}

fn cmd_fp(arg: &OsString) -> Res {
    let pub_key = load_pub(arg)?;
    println!("{}", fingerprint(&pub_key));
    Ok(0)
}

// ---- key holder ------------------------------------------------------------

/// Answers one holder request; the reply payload, or None (refused).  'S'
/// signs only an A2A auth context.
fn hold_answer(k: &UserKey, op: u8, p: &[u8], deadline: i64, quit: &mut bool) -> Option<Vec<u8>> {
    match op {
        b'P' => Some(k.pub_key.to_vec()),
        b'S' => {
            let ll = A2A_LABEL.len() + 1;
            if p.len() <= ll || &p[..ll - 1] != A2A_LABEL.as_bytes() || p[ll - 1] != 0 {
                return None;
            }
            key_sign(k, p).map(|s| s.to_vec())
        }
        b'D' if p.len() == 32 => x25519(&k.priv_key[32..], p).map(|s| s.to_vec()),
        b'T' if deadline == 0 => Some(b"never".to_vec()),
        b'T' => Some((deadline - now()).max(0).to_string().into_bytes()),
        b'Q' => {
            *quit = true;
            Some(Vec::new())
        }
        _ => None,
    }
}

/// Reads one request from c and answers it; false = end the holder.
fn hold_serve<S: Read + Write>(k: &UserKey, c: &mut S, deadline: i64) -> bool {
    let mut quit = false;
    let mut h = [0u8; 3];
    let mut ans = None;
    if c.read_exact(&mut h).is_ok() {
        let n = usize::from(u16::from_be_bytes([h[1], h[2]]));
        let mut p = Zeroizing::new(vec![0u8; n.min(HOLD_MAX)]);
        if n <= HOLD_MAX && c.read_exact(&mut p).is_ok() {
            ans = hold_answer(k, h[0], &p, deadline, &mut quit).map(Zeroizing::new);
        }
    }
    let mut r = vec![u8::from(ans.is_none()), 0, 0];
    if let Some(a) = &ans {
        r[2] = a.len() as u8;
        r.extend_from_slice(a);
    }
    let _ = c.write_all(&r);
    r.zeroize();
    !quit
}

/// Only the user who started the holder may talk to it.
#[cfg(unix)]
fn peer_is_me(c: &std::os::unix::net::UnixStream) -> bool {
    let me = nix::unistd::getuid().as_raw();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use nix::sys::socket::{getsockopt, sockopt};
        getsockopt(c, sockopt::PeerCredentials).is_ok_and(|cr| cr.uid() == me)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        nix::unistd::getpeereid(c).is_ok_and(|(u, _)| u.as_raw() == me)
    }
}

/// `bot-auth __hold <socket> <deadline|0>`: the holder process that
/// `unlock` starts.  Reads the 64-byte key from stdin, binds the socket,
/// says "OK" on stdout, then serves until the deadline, `lock` or a signal.
#[cfg(unix)]
fn cmd_hold(name: &[u8], deadline: &[u8]) -> Res {
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let name = String::from_utf8_lossy(name).into_owned();
    let deadline: i64 = std::str::from_utf8(deadline)
        .ok()
        .and_then(|d| d.parse().ok())
        .ok_or(Die(1, "bad deadline"))?;
    let mut k = UserKey {
        priv_key: Zeroizing::new([0u8; KEY_LEN]),
        pub_key: [0u8; KEY_LEN],
        held: None,
    };
    let _lock = region::lock(k.priv_key.as_ptr(), KEY_LEN).ok();
    std::io::stdin()
        .read_exact(k.priv_key.as_mut())
        .map_err(|_| Die(1, "no key on stdin"))?;
    k.pub_key = derive_pub(&k.priv_key);
    let _ = nix::unistd::setsid();
    let _ = std::fs::remove_file(&name); // stale: unlock checked no holder answers
    let old = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let ls = UnixListener::bind(&name);
    nix::sys::stat::umask(old);
    let ls = ls.map_err(|_| Die(1, "cannot create the key holder's socket"))?;
    let _ = std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o600));
    ls.set_nonblocking(true)
        .map_err(|_| Die(1, "cannot create the key holder's socket"))?;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }
    {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"OK\n");
        let _ = out.flush();
    }
    // stdout is a pipe to `unlock`; from here on nothing is printed.
    let mut go_on = true;
    while go_on && !stop.load(Ordering::Relaxed) && (deadline == 0 || now() < deadline) {
        match ls.accept() {
            Ok((mut c, _)) => {
                let _ = c.set_nonblocking(false);
                let t = Some(std::time::Duration::from_secs(2));
                let _ = c.set_read_timeout(t);
                let _ = c.set_write_timeout(t);
                if peer_is_me(&c) {
                    go_on = hold_serve(&k, &mut c, deadline);
                }
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }
    let _ = std::fs::remove_file(&name);
    drop(k);
    Ok(0)
}

/// The current user's SID ("S-1-5-21-..."), from whoami(1).
#[cfg(windows)]
fn current_sid() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let sid = text
        .trim()
        .rsplit(',')
        .next()?
        .trim_matches('"')
        .to_string();
    (sid.starts_with("S-1-") && sid[4..].chars().all(|c| c.is_ascii_digit() || c == '-'))
        .then_some(sid)
}

/// `bot-auth __hold <pipe> <deadline|0>` on Windows: a named pipe only the
/// current user can open (DACL from its SID), remote clients refused.
#[cfg(windows)]
fn cmd_hold(name: &[u8], deadline: &[u8]) -> Res {
    use interprocess::os::windows::named_pipe::{PipeListenerOptions, PipeMode, pipe_mode};
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    let name = String::from_utf8_lossy(name).into_owned();
    let deadline: i64 = std::str::from_utf8(deadline)
        .ok()
        .and_then(|d| d.parse().ok())
        .ok_or(Die(1, "bad deadline"))?;
    let mut k = UserKey {
        priv_key: Zeroizing::new([0u8; KEY_LEN]),
        pub_key: [0u8; KEY_LEN],
        held: None,
    };
    let _lock = region::lock(k.priv_key.as_ptr(), KEY_LEN).ok();
    std::io::stdin()
        .read_exact(k.priv_key.as_mut())
        .map_err(|_| Die(1, "no key on stdin"))?;
    k.pub_key = derive_pub(&k.priv_key);
    let sd = current_sid()
        .and_then(|sid| widestring::U16CString::from_str(format!("D:P(A;;GA;;;{sid})")).ok())
        .and_then(|w| SecurityDescriptor::deserialize(&w).ok())
        .ok_or(Die(1, "cannot build the pipe's access list"))?;
    let ls = PipeListenerOptions::new()
        .path(name.as_str())
        .mode(PipeMode::Bytes)
        .nonblocking(true)
        .accept_remote(false)
        .security_descriptor(Some(sd))
        .create_duplex::<pipe_mode::Bytes>()
        .map_err(|_| Die(1, "cannot create the key holder's pipe"))?;
    {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"OK\n");
        let _ = out.flush();
    }
    let mut go_on = true;
    while go_on && (deadline == 0 || now() < deadline) {
        match ls.accept() {
            Ok(mut c) => {
                let _ = c.set_nonblocking(false);
                go_on = hold_serve(&k, &mut c, deadline);
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }
    drop(k);
    Ok(0)
}

fn local_time(t: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(t, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

fn cmd_unlock(keyfile: &OsString, expire: Option<&[u8]>, passfile: Option<&OsString>) -> Res {
    let Some(secs) = parse_expire(expire.unwrap_or(b"1h")) else {
        return Err(Die(
            1,
            "--expire: use e.g. 30m, 1h, 6h, 1d, a number of seconds, or never",
        ));
    };
    if secs == 0 {
        return Err(Die(
            1,
            "--expire 0 means ask every time: use no key holder at all",
        ));
    }
    let Some(name) = holder_name(keyfile) else {
        return Err(Die(1, "cannot name the key holder"));
    };
    if let Some(t) = holder_call(&name, b'T', &[]) {
        let t = String::from_utf8_lossy(&t).into_owned();
        let unit = if t == "never" { "" } else { " s" };
        println!("already unlocked ({t}{unit} left)");
        return Ok(0);
    }
    let shown = keyfile.to_string_lossy();
    if !is_irckey(&read_key_line(keyfile)?) {
        println!("{shown} has no passphrase: nothing to unlock (add one: keygen --passwd)");
        return Ok(0);
    }
    let k = load_key_ex(keyfile, false, passfile)?;
    let deadline = if secs > 0 { now() + secs } else { 0 };
    let exe = std::env::current_exe().map_err(|_| Die(1, "cannot start the key holder"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__hold")
        .arg(&name)
        .arg(deadline.to_string())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    cmd.current_dir("/");
    #[cfg(windows)]
    {
        // no console of its own, out of the unlock window's Ctrl-C group:
        // the unlock window closes and the holder keeps running
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .spawn()
        .map_err(|_| Die(1, "cannot start the key holder"))?;
    let sent = child
        .stdin
        .take()
        .is_some_and(|mut i| i.write_all(k.priv_key.as_ref()).is_ok());
    drop(k);
    let mut ready = String::new();
    if let Some(o) = child.stdout.take() {
        let _ = std::io::BufReader::new(o).read_line(&mut ready);
    }
    if !sent || ready != "OK\n" {
        let _ = child.kill();
        return Err(Die(1, "the key holder did not start"));
    }
    let pid = child.id();
    if deadline > 0 {
        println!(
            "unlocked {shown} until {} (holder pid {pid})",
            local_time(deadline)
        );
    } else {
        println!("unlocked {shown} until bot-auth lock (holder pid {pid})");
    }
    Ok(0)
}

fn cmd_lock(keyfile: &OsString) -> Res {
    let Some(name) = holder_name(keyfile) else {
        return Err(Die(1, "cannot name the key holder"));
    };
    if holder_call(&name, b'Q', &[]).is_none() {
        println!("locked (no key holder was running)");
    } else {
        println!("locked");
    }
    Ok(0)
}

fn cmd_status(keyfile: &OsString) -> Res {
    let Some(name) = holder_name(keyfile) else {
        return Err(Die(1, "cannot name the key holder"));
    };
    match holder_call(&name, b'T', &[]) {
        Some(t) if !t.is_empty() => {
            println!("unlocked {}", String::from_utf8_lossy(&t));
            Ok(0)
        }
        _ => {
            println!("locked");
            Ok(EXIT_LOCKED)
        }
    }
}

fn usage() -> Res {
    eprintln!(
        "usage: bot-auth auth <keyfile> <botnick> <yournick>\n\
         \x20      bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply> [--pin <pinfile>]\n\
         \x20      bot-auth cmd  <keyfile> <botnick> <yournick> <botpubkey|@file> [--sealed <replykeyfile>]\n\
         \x20                    (command on stdin)\n\
         \x20      bot-auth reply <replykeyfile> <botnick> <yournick>   (~A2R lines on stdin)\n\
         \x20      bot-auth fp   <pubkey|file>\n\
         \x20      bot-auth unlock <keyfile> [--expire <30m|1h|6h|1d|secs|never>] [--passphrase-file <f>]\n\
         \x20      bot-auth lock   <keyfile>\n\
         \x20      bot-auth status <keyfile>\n\
         keyfile is your <ts>_<name>.private.b64 (chmod 600). See utils/README.txt."
    );
    Ok(1)
}

fn run() -> Res {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let argc = argv.len();
    let b = |i: usize| argv[i].as_encoded_bytes();
    if argc < 2 {
        return usage();
    }
    match (b(1), argc) {
        (b"auth", 5) => cmd_auth(&argv[2], b(3), b(4)),
        (b"open", 7 | 9) => {
            let pin = if argc == 9 {
                if b(7) != b"--pin" {
                    return usage();
                }
                Some(&argv[8])
            } else {
                None
            };
            cmd_open(&argv[2], b(3), b(4), b(5), b(6), pin)
        }
        (b"cmd", 6) => cmd_cmd(&argv[2], b(3), b(4), &argv[5], None),
        (b"cmd", 8) if b(6) == b"--sealed" => {
            cmd_cmd(&argv[2], b(3), b(4), &argv[5], Some(&argv[7]))
        }
        (b"reply", 5) => cmd_reply(&argv[2], b(3), b(4)),
        (b"fp", 3) => cmd_fp(&argv[2]),
        (b"unlock", n) if n >= 3 => {
            let (mut exp, mut pf) = (None, None);
            let mut i = 3;
            while i < argc {
                match b(i) {
                    b"--expire" if i + 1 < argc && exp.is_none() => exp = Some(b(i + 1)),
                    b"--passphrase-file" if i + 1 < argc && pf.is_none() => pf = Some(&argv[i + 1]),
                    _ => return usage(),
                }
                i += 2;
            }
            cmd_unlock(&argv[2], exp, pf)
        }
        (b"lock", 3) => cmd_lock(&argv[2]),
        (b"status", 3) => cmd_status(&argv[2]),
        #[cfg(any(unix, windows))]
        (b"__hold", 4) => cmd_hold(b(2), b(3)),
        _ => usage(),
    }
}

fn main() {
    #[cfg(unix)]
    {
        let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
        // no same-uid ptrace of the key holder
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let _ = nix::sys::prctl::set_dumpable(false);
    }
    // Every secret is dropped (wiped) inside run() before the exit.
    let rc = match run() {
        Ok(rc) => rc,
        Err(Die(rc, msg)) => {
            if !msg.is_empty() {
                eprintln!("bot-auth: {msg}");
            }
            rc
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(rc);
}
