//! Signed self-update (utils.c): the release manifest is fetched with its
//! detached Ed25519 signature and verified against BOT_UPDATE_PUBKEY_B64
//! before any field in it is trusted.  Fail closed: an unconfigured key, an
//! unreachable server or a bad signature all stop the update.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use crate::consts::*;
use crate::cstr::{Tok, eq_ic};
use crate::state::BotState;
use crate::{config, crypto, dcc, irc_client, ircf, logm};

/// Largest manifest, signature or archive the updater will take.
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;

/// glibc strverscmp for the version strings ("v2.10.0" > "v2.9.1").
pub fn strverscmp(s1: &str, s2: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let a = s1.as_bytes();
    let b = s2.as_bytes();
    let at = |v: &[u8], i: usize| v.get(i).copied().unwrap_or(0);
    let mut i = 0;
    while at(a, i) == at(b, i) {
        if at(a, i) == 0 {
            return Ordering::Equal;
        }
        i += 1;
    }
    let (mut c1, mut c2) = (at(a, i), at(b, i));
    if c1.is_ascii_digit() && c2.is_ascii_digit() {
        let mut state = Ordering::Equal;
        let (mut p1, mut p2) = (i + 1, i + 1);
        loop {
            if state == Ordering::Equal {
                state = c1.cmp(&c2);
            }
            c1 = if at(a, p1).is_ascii_digit() {
                p1 += 1;
                at(a, p1 - 1)
            } else {
                0
            };
            c2 = if at(b, p2).is_ascii_digit() {
                p2 += 1;
                at(b, p2 - 1)
            } else {
                0
            };
            if c1 == 0 && c2 == 0 {
                break;
            }
            if c1 == 0 {
                return Ordering::Less;
            }
            if c2 == 0 {
                return Ordering::Greater;
            }
        }
        return state;
    }
    c1.cmp(&c2)
}

/// Release manifests spell versions with a leading 'v' ("v2.3.0") while
/// BOT_VERSION does not ("2.3.0"), and an admin may type either.  Compare
/// them on the numeric part alone: strverscmp("v0.0.1", "2.3.0") would
/// otherwise compare 'v' against '2' and report a downgrade as an upgrade,
/// which is exactly what the downgrade guard exists to stop.
fn strip_v(v: &str) -> &str {
    v.strip_prefix('v')
        .or_else(|| v.strip_prefix('V'))
        .unwrap_or(v)
}

/// updater_version_cmp() in utils.c.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    strverscmp(strip_v(a), strip_v(b))
}

fn version_eq(a: &str, b: &str) -> bool {
    eq_ic(strip_v(a), strip_v(b))
}

/// ---- Host capability probe (answered in CMD_UPGRADE_READY) --------------
/// Both answers describe the RUNNING binary, not the machine in the abstract:
/// a bot reports what it can be replaced with.  The arch is spelled the way
/// `uname -m` spells it, to match the manifest; the libc is decided at
/// compile time because the binary is already linked against one.
pub fn host_arch() -> String {
    std::env::consts::ARCH.to_string()
}

pub fn host_libc() -> String {
    if cfg!(target_env = "musl") {
        "musl".to_string()
    } else if cfg!(target_os = "linux") {
        "gnu".to_string()
    } else {
        "unknown".to_string()
    }
}

/// The variant this binary was built from.  The C twin answers "c"; both are
/// wire- and config-compatible, so a node may be flipped either way.  Same
/// value the compiled release URL carries, so "keep my variant" and the URL
/// can never disagree.
pub fn host_variant() -> &'static str {
    BOT_UPDATE_VARIANT
}

/// The first CPU feature graviola needs that this host lacks, or `None`.
///
/// graviola (the rustls provider, for TLS IRC and the updater's HTTPS)
/// *asserts* its CPU features lazily, on the first crypto call — deep inside
/// a handshake, where a panic takes the whole bot down.  That is how an
/// Ivy Bridge node (no BMI1/ADX/AVX2) died mid-upgrade in run 96e79880:
/// building the provider does no crypto, so wrapping only that proved
/// nothing.  The list mirrors graviola 0.4.1's verify_cpu_features(), in its
/// order, so the name reported matches graviola's own message.
pub fn tls_cpu_missing() -> Option<&'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::is_x86_feature_detected as has;
        let checks: [(&'static str, bool); 6] = [
            ("aes", has!("aes")),
            ("pclmulqdq", has!("pclmulqdq")),
            ("bmi1", has!("bmi1")),
            ("adx", has!("adx")),
            ("avx", has!("avx")),
            ("avx2", has!("avx2")),
        ];
        checks.iter().find(|(_, ok)| !ok).map(|(name, _)| *name)
    }
    #[cfg(target_arch = "aarch64")]
    {
        use std::arch::is_aarch64_feature_detected as has;
        let checks: [(&'static str, bool); 4] = [
            ("neon", has!("neon")),
            ("aes", has!("aes")),
            ("pmull", has!("pmull")),
            ("sha2", has!("sha2")),
        ];
        checks.iter().find(|(_, ok)| !ok).map(|(name, _)| *name)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Some("a supported CPU architecture")
    }
}

/// Why HTTPS cannot be used on this host, for an operator-facing reason.
pub fn tls_unusable_reason() -> Option<String> {
    tls_cpu_missing()
        .map(|f| format!("this CPU lacks {f}, which the Rust build's TLS needs — use the C build"))
}

/// Install the rustls provider once, and say whether HTTPS is usable at all.
///
/// ureq is built with `rustls-no-provider`, so it reads the process default
/// and panics if there is none.  irc_client installs it too, but only on the
/// first TLS IRC connection -- a bot on a plaintext server reaches the
/// updater without one.  A CPU graviola cannot run on is refused here, before
/// any crypto, instead of the bot dying mid-download.
fn tls_ready() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        if tls_cpu_missing().is_some() {
            return false;
        }
        let _ = rustls_graviola::default_provider().install_default();
        true
    })
}

fn agent() -> ureq::Agent {
    let quick = QUICK_FETCH.load(std::sync::atomic::Ordering::Relaxed);
    // Always bounded: an unbounded transfer would wedge the bot, which
    // serves neither IRC nor its hub link while it blocks.
    let (connect, global) = if quick {
        (5, UPGRADE_QUICK_TIMEOUT)
    } else {
        (30, UPDATE_FETCH_TIMEOUT)
    };
    ureq::Agent::config_builder()
        .user_agent("ircbot-updater/1.0")
        .timeout_connect(Some(std::time::Duration::from_secs(connect)))
        .timeout_global(Some(std::time::Duration::from_secs(global)))
        .build()
        .into()
}

/// Manifest reads answered from the event loop (a PREPARE check) run on a
/// short budget: the bot serves neither IRC nor its hub link while ureq
/// blocks, and "unable: manifest fetch failed" beats a dropped link.
static QUICK_FETCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A `file://` URL is read straight off disk: ureq speaks HTTP only, while
/// the C updater gets this for free from libcurl.  Reachable only under the
/// IRCBOT_UPDATE_BASE override (validate_url() still rejects it otherwise),
/// and the signature and hash checks are unchanged either way.
fn file_url_path(url: &str) -> Option<&str> {
    url.strip_prefix("file://")
}

fn fetch(url: &str, limit: u64) -> Option<Vec<u8>> {
    if let Some(path) = file_url_path(url) {
        let meta = std::fs::metadata(path).ok()?;
        if meta.len() > limit {
            return None;
        }
        return std::fs::read(path).ok();
    }
    if !tls_ready() {
        return None;
    }
    let mut resp = agent().get(url).call().ok()?;
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .ok()
}

fn download(url: &str, path: &str) -> bool {
    download_with(url, path, &mut |_, _| {})
}

/// `std::io::copy`, telling `tick` as it goes when the size is known.
fn copy_with(
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
    total: u64,
    tick: &mut dyn FnMut(u64, u64),
) -> bool {
    let mut buf = [0u8; 65536];
    let mut got = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => return true,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    return false;
                }
                got += n as u64;
                if total > 0 {
                    tick(got, total);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

/// As `download`; `tick` hears the bytes so far against the size the server gave.
fn download_with(url: &str, path: &str, tick: &mut dyn FnMut(u64, u64)) -> bool {
    if let Some(src) = file_url_path(url) {
        return std::fs::metadata(src).is_ok_and(|m| m.len() <= MAX_ARCHIVE)
            && std::fs::copy(src, path).is_ok();
    }
    if !tls_ready() {
        return false;
    }
    let Ok(mut resp) = agent().get(url).call() else {
        return false;
    };
    let total = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let Ok(mut f) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    else {
        return false;
    };
    let mut reader = resp.body_mut().with_config().limit(MAX_ARCHIVE).reader();
    copy_with(&mut reader, &mut f, total, tick) && f.flush().is_ok()
}

/// Test hook, compiled in only with the `test-hooks` feature (the testnet's
/// builds; never a release): a non-empty IRCBOT_UPDATE_BASE overrides the
/// compiled release ROOT (`BOT_UPDATE_BASE`) so the sandbox can read a local
/// ircbot-releases tree over file://, and IRCBOT_UPDATE_PUBKEY then names the
/// throwaway key that signs it.  A production binary has no code that reads
/// either: its root and key are the compiled-in ones, so nobody who can set
/// the daemon's environment can point it at their own signed releases.
/// Nothing a hub sends can set or move the root either.
#[cfg(feature = "test-hooks")]
fn env_root() -> Option<String> {
    std::env::var("IRCBOT_UPDATE_BASE")
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(not(feature = "test-hooks"))]
fn env_root() -> Option<String> {
    None
}

#[cfg(feature = "test-hooks")]
fn env_pubkey() -> Option<String> {
    env_root()?;
    std::env::var("IRCBOT_UPDATE_PUBKEY")
        .ok()
        .filter(|s| !s.is_empty())
}

#[cfg(not(feature = "test-hooks"))]
fn env_pubkey() -> Option<String> {
    None
}

fn update_root() -> String {
    env_root().unwrap_or_else(|| BOT_UPDATE_BASE.to_string())
}

/// The release tree `<root>/<variant>` the next manifest read uses; empty =
/// this build's own variant.  A hub-driven run or -checkupdate names the
/// variant (set_tree); the root is never the hub's to choose.
static UPDATE_TREE: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

fn set_tree(variant: &str) -> bool {
    if variant.is_empty()
        || variant.len() > 7
        || variant.contains(['/', ';', '|', '&', '`', '$', ' ', '\t', '\r', '\n'])
    {
        return false;
    }
    match UPDATE_TREE.write() {
        Ok(mut slot) => {
            *slot = format!("{}/{variant}", update_root());
            true
        }
        Err(_) => false,
    }
}

fn update_tree() -> String {
    match UPDATE_TREE.read() {
        Ok(t) if !t.is_empty() => t.clone(),
        _ => format!("{}/{}", update_root(), host_variant()),
    }
}

fn fetch_verified_manifest() -> Result<String, &'static str> {
    // Pinned key; only a test-hooks build takes a throwaway one (env_pubkey).
    let pubkey_b64 = env_pubkey().unwrap_or_else(|| BOT_UPDATE_PUBKEY_B64.to_string());
    if pubkey_b64.is_empty() {
        return Err("self-updater disabled (no signing key configured)");
    }
    let pk = crypto::update_pubkey_b64_decode(&pubkey_b64)
        .ok_or("configured update public key is malformed")?;
    let tree = update_tree();
    let (man_url, sig_url) = (
        format!("{tree}/releases.txt"),
        format!("{tree}/releases.sig"),
    );
    let man = fetch(&man_url, MAX_MANIFEST).ok_or("failed to download release manifest")?;
    let sig = fetch(&sig_url, MAX_MANIFEST)
        .ok_or("failed to download release signature (releases.txt.sig)")?;
    let sig_text = String::from_utf8_lossy(&sig);
    let sig_bytes = crypto::b64_decode(sig_text.trim_end());
    let ok = sig_bytes.is_some_and(|s| s.len() == 64 && crypto::ed25519_verify(&pk, &man, &s));
    if !ok {
        return Err("release manifest signature INVALID — possible tampering");
    }
    Ok(String::from_utf8_lossy(&man).into_owned())
}

/// One manifest line: version date url sha256 deps.
fn parse_release(line: &str) -> Option<[&str; 5]> {
    let mut t = Tok::new(line);
    let f = [
        t.next(" \t")?,
        t.next(" \t")?,
        t.next(" \t")?,
        t.next(" \t")?,
        t.next(" \t")?,
    ];
    let caps = [63, 63, 511, 127, 255];
    f.iter().zip(caps).all(|(s, c)| s.len() <= c).then_some(f)
}

fn valid_dependency_name(dep: &str) -> bool {
    !dep.is_empty()
        && dep.len() <= 64
        && dep
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.+".contains(&c))
}

/// A build tool on PATH, or a library pkg-config (or the compiler) knows.
fn check_dependency(dep: &str) -> bool {
    if !valid_dependency_name(dep) {
        return false;
    }
    let script = if ["gcc", "make", "tar", "bash", "cargo", "rustc"].contains(&dep) {
        format!("command -v {dep} >/dev/null 2>&1")
    } else {
        format!(
            "pkg-config --exists {dep} >/dev/null 2>&1 || echo '#include <{dep}.h>' | gcc -E - >/dev/null 2>&1"
        )
    };
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `update`: list the signed releases newer than this build.
/// `ircbot -checkupdate [variant]`: fetch the release manifest and its
/// signature exactly as a hub-driven upgrade does — the release tree
/// `<base>/<variant>`, the compiled-in base and pinned key unless
/// IRCBOT_UPDATE_BASE says otherwise — verify one against the other, and
/// report.  Nothing past the manifest is downloaded and nothing is installed,
/// so an operator (or the testnet) can prove a host reaches and trusts the
/// real release channel — TLS, CA store, pinned key — without upgrading
/// anything.  Returns the process exit code: 0 = verified.
pub fn check_cli(variant: Option<&str>) -> i32 {
    let want = variant.filter(|v| !v.is_empty()).unwrap_or(host_variant());
    if want.len() > 7 || want.contains(['/', ';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        println!("checkupdate: FAIL malformed variant");
        return 1;
    }
    if !set_tree(want) {
        println!("checkupdate: FAIL could not record the release base");
        return 1;
    }
    let base = update_tree();
    let manifest = match fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            println!("checkupdate: FAIL {e} ({base})");
            return 1;
        }
    };
    let mut rows = 0;
    let mut newest = String::new();
    for line in manifest.lines() {
        let Some(version) = line.split_whitespace().next() else {
            continue;
        };
        if line.starts_with('#') {
            continue;
        }
        rows += 1;
        if newest.is_empty() || version_cmp(version, &newest) == std::cmp::Ordering::Greater {
            newest = version.to_string();
        }
    }
    println!(
        "checkupdate: OK {want} manifest verified: {rows} release row(s), newest {}, running {BOT_VERSION}",
        if newest.is_empty() { "-" } else { &newest }
    );
    0
}

pub fn check_for_updates(state: &mut BotState, nick: &str) {
    logm!(
        state,
        L_DEBUG,
        "[DEBUG] updater_check_for_updates called.\n"
    );
    let manifest = match fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            ircf!(state, "PRIVMSG {} :Update check failed: {}.\r\n", nick, e);
            return;
        }
    };
    ircf!(
        state,
        "PRIVMSG {} :--- Available Updates (Current: {}) ---\r\n",
        nick,
        BOT_VERSION
    );
    let mut found = 0;
    for line in manifest
        .split('\n')
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some([version, date, _url, _hash, deps]) = parse_release(line) else {
            continue;
        };
        if version_cmp(version, BOT_VERSION) != std::cmp::Ordering::Greater {
            continue;
        }
        found += 1;
        let failed: Vec<&str> = deps
            .split(',')
            .filter(|d| !d.is_empty() && !check_dependency(d))
            .collect();
        let status = if failed.is_empty() {
            "[OK]".to_string()
        } else {
            format!("[FAILED: {}]", failed.join(", "))
        };
        ircf!(
            state,
            "PRIVMSG {} :{} ({}) - Dependencies: {}\r\n",
            nick,
            version,
            date,
            status
        );
    }
    if found == 0 {
        ircf!(state, "PRIVMSG {} :Bot is up-to-date.\r\n", nick);
    } else {
        ircf!(
            state,
            "PRIVMSG {} :To upgrade, type: update <version>. IE: update v2.0.0\r\n",
            nick
        );
    }
}

/// An https:// URL whose host is exactly github.com, githubusercontent.com
/// or a subdomain of it (raw. for manifests; downloads redirect to
/// objects.).  "Contains github.com" let https://evil.example/github.com
/// through; userinfo (github.com@evil.example) is refused outright.
fn url_host_trusted(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let end = rest.find(['/', ':', '?', '#', '@']).unwrap_or(rest.len());
    if rest[end..].starts_with('@') {
        return false;
    }
    let host = rest[..end].to_ascii_lowercase();
    host == "github.com"
        || host == "githubusercontent.com"
        || host.ends_with(".githubusercontent.com")
}

fn validate_url(url: &str) -> bool {
    if url.contains([';', '|', '&', '`', '$']) {
        return false;
    }
    if let Some(b) = env_root()
        && url.starts_with(&b)
    {
        return true;
    }
    url_host_trusted(url)
}

/// Keep [A-Za-z0-9._-]; the result must end in ".tar.gz".
fn sanitize_filename(input: &str) -> Option<String> {
    let out: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
        .take(255)
        .collect();
    (out.len() >= 8 && out.ends_with(".tar.gz")).then_some(out)
}

/// `update <version>`: download, verify, build and exec the new release.
pub fn perform_upgrade(state: &mut BotState, nick: &str, version: &str) {
    logm!(
        state,
        L_DEBUG,
        "[DEBUG] updater_perform_upgrade called for {}.\n",
        version
    );
    // Downgrade protection: a replayed old manifest cannot roll us back.
    if version_cmp(version, BOT_VERSION) == std::cmp::Ordering::Less {
        ircf!(
            state,
            "PRIVMSG {} :Refusing downgrade: {} is older than the running version {}.\r\n",
            nick,
            version,
            BOT_VERSION
        );
        return;
    }
    // One install path: the same checks, staging, script and failback as a
    // hub-driven upgrade, with this id instead of a run's.  On success this does
    // not return.
    let id = format!("local-{}", cron_now());
    ircf!(state, "PRIVMSG {} :Installing {}...\r\n", nick, version);
    if let Err(err) = hub_commit(state, &id, version, "") {
        ircf!(state, "PRIVMSG {} :Upgrade aborted: {}.\r\n", nick, err);
    }
}

/// A bot with no hub: there is no link to report on, so the first time it is on
/// IRC it settles its own upgrade.  Once per process.
pub fn standalone_tick(state: &mut BotState) {
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    use std::sync::atomic::Ordering::Relaxed;
    if DONE.load(Relaxed) || !state.hubs.is_empty() || state.status & crate::state::S_AUTHED == 0 {
        return;
    }
    DONE.store(true, Relaxed);
    let Some(p) = take_pending_upgrade() else {
        return;
    };
    if version_cmp(BOT_VERSION, &p.version) == std::cmp::Ordering::Equal {
        failback_confirm();
        logm!(state, L_INFO, "[UPGRADE] Now running {}\n", BOT_VERSION);
        return;
    }
    let note = failback_note().unwrap_or_else(|| "reason unknown".to_string());
    logm!(
        state,
        L_INFO,
        "[UPGRADE] The upgrade to {} did not hold, back on {}: {}\n",
        p.version,
        BOT_VERSION,
        note
    );
}

// ======================================================================
// Hub-driven upgrade (CMD_UPGRADE_COMMIT) — mirrors utils.c
//
// A hub-configured bot never upgrades itself from an IRC command (see the
// gate in commands.rs); its hub drives the whole network in a rolling plan.
// This entry point is kept PARALLEL to perform_upgrade() rather than folded
// into it: that function's QUIT/exec sequence is delicate and is still the
// entire story for standalone bots, while this path differs in nearly every
// other respect —
//   - no admin nick to answer: progress goes to the log, and the outcome to
//     the hub as CMD_UPGRADE_RESULT after the restart,
//   - the artifact is chosen by {kind,arch,libc} rather than "first row with
//     this version" — a prebuilt binary matching this host beats a source
//     build, and a source build needs its dependencies present,
//   - the old binary and config are RETAINED as <exe>.prev / <config>.prev,
//     never deleted, so the hub can order a rollback after the new build is
//     already running.
// ======================================================================

/// One artifact row of the release manifest.  Columns 1-5 are the legacy
/// format `parse_release` already reads; 6-9 were appended for the network
/// upgrade and are absent from older manifests, which is why they default to
/// a source build that fits anything.
struct ManifestRow {
    url: String,
    hash: String,
    deps: String,
    kind: String,
    arch: String,
    libc: String,
    min_from: String,
    /// Column 10: the CPU features this artifact needs ("-" = none).
    cpu: String,
    /// Column 11: archive + unpacked bytes, 0 = unknown.
    size: u64,
}

impl ManifestRow {
    /// Does this row's {arch,libc} fit the running host?  "any" fits
    /// everything, which is what source tarballs and older manifests carry.
    fn fits_host(&self) -> bool {
        (self.arch == "any" || eq_ic(&self.arch, &host_arch()))
            && (self.libc == "any" || eq_ic(&self.libc, &host_libc()))
    }

    /// Every dependency the row names must be present; a prebuilt binary
    /// carries "none".  Returns the missing ones.
    fn missing_deps(&self) -> Vec<&str> {
        if eq_ic(&self.deps, "none") {
            return Vec::new();
        }
        self.deps
            .split(',')
            .filter(|d| !d.is_empty() && !check_dependency(d))
            .collect()
    }
}

// ---- Preflight (PREPARE) ----------------------------------------------
//
// Can this host take the build at all?  Asked before anything changes, so a
// full disk or a read-only directory is an "unable" with a reason an admin can
// act on, not a failed restart.  Each reason starts with a fixed code word
// (disk:, dir:, exe:, exec:, tool:, net:).  Only a probe file is written, and
// it is gone again before this returns.  The instance dir is the cwd.

fn preflight_tool(name: &str) -> bool {
    let path = std::env::var("PATH").ok().filter(|p| !p.is_empty());
    path.as_deref()
        .unwrap_or("/usr/bin:/bin")
        .split(':')
        .filter(|d| !d.is_empty())
        .any(|d| {
            let c = format!("{d}/{name}");
            nix::unistd::access(c.as_str(), nix::unistd::AccessFlags::X_OK).is_ok()
        })
}

fn io_text(e: &std::io::Error) -> String {
    nix::errno::Errno::from_raw(e.raw_os_error().unwrap_or(0))
        .desc()
        .to_string()
}

fn preflight_dir_probe(dir: &str) -> Result<(), String> {
    let (probe, moved) = (".upgrade.probe", ".upgrade.probe2");
    let done = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(probe)?;
        f.write_all(b"x")?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(probe, moved)
    })();
    let _ = std::fs::remove_file(probe);
    let _ = std::fs::remove_file(moved);
    done.map_err(|e| format!("dir: cannot write {}: {}", clip(dir, 160), io_text(&e)))
}

/// The binary must be ours, and not immutable: a hard link fails on that where
/// a rename could not be tried without moving it.  A filesystem with no hard
/// links at all still passes: it is a different errno.
fn preflight_exe(exe: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(exe)
        .map_err(|e| format!("exe: cannot read {}: {}", clip(exe, 160), io_text(&e)))?;
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(format!(
            "exe: cannot replace {}: owned by another user",
            clip(exe, 160)
        ));
    }
    let probe = ".upgrade.probe3";
    let _ = std::fs::remove_file(probe);
    let linked = std::fs::hard_link(exe, probe);
    let _ = std::fs::remove_file(probe);
    if let Err(e) = linked
        && [nix::errno::Errno::EPERM, nix::errno::Errno::EACCES]
            .map(|n| n as i32)
            .contains(&e.raw_os_error().unwrap_or(0))
    {
        return Err(format!(
            "exe: cannot replace {}: {}",
            clip(exe, 160),
            io_text(&e)
        ));
    }
    Ok(())
}

fn clip(s: &str, cap: usize) -> &str {
    let mut end = s.len().min(cap);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Everything the swap will write, plus a margin.  A manifest row without the
/// size column gets a fixed allowance; a source build always gets one on top,
/// for its objects.
fn preflight_space(
    dir: &str,
    exe: &str,
    cfg: &str,
    size: u64,
    is_bin: bool,
    variant: &str,
) -> Result<(), String> {
    use nix::sys::statvfs::{FsFlags, statvfs};
    let Ok(sv) = statvfs(".") else {
        return Ok(()); // unknown: the stage will tell
    };
    if sv.flags().contains(FsFlags::ST_NOEXEC) {
        return Err(format!("exec: {} is mounted noexec", clip(dir, 160)));
    }
    if sv.files() > 0 && sv.files_available() < UPGRADE_MIN_INODES {
        return Err(format!("disk: no free inodes in {}", clip(dir, 160)));
    }
    let mut need = size;
    if need == 0 && is_bin {
        need = UPGRADE_SPACE_BIN_DEFAULT;
    }
    if !is_bin {
        need += if variant == "rs" {
            UPGRADE_SPACE_BUILD_RS
        } else {
            UPGRADE_SPACE_BUILD_C
        };
    }
    need += std::fs::metadata(cfg).map(|m| m.len()).unwrap_or(0);
    need += std::fs::metadata(exe).map(|m| m.len()).unwrap_or(0);
    need += UPGRADE_SPACE_MARGIN;
    let have = sv.blocks_available().saturating_mul(sv.fragment_size());
    if have < need {
        return Err(format!(
            "disk: needs {} MB in {}, has {} MB",
            need / (1024 * 1024) + 1,
            clip(dir, 160),
            have / (1024 * 1024)
        ));
    }
    Ok(())
}

/// HEAD on the artifact.  A server that does not do HEAD says nothing either
/// way, so it passes and the download decides.
fn preflight_artifact(url: &str) -> Result<(), String> {
    let name = clip(url.rsplit('/').next().unwrap_or(url), 120);
    if let Some(path) = file_url_path(url) {
        return std::fs::metadata(path)
            .map(|_| ())
            .map_err(|e| format!("net: cannot reach {name}: {}", io_text(&e)));
    }
    if !tls_ready() {
        return Ok(()); // the manifest read has already said why
    }
    match agent().head(url).call() {
        Ok(_) | Err(ureq::Error::StatusCode(405 | 501)) => Ok(()),
        Err(ureq::Error::StatusCode(code)) => Err(format!("net: {code} from {name}")),
        Err(e) => Err(format!("net: cannot reach {name}: {e}")),
    }
}

fn preflight_host(
    exe: &str,
    cfg: &str,
    url: &str,
    size: u64,
    kind: &str,
    variant: &str,
) -> Result<(), String> {
    let dir = std::env::current_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    preflight_space(
        &dir,
        exe,
        cfg,
        size,
        kind.eq_ignore_ascii_case("bin"),
        variant,
    )?;
    preflight_dir_probe(&dir)?;
    preflight_exe(exe)?;
    if nix::unistd::access("/bin/bash", nix::unistd::AccessFlags::X_OK).is_err() {
        return Err("tool: /bin/bash not found".to_string());
    }
    if !preflight_tool("tar") {
        return Err("tool: tar not found".to_string());
    }
    preflight_artifact(url)
}

/// Parse one manifest line, tolerating the 5-column legacy form.
fn parse_row(line: &str) -> Option<(String, ManifestRow)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 5 {
        return None;
    }
    let caps = [63, 63, 511, 127, 255, 7, 31, 15, 63, 255];
    if f.iter().zip(caps).any(|(s, c)| s.len() > c) {
        return None;
    }
    let at = |i: usize, dflt: &str| f.get(i).copied().unwrap_or(dflt).to_string();
    Some((
        f[0].to_string(),
        ManifestRow {
            url: f[2].to_string(),
            hash: f[3].to_string(),
            deps: f[4].to_string(),
            kind: at(5, "src"),
            arch: at(6, "any"),
            libc: at(7, "any"),
            min_from: at(8, "*"),
            cpu: at(9, "-"),
            size: f.get(10).and_then(|v| v.parse().ok()).unwrap_or(0),
        },
    ))
}

/// Choose the artifact for `version`: a usable prebuilt binary for this host
/// wins, otherwise a source tarball whose build dependencies are installed.
/// `Err` explains why nothing was usable.
fn manifest_select(manifest: &str, version: &str, variant: &str) -> Result<ManifestRow, String> {
    let mut why = "requested version is not in the manifest".to_string();
    let mut pick: Option<ManifestRow> = None;

    for line in manifest
        .split('\n')
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((row_ver, row)) = parse_row(line) else {
            continue;
        };
        if !version_eq(&row_ver, version) {
            continue;
        }
        if !validate_url(&row.url) {
            why = "untrusted artifact URL in manifest".to_string();
            continue;
        }
        if !row.fits_host() {
            why = "no artifact for this host arch/libc".to_string();
            continue;
        }
        if let Some(f) = cpu_missing(&row.cpu, &host_arch(), host_cpu_features()) {
            why = format!("this CPU lacks {f}, which the {variant} build needs");
            continue;
        }
        if row.min_from != "*"
            && version_cmp(BOT_VERSION, &row.min_from) == std::cmp::Ordering::Less
        {
            why = format!(
                "running version is below the artifact's min_from {}",
                row.min_from
            );
            continue;
        }
        let missing = row.missing_deps();
        if !missing.is_empty() {
            why = format!("missing build dependencies: {}", missing.join(", "));
            continue;
        }
        // Usable.  Prefer a prebuilt binary; keep looking only if this is a
        // source row that a later binary row could beat.
        let is_bin = eq_ic(&row.kind, "bin");
        pick = Some(row);
        if is_bin {
            break;
        }
    }
    pick.ok_or(why)
}

/// One upgrade's failback script, the same text in all four trees.  A node must
/// recover by itself: its admin may have no shell on the host.  It is called from
/// the upgrade script's background loop every 10 s and from a temporary crontab
/// line every minute, which outlives a reboot or a killed loop.  It holds no
/// secrets, and removes itself and the line once the new build confirms or the
/// old one is back.
const FAILBACK_BODY: &str = r##"umask 077
PATH="${PATH:-}:/usr/bin:/bin"; export PATH
cd "$D" 2>/dev/null || exit 1
STATE=.upgrade.state; CONF=.upgrade.confirmed; SELF=${SELF:-.upgrade.failback}
LOCK=.upgrade.lock; TRIES=.upgrade.tries; PREV="$EXE.prev"
FAILTAG="# $PRODUCT:failback:$D:"; PRODTAG="# $PRODUCT:production:$D:"
# A hardened daemon is not dumpable, so its /proc/<pid>/exe cannot be read: the
# pid file and the process name say whether it is ours.
COMM=$(basename "$EXE" | cut -c1-15)
HLOCK="${HOME:-$D}/.irc-cron.lock"
HELD=""

take_lock() {
  i=0
  while :; do
    if ( set -C; echo $$ >"$1" ) 2>/dev/null; then HELD="$HELD $1"; return 0; fi
    h=$(cat "$1" 2>/dev/null)
    if [ -n "$h" ] && kill -0 "$h" 2>/dev/null; then
      i=$((i + 1)); [ "$i" -ge "$2" ] && return 1
      sleep 1
    else
      rm -f "$1"
    fi
  done
}
drop_locks() { for l in $HELD; do rm -f "$l"; done; HELD=""; }
trap drop_locks EXIT

clean() { printf '%s' "$1" | tr -d '|\r\n' | cut -c1-160; }
set_state() { # phase pid note
  printf '%s|%s|%s|%s|%s\n' "$ID" "$1" "$(date +%s)" "$2" "$(clean "$3")" >"$STATE.tmp" &&
    mv -f "$STATE.tmp" "$STATE"
}
read_state() {
  rid=""; phase=""; since=0; spid=""; note=""
  [ -f "$STATE" ] || return 1
  IFS='|' read -r rid phase since spid note <"$STATE" || return 1
  [ "$rid" = "$ID" ]
}
pid_now() { [ -f "$PIDF" ] && tr -dc 0-9 <"$PIDF"; }
alive() {
  p=$(pid_now)
  [ -n "$p" ] && kill -0 "$p" 2>/dev/null && [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "$COMM" ]
}
start_exe() { "$EXE" </dev/null >/dev/null 2>&1 & }

# Read, change, write, read back, compare.  Only an answer that says there is
# no crontab counts as empty: any other read error writes nothing, so a bad read
# can never wipe an admin's jobs.  Only a line holding this tag changes, along with
# tagged lines whose directory is gone; every other line stays as it was.
cron_read() { # file
  if ! crontab -l >"$1" 2>"$1.err"; then
    grep -Eqi 'no crontab|no such file|does not exist' "$1.err" || return 1
    : >"$1"
  fi
}
cron_sweep() { # in out
  sed -nE 's/.*# (ircbot|irchub):(production|failback):(\/[^:]*):$/\3/p' "$1" |
    while read -r dd; do [ -d "$dd" ] || printf ':%s:\n' "$dd"; done >"$2.dead"
  if [ -s "$2.dead" ]; then grep -vF -f "$2.dead" "$1" >"$2"; else cp "$1" "$2"; fi
}
cron_edit() { # add|remove tag line
  command -v crontab >/dev/null 2>&1 || return 3
  take_lock "$HLOCK" 15 || return 1
  T=".upgrade.cron.$$"; rc=1; n=0
  while [ "$n" -lt 3 ]; do
    n=$((n + 1))
    cron_read "$T.cur" || break
    if [ "$1" = remove ] && ! grep -qF "$2" "$T.cur"; then rc=0; break; fi
    if [ "$1" = add ] && grep -qF "$2" "$T.cur"; then rc=0; break; fi
    cron_sweep "$T.cur" "$T.swept"
    grep -vF "$2" "$T.swept" >"$T.rest"
    cp "$T.rest" "$T.new"
    [ "$1" = add ] && printf '%s\n' "$3" >>"$T.new"
    crontab "$T.new" >/dev/null 2>&1 || { sleep 1; continue; }
    crontab -l >"$T.chk" 2>/dev/null
    grep -vF "$2" "$T.chk" | grep -v '^# \(DO NOT EDIT\|(\)' >"$T.a"
    grep -v '^# \(DO NOT EDIT\|(\)' "$T.rest" >"$T.b"
    if cmp -s "$T.a" "$T.b"; then
      if [ "$1" = add ]; then grep -qF "$2" "$T.chk" && { rc=0; break; }
      else grep -qF "$2" "$T.chk" || { rc=0; break; }; fi
    fi
    sleep 1
  done
  rm -f "$T".*
  rm -f "$HLOCK"; HELD=$(printf '%s' "$HELD" | sed "s| $HLOCK||")
  return "$rc"
}
fail_line() {
  printf "* * * * * [ -x '%s/%s' ] && '%s/%s' tick >/dev/null 2>&1 %s\n" \
    "$D" "$SELF" "$D" "$SELF" "$FAILTAG"
}
prod_line() {
  printf "*/5 * * * * touch '%s/.cron.seen'; [ -x '%s' ] && '%s' >/dev/null 2>&1 %s\n" \
    "$D" "$EXE" "$EXE" "$PRODTAG"
}
# What this instance's production line is: 0 ours, 10 a hand-written line runs
# this binary, 11 none, 3 no crontab tool, 1 it cannot be read.
cron_status() {
  command -v crontab >/dev/null 2>&1 || return 3
  T=".upgrade.cron.$$"
  cron_read "$T.st" || { rm -f "$T".*; return 1; }
  rc=11
  if grep -qF "$PRODTAG" "$T.st"; then rc=0
  elif grep -vE '^[[:space:]]*#' "$T.st" | grep -qF "$EXE"; then rc=10
  fi
  rm -f "$T".*
  return "$rc"
}
safe_path() { case "$D" in *[!A-Za-z0-9._/-]*) return 1 ;; esac; }

# keep = leave the state file, for the build that has to report it
finish() {
  cron_edit remove "$FAILTAG"
  [ "${1:-}" = keep ] || rm -f "$STATE"
  rm -f "$CONF" "$TRIES" "$SELF" "./$SCRIPT"
  drop_locks
  exit 1
}

restore() { # reason
  read_state
  [ -n "$spid" ] && [ "$spid" != "$PPID" ] && [ "$spid" != "$$" ] && kill "$spid" 2>/dev/null
  if alive; then
    p=$(pid_now); kill "$p" 2>/dev/null
    i=0
    while kill -0 "$p" 2>/dev/null && [ "$i" -lt 5 ]; do sleep 1; i=$((i + 1)); done
    kill -9 "$p" 2>/dev/null
  fi
  if [ ! -f "$PREV" ]; then
    [ -x "$EXE" ] && ! alive && start_exe
    set_state failback-gave-up "" "$1; no previous build retained"
    return
  fi
  mv -f "$EXE" "$EXE.failed" 2>/dev/null
  if ! mv -f "$PREV" "$EXE"; then
    mv -f "$EXE.failed" "$EXE" 2>/dev/null
    set_state failback-gave-up "" "$1; could not restore the previous build"
    return
  fi
  [ -f "$CFG.prev" ] && cp -f "$CFG.prev" "$CFG"
  rm -f "$PIDF"
  set_state restored "" "$1"
  start_exe
}

tick() {
  # Another upgrade's state: it is about to replace this script, so leave it be.
  read_state || { [ -n "$rid" ] && exit 1; finish; }
  now=$(date +%s); age=$((now - since))
  if [ "$now" -ge "$HARD" ]; then
    case "$phase" in
      restored|failback-gave-up) ;;
      *) set_state failback-gave-up "" "the upgrade never finished" ;;
    esac
    finish keep
  fi
  case "$phase" in
    installing)
      if ! kill -0 "$spid" 2>/dev/null; then restore "the install was interrupted"
      elif [ "$age" -ge "$INSTALL_LIMIT" ]; then restore "the install took over $INSTALL_LIMIT s"
      fi ;;
    started)
      if [ -f "$CONF" ] && [ "$(cat "$CONF" 2>/dev/null)" = "$ID" ] && alive; then finish
      elif ! alive; then
        [ "$age" -ge "$WATCH" ] && restore "the new build did not stay up"
      elif [ "$age" -ge "$CONFIRM_LIMIT" ]; then restore "$NOTE within $CONFIRM_LIMIT s"
      fi ;;
    restored)
      alive && finish keep
      t=$(cat "$TRIES" 2>/dev/null); t=$((${t:-0} + 1)); echo "$t" >"$TRIES"
      if [ "$t" -ge 5 ]; then
        set_state failback-gave-up "" "$note; the previous build will not start"
        finish keep
      fi
      start_exe ;;
    failback-gave-up) finish keep ;;
    *) finish ;;
  esac
  return 0
}

# The cron-* arguments are a one-shot helper's: it runs once and removes itself.
case "${1:-tick}" in
  install)
    safe_path || exit 3
    cron_edit add "$FAILTAG" "$(fail_line)"; exit $? ;;
  phase) take_lock "$LOCK" 20 && set_state "$2" "$3" "" ;;
  restore) take_lock "$LOCK" 20 && restore "$2" ;;
  done) take_lock "$LOCK" 20; finish ;;
  # A loop names its upgrade: a loop that outlived it stops here, touching nothing.
  tick) [ -n "${2:-}" ] && [ "$2" != "$ID" ] && exit 1
    take_lock "$LOCK" 2 || exit 0; tick ;;
  cron-status) cron_status; rc=$?; rm -f "$SELF"; exit "$rc" ;;
  cron-on)
    cron_status; rc=$?
    if [ "$rc" = 11 ]; then
      if safe_path; then
        touch .cron.seen
        cron_edit add "$PRODTAG" "$(prod_line)" && cron_status; rc=$?
      else
        rc=4
      fi
    fi
    rm -f "$SELF"; exit "$rc" ;;
  cron-off)
    rc=0
    cron_edit remove "$PRODTAG" || rc=$?
    if [ "$rc" = 0 ]; then rm -f .cron.seen; cron_status; rc=$?; fi
    rm -f "$SELF"; exit "$rc" ;;
  cron-drop)
    rc=0
    cron_edit remove "$PRODTAG" || rc=$?
    cron_edit remove "$FAILTAG" || rc=$?
    if [ "$rc" = 0 ]; then
      cron_status; [ $? = 10 ] && rc=10
    fi
    rm -f "$SELF" .cron.seen; exit "$rc" ;;
esac
exit 0
"##;
const FAILBACK_FILE: &str = ".upgrade.failback";
const FAILBACK_STATE: &str = ".upgrade.state";
const FAILBACK_CONFIRM: &str = ".upgrade.confirmed";

fn failback_quoted(name: &str, value: &str) -> String {
    format!("{name}='{}'\n", value.replace('\'', "'\\''"))
}

/// Run the script with one argument; its exit status, -1 if it could not run.
fn failback_run(arg: &str) -> i32 {
    Command::new(format!("./{FAILBACK_FILE}"))
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(-1)
}

/// Takes the upgrade back out of cron and off the disk.
fn failback_clear() {
    if std::path::Path::new(FAILBACK_FILE).exists() {
        let _ = failback_run("done");
    }
    let _ = std::fs::remove_file(FAILBACK_STATE);
    let _ = std::fs::remove_file(FAILBACK_CONFIRM);
}

/// The new build is up and has proved it can do its job.
pub fn failback_confirm() {
    let Ok(line) = std::fs::read_to_string(FAILBACK_STATE) else {
        return;
    };
    let Some((id, rest)) = line.split_once('|') else {
        return;
    };
    if !rest.starts_with("started|") {
        return;
    }
    let tmp = format!("{FAILBACK_CONFIRM}.tmp");
    if std::fs::write(&tmp, format!("{id}\n")).is_ok() {
        let _ = std::fs::rename(&tmp, FAILBACK_CONFIRM);
    }
}

/// Why this build is running instead of the one asked for: the note the script
/// wrote when it restored it.  Taken once.
pub fn failback_note() -> Option<String> {
    let line = std::fs::read_to_string(FAILBACK_STATE).ok()?;
    let line = line.lines().next()?;
    let (_, rest) = line.split_once('|')?;
    if !rest.starts_with("restored|") && !rest.starts_with("failback-gave-up|") {
        return None;
    }
    let note = rest.rsplit('|').next()?;
    if note.is_empty() {
        return None;
    }
    let out = note.to_string();
    let _ = std::fs::remove_file(FAILBACK_STATE);
    Some(out)
}

// ---- Production crontab line ---------------------------------------------
//
// An instance's keepalive line, tagged "# <product>:production:<dir>:".  Off
// unless a hub says otherwise, and only ever this one tagged line: everything
// else in the crontab is read and left alone.  The script runs as a child, so a
// slow crontab never holds up the event loop.
const CRON_HELPER: &str = ".cron.helper";

struct CronState {
    child: Option<std::process::Child>,
    started: u64,
    next: u64,
    stat: u64,
    wanted: i8, // -1 no hub has said, 0 off, 1 on
    status: String,
    ours: bool,
}

static CRON: std::sync::Mutex<CronState> = std::sync::Mutex::new(CronState {
    child: None,
    started: 0,
    next: 0,
    stat: 0,
    wanted: -1,
    status: String::new(),
    ours: false,
});

fn cron_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cron_note(c: &mut CronState, rc: i32, now: u64) {
    c.ours = rc == 0;
    c.status = match rc {
        0 => "yes",
        10 => "manual",
        _ if rc == 11 || c.wanted != 1 => "no",
        3 => "failed:no crontab tool",
        4 => "failed:unsafe path",
        _ => "failed:cannot read crontab",
    }
    .to_string();
    c.stat = now;
}

/// What `cron_tick` last found: yes, silent, manual, no or failed:<why>.
pub fn cron_status() -> String {
    CRON.lock().map(|c| c.status.clone()).unwrap_or_default()
}

/// A hub's order.
pub fn cron_set(on: bool) {
    if let Ok(mut c) = CRON.lock() {
        let want = i8::from(on);
        if want != c.wanted {
            c.next = 0;
        }
        c.wanted = want;
    }
}

/// True when the status changed, so the hub should hear it.
pub fn cron_tick(exe: &str) -> bool {
    let Ok(mut c) = CRON.lock() else {
        return false;
    };
    let now = cron_now();
    let before = c.status.clone();
    if let Some(child) = c.child.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                if now.saturating_sub(c.started) > CRON_HELPER_TIMEOUT {
                    let _ = c.child.as_mut().map(std::process::Child::kill);
                }
                return false;
            }
            Ok(Some(st)) => {
                let rc = st.code().unwrap_or(1);
                c.child = None;
                let _ = std::fs::remove_file(CRON_HELPER);
                cron_note(&mut c, rc, now);
            }
            Err(_) => {
                c.child = None;
                let _ = std::fs::remove_file(CRON_HELPER);
                cron_note(&mut c, 1, now);
            }
        }
    }
    if now >= c.next && !exe.is_empty() {
        let mut fail = None;
        if c.wanted == 1 && !std::path::Path::new(PASS_FILE).exists() {
            fail = Some(format!("no {}", PASS_FILE));
        } else if !failback_write(
            CRON_HELPER,
            exe,
            "",
            true,
            CONFIG_FILE,
            PID_FILE,
            "upgrade.sh",
            "",
            CRON_HELPER,
        ) {
            fail = Some("cannot write here".to_string());
        }
        if let Some(why) = fail {
            c.status = format!("failed:{why}");
            c.next = now + CRON_CHECK_SECS;
        } else {
            let arg = match c.wanted {
                1 => "cron-on",
                0 => "cron-off",
                _ => "cron-status",
            };
            if let Ok(child) = Command::new(format!("./{CRON_HELPER}"))
                .arg(arg)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                c.child = Some(child);
                c.started = now;
            }
            // Set before it finishes: an order that arrives meanwhile clears this,
            // and must not be overwritten when this child ends.
            c.next = now + CRON_CHECK_SECS;
        }
    }
    // The line stamps .cron.seen each time it runs: no stamp, no cron daemon.
    if c.ours && now.saturating_sub(c.stat) >= 60 {
        c.stat = now;
        let seen = std::fs::metadata(".cron.seen")
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let quiet = seen.is_none_or(|s| now.saturating_sub(s) > CRON_SILENT_SECS);
        c.status = if quiet { "silent" } else { "yes" }.to_string();
    }
    before != c.status
}

/// The node is being deleted: both tagged lines go.  0 gone, 10 gone but a
/// hand-written line still runs this binary, anything else could not.
pub fn cron_drop(exe: &str) -> i32 {
    if let Ok(mut c) = CRON.lock()
        && let Some(mut child) = c.child.take()
    {
        let _ = child.kill();
        let _ = child.wait();
    }
    if !failback_write(
        CRON_HELPER,
        exe,
        "",
        true,
        CONFIG_FILE,
        PID_FILE,
        "upgrade.sh",
        "",
        CRON_HELPER,
    ) {
        return 1;
    }
    let rc = Command::new(format!("./{CRON_HELPER}"))
        .arg("cron-drop")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(1);
    let _ = std::fs::remove_file(CRON_HELPER);
    rc
}

/// A keepalive line can fire while an upgrade installs, when no daemon holds the
/// pid lock.  Starting the old build then would make the new one refuse to start,
/// so a start waits that out.  A stale file past its limits stops nothing.
pub fn install_in_progress() -> bool {
    let Ok(line) = std::fs::read_to_string(FAILBACK_STATE) else {
        return false;
    };
    let f: Vec<&str> = line.trim_end().split('|').collect();
    if f.get(1) != Some(&"installing") {
        return false;
    }
    let (Some(since), Some(pid)) = (
        f.get(2).and_then(|v| v.parse::<u64>().ok()),
        f.get(3).and_then(|v| v.parse::<i32>().ok()),
    ) else {
        return false;
    };
    if pid <= 0 || cron_now().saturating_sub(since) > UPGRADE_BUILD_SECS + 60 {
        return false;
    }
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Lay the script down, before anything changes.  The state goes first: a tick
/// that finds none takes the script away again, and exec keeps this pid, so it
/// already names the upgrade script.
/// The script, for one upgrade (FAILBACK_FILE) or one crontab change (CRON_HELPER).
#[allow(clippy::too_many_arguments)]
fn failback_write(
    path: &str,
    exe: &str,
    id: &str,
    is_bin: bool,
    cfg: &str,
    pidf: &str,
    script: &str,
    note: &str,
    self_name: &str,
) -> bool {
    let Some(slash) = exe.rfind('/') else {
        return false;
    };
    let dir = &exe[..slash];
    let install = if is_bin {
        UPGRADE_INSTALL_SECS
    } else {
        UPGRADE_BUILD_SECS
    };
    let now = cron_now();
    let mut text =
        String::from("#!/bin/sh\n# Written by ircbot: removes itself.  See its README.\n");
    for (name, value) in [
        ("PRODUCT", "ircbot"),
        ("SELF", self_name),
        ("D", dir),
        ("EXE", exe),
        ("ID", id),
        ("CFG", cfg),
        ("PIDF", pidf),
        ("SCRIPT", script),
        ("NOTE", note),
    ] {
        text.push_str(&failback_quoted(name, value));
    }
    text.push_str(&format!(
        "INSTALL_LIMIT={install}\nCONFIRM_LIMIT={UPGRADE_CONFIRM_SECS}\nWATCH={UPGRADE_WATCH_SECS}\nHARD={}\n",
        now + install + UPGRADE_CONFIRM_SECS + UPGRADE_FAILBACK_EXPIRY
    ));
    text.push_str(FAILBACK_BODY);
    let wrote = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(path)
        .and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o700))
        })
        .is_ok();
    if !wrote {
        let _ = std::fs::remove_file(path);
    }
    wrote
}

fn failback_stage(
    exe: &str,
    id: &str,
    is_bin: bool,
    cfg: &str,
    pidf: &str,
    script: &str,
    note: &str,
) -> bool {
    // The state first: a tick that finds none takes the script away again, and
    // the previous upgrade's loop may still tick.  Its script, finding this
    // upgrade's state, leaves it be.
    let now = cron_now();
    let _ = std::fs::remove_file(FAILBACK_CONFIRM);
    let tmp = format!("{FAILBACK_STATE}.tmp");
    let state = format!("{id}|installing|{now}|{}|\n", std::process::id());
    if std::fs::write(&tmp, state).is_err() || std::fs::rename(&tmp, FAILBACK_STATE).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    // Then the script, whole or not at all: a tick never runs a half-written one.
    let stmp = format!("{FAILBACK_FILE}.tmp");
    if !failback_write(&stmp, exe, id, is_bin, cfg, pidf, script, note, FAILBACK_FILE)
        || std::fs::rename(&stmp, FAILBACK_FILE).is_err()
    {
        let _ = std::fs::remove_file(&stmp);
        let _ = std::fs::remove_file(FAILBACK_STATE);
        return false;
    }
    true
}

// ---- Staging -------------------------------------------------------------
//
// Get the new build ready and proven while the old one keeps running.  A thread
// does the work under STAGE_DIR and notes each phase; the event loop reads that
// and tells the hub.  COMMIT then only swaps a file.  Nothing here touches <exe>,
// and everything here is gone again if no COMMIT comes.
const STAGE_DIR: &str = ".upgrade.stage";

#[derive(Default)]
struct StageState {
    gen_id: u64,
    id: String,
    ver: String,
    phase: String,
    code: String,
    note: String,
    started: u64,
    said: u64,
    done: u64,
    ready: bool,
    running: bool,
    changed: bool,
}

static STAGE: std::sync::Mutex<Option<StageState>> = std::sync::Mutex::new(None);
static STAGE_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn stage_rm() {
    let _ = std::fs::remove_dir_all(STAGE_DIR);
}

/// In the thread: one note, unless a newer stage has replaced this one.
fn stage_say(id: u64, phase: &str, code: &str, note: &str) {
    if let Ok(mut g) = STAGE.lock()
        && let Some(s) = g.as_mut()
        && s.gen_id == id
    {
        if s.phase != phase {
            s.changed = true;
        }
        s.phase = phase.to_string();
        s.code = code.to_string();
        s.note = note.replace(['|', '\r', '\n'], " ");
    }
}

fn stage_cancelled(id: u64) -> bool {
    STAGE_GEN.load(std::sync::atomic::Ordering::Relaxed) != id
}

/// A child with a limit, and a way out if the stage is called off.  Err is the
/// first line it wrote, or that it ran out of time.
fn stage_run(id: u64, cmd: &mut Command, limit: u64) -> Result<(), String> {
    let log = format!("{STAGE_DIR}/run.log");
    let out = std::fs::File::create(&log).map_err(|e| e.to_string())?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| e.to_string())?;
    let end = std::time::Instant::now() + std::time::Duration::from_secs(limit);
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(()),
            Ok(Some(_)) => {
                let text = std::fs::read_to_string(&log).unwrap_or_default();
                return Err(text
                    .lines()
                    .next()
                    .unwrap_or("it exited with an error")
                    .to_string());
            }
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
        if stage_cancelled(id) || std::time::Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ran past its limit".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// One stage's download, in the stage's own thread, saying how far it has got.
fn download_said(id: u64, url: &str, path: &str) -> bool {
    let mut last = -1i64;
    let mut said = std::time::Instant::now() - std::time::Duration::from_secs(60);
    download_with(url, path, &mut |got, total| {
        let pct = (got * 100 / total.max(1)) as i64;
        if pct != last && said.elapsed().as_secs() >= 2 {
            last = pct;
            said = std::time::Instant::now();
            stage_say(id, "fetching", "", &format!("{pct}%"));
        }
    })
}

/// Files make has compiled so far: a top-level .c with its object in place.
fn stage_count_c(dir: &str) -> (usize, usize) {
    let (mut total, mut done) = (0, 0);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(base) = name.to_str().and_then(|n| n.strip_suffix(".c")) else {
            continue;
        };
        if base.is_empty() || base.len() > 198 {
            continue;
        }
        total += 1;
        if ["", "build/", "build/obj/", "obj/"]
            .iter()
            .any(|w| std::path::Path::new(&format!("{dir}/{w}{base}.o")).exists())
        {
            done += 1;
        }
    }
    (total, done)
}

/// Crates cargo has got to, against the packages its lock file names.
fn stage_count_crates(dir: &str) -> (usize, usize) {
    let total = std::fs::read_to_string(format!("{dir}/Cargo.lock"))
        .map(|t| t.lines().filter(|l| l.starts_with("[[package]]")).count())
        .unwrap_or(0);
    let done = std::fs::read_dir(format!("{dir}/target/release/.fingerprint"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .count()
        })
        .unwrap_or(0);
    (total, done)
}

/// How far a build has got, in the words of the note: "40% 18 of 45 files", or
/// "~60% 120 of 200 crates", whose sizes differ too much for more than an estimate.
fn stage_build_note(dir: &str) -> Option<String> {
    let crates = std::path::Path::new(&format!("{dir}/Cargo.toml")).exists();
    let (total, done) = if crates {
        stage_count_crates(dir)
    } else {
        stage_count_c(dir)
    };
    if total == 0 {
        return None;
    }
    let done = done.min(total);
    let pct = (done * 100 / total).min(99);
    Some(if crates {
        format!("~{pct}% {done} of {total} crates")
    } else {
        format!("{pct}% {done} of {total} files")
    })
}

/// `stage_run` for a build: at most one look every 5 s, and a word only on a change.
fn stage_run_build(id: u64, dir: &str, cmd: &mut Command, limit: u64) -> Result<(), String> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let (stop, dir) = (stop.clone(), dir.to_string());
        std::thread::spawn(move || {
            let mut last = String::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Some(note) = stage_build_note(&dir)
                    && note != last
                {
                    stage_say(id, "building", "src", &note);
                    last = note;
                }
                for _ in 0..25 {
                    if stop.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        })
    };
    let r = stage_run(id, cmd, limit);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watcher.join();
    r
}

/// The whole job, on its own thread.
fn stage_job(id: u64, ver: &str, variant: &str) -> Result<(), (&'static str, String)> {
    // A run names no variant unless the admin chose one: this host's own, as at PREPARE.
    let variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    stage_say(id, "fetching", "", "");
    hub_set_tree(variant).map_err(|e| ("net", e))?;
    let manifest = fetch_verified_manifest().map_err(|e| {
        let t = e.to_string();
        (
            if t.contains("signature") {
                "sig"
            } else {
                "net"
            },
            t,
        )
    })?;
    let row = manifest_select(&manifest, ver, variant).map_err(|e| ("build", e))?;
    let is_bin = row.kind.eq_ignore_ascii_case("bin");
    let word = if is_bin { "bin" } else { "src" };
    let archive = format!("{STAGE_DIR}/archive.tar.gz");
    if !download_said(id, &row.url, &archive) {
        return Err(("net", "artifact download failed".to_string()));
    }
    stage_say(id, "verifying", word, "");
    if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&row.hash)) {
        return Err(("hash", "artifact SHA-256 mismatch".to_string()));
    }
    let bdir = format!("{STAGE_DIR}/build");
    std::fs::create_dir(&bdir)
        .map_err(|_| ("dir", "could not make the build directory".to_string()))?;
    stage_run(
        id,
        Command::new("tar").args(["-xzf", &archive, "--strip-components=1", "-C", &bdir]),
        120,
    )
    .map_err(|_| ("archive", "could not unpack the artifact".to_string()))?;
    let mut bin = format!("{bdir}/ircbot");
    if !is_bin {
        stage_say(id, "building", "src", "");
        let cargo = format!("{bdir}/Cargo.toml");
        let limit = UPGRADE_BUILD_SECS - 60;
        let ran = if std::path::Path::new(&cargo).exists() {
            bin = format!("{bdir}/target/release/ircbot");
            stage_run_build(
                id,
                &bdir,
                Command::new("cargo").args(["build", "--release", "--manifest-path", &cargo]),
                limit,
            )
        } else {
            stage_run_build(id, &bdir, Command::new("make").args(["-C", &bdir]), limit)
        };
        match ran {
            Err(e) if e.contains("past its limit") => {
                return Err(("build", "the build ran past its limit".to_string()));
            }
            Err(e) => return Err(("build", format!("the build failed: {}", clip(&e, 200)))),
            Ok(()) => {}
        }
    }
    if !std::path::Path::new(&bin).exists() {
        return Err(("archive", "the artifact holds no ircbot binary".to_string()));
    }
    let _ = std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700));
    stage_say(id, "testing", word, "");
    stage_run(id, Command::new(&bin).arg("-selftest"), SELFTEST_TIMEOUT).map_err(|e| {
        (
            "selftest",
            format!("new build failed its selftest: {}", clip(&e, 200)),
        )
    })?;
    std::fs::rename(&bin, format!("{STAGE_DIR}/new"))
        .map_err(|_| ("dir", "could not keep the staged build".to_string()))?;
    let _ = std::fs::remove_dir_all(&bdir);
    let _ = std::fs::remove_file(&archive);
    stage_say(id, "staged", word, "");
    Ok(())
}

/// A hub's STAGE.  Starting again for the same build is a no-op, so a repeat costs
/// nothing.
pub fn stage_start(id: &str, ver: &str, variant: &str) {
    if let Ok(g) = STAGE.lock()
        && let Some(s) = g.as_ref()
        && s.id == id
        && (s.running || s.ready)
    {
        return;
    }
    stage_clear();
    stage_rm();
    let gen_id = STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let mut s = StageState {
        gen_id,
        id: id.to_string(),
        ver: ver.to_string(),
        phase: "fetching".to_string(),
        started: cron_now(),
        running: true,
        ..Default::default()
    };
    if std::fs::create_dir(STAGE_DIR).is_err() {
        s.phase = "failed".to_string();
        s.code = "dir".to_string();
        s.note = format!("could not make {STAGE_DIR}");
        s.running = false;
    }
    let go = s.running;
    if let Ok(mut g) = STAGE.lock() {
        *g = Some(s);
    }
    if !go {
        return;
    }
    let (ver, variant) = (ver.to_string(), variant.to_string());
    std::thread::spawn(move || {
        let done = stage_job(gen_id, &ver, &variant);
        if let Err((code, note)) = &done {
            stage_say(gen_id, "failed", code, note);
        }
        if let Ok(mut g) = STAGE.lock()
            && let Some(s) = g.as_mut()
            && s.gen_id == gen_id
        {
            s.running = false;
            s.changed = true;
            s.ready = done.is_ok();
            s.done = cron_now();
        }
    });
}

pub fn stage_clear() {
    STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let had = STAGE.lock().ok().and_then(|mut g| g.take()).is_some();
    if had {
        stage_rm();
    }
}

/// When the hub should hear: the run's id and "phase|code|note".
pub fn stage_tick() -> Option<(String, String)> {
    let now = cron_now();
    let mut expired = false;
    let out = {
        let mut g = STAGE.lock().ok()?;
        let s = g.as_mut()?;
        if s.running && now.saturating_sub(s.started) > UPGRADE_BUILD_SECS {
            s.running = false;
            s.phase = "failed".to_string();
            s.code = "limit".to_string();
            s.note = "the stage ran past its limit".to_string();
            s.changed = true;
            STAGE_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // A failed stage holds nothing worth keeping, and the run may not come back to say so.
        if s.changed && !s.running && s.phase == "failed" {
            stage_rm();
        }
        if s.ready && now.saturating_sub(s.done) > UPGRADE_STAGE_KEEP {
            expired = true;
            None
        } else if s.changed
            || s.said == 0
            || (s.running && now.saturating_sub(s.said) >= UPGRADE_STAGE_BEAT)
        {
            // A beat while it works: silence is how the driver tells a stage has died.
            s.changed = false;
            s.said = now;
            Some((s.id.clone(), format!("{}|{}|{}", s.phase, s.code, s.note)))
        } else {
            None
        }
    };
    if expired {
        stage_clear();
    }
    out
}

/// A stage belongs to one process: whatever a dead one left is rubbish.
pub fn stage_boot_clean() {
    stage_rm();
}

/// The staged build for this run, ready to swap in.
fn stage_ready_for(id: &str, ver: &str) -> bool {
    STAGE.lock().ok().is_some_and(|g| {
        g.as_ref()
            .is_some_and(|s| s.ready && s.id == id && s.ver == ver)
    }) && std::path::Path::new(&format!("{STAGE_DIR}/new")).exists()
}

/// The upgrade script for a hub-driven commit.  `kind` decides the middle of
/// it: a prebuilt binary is unpacked and moved into place, a source tarball
/// is compiled first.  Either way the previous binary stays at <exe>.prev —
/// the hub, not the script, decides whether to keep it.
fn hub_upgrade_script(pid: u32, kind: &str, archive: &str, exe: &str, selftest: bool) -> String {
    // One rollback path for every failure: put <exe>.prev back and run it, so
    // a bot that cannot upgrade still comes back on the old build.  The marker
    // is kept, so the old build reports "version-mismatch" to its hub at once.
    //
    // Startup watchdog: the new build daemonizes, so the script outlives it.
    // It starts it, waits UPGRADE_WATCH_SECS, and if the daemon is not alive
    // puts the retained binary (and config) back and starts that instead — a
    // build that cannot come up on this host costs one restart, not a dead
    // node only an admin can revive.  The bot execs this script, so OLD_PID
    // is normally the script itself: no point waiting 30 s on it.
    let staged = kind.eq_ignore_ascii_case("staged");
    let tar = if staged {
        String::new()
    } else {
        format!(
            "tar -xzf \"{archive}\" --strip-components=1 -C \"$UPGRADE_DIR\" 2>/dev/null || rollback \"could not extract artifact\"\n"
        )
    };
    let build = if staged {
        // Fetched, built and selftested while the old build ran: only the swap is left.
        format!(
            "NEW_BIN=\"{STAGE_DIR}/new\"\n[ -x \"$NEW_BIN\" ] || rollback \"the staged build is gone\""
        )
    } else if eq_ic(kind, "bin") {
        // Prebuilt: the tarball holds the binary itself, no toolchain needed.
        // No "run it once" probe — ircbot has no --version flag and starting a
        // second instance would fight the one we are replacing.  The hub is
        // the health monitor: it waits for this node to reappear announcing
        // the new version and sends CMD_UPGRADE_ABORT if it never does.
        r#"NEW_BIN="$UPGRADE_DIR/ircbot"
chmod 700 "$NEW_BIN" 2>/dev/null
[ -x "$NEW_BIN" ] || rollback "artifact binary is not executable""#
            .to_string()
    } else {
        r#"cd "$UPGRADE_DIR" || rollback "build directory vanished"
if [ -f Cargo.toml ]; then
  cargo build --release --bin ircbot >build.log 2>&1
  BUILT=target/release/ircbot
else
  make clean >/dev/null 2>&1
  make >make.log 2>&1
  BUILT=ircbot
fi
cd ..
NEW_BIN="$UPGRADE_DIR/$BUILT"
[ -f "$NEW_BIN" ] || rollback "build failed (see $UPGRADE_DIR)""#
            .to_string()
            // A source build is only testable once built: its -selftest runs
            // here, before the mv, for a target that knows the flag.
            + if selftest {
                "\n\"$NEW_BIN\" -selftest </dev/null >/dev/null 2>&1 || rollback \"new build failed its selftest\""
            } else {
                ""
            }
    };
    format!(
        r#"#!/bin/bash
set -u
OLD_PID={pid}
for i in $(seq 1 30); do
  [ "$OLD_PID" = "$$" ] && break
  kill -0 $OLD_PID 2>/dev/null || break
  sleep 1
done
UPGRADE_DIR="./bot_build_tmp"
rm -rf "$UPGRADE_DIR"
mkdir "$UPGRADE_DIR" || exit 1
rollback() {{
  echo "[UPGRADE] FAILED: $1 — restoring previous build"
  ./{FAILBACK_FILE} restore "$1"
  rm -rf "$UPGRADE_DIR" "{archive}"
  wait
  grep -qx "OLD_PID=$OLD_PID" ./upgrade.sh 2>/dev/null && rm -f ./upgrade.sh
  exit 0
}}
./{FAILBACK_FILE} phase installing $$
FB_ID=$(cut -d'|' -f1 <"{FAILBACK_STATE}" 2>/dev/null)
( while ./{FAILBACK_FILE} tick "$FB_ID"; do sleep 10; done ) </dev/null >/dev/null 2>&1 &
{tar}{build}
mv -f "$NEW_BIN" "{exe}" || rollback "could not install new binary"
chmod 700 "{exe}"
rm -f "{PID_FILE}"
rm -rf "$UPGRADE_DIR" "{archive}" 2>/dev/null
rm -rf {STAGE_DIR} 2>/dev/null
./{FAILBACK_FILE} phase started $$
"{exe}" </dev/null >/dev/null 2>&1
wait
grep -qx "OLD_PID=$OLD_PID" ./upgrade.sh 2>/dev/null && rm -f ./upgrade.sh
exit 0
"#,
    )
}

/// ---- Upgrade hand-off marker -------------------------------------------
/// exec() throws away everything the old process knew, so the upgrade id and
/// the version we were aiming at are left in a file for the new binary to
/// find.  Read exactly once, on the first authenticated hub link after the
/// restart, and removed there.
pub fn marker_write(upgrade_id: &str, target_ver: &str, variant: &str, ops: &[String]) -> bool {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(UPGRADE_MARKER_FILE)
        // id|version|variant.  The variant is what makes a C<->Rust switch at
        // the same version checkable: without it the old build, restored by
        // the script's watchdog, would read the marker and report "ok".
        // Line 2, "ops #a #b": the channels to be back in, opped, before the
        // restarted build reports "ok".  Older builds read only line 1.
        .and_then(|mut f| {
            let mut ops_line = String::from("ops");
            for c in ops
                .iter()
                .filter(|c| !c.is_empty() && !c.contains([' ', '\r', '\n']))
            {
                ops_line.push(' ');
                ops_line.push_str(c);
            }
            f.write_all(format!("{upgrade_id}|{target_ver}|{variant}\n{ops_line}\n").as_bytes())
        })
        .is_ok()
}

/// The hand-off marker, as the restarted process reads it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingUpgrade {
    pub id: String,
    pub version: String,
    /// May be empty.
    pub variant: String,
    /// Channels opped in before the restart (line 2); empty when absent.
    pub ops: Vec<String>,
}

/// Read and consume the marker.  `None` for every ordinary start.
pub fn take_pending_upgrade() -> Option<PendingUpgrade> {
    let body = std::fs::read_to_string(UPGRADE_MARKER_FILE).ok();
    // Consumed whatever it said: a marker we cannot parse must not be retried
    // on every reconnect for the rest of this process's life.
    let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
    parse_marker(&body?)
}

fn parse_marker(body: &str) -> Option<PendingUpgrade> {
    let mut lines = body.lines();
    let line = lines.next()?.trim_end_matches(['\r', '\n']);
    let mut f = line.splitn(3, '|');
    let (id, ver) = (f.next()?, f.next()?);
    let variant = f.next().unwrap_or("");
    if id.is_empty() || ver.is_empty() || variant.len() > 7 {
        return None;
    }
    let ops = lines
        .find_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some("ops")).then(|| w.map(str::to_string).collect::<Vec<_>>())
        })
        .unwrap_or_default();
    Some(PendingUpgrade {
        id: id.to_string(),
        version: ver.to_string(),
        variant: variant.to_string(),
        ops,
    })
}

/// The feature names this host's CPU reports (/proc/cpuinfo `flags` on
/// x86_64, `Features` on aarch64).  Read once.
fn host_cpu_features() -> &'static std::collections::HashSet<String> {
    use std::sync::OnceLock;
    static SET: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    SET.get_or_init(|| {
        let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        cpuinfo_features(&text)
    })
}

fn cpuinfo_features(text: &str) -> std::collections::HashSet<String> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| matches!(k.trim(), "flags" | "Features"))
        .flat_map(|(_, v)| v.split_whitespace().map(str::to_string))
        .collect()
}

/// The first feature a manifest `cpu` column (column 10) needs that `have`
/// lacks on `arch`, or `None`.  "-" or empty = no requirement; an entry may
/// be arch-qualified ("x86_64:avx2") and then applies only on that arch;
/// "neon" is accepted for aarch64's "asimd".
fn cpu_missing<'a>(
    spec: &'a str,
    arch: &str,
    have: &std::collections::HashSet<String>,
) -> Option<&'a str> {
    if spec.is_empty() || spec == "-" {
        return None;
    }
    spec.split(',').filter(|e| !e.is_empty()).find_map(|entry| {
        let feat = match entry.split_once(':') {
            Some((a, f)) if a == arch => f,
            Some(_) => return None,
            None => entry,
        };
        let ok = have.contains(feat) || (feat == "neon" && have.contains("asimd"));
        (!ok).then_some(feat)
    })
}

/// A PREPARE refused because this CPU cannot run the wanted build: say so,
/// and when the OTHER build of the same version fits, say that too.  Never
/// switches — the admin decides (=c / =rs).
fn other_variant_hint(why: String, target_ver: &str, want_variant: &str) -> String {
    let other = if want_variant == "c" { "rs" } else { "c" };
    let fits = hub_set_tree(other).is_ok() && {
        QUICK_FETCH.store(true, std::sync::atomic::Ordering::Relaxed);
        let m = fetch_verified_manifest();
        QUICK_FETCH.store(false, std::sync::atomic::Ordering::Relaxed);
        m.is_ok_and(|m| manifest_select(&m, target_ver, other).is_ok())
    };
    let _ = hub_set_tree(want_variant);
    if fits {
        format!("{why} — the {other} build fits: select this node with ={other}")
    } else {
        why
    }
}

/// Unpack `archive` into a staging directory and run the binary in it with
/// `-selftest` from the working directory (so it reads this node's config and
/// pass file), killed after SELFTEST_TIMEOUT.  The staging directory is
/// always removed.  `Err` carries the first line of what the build printed.
fn staged_selftest(archive: &str) -> Result<(), String> {
    let dir = "./ircbot_selftest_tmp";
    let _ = std::fs::remove_dir_all(dir);
    let out = (|| {
        std::fs::create_dir(dir)
            .map_err(|_| "could not create the staging directory".to_string())?;
        let ok = Command::new("tar")
            .args(["-xzf", archive, "--strip-components=1", "-C", dir])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return Err("could not extract artifact".to_string());
        }
        run_selftest(&format!("{dir}/ircbot"))
    })();
    let _ = std::fs::remove_dir_all(dir);
    out
}

/// Run `bin -selftest`, polling for its exit and killing it at the timeout.
fn run_selftest(bin: &str) -> Result<(), String> {
    use std::io::Read;
    let mut child = Command::new(bin)
        .arg("-selftest")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run it ({e})"))?;
    let end = std::time::Instant::now() + std::time::Duration::from_secs(SELFTEST_TIMEOUT);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() < end => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {SELFTEST_TIMEOUT} s"));
            }
        }
    };
    let mut text = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut text);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut text);
    }
    if status.success() {
        return Ok(());
    }
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    Err(if first.is_empty() {
        format!("exited with {status}")
    } else {
        first.chars().take(160).collect()
    })
}

/// Put back the binary and config a hub-driven upgrade retained, then restart
/// onto them.  Used for CMD_UPGRADE_ABORT: by the time it arrives the new
/// build is already the running process, so undoing it means another exec.
/// Returns false when there is nothing retained to go back to.
pub fn hub_rollback(state: &mut BotState, reason: &str) -> bool {
    let exe = state.executable_path.clone();
    let prev_exe = format!("{exe}{UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{CONFIG_FILE}{UPGRADE_PREV_SUFFIX}");
    if !std::path::Path::new(&prev_exe).exists() {
        logm!(
            state,
            L_INFO,
            "[UPGRADE] Rollback requested ({}) but no retained binary\n",
            reason
        );
        return false;
    }
    logm!(
        state,
        L_INFO,
        "[UPGRADE] Rolling back to the retained build: {}\n",
        reason
    );
    // Config first: if the restart races us, the old binary must not come up
    // against a config only the newer build understands.
    if std::path::Path::new(&prev_cfg).exists() && std::fs::rename(&prev_cfg, CONFIG_FILE).is_err()
    {
        logm!(
            state,
            L_INFO,
            "[UPGRADE] Could not restore {}; keeping the current one\n",
            prev_cfg
        );
    }
    if std::fs::rename(&prev_exe, &exe).is_err() {
        logm!(state, L_INFO, "[UPGRADE] Could not restore {}\n", prev_exe);
        return false;
    }
    let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
    failback_clear();

    ircf!(
        state,
        "QUIT :Upgrade aborted; restoring previous build...\r\n"
    );
    irc_client::disconnect(state);
    dcc::close_all(state, "Bot rolling back; closing.");
    crate::hub_client::disconnect(state);
    state.pid_file = None;
    let _ = std::fs::remove_file(PID_FILE);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new(&exe).exec();
    eprintln!("exec rollback failed: {err}");
    std::process::exit(1);
}

/// The checks a hub-driven upgrade needs that touch no network: version
/// order, the variant, min_from and the unattended-restart prerequisites.
/// The same version is only "already running" when the variant matches too —
/// a different variant is a switch between the C and Rust builds.
fn hub_local_check(
    state: &BotState,
    target_ver: &str,
    want_variant: &str,
    min_from: &str,
) -> Result<(), String> {
    if want_variant.len() > 7
        || want_variant.is_empty()
        || want_variant.contains(['/', ';', '|', '&', '`', '$', ' ', '\t', '\r', '\n'])
    {
        return Err("rejected malformed variant from hub".to_string());
    }
    // Same downgrade guard as the standalone path: a validly signed but stale
    // manifest must not be able to walk us back onto a known-bad build.
    match version_cmp(target_ver, BOT_VERSION) {
        std::cmp::Ordering::Less => {
            return Err("target is older than the running version".to_string());
        }
        std::cmp::Ordering::Equal if want_variant == host_variant() => {
            return Err("already running the target version".to_string());
        }
        _ => {}
    }
    if !min_from.is_empty()
        && min_from != "*"
        && version_cmp(BOT_VERSION, min_from) == std::cmp::Ordering::Less
    {
        // The hub walks the intermediate releases when it sees this.
        return Err("running version is below the target's min_from".to_string());
    }
    // An unattended restart needs the machine-bound password file; without it
    // the new binary would stop at a password prompt with nobody to answer.
    if !std::path::Path::new(PASS_FILE).exists() {
        return Err(format!("no {PASS_FILE}; cannot restart unattended"));
    }
    if !state.executable_path.starts_with('/') {
        return Err("executable path is not absolute".to_string());
    }
    Ok(())
}

/// Point the updater at the tree a hub-driven run names: <root>/<variant>.
/// The run picks only the variant — that is what lets one network-wide run
/// leave each node on its own kind of build, and lets an admin move a node
/// from the Rust build to the C one.  The root is this build's own (or the
/// operator's env override): the only tree its pinned key can verify.
fn hub_set_tree(want_variant: &str) -> Result<(), String> {
    if !set_tree(want_variant) {
        return Err("rejected malformed release variant".to_string());
    }
    Ok(())
}

/// CMD_UPGRADE_PREPARE: could this bot take `target_ver` as `variant`?
/// Everything COMMIT will need short of the download is checked here — the
/// signed manifest for the wanted build must verify and list an artifact
/// for this host, and this host must be able to fetch it at all.  A node
/// that answers "ready" and then fails at COMMIT is what turns a routine
/// run into an abort, so the question is asked in full up front.
pub fn hub_prepare_check(
    state: &BotState,
    target_ver: &str,
    variant: &str,
    min_from: &str,
) -> Result<(), String> {
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    hub_local_check(state, target_ver, want_variant, min_from)?;
    // A local (file://) tree needs no TLS; anything else does, and on a CPU
    // graviola cannot run on the fetch itself would kill the bot.
    if file_url_path(&update_root()).is_none()
        && let Some(why) = tls_unusable_reason()
    {
        return Err(why);
    }
    hub_set_tree(want_variant)?;
    QUICK_FETCH.store(true, std::sync::atomic::Ordering::Relaxed);
    let manifest = fetch_verified_manifest();
    QUICK_FETCH.store(false, std::sync::atomic::Ordering::Relaxed);
    let row = match manifest_select(
        &manifest.map_err(|e| e.to_string())?,
        target_ver,
        want_variant,
    ) {
        Ok(row) => row,
        Err(why) if why.starts_with("this CPU lacks ") => {
            return Err(other_variant_hint(why, target_ver, want_variant));
        }
        Err(why) => return Err(why),
    };
    let name = row.url.rsplit('/').next().unwrap_or("");
    if !name.starts_with("ircbot-") {
        return Err("manifest artifact is not a ircbot release".to_string());
    }
    preflight_host(
        &state.executable_path,
        CONFIG_FILE,
        &row.url,
        row.size,
        &row.kind,
        want_variant,
    )
}

/// Run the upgrade the hub just committed us to.  `Err` means nothing was
/// touched (the caller answers CMD_UPGRADE_RESULT fail and stays on the
/// current build); on success this does not return — the process is replaced
/// and reports in after the restart.
pub fn hub_commit(
    state: &mut BotState,
    upgrade_id: &str,
    target_ver: &str,
    variant: &str,
) -> Result<(), String> {
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    hub_local_check(state, target_ver, want_variant, "")?;
    if file_url_path(&update_root()).is_none()
        && let Some(why) = tls_unusable_reason()
    {
        return Err(why);
    }
    hub_set_tree(want_variant)?;
    logm!(
        state,
        L_INFO,
        "[UPGRADE] Hub commit {}: {} -> {} (variant {})\n",
        upgrade_id,
        BOT_VERSION,
        target_ver,
        want_variant
    );

    let (row_kind, archive) = if stage_ready_for(upgrade_id, target_ver) {
        logm!(
            state,
            L_INFO,
            "[UPGRADE] Using the build staged for {}\n",
            target_ver
        );
        ("staged".to_string(), String::new())
    } else {
        stage_clear();
        let manifest = fetch_verified_manifest().map_err(|e| e.to_string())?;
        let row = manifest_select(&manifest, target_ver, want_variant)?;

        let url_name = row
            .url
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("ircbot.tar.gz");
        let archive =
            sanitize_filename(url_name).ok_or("artifact filename in manifest is not acceptable")?;

        // Every release artifact is named "<product>-…tar.gz" (see the releases
        // repo README).  A base override that names the OTHER product's tree
        // would otherwise hand this daemon the wrong binary and install it over
        // itself — fail closed here, where nothing has been downloaded yet.
        if !archive.starts_with("ircbot-") {
            return Err("manifest artifact is not a ircbot release".to_string());
        }

        logm!(
            state,
            L_INFO,
            "[UPGRADE] Fetching {} artifact {}\n",
            row.kind,
            archive
        );
        if !download(&row.url, &archive) {
            return Err("artifact download failed".to_string());
        }
        if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&row.hash)) {
            let _ = std::fs::remove_file(&archive);
            return Err("artifact SHA-256 mismatch".to_string());
        }
        // Run the new build's own -selftest BEFORE anything is renamed: a build
        // that cannot run here (a CPU it needs, a library, a config it cannot
        // read) is refused with nothing touched.
        if version_cmp(target_ver, UPGRADE_TARGET_MIN) == std::cmp::Ordering::Less {
            let _ = std::fs::remove_file(&archive);
            return Err(format!(
                "target predates {UPGRADE_TARGET_MIN}, the oldest the mesh links with"
            ));
        }
        if eq_ic(&row.kind, "bin") {
            logm!(
                state,
                L_INFO,
                "[UPGRADE] Running the new build's selftest\n"
            );
            if let Err(e) = staged_selftest(&archive) {
                let _ = std::fs::remove_file(&archive);
                return Err(format!("new build failed its selftest: {e}"));
            }
        }

        (row.kind.clone(), archive)
    };

    // End the previous upgrade's failback before laying down anything of this
    // one.  Its loop may be inside finish(), which edits cron for a second or
    // more before removing the state, the script and upgrade.sh: whatever this
    // upgrade had written by then would go with them (nightly 2026-11-06).
    // "done" waits on the lock a tick holds, so that tick is over when it returns.
    failback_clear();

    // Flush the live config, then snapshot the pair we may have to restore.
    // The config is copied (the running bot still needs it); the binary is
    // renamed, which is atomic and leaves <exe>.prev ready for a rollback.
    let saves = config::saves();
    config::write_with_state_pass(state);
    if config::saves() == saves {
        if !archive.is_empty() {
            let _ = std::fs::remove_file(&archive);
        }
        return Err("could not save the config before the swap".to_string());
    }
    let exe = state.executable_path.clone();
    let prev_exe = format!("{exe}{UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{CONFIG_FILE}{UPGRADE_PREV_SUFFIX}");
    if std::fs::copy(CONFIG_FILE, &prev_cfg).is_err() {
        let _ = std::fs::remove_file(&archive);
        return Err("could not snapshot config for rollback".to_string());
    }
    // Both are copied: <exe> stays in place until the new one is renamed over
    // it, so there is never a moment with no binary there.
    let prev_tmp = format!("{prev_exe}.tmp");
    if std::fs::copy(&exe, &prev_tmp).is_err() || std::fs::rename(&prev_tmp, &prev_exe).is_err() {
        let _ = std::fs::remove_file(&prev_tmp);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not retain previous binary".to_string());
    }

    // From here a failure is the script's to handle: it restores <exe>.prev
    // and restarts the old build rather than leaving the node with no binary.
    let script = hub_upgrade_script(std::process::id(), &row_kind, &archive, &exe, true);
    // The channels we hold ops in now: after the restart the "ok" is held
    // until we are back in each of them, opped (hub_client::upgrade_ready_tick).
    let ops: Vec<String> = state
        .chans
        .iter()
        .filter(|c| c.status == crate::state::ChanStatus::In && c.i_am_opped)
        .map(|c| c.name.clone())
        .collect();
    let staged = marker_write(upgrade_id, target_ver, want_variant, &ops)
        && OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o700)
            .open("upgrade.sh.tmp")
            .and_then(|mut f| {
                f.write_all(script.as_bytes())?;
                f.set_permissions(std::fs::Permissions::from_mode(0o700))
            })
            .and_then(|_| std::fs::rename("upgrade.sh.tmp", "upgrade.sh"))
            .map_err(|_| {
                let _ = std::fs::remove_file("upgrade.sh.tmp");
            })
            .is_ok()
        && failback_stage(
            &exe,
            upgrade_id,
            !row_kind.eq_ignore_ascii_case("src"),
            CONFIG_FILE,
            PID_FILE,
            "upgrade.sh",
            if !state.hubs.is_empty() {
                "no hub link and IRC"
            } else {
                "no IRC"
            },
        );
    if !staged {
        failback_clear();
        let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
        let _ = std::fs::remove_file(&prev_exe);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not stage the upgrade script".to_string());
    }

    let cron = failback_run("install");
    if cron != 0 {
        logm!(
            state,
            L_INFO,
            "[UPGRADE] No cron failback on this host ({}): it will not survive a reboot during this upgrade\n",
            cron
        );
    }
    logm!(
        state,
        L_INFO,
        "[UPGRADE] Installing {} and restarting\n",
        target_ver
    );
    ircf!(
        state,
        "QUIT :Upgrading to {} (hub-managed)...\r\n",
        target_ver
    );
    irc_client::disconnect(state);
    dcc::close_all(state, "Bot upgrading; closing.");
    crate::hub_client::disconnect(state);
    state.pid_file = None;
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new("./upgrade.sh").exec();
    // exec failed: <exe> was never moved, so this node is still whole.
    logm!(state, L_INFO, "[UPGRADE] Could not run upgrade.sh: {}\n", err);
    failback_clear();
    let _ = std::fs::remove_file(&prev_exe);
    let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
    eprintln!("exec upgrade.sh failed: {err}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    /// The marker carries the variant so a same-version C<->Rust switch is
    /// checkable; a marker with no variant still parses.
    #[test]
    fn marker_parse() {
        let p = parse_marker("abc-1|2.4.5|c\nops #a #B\n").unwrap();
        assert_eq!(
            (p.id.as_str(), p.version.as_str(), p.variant.as_str()),
            ("abc-1", "2.4.5", "c")
        );
        assert_eq!(p.ops, vec!["#a".to_string(), "#B".to_string()]);
        // An empty ops line, and a one-line marker with no variant.
        assert!(
            parse_marker("abc-1|2.4.5|rs\nops\n")
                .unwrap()
                .ops
                .is_empty()
        );
        let bare = parse_marker("abc-1|2.4.5\n").unwrap();
        assert_eq!((bare.variant.as_str(), bare.ops.len()), ("", 0));
        assert_eq!(parse_marker("|2.4.5|c"), None);
        assert_eq!(parse_marker("abc"), None);
    }

    #[test]
    fn cpu_column() {
        let have = cpuinfo_features(
            "processor\t: 0\nflags\t\t: fpu aes pclmulqdq avx\n\nprocessor\t: 1\nflags\t\t: fpu aes\n",
        );
        assert_eq!(cpu_missing("-", "x86_64", &have), None);
        assert_eq!(cpu_missing("", "x86_64", &have), None);
        assert_eq!(cpu_missing("aes,pclmulqdq,avx", "x86_64", &have), None);
        assert_eq!(cpu_missing("aes,avx2,bmi1", "x86_64", &have), Some("avx2"));
        // Arch-qualified entries apply only on their own arch.
        assert_eq!(
            cpu_missing("aarch64:sha2,x86_64:avx", "x86_64", &have),
            None
        );
        assert_eq!(
            cpu_missing("aarch64:sha2,x86_64:adx", "x86_64", &have),
            Some("adx")
        );
        let arm = cpuinfo_features("Features\t: fp asimd aes pmull sha2\n");
        assert_eq!(cpu_missing("neon,aes,pmull,sha2", "aarch64", &arm), None);
        assert_eq!(
            cpu_missing("x86_64:avx2,aarch64:neon", "aarch64", &arm),
            None
        );
    }

    /// A 9-column row has no cpu column: no requirement.
    #[test]
    fn cpu_column_missing_is_none() {
        let (_, row) =
            parse_row("v9.0.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none src any any *")
                .unwrap();
        assert_eq!(row.cpu, "-");
        let (_, row) = parse_row(
            "v9.0.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none bin x86_64 any * aes,avx2",
        )
        .unwrap();
        assert_eq!(row.cpu, "aes,avx2");
    }

    /// The hub-driven script never waits on itself, keeps the marker on
    /// rollback, and holds the new build to the startup watchdog.
    #[test]
    fn hub_script_has_watchdog() {
        let sc = hub_upgrade_script(42, "bin", "a.tar.gz", "/x/ircbot", true);
        assert!(!sc.contains("-selftest"));
        let src = hub_upgrade_script(42, "src", "a.tar.gz", "/x/ircbot", true);
        assert!(src.contains(r#""$NEW_BIN" -selftest"#));
        assert!(sc.contains(r#"[ "$OLD_PID" = "$$" ] && break"#));
        assert!(sc.contains("phase started $$"));
        // Nothing retained: the binary in place is never moved aside.
        let rollback = sc.split("rollback() {").nth(1).unwrap();
        let rollback = rollback.split('}').next().unwrap();
        assert!(!rollback.contains(UPGRADE_MARKER_FILE));
    }

    #[test]
    fn tls_cpu_reason_matches_probe() {
        assert_eq!(tls_cpu_missing().is_some(), tls_unusable_reason().is_some());
    }

    #[test]
    fn versions() {
        assert_eq!(strverscmp("v2.10.0", "v2.9.1"), Greater);
        assert_eq!(strverscmp("2.3.0", "2.3.0"), Equal);
        assert_eq!(strverscmp("2.3.0", "2.3.1"), Less);
        assert_eq!(strverscmp("v2.3.0", "2.3.0"), Greater);
    }

    /// The downgrade guard compares through version_cmp, which must ignore a
    /// leading 'v' on either side — strverscmp alone ranks "v0.0.1" above
    /// "2.3.0" because it compares 'v' against '2'.
    #[test]
    fn version_cmp_ignores_v_prefix() {
        assert_eq!(strverscmp("v0.0.1", "2.3.0"), Greater);
        assert_eq!(version_cmp("v0.0.1", "2.3.0"), Less);
        assert_eq!(version_cmp("v2.3.0", "2.3.0"), Equal);
        assert_eq!(version_cmp("2.4.0", "v2.3.0"), Greater);
        assert!(version_eq("v2.3.0", "2.3.0"));
    }

    /// A prebuilt binary for this host beats the source row; an unusable
    /// binary row falls back to source rather than failing the upgrade.
    #[test]
    fn manifest_prefers_matching_binary() {
        let src = "v9.0.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none src any any *";
        let bin = format!(
            "v9.0.0 2026-09-20 https://github.com/x/y/v9-bin.tar.gz bb none bin {} {} *",
            host_arch(),
            host_libc()
        );
        let other =
            "v9.0.0 2026-09-20 https://github.com/x/y/v9-sparc.tar.gz cc none bin sparc64 gnu *";

        let m = format!("# comment\n{src}\n{bin}\n");
        assert_eq!(manifest_select(&m, "9.0.0", "c").unwrap().kind, "bin");
        let m = format!("{other}\n{src}\n");
        assert_eq!(manifest_select(&m, "v9.0.0", "c").unwrap().kind, "src");
        let m = format!("{other}\n");
        assert!(manifest_select(&m, "v9.0.0", "c").is_err());
        assert!(manifest_select(&m, "v1.0.0", "c").is_err());
    }

    /// min_from is a floor on the version we may upgrade FROM: a row that
    /// demands more than we run is skipped, which is what makes the hub walk
    /// the intermediate releases.
    #[test]
    fn manifest_honors_min_from() {
        let row = "v9.0.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none src any any 99.0.0";
        assert!(manifest_select(row, "9.0.0", "c").is_err());
        let row = "v9.0.0 2026-09-20 https://github.com/x/y/v9.tar.gz aa none src any any 1.0.0";
        assert!(manifest_select(row, "9.0.0", "c").is_ok());
    }

    #[test]
    fn names_and_urls() {
        assert_eq!(
            sanitize_filename("v2.3.0.tar.gz").as_deref(),
            Some("v2.3.0.tar.gz")
        );
        assert!(sanitize_filename("evil.sh").is_none());
        assert!(validate_url("https://github.com/x/y/archive/v1.tar.gz"));
        assert!(!validate_url("https://github.com/x;rm"));
        assert!(!validate_url("http://github.com/x"));
    }
}
