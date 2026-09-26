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
    std::io::copy(&mut reader, &mut f).is_ok() && f.flush().is_ok()
}

/// Fetch the manifest and its signature and verify one against the other.
/// A non-empty IRCBOT_UPDATE_BASE repoints the updater at a local
/// ircbot-releases tree (the sandboxed testnet uses a file:// base with no
/// outbound network).  Signature + SHA-256 verification stay active; only the
/// github/https host allow-list in validate_url() is relaxed for this base.
fn update_base() -> Option<String> {
    if let Ok(b) = HUB_UPDATE_BASE.read()
        && !b.is_empty()
    {
        return Some(b.clone());
    }
    std::env::var("IRCBOT_UPDATE_BASE")
        .ok()
        .filter(|s| !s.is_empty())
}

/// The release base the hub named at CMD_UPGRADE_PREPARE time.  The C twin
/// puts it in the environment (setenv); `#![forbid(unsafe_code)]` rules that
/// out here, so it lives in a process-global that update_base() consults
/// ahead of the env var.  Same effect, same verification: only the
/// github/https host allow-list is relaxed, never the signature or hash.
static HUB_UPDATE_BASE: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

fn set_hub_update_base(base: &str) -> bool {
    match HUB_UPDATE_BASE.write() {
        Ok(mut slot) => {
            slot.clear();
            slot.push_str(base);
            true
        }
        Err(_) => false,
    }
}

fn fetch_verified_manifest() -> Result<String, &'static str> {
    let base = update_base();
    // Test key honored only alongside the local-source override (sandbox).
    let pubkey_b64: String = match (&base, std::env::var("IRCBOT_UPDATE_PUBKEY")) {
        (Some(_), Ok(k)) if !k.is_empty() => k,
        _ => BOT_UPDATE_PUBKEY_B64.to_string(),
    };
    if pubkey_b64.is_empty() {
        return Err("self-updater disabled (no signing key configured)");
    }
    let pk = crypto::update_pubkey_b64_decode(&pubkey_b64)
        .ok_or("configured update public key is malformed")?;
    let (man_url, sig_url) = match &base {
        Some(b) => (format!("{b}/releases.txt"), format!("{b}/releases.sig")),
        None => (BOT_UPDATE_URL.to_string(), BOT_UPDATE_SIG_URL.to_string()),
    };
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
    if update_base().is_none() && !set_hub_update_base(&format!("{BOT_UPDATE_BASE}/{want}")) {
        println!("checkupdate: FAIL could not record the release base");
        return 1;
    }
    let base = update_base().unwrap_or_default();
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

fn validate_url(url: &str) -> bool {
    if url.contains([';', '|', '&', '`', '$']) {
        return false;
    }
    if let Some(b) = update_base()
        && url.starts_with(&b)
    {
        return true;
    }
    url.starts_with("https://")
        && (url.contains("github.com") || url.contains("githubusercontent.com"))
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

fn upgrade_script(pid: u32, archive: &str, backup: &str, exe: &str) -> String {
    format!(
        r#"#!/bin/bash
OLD_PID={pid}
echo "[UPGRADE] Waiting for old process (PID: $OLD_PID) to exit..."
for i in {{1..30}}; do
  if ! kill -0 $OLD_PID 2>/dev/null; then
    break
  fi
  sleep 1
done
UPGRADE_DIR="./bot_build_tmp"
rm -rf "$UPGRADE_DIR"
mkdir "$UPGRADE_DIR"
if [ ! -d "$UPGRADE_DIR" ]; then
  echo "[UPGRADE] FATAL: Could not create build directory."
  exit 1
fi
echo "[UPGRADE] Unpacking archive..."
if ! tar -xzf "{archive}" --strip-components=1 -C "$UPGRADE_DIR" 2>/dev/null; then
  echo "[UPGRADE] FATAL: Failed to extract archive."
  mv "{backup}" "{exe}" 2>/dev/null
  exit 1
fi
echo "[UPGRADE] Entering $UPGRADE_DIR and compiling..."
cd "$UPGRADE_DIR"
if [ -f Cargo.toml ]; then
  cargo build --release 2>&1 | tee build.log
  NEW_BIN=target/release/ircbot
else
  make clean >/dev/null 2>&1
  make 2>&1 | tee make.log
  NEW_BIN=ircbot
fi
if [ ! -f "$NEW_BIN" ]; then
  echo "[UPGRADE] FATAL: Build failed. Binary not found."
  echo "[UPGRADE] Restoring backup..."
  cd ..
  mv "{backup}" "{exe}" 2>/dev/null
  rm -f "{PID_FILE}"
  rm -rf "$UPGRADE_DIR"
  rm -f "{archive}"
  exit 1
fi
echo "[UPGRADE] Moving new binary into place..."
mv "$NEW_BIN" "{exe}"
chmod 700 "{exe}"
cd ..
echo "[UPGRADE] Removing old PID file..."
rm -f "{PID_FILE}"
echo "[UPGRADE] Removing backup..."
rm -f "{backup}"
echo "[UPGRADE] Scheduling cleanup..."
(sleep 5; rm -rf "$UPGRADE_DIR" "{archive}" "./upgrade.sh" 2>/dev/null) &
echo "[UPGRADE] Restarting bot..."
exec {exe}
"#
    )
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
    let manifest = match fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            ircf!(state, "PRIVMSG {} :Upgrade aborted: {}.\r\n", nick, e);
            return;
        }
    };
    let mut release = None;
    for line in manifest.split('\n').filter(|l| !l.is_empty()) {
        let Some(f) = parse_release(line) else {
            continue;
        };
        if version_eq(f[0], version) {
            if !validate_url(f[2]) {
                ircf!(
                    state,
                    "PRIVMSG {} :Error: Invalid or untrusted URL in release file.\r\n",
                    nick
                );
                return;
            }
            release = Some((f[2].to_string(), f[3].to_string(), f[4].to_string()));
            break;
        }
    }
    let Some((url, hash, deps)) = release else {
        ircf!(
            state,
            "PRIVMSG {} :Error: Version '{}' not found in release file.\r\n",
            nick,
            version
        );
        return;
    };
    let failed: Vec<&str> = deps
        .split(',')
        .filter(|d| !d.is_empty() && !check_dependency(d))
        .collect();
    if !failed.is_empty() {
        ircf!(
            state,
            "PRIVMSG {} :Error: Cannot upgrade. Missing dependencies: {}\r\n",
            nick,
            failed.join(", ")
        );
        return;
    }
    let url_name = url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty() && url.contains('/'))
        .unwrap_or("ircbot.tar.gz");
    let Some(archive) = sanitize_filename(url_name) else {
        ircf!(
            state,
            "PRIVMSG {} :Error: Invalid filename in URL.\r\n",
            nick
        );
        return;
    };
    ircf!(state, "PRIVMSG {} :Downloading {}...\r\n", nick, archive);
    if !download(&url, &archive) {
        ircf!(
            state,
            "PRIVMSG {} :Error: Failed to download new version.\r\n",
            nick
        );
        return;
    }
    ircf!(state, "PRIVMSG {} :Verifying hash...\r\n", nick);
    if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&hash)) {
        ircf!(
            state,
            "PRIVMSG {} :Error: SHA256 hash mismatch! Aborting upgrade.\r\n",
            nick
        );
        let _ = std::fs::remove_file(&archive);
        return;
    }
    config::write_with_state_pass(state);
    let exe = state.executable_path.clone();
    let backup = format!("{exe}.backup");
    let _ = std::fs::rename(&exe, &backup);
    ircf!(
        state,
        "PRIVMSG {} :Hash verified. Creating upgrade script...\r\n",
        nick
    );

    // Created 0700 in one step: no writable window on a script we exec.
    let script = upgrade_script(std::process::id(), &archive, &backup, &exe);
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open("upgrade.sh")
        .and_then(|mut f| {
            f.write_all(script.as_bytes())?;
            f.set_permissions(std::fs::Permissions::from_mode(0o700))
        });
    if written.is_err() {
        ircf!(
            state,
            "PRIVMSG {} :Error: Could not create upgrade.sh script.\r\n",
            nick
        );
        let _ = std::fs::remove_file(&archive);
        let _ = std::fs::rename(&backup, &exe);
        return;
    }
    ircf!(state, "QUIT :Upgrading to {}...\r\n", version);
    irc_client::disconnect(state);
    dcc::close_all(state, "Bot upgrading; closing.");
    state.pid_file = None;
    std::thread::sleep(std::time::Duration::from_secs(1));
    let err = Command::new("./upgrade.sh").exec();
    eprintln!("execl failed: {err}");
    std::process::exit(1);
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

/// The upgrade script for a hub-driven commit.  `kind` decides the middle of
/// it: a prebuilt binary is unpacked and moved into place, a source tarball
/// is compiled first.  Either way the previous binary stays at <exe>.prev —
/// the hub, not the script, decides whether to keep it.
fn hub_upgrade_script(
    pid: u32,
    kind: &str,
    archive: &str,
    prev: &str,
    exe: &str,
    selftest: bool,
) -> String {
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
    let build = if eq_ic(kind, "bin") {
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
  cargo build --release >build.log 2>&1
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
  mv -f "{prev}" "{exe}" 2>/dev/null
  rm -f "{PID_FILE}"
  rm -rf "$UPGRADE_DIR" "{archive}"
  exec "{exe}"
}}
tar -xzf "{archive}" --strip-components=1 -C "$UPGRADE_DIR" 2>/dev/null || rollback "could not extract artifact"
{build}
mv -f "$NEW_BIN" "{exe}" || rollback "could not install new binary"
chmod 700 "{exe}"
rm -f "{PID_FILE}"
rm -rf "$UPGRADE_DIR" "{archive}" 2>/dev/null
"{exe}" </dev/null >/dev/null 2>&1
sleep {watch}
P=$(cat "{PID_FILE}" 2>/dev/null | tr -dc 0-9)
if [ -z "$P" ] || ! kill -0 "$P" 2>/dev/null; then
  echo "[UPGRADE] new build did not stay up — restoring previous build"
  mv -f "{exe}" "{exe}.failed" 2>/dev/null
  mv -f "{prev}" "{exe}" || exit 1
  [ -f "{cfg_prev}" ] && cp -f "{cfg_prev}" "{CONFIG_FILE}"
  rm -f "{PID_FILE}" ./upgrade.sh
  exec "{exe}"
fi
rm -f ./upgrade.sh
exit 0
"#,
        watch = UPGRADE_WATCH_SECS,
        cfg_prev = format!("{CONFIG_FILE}{UPGRADE_PREV_SUFFIX}"),
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
    /// "" when an older build wrote a two-field line 1.
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
fn other_variant_hint(why: String, target_ver: &str, want_variant: &str, base: &str) -> String {
    let other = if want_variant == "c" { "rs" } else { "c" };
    let fits = hub_set_tree(base, other).is_ok() && {
        QUICK_FETCH.store(true, std::sync::atomic::Ordering::Relaxed);
        let m = fetch_verified_manifest();
        QUICK_FETCH.store(false, std::sync::atomic::Ordering::Relaxed);
        m.is_ok_and(|m| manifest_select(&m, target_ver, other).is_ok())
    };
    let _ = hub_set_tree(base, want_variant);
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
fn hub_set_tree(base: &str, want_variant: &str) -> Result<(), String> {
    // The hub names the release tree ROOT; the variant picks the subtree.
    // That is what lets one network-wide run leave each node on its own kind
    // of build — and lets an admin move a node from the Rust build to the C
    // one by naming the other variant.
    let root = if base.is_empty() {
        BOT_UPDATE_BASE
    } else {
        base
    };
    if root.len() >= 512 || root.contains([';', '|', '&', '`', '$', ' ', '\t', '\r', '\n']) {
        return Err("rejected malformed manifest base from hub".to_string());
    }
    if !set_hub_update_base(&format!("{root}/{want_variant}")) {
        return Err("could not record the hub's manifest base".to_string());
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
    base: &str,
) -> Result<(), String> {
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    hub_local_check(state, target_ver, want_variant, min_from)?;
    // A local (file://) tree needs no TLS; anything else does, and on a CPU
    // graviola cannot run on the fetch itself would kill the bot.
    if file_url_path(base).is_none()
        && let Some(why) = tls_unusable_reason()
    {
        return Err(why);
    }
    hub_set_tree(base, want_variant)?;
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
            return Err(other_variant_hint(why, target_ver, want_variant, base));
        }
        Err(why) => return Err(why),
    };
    let name = row.url.rsplit('/').next().unwrap_or("");
    if !name.starts_with("ircbot-") {
        return Err("manifest artifact is not a ircbot release".to_string());
    }
    Ok(())
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
    base: &str,
) -> Result<(), String> {
    // The hub may point us at a different release base than the compiled-in
    // one (the testnet serves a local ircbot-releases tree).  It travels the
    // same path as the operator-set env var, so signature and hash checks are
    // unchanged — see update_base().
    let want_variant = if variant.is_empty() {
        host_variant()
    } else {
        variant
    };
    hub_local_check(state, target_ver, want_variant, "")?;
    if file_url_path(base).is_none()
        && let Some(why) = tls_unusable_reason()
    {
        return Err(why);
    }
    hub_set_tree(base, want_variant)?;
    logm!(
        state,
        L_INFO,
        "[UPGRADE] Hub commit {}: {} -> {} (variant {})\n",
        upgrade_id,
        BOT_VERSION,
        target_ver,
        want_variant
    );

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
    // read) is refused with nothing touched.  Only a build new enough to know
    // the flag is asked — an older one would start a second daemon instead.
    if eq_ic(&row.kind, "bin")
        && version_cmp(target_ver, SELFTEST_MIN_BOT) != std::cmp::Ordering::Less
    {
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

    // Flush the live config, then snapshot the pair we may have to restore.
    // The config is copied (the running bot still needs it); the binary is
    // renamed, which is atomic and leaves <exe>.prev ready for a rollback.
    config::write_with_state_pass(state);
    let exe = state.executable_path.clone();
    let prev_exe = format!("{exe}{UPGRADE_PREV_SUFFIX}");
    let prev_cfg = format!("{CONFIG_FILE}{UPGRADE_PREV_SUFFIX}");
    if std::fs::copy(CONFIG_FILE, &prev_cfg).is_err() {
        let _ = std::fs::remove_file(&archive);
        return Err("could not snapshot config for rollback".to_string());
    }
    if std::fs::rename(&exe, &prev_exe).is_err() {
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not retain previous binary".to_string());
    }

    // From here a failure is the script's to handle: it restores <exe>.prev
    // and restarts the old build rather than leaving the node with no binary.
    let script = hub_upgrade_script(
        std::process::id(),
        &row.kind,
        &archive,
        &prev_exe,
        &exe,
        version_cmp(target_ver, SELFTEST_MIN_BOT) != std::cmp::Ordering::Less,
    );
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
            .open("upgrade.sh")
            .and_then(|mut f| {
                f.write_all(script.as_bytes())?;
                f.set_permissions(std::fs::Permissions::from_mode(0o700))
            })
            .is_ok();
    if !staged {
        let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
        let _ = std::fs::rename(&prev_exe, &exe);
        let _ = std::fs::remove_file(&prev_cfg);
        let _ = std::fs::remove_file(&archive);
        return Err("could not stage the upgrade script".to_string());
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
    // exec failed: put the old binary back so the node is not left dead.
    let _ = std::fs::rename(&prev_exe, &exe);
    let _ = std::fs::remove_file(UPGRADE_MARKER_FILE);
    eprintln!("exec upgrade.sh failed: {err}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    /// The marker carries the variant so a same-version C<->Rust switch is
    /// checkable; a legacy two-field marker still parses, with no variant.
    #[test]
    fn marker_parse() {
        let p = parse_marker("abc-1|2.4.5|c\nops #a #B\n").unwrap();
        assert_eq!(
            (p.id.as_str(), p.version.as_str(), p.variant.as_str()),
            ("abc-1", "2.4.5", "c")
        );
        assert_eq!(p.ops, vec!["#a".to_string(), "#B".to_string()]);
        // An empty ops line, and a legacy one-line marker with no variant.
        assert!(
            parse_marker("abc-1|2.4.5|rs\nops\n")
                .unwrap()
                .ops
                .is_empty()
        );
        let legacy = parse_marker("abc-1|2.4.5\n").unwrap();
        assert_eq!((legacy.variant.as_str(), legacy.ops.len()), ("", 0));
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
        let sc = hub_upgrade_script(42, "bin", "a.tar.gz", "/x/ircbot.prev", "/x/ircbot", true);
        assert!(!sc.contains("-selftest"));
        let src = hub_upgrade_script(42, "src", "a.tar.gz", "/x/ircbot.prev", "/x/ircbot", true);
        assert!(src.contains(r#""$NEW_BIN" -selftest"#));
        assert!(sc.contains(r#"[ "$OLD_PID" = "$$" ] && break"#));
        assert!(sc.contains(&format!("sleep {UPGRADE_WATCH_SECS}")));
        assert!(sc.contains(r#"mv -f "/x/ircbot.prev" "/x/ircbot" || exit 1"#));
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
