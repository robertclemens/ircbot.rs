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
use crate::cstr::{eq_ic, Tok};
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
            c1 = if at(a, p1).is_ascii_digit() { p1 += 1; at(a, p1 - 1) } else { 0 };
            c2 = if at(b, p2).is_ascii_digit() { p2 += 1; at(b, p2 - 1) } else { 0 };
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

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().user_agent("ircbot-updater/1.0").build().into()
}

fn fetch(url: &str, limit: u64) -> Option<Vec<u8>> {
    let mut resp = agent().get(url).call().ok()?;
    resp.body_mut().with_config().limit(limit).read_to_vec().ok()
}

fn download(url: &str, path: &str) -> bool {
    let Ok(mut resp) = agent().get(url).call() else { return false };
    let Ok(mut f) = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path) else {
        return false;
    };
    let mut reader = resp.body_mut().with_config().limit(MAX_ARCHIVE).reader();
    std::io::copy(&mut reader, &mut f).is_ok() && f.flush().is_ok()
}

/// Fetch the manifest and its signature and verify one against the other.
fn fetch_verified_manifest() -> Result<String, &'static str> {
    if BOT_UPDATE_PUBKEY_B64.is_empty() {
        return Err("self-updater disabled (no signing key configured)");
    }
    let pub_key = crypto::b64_decode(BOT_UPDATE_PUBKEY_B64)
        .filter(|p| p.len() == 32)
        .ok_or("configured update public key is malformed")?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pub_key);
    let man = fetch(BOT_UPDATE_URL, MAX_MANIFEST).ok_or("failed to download release manifest")?;
    let sig = fetch(BOT_UPDATE_SIG_URL, MAX_MANIFEST).ok_or("failed to download release signature (releases.txt.sig)")?;
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
    let f = [t.next(" \t")?, t.next(" \t")?, t.next(" \t")?, t.next(" \t")?, t.next(" \t")?];
    let caps = [63, 63, 511, 127, 255];
    f.iter().zip(caps).all(|(s, c)| s.len() <= c).then_some(f)
}

fn valid_dependency_name(dep: &str) -> bool {
    !dep.is_empty() && dep.len() <= 64 && dep.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.+".contains(&c))
}

/// A build tool on PATH, or a library pkg-config (or the compiler) knows.
fn check_dependency(dep: &str) -> bool {
    if !valid_dependency_name(dep) {
        return false;
    }
    let script = if ["gcc", "make", "tar", "bash", "cargo", "rustc"].contains(&dep) {
        format!("command -v {dep} >/dev/null 2>&1")
    } else {
        format!("pkg-config --exists {dep} >/dev/null 2>&1 || echo '#include <{dep}.h>' | gcc -E - >/dev/null 2>&1")
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
pub fn check_for_updates(state: &mut BotState, nick: &str) {
    logm!(state, L_DEBUG, "[DEBUG] updater_check_for_updates called.\n");
    let manifest = match fetch_verified_manifest() {
        Ok(m) => m,
        Err(e) => {
            ircf!(state, "PRIVMSG {} :Update check failed: {}.\r\n", nick, e);
            return;
        }
    };
    ircf!(state, "PRIVMSG {} :--- Available Updates (Current: {}) ---\r\n", nick, BOT_VERSION);
    let mut found = 0;
    for line in manifest.split('\n').filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let Some([version, date, _url, _hash, deps]) = parse_release(line) else { continue };
        if strverscmp(version, BOT_VERSION) != std::cmp::Ordering::Greater {
            continue;
        }
        found += 1;
        let failed: Vec<&str> = deps.split(',').filter(|d| !d.is_empty() && !check_dependency(d)).collect();
        let status = if failed.is_empty() { "[OK]".to_string() } else { format!("[FAILED: {}]", failed.join(", ")) };
        ircf!(state, "PRIVMSG {} :{} ({}) - Dependencies: {}\r\n", nick, version, date, status);
    }
    if found == 0 {
        ircf!(state, "PRIVMSG {} :Bot is up-to-date.\r\n", nick);
    } else {
        ircf!(state, "PRIVMSG {} :To upgrade, type: update <version>. IE: update v2.0.0\r\n", nick);
    }
}

fn validate_url(url: &str) -> bool {
    url.starts_with("https://")
        && (url.contains("github.com") || url.contains("githubusercontent.com"))
        && !url.contains([';', '|', '&', '`', '$'])
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
    logm!(state, L_DEBUG, "[DEBUG] updater_perform_upgrade called for {}.\n", version);
    // Downgrade protection: a replayed old manifest cannot roll us back.
    if strverscmp(version, BOT_VERSION) == std::cmp::Ordering::Less {
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
        let Some(f) = parse_release(line) else { continue };
        if eq_ic(f[0], version) {
            if !validate_url(f[2]) {
                ircf!(state, "PRIVMSG {} :Error: Invalid or untrusted URL in release file.\r\n", nick);
                return;
            }
            release = Some((f[2].to_string(), f[3].to_string(), f[4].to_string()));
            break;
        }
    }
    let Some((url, hash, deps)) = release else {
        ircf!(state, "PRIVMSG {} :Error: Version '{}' not found in release file.\r\n", nick, version);
        return;
    };
    let failed: Vec<&str> = deps.split(',').filter(|d| !d.is_empty() && !check_dependency(d)).collect();
    if !failed.is_empty() {
        ircf!(state, "PRIVMSG {} :Error: Cannot upgrade. Missing dependencies: {}\r\n", nick, failed.join(", "));
        return;
    }
    let url_name = url.rsplit('/').next().filter(|s| !s.is_empty() && url.contains('/')).unwrap_or("ircbot.tar.gz");
    let Some(archive) = sanitize_filename(url_name) else {
        ircf!(state, "PRIVMSG {} :Error: Invalid filename in URL.\r\n", nick);
        return;
    };
    ircf!(state, "PRIVMSG {} :Downloading {}...\r\n", nick, archive);
    if !download(&url, &archive) {
        ircf!(state, "PRIVMSG {} :Error: Failed to download new version.\r\n", nick);
        return;
    }
    ircf!(state, "PRIVMSG {} :Verifying hash...\r\n", nick);
    if !crypto::sha256_file_hex(&archive).is_some_and(|h| h.eq_ignore_ascii_case(&hash)) {
        ircf!(state, "PRIVMSG {} :Error: SHA256 hash mismatch! Aborting upgrade.\r\n", nick);
        let _ = std::fs::remove_file(&archive);
        return;
    }
    config::write_with_state_pass(state);
    let exe = state.executable_path.clone();
    let backup = format!("{exe}.backup");
    let _ = std::fs::rename(&exe, &backup);
    ircf!(state, "PRIVMSG {} :Hash verified. Creating upgrade script...\r\n", nick);

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
        ircf!(state, "PRIVMSG {} :Error: Could not create upgrade.sh script.\r\n", nick);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn versions() {
        assert_eq!(strverscmp("v2.10.0", "v2.9.1"), Greater);
        assert_eq!(strverscmp("2.3.0", "2.3.0"), Equal);
        assert_eq!(strverscmp("2.3.0", "2.3.1"), Less);
        assert_eq!(strverscmp("v2.3.0", "2.3.0"), Greater);
    }

    #[test]
    fn names_and_urls() {
        assert_eq!(sanitize_filename("v2.3.0.tar.gz").as_deref(), Some("v2.3.0.tar.gz"));
        assert!(sanitize_filename("evil.sh").is_none());
        assert!(validate_url("https://github.com/x/y/archive/v1.tar.gz"));
        assert!(!validate_url("https://github.com/x;rm"));
        assert!(!validate_url("http://github.com/x"));
    }
}
