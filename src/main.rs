//! ircbot: an IRC bot that joins an encrypted hub mesh (safe-Rust port of
//! ircbot.c).  Entry point: process hardening, the setup wizard, the
//! machine-bound password file, daemonizing, and the poll loop.

#![forbid(unsafe_code)]

mod auth;
mod bot_comms;
mod channel;
mod commands;
mod config;
mod consts;
mod crypto;
mod cstr;
mod dcc;
mod hub_client;
mod irc_client;
mod irc_parser;
mod logging;
mod net;
mod secret;
mod state;
mod updater;

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mio::{Events, Poll};
use zeroize::Zeroizing;

use consts::*;
use cstr::{now, trunc_string};
use state::{is_rfc_nick, is_valid_bot_nick, BotState, ChanStatus, HubEntry, MaskRecord, UserRecord, S_DIE};

/// Keep secrets out of anything that lands on disk: no core dump (which
/// would carry the identity key and config password), no same-uid ptrace
/// attach.  RLIMIT_CORE 0 also survives the updater's exec.  Neither
/// defends against root.
fn harden_process() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    let _ = nix::sys::prctl::set_dumpable(false);
}

// ---- Terminal input ----------------------------------------------------------------------

/// One line from stdin, without the line ending, cut to `len`-1 bytes.
fn read_line(len: usize) -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::new());
    if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        return Zeroizing::new(String::new());
    }
    let end = line.find(['\r', '\n']).unwrap_or(line.len());
    Zeroizing::new(trunc_string(&line[..end], len))
}

fn get_input(prompt: &str, len: usize) -> Zeroizing<String> {
    print!("{prompt}: ");
    let _ = io::stdout().flush();
    read_line(len)
}

/// Read a password with terminal echo off (plain read when stdin is not a
/// terminal, e.g. `echo pass | ./ircbot`).
fn get_password(prompt: &str, len: usize) -> Zeroizing<String> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    print!("{prompt}: ");
    let _ = io::stdout().flush();
    let stdin = io::stdin();
    let old = tcgetattr(&stdin).ok();
    if let Some(o) = &old {
        let mut t = o.clone();
        t.local_flags.remove(LocalFlags::ECHO);
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &t);
    }
    let pass = read_line(len);
    if let Some(o) = &old {
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, o);
    }
    println!();
    pass
}

fn get_confirmed_password(prompt: &str) -> Option<Zeroizing<String>> {
    let p = get_password(prompt, MAX_PASS);
    let c = get_password("Confirm password", MAX_PASS);
    if *p == *c && !p.is_empty() {
        println!("Passwords match. Accepted.");
        Some(p)
    } else {
        println!("🚨 ERROR: Passwords do not match or are empty. Please try again.");
        None
    }
}

// ---- Machine-bound password file -----------------------------------------------------------

/// "<home ino>:<home dev>:<uid>:<gid>:<machine>" -- what binds the pass
/// file to this account on this host.
fn passfile_context() -> Zeroizing<String> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let (ino, dev) = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .and_then(|u| fs::metadata(u.dir).ok())
        .map_or((0, 0), |m| (m.ino(), m.dev()));
    let machine = nix::sys::utsname::uname()
        .map(|u| u.machine().to_string_lossy().into_owned())
        .unwrap_or_default();
    Zeroizing::new(format!("{}:{}:{}:{}:{}", ino, dev, uid.as_raw(), gid.as_raw(), cstr::trunc(&machine, 65)))
}

fn passfile_create(path: &str, password: &str) -> bool {
    let mut salt = [0u8; SALT_SIZE];
    if !crypto::random_bytes(&mut salt) {
        eprintln!("RNG failure.");
        return false;
    }
    let ctx = passfile_context();
    let key = crypto::derive_config_key(ctx.as_bytes(), &salt);
    drop(ctx);
    let Some(enc) = crypto::gcm_seal(key.as_ref(), &[], password.as_bytes()) else {
        eprintln!("Encryption failed.");
        return false;
    };
    let mut f = match OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open: {e}");
            return false;
        }
    };
    if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
        eprintln!("fchmod: {e}");
        return false;
    }
    // On disk: salt || iv || ct || tag -- the C bot's layout.
    let ok = f.write_all(&salt).is_ok() && f.write_all(&enc).is_ok();
    if !ok {
        eprintln!("write {PASS_FILE} failed");
    }
    ok
}

fn passfile_load(path: &str) -> Option<Zeroizing<String>> {
    let md = fs::metadata(path).ok()?;
    if md.uid() != nix::unistd::getuid().as_raw() {
        eprintln!("[WARN] {path}: wrong owner, ignoring.");
        return None;
    }
    if md.permissions().mode() & 0o777 != 0o600 {
        eprintln!("[WARN] {path}: must be 0600, ignoring.");
        return None;
    }
    if md.len() < (SALT_SIZE + GCM_IV_LEN + 1 + GCM_TAG_LEN) as u64 {
        return None;
    }
    let mut buf = Zeroizing::new(Vec::new());
    fs::File::open(path).ok()?.read_to_end(&mut buf).ok()?;
    let ctx = passfile_context();
    let key = crypto::derive_config_key(ctx.as_bytes(), &buf[..SALT_SIZE]);
    match crypto::gcm_open(key.as_ref(), &[], &buf[SALT_SIZE..]) {
        Some(p) if !p.is_empty() && p.len() < MAX_PASS => Some(Zeroizing::new(String::from_utf8_lossy(&p).into_owned())),
        _ => {
            eprintln!("[WARN] {path}: decryption failed (wrong machine or tampered file).");
            None
        }
    }
}

// ---- Setup wizard ----------------------------------------------------------------------------

/// A user's public key for the wizard: pasted, or a path to .public.b64.
fn wizard_read_pubkey(who: &str) -> String {
    loop {
        let input = get_input("Public key (paste the 88 chars, or a path to the .public.b64)", 4096);
        if input.is_empty() {
            println!("ERROR: a public key is required. Make one with 'utils/keygen {who}' and give its .public.b64.");
            continue;
        }
        // A keygen private file has the same shape: refuse it by name.
        if input.contains(".private.") {
            println!("ERROR: that is a PRIVATE key file — it stays with the admin. Use the matching .public.b64.");
            continue;
        }
        let (key, raw) = match crypto::pubkey_b64_decode(&input) {
            Some(raw) => (input.to_string(), raw),
            None => {
                let file = fs::read_to_string(input.as_str()).ok();
                let line = file
                    .as_deref()
                    .and_then(|s| s.lines().next())
                    .map(|l| l.split([' ', '\t', '\r', '\n']).next().unwrap_or("").to_string())
                    .unwrap_or_default();
                match crypto::pubkey_b64_decode(&line) {
                    Some(raw) if !line.is_empty() => (line, raw),
                    _ => {
                        println!(
                            "ERROR: not an 88-char public key{}. Use the .public.b64 (never the .private.b64).",
                            if file.is_some() { " in that file" } else { "" }
                        );
                        continue;
                    }
                }
            }
        };
        println!("  Key fingerprint for {}: {}", who, crypto::key_fingerprint(&raw));
        let yn = get_input("Use this key? (Y/n)", 16);
        if !yn.starts_with(['n', 'N']) {
            return key;
        }
    }
}

fn run_config_wizard() -> io::Result<()> {
    let poll = Poll::new()?;
    println!("--- IRC Bot Initial Setup ---");
    println!("No config file found. Let's create one.\n");

    let (mut state, config_pass, server, chan, hub_managed, admin) = loop {
        let mut state = BotState::new(poll.registry().try_clone()?);
        println!("==========================================");
        println!("         Starting Configuration Wizard      ");
        println!("==========================================");
        println!("\n--- Setup Config Master Password ---");
        let config_pass = loop {
            if let Some(p) = get_confirmed_password("Enter new config password") {
                break p;
            }
        };

        // Identity first, so the operator can register the UUID and pubkey
        // on the hub.  The private key never leaves this machine.
        println!("\n--- Bot Identity (Curve25519) ---");
        let Some((priv_key, pub_key)) = crypto::generate_combined_keypair() else {
            eprintln!("🚨 ERROR: Failed to generate bot keypair.");
            return Ok(());
        };
        let Some(uuid) = crypto::gen_uuid_v4() else {
            eprintln!("🚨 ERROR: RAND_bytes failed.");
            return Ok(());
        };
        state.bot_uuid = uuid;
        *state.hub_key = crypto::b64_encode(priv_key.as_ref());
        state.hub_key_raw.set(&priv_key);
        drop(priv_key);
        println!("\n  Bot UUID:        {}", state.bot_uuid);
        println!("  Bot public key:  {}", crypto::b64_encode(&pub_key));
        println!("  Key fingerprint: {}", crypto::key_fingerprint(&pub_key));
        println!("\n  Save these — when registering this bot in hub_admin's");
        println!("  'Add Bot' menu the hub will ask for the UUID and pubkey above.");
        println!("  (Standalone bots: other bots trust this one with");
        println!("  '+bot <nick!user@host> <UUID> <public key>'.)");
        print!("\n  Press Enter to continue...");
        let _ = io::stdout().flush();
        let _ = read_line(4096);

        println!("\n--- Setup Bot Nickname ---");
        loop {
            state.target_nick = get_input("Enter bot nick", MAX_NICK).to_string();
            if is_rfc_nick(&state.target_nick) {
                state.current_nick = state.target_nick.clone();
                break;
            }
            if state.target_nick.contains('|') {
                println!("ERROR: Nick cannot contain '|' (reserved as protocol delimiter).");
            } else if !is_valid_bot_nick(&state.target_nick) {
                println!("ERROR: Invalid nick length (1-{} characters).", MAX_NICK - 1);
            } else {
                println!("ERROR: Not a valid IRC nick: start with a letter or one of []\\`_^{{}}, then letters, digits, those or '-'.");
            }
        }
        state.user = get_input("Enter bot username (ident)", 64).to_string();
        state.gecos = get_input("Enter bot real name (gecos)", 128).to_string();
        state.vhost = get_input("Enter VHOST IP (optional, press Enter for default [no vhost])", 128).to_string();

        println!("\n--- Setup IRC Server ---");
        let server = loop {
            let s = get_input("Enter IRC server (e.g., irc.efnet.org)", MAX_BUFFER);
            if s.len() > 3 && s.contains('.') {
                break s.to_string();
            }
            println!("🚨 ERROR: Invalid server format.");
        };

        // A hub-managed bot owns none of the hub-authoritative records, so
        // they are not asked for.
        println!("\n--- Management Mode ---");
        println!("Hub-managed: admins, usermasks and channels live on the hub and are");
        println!("  managed with hub_admin. This bot only needs hub addresses and");
        println!("  their pinned public keys.");
        println!("Standalone:  this bot owns its own admin list and channels.\n");
        let hub_managed = !get_input("Hub-managed? (Y/n)", 16).starts_with(['n', 'N']);

        let mut chan = String::new();
        let mut admin: Option<(String, String, Vec<String>)> = None;
        if hub_managed {
            println!("\n--- Hub Configuration ---");
            println!("You'll need each hub's address and public key (the base64 from");
            println!("the hub's hub_public.b64 file). Each hub has its own keypair, so");
            println!("the key is pinned per hub.");
            while state.hubs.len() < MAX_SERVERS {
                println!("\n--- Hub #{} Address ---", state.hubs.len() + 1);
                let addr = loop {
                    let a = get_input("Enter hub address (e.g., 127.0.0.1:6000)", 256);
                    let ok = a.rfind(':').is_some_and(|c| c > 0 && c + 1 < a.len() && (1..65536).contains(&cstr::atoi(&a[c + 1..])));
                    if ok {
                        break a.to_string();
                    }
                    println!("🚨 ERROR: Invalid format. Use HOST:PORT or IP:PORT.");
                };
                if state.hubs.iter().any(|h| h.addr == addr) {
                    println!("🚨 ERROR: '{addr}' already added; skipping.");
                } else {
                    println!("\n--- Hub #{} Public Key ---", state.hubs.len() + 1);
                    println!("Paste the base64 from the hub's hub_public.b64 file (44 or 88 chars).");
                    let ed_pub = loop {
                        let k = get_input("Hub public key", 256);
                        let k = k.trim_end_matches([' ', '\r', '\n', '\t']);
                        match crypto::b64_decode(k) {
                            Some(d) if d.len() == 32 || d.len() == HUB_KEY_RAW_LEN => {
                                // The Ed25519 half is what the handshake verifies.
                                let mut p = [0u8; 32];
                                p.copy_from_slice(&d[..32]);
                                break p;
                            }
                            _ => println!(
                                "🚨 ERROR: Expected base64 of a 32-byte Ed25519 key (44 chars) or 64-byte combined key (88 chars)."
                            ),
                        }
                    };
                    state.hubs.push(HubEntry { addr: addr.clone(), ed_pub, ed_pub_set: true });
                    println!("\n✓ Hub added: {addr}");
                }
                if state.hubs.len() >= MAX_SERVERS {
                    println!("Reached hub limit ({MAX_SERVERS}).");
                    break;
                }
                if !get_input("Add another hub? (y/N)", 16).starts_with(['y', 'Y']) {
                    break;
                }
            }
            if state.hubs.is_empty() {
                println!("\n🚨 ERROR: A hub-managed bot needs at least one hub. Restarting setup.\n");
                continue;
            }
            println!(
                "\n✓ Hub configuration saved ({} hub{}).",
                state.hubs.len(),
                if state.hubs.len() == 1 { "" } else { "s" }
            );
            println!("\n  Admins, usermasks and channels for this bot are added with");
            println!("  hub_admin (IRC Admin Commands), not here. This wizard assumes");
            println!("  the hub network runs with opt 'h' (hub-only mutations), which");
            println!("  is the default — it cannot verify that until the first sync.");
            println!("  If your hub does not set opt 'h', you can also add them later");
            println!("  from IRC with '+admin' and 'join'.");
        } else {
            println!("\n--- Setup First Admin ---");
            let name = loop {
                let n = get_input("Enter admin friendly name (no spaces, e.g. robert)", 64);
                if !n.is_empty() && !n.contains(' ') && !n.contains('|') {
                    break n.to_string();
                }
                println!("ERROR: Name cannot contain spaces or '|'.");
            };
            println!("\nThe admin signs in with a Curve25519 key, not a password.");
            println!("On the admin's own machine run 'utils/keygen {name}' (or see");
            println!("'help +admin' for an openssl recipe) and give its .public.b64 here.");
            println!("The .private.b64 stays with the admin (chmod 600) for their IRC script.");
            let pubkey = wizard_read_pubkey(&name);
            println!("\n--- Setup Admin Usermasks ---");
            println!("Enter usermasks for this admin (e.g. nick!*@*.example.com).");
            println!("Press Enter with no mask when done (at least one required).\n");
            let mut masks: Vec<String> = Vec::new();
            while masks.len() < 20 {
                print!("Usermask {}{}: ", masks.len() + 1, if masks.is_empty() { " (required)" } else { " (or Enter to finish)" });
                let _ = io::stdout().flush();
                let mut line = String::new();
                if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let m = trunc_string(line.split('\n').next().unwrap_or(""), MAX_MASK_LEN);
                if m.is_empty() {
                    if masks.is_empty() {
                        println!("ERROR: At least one usermask required.");
                        continue;
                    }
                    break;
                }
                if !m.contains('!') || !m.contains('@') {
                    println!("ERROR: Mask must contain '!' and '@'. Try again.");
                    continue;
                }
                masks.push(m);
            }
            println!("\n--- Setup Initial Channel ---");
            loop {
                chan = get_input("Enter channel to join (e.g., #bots) [Optional, Enter to skip]", MAX_CHAN).to_string();
                if chan.is_empty() || (chan.starts_with('#') && chan.len() > 1) {
                    break;
                }
                println!("🚨 ERROR: Channel must start with '#'.");
            }
            admin = Some((name, pubkey, masks));
        }

        println!("\n==========================================");
        println!("     Configuration Summary (Review)         ");
        println!("==========================================");
        println!("Bot Nick: {}", state.target_nick);
        println!("IRC Server: {server}");
        if hub_managed {
            println!("Mode: HUB-MANAGED ({} hub{})", state.hubs.len(), if state.hubs.len() == 1 { "" } else { "s" });
            println!("Admins/channels: managed on the hub");
        } else if let Some((name, key, masks)) = &admin {
            println!("Mode: STANDALONE");
            println!("Admin: {} ({} usermask{})", name, masks.len(), if masks.len() == 1 { "" } else { "s" });
            if let Some(raw) = crypto::pubkey_b64_decode(key) {
                println!("Admin key: {}", crypto::key_fingerprint(&raw));
            }
            println!("Channel: {}", if chan.is_empty() { "(none)" } else { chan.as_str() });
        }
        if get_input("Does this look correct? (Y/n)", 16).starts_with(['n', 'N']) {
            println!("\nRestarting configuration wizard...\n");
            continue;
        }
        break (state, config_pass, server, chan, hub_managed, admin);
    };

    // Standalone only: the hub is authoritative for a|/m| records and would
    // replace them on the first sync.
    if !hub_managed {
        if let Some((name, key, masks)) = admin {
            let uuid = crypto::gen_uuid_v4().unwrap_or_default();
            let t = now();
            state.user_records.push(UserRecord {
                uuid: uuid.clone(),
                name,
                has_pubkey: !key.is_empty(),
                pubkey_b64: key,
                typ: 'a',
                is_active: true,
                timestamp: t,
                ..UserRecord::default()
            });
            for m in masks.into_iter().take(MAX_USER_MASKS) {
                state.mask_records.push(MaskRecord { uuid: uuid.clone(), mask: m, is_active: true, last_used: 0, timestamp: t });
            }
        }
    }
    state.server_list.push(server);
    if !chan.is_empty() {
        if let Some(ci) = channel::add(&mut state, &chan) {
            let c = &mut state.chans[ci];
            c.is_managed = true;
            c.timestamp = now();
            c.status = ChanStatus::Out;
        }
    }

    println!("\n--- Finalizing Configuration ---");
    config::write(&mut state, &config_pass);
    println!("\nConfiguration saved to {CONFIG_FILE}.");
    println!("You can now start the bot:");
    println!("  Run './ircbot -p' to create a machine-bound password file, then './ircbot'");
    println!("  Or run './ircbot' directly and enter the password when prompted.");
    Ok(())
}

// ---- Daemon ------------------------------------------------------------------------------------

/// Detach: new session, stdio to /dev/null, umask 027.  The working
/// directory stays (config and log paths are relative).
fn daemonize() {
    if let Err(e) = nix::unistd::daemon(true, false) {
        eprintln!("daemon: {e}");
        std::process::exit(1);
    }
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o027));
}

/// The pid file, flock'd: the lock is what marks this bot as running.
fn lock_pid_file() -> Option<fs::File> {
    let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(PID_FILE).ok()?;
    if f.try_lock().is_err() {
        let mut existing = String::new();
        let _ = f.read_to_string(&mut existing);
        let existing = existing.lines().next().unwrap_or("");
        if existing.is_empty() {
            eprintln!("Already running — {PID_FILE} locked");
        } else {
            eprintln!("Already running (pid {existing}) — {PID_FILE}");
        }
        return None;
    }
    // Truncate first so no stale bytes remain when the new pid is shorter.
    f.set_len(0).ok()?;
    writeln!(f, "{}", std::process::id()).ok()?;
    Some(f)
}

fn main() {
    harden_process();
    logging::install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    let do_setup = args.iter().skip(1).any(|a| a == "-setup");
    let do_passfile = args.iter().skip(1).any(|a| a == "-p");

    if do_setup {
        if fs::metadata(CONFIG_FILE).is_ok() {
            eprintln!("Error: Config file '{CONFIG_FILE}' already exists.");
            std::process::exit(1);
        }
        if let Err(e) = run_config_wizard() {
            eprintln!("Setup failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    if do_passfile {
        let pass = loop {
            let p1 = get_password("Config Password", MAX_PASS);
            if p1.is_empty() {
                eprintln!("Password cannot be empty.");
                std::process::exit(1);
            }
            let p2 = get_password("Confirm Config Password", MAX_PASS);
            if *p1 == *p2 {
                break p1;
            }
            println!("Passwords do not match. Try again.");
        };
        if passfile_create(PASS_FILE, &pass) {
            println!("Saved: {PASS_FILE} (0600, machine-bound)");
            return;
        }
        eprintln!("Failed to create {PASS_FILE}.");
        std::process::exit(1);
    }

    if fs::metadata(CONFIG_FILE).is_err() {
        eprintln!("No config file found. First run: ./ircbot -setup");
        std::process::exit(1);
    }

    // Password: the machine-bound pass file, else a prompt on stdin.
    let password = match passfile_load(PASS_FILE) {
        Some(p) => p,
        None => {
            let p = get_password("Config Password", MAX_PASS);
            if p.is_empty() {
                eprintln!("No password provided.");
                std::process::exit(1);
            }
            p
        }
    };

    println!("{BOT_NAME} {BOT_VERSION}");
    daemonize();

    let Some(pid_file) = lock_pid_file() else { std::process::exit(1) };
    let code = run(password, pid_file);
    std::process::exit(code);
}

/// Load the config and run the poll loop until `die` or a signal.
fn run(password: Zeroizing<String>, pid_file: fs::File) -> i32 {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("poll: {e}");
            let _ = fs::remove_file(PID_FILE);
            return 1;
        }
    };
    let registry = match poll.registry().try_clone() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("poll: {e}");
            let _ = fs::remove_file(PID_FILE);
            return 1;
        }
    };
    let mut state = BotState::new(registry);
    state.pid_file = Some(pid_file);
    if !state.hub_key_raw.is_locked() {
        eprintln!("Warning: mlock failed - secrets may reach swap.");
    }
    state.executable_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => {
            let _ = fs::remove_file(PID_FILE);
            return 1;
        }
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&shutdown));
    }

    if !config::load(&mut state, &password, CONFIG_FILE) {
        let _ = fs::remove_file(PID_FILE);
        return 1;
    }
    state.set_startup_pass(&password);
    drop(password);

    let mut events = Events::with_capacity(64);
    while state.status & S_DIE == 0 && !shutdown.load(Ordering::Relaxed) {
        irc_client::check_status(&mut state);
        channel::check_joins(&mut state);

        // Debounced flush of last_seen / last_used (set on every successful
        // admin auth): at most once per CONFIG_WRITE_DEBOUNCE_S, local only.
        let t = now();
        if state.config_dirty && t - state.last_config_write >= CONFIG_WRITE_DEBOUNCE_S {
            config::write_local_with_state_pass(&state);
            state.config_dirty = false;
            state.last_config_write = t;
        }

        dcc::check_timeouts(&mut state);
        if !state.hubs.is_empty() {
            hub_client::connect(&mut state);
            hub_client::heartbeat(&mut state);
        }

        match poll.poll(&mut events, Some(Duration::from_secs(1))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                logm!(state, L_INFO, "[INFO] poll failed: {}\n", e);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        }
        for ev in events.iter() {
            let token = ev.token();
            let readable = ev.is_readable() || ev.is_read_closed() || ev.is_error();
            let writable = ev.is_writable() || ev.is_write_closed() || ev.is_error();
            match net::slot_of(token) {
                net::SLOT_IRC => irc_client::handle_event(&mut state, token, readable, writable),
                net::SLOT_HUB => hub_client::handle_event(&mut state, token, readable, writable),
                s => dcc::handle_event(&mut state, s - net::SLOT_DCC0, token, readable, writable),
            }
        }
    }

    // Cleanup.  The pid file is unlinked while its flock is still held, then
    // released: a replacement that starts in between is refused.
    dcc::close_all(&mut state, "Bot shutting down.");
    config::write_with_state_pass(&mut state);
    irc_client::disconnect(&mut state);
    hub_client::disconnect(&mut state);
    let _ = fs::remove_file(PID_FILE);
    state.pid_file = None;
    0
}
