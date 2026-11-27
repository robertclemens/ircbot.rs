//! ircbot: an IRC bot that joins an encrypted hub mesh (safe-Rust port of
//! ircbot.c).  Entry point: process hardening, the setup wizard, the
//! machine-bound password file, daemonizing, and the poll loop.

#![forbid(unsafe_code)]

mod access;
mod auth;
mod bot_comms;
mod botflood;
// Shared byte for byte with irchub.rs: the hub half (diff) is unused here.
#[allow(dead_code)]
mod cfg_delta;
mod chancfg;
mod chancmd;
mod chanenf;
mod chanflood;
mod chanlive;
mod channel;
mod cli_fmt;
mod commands;
mod config;
mod consts;
mod crypto;
mod cstr;
mod dcc;
mod elf_needs;
mod glob_overlap;
mod hub_client;
mod irc_client;
mod irc_parser;
mod logging;
mod net;
mod pool;
mod pool_rec;
mod secret;
mod sendq;
mod state;
mod updater;

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mio::{Events, Poll};
use zeroize::Zeroizing;

use cli_fmt as cli;
use consts::*;
use cstr::{now, trunc_string};
use state::{
    BotState, ChanStatus, HubEntry, MaskRecord, S_DIE, UserRecord, is_rfc_nick, is_valid_bot_nick,
};

/// Keep secrets out of anything that lands on disk: no core dump (which
/// would carry the identity key and config password), no same-uid ptrace
/// attach.  RLIMIT_CORE 0 also survives the updater's exec.  Neither
/// defends against root.
fn harden_process() {
    // Private by default whatever the shell's umask (Ubuntu's is 002): the setup wizard,
    // pid, log and upgrade staging all inherit it.
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    let _ = nix::sys::prctl::set_dumpable(false);
}

// ---- Terminal input ----------------------------------------------------------------------

/// One line from stdin, without the line ending, cut to `len`-1 bytes.
fn read_line(len: usize) -> Zeroizing<String> {
    // Room up front: a read_line that has to grow the String frees the old
    // allocation unwiped, with the password in it (review 2026-10-25 L1).
    let mut line = Zeroizing::new(String::with_capacity(4096));
    if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        return Zeroizing::new(String::new());
    }
    let end = line.find(['\r', '\n']).unwrap_or(line.len());
    Zeroizing::new(trunc_string(&line[..end], len))
}

/// Read a password with terminal echo off (plain read when stdin is not a
/// terminal, e.g. `echo pass | ./ircbot`).
fn get_password(prompt: &str, len: usize) -> Zeroizing<String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
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
    Zeroizing::new(format!(
        "{}:{}:{}:{}:{}",
        ino,
        dev,
        uid.as_raw(),
        gid.as_raw(),
        cstr::trunc(&machine, 65)
    ))
}

fn passfile_create(path: &str, password: &str) -> bool {
    let mut salt = [0u8; SALT_SIZE];
    if !crypto::random_bytes(&mut salt) {
        eprintln!("RNG failure.");
        return false;
    }
    let ctx = passfile_context();
    let key = crypto::derive_config_key(ctx.as_bytes(), &salt, PBKDF2_ITERATIONS);
    drop(ctx);
    let Some(enc) = crypto::gcm_seal(key.as_ref(), &[], password.as_bytes()) else {
        eprintln!("Encryption failed.");
        return false;
    };
    // Written beside it and renamed over it, so a rewrite (-p) never leaves
    // a half-written pass file.
    let tmp = format!("{path}.tmp");
    let mut f = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("open: {e}");
            return false;
        }
    };
    if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
        eprintln!("fchmod: {e}");
        let _ = fs::remove_file(&tmp);
        return false;
    }
    // On disk: salt || iv || ct || tag -- the C bot's layout.
    let mut ok = f.write_all(&salt).is_ok() && f.write_all(&enc).is_ok();
    if !ok {
        eprintln!("write {PASS_FILE} failed");
    }
    drop(f);
    if ok {
        ok = match fs::rename(&tmp, path) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("rename {PASS_FILE}: {e}");
                false
            }
        };
    }
    if !ok {
        let _ = fs::remove_file(&tmp);
    }
    ok
}

/// The password from the machine-bound pass file.
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
    let key = crypto::derive_config_key(ctx.as_bytes(), &buf[..SALT_SIZE], PBKDF2_ITERATIONS);
    match crypto::gcm_open(key.as_ref(), &[], &buf[SALT_SIZE..]) {
        Some(p) if !p.is_empty() && p.len() < MAX_PASS => {
            Some(Zeroizing::new(String::from_utf8_lossy(&p).into_owned()))
        }
        _ => {
            eprintln!(
                "[WARN] {path}: decryption failed (wrong machine, tampered, or written before 2.5.0)."
            );
            None
        }
    }
}

// ---- Setup wizard ----------------------------------------------------------------------------

/// A user's public key for the wizard: pasted, or a path to .public.b64.
fn wizard_read_pubkey(who: &str) -> String {
    loop {
        let input = cli::ask("public key", 4096);
        if cli::eof() {
            cli::err("no public key given: setup stopped");
            std::process::exit(1);
        }
        if input.is_empty() {
            cli::err(&format!(
                "a public key is required: make one with 'utils/keygen {who}' and give its .public.b64"
            ));
            continue;
        }
        // A keygen private file has the same shape: refuse it by name.
        if input.contains(".private.") {
            cli::err("that is a PRIVATE key file: it stays with the admin; give the .public.b64");
            continue;
        }
        let (key, raw) = match crypto::pubkey_b64_decode(&input) {
            Some(raw) => (input.to_string(), raw),
            None => {
                let file = fs::read_to_string(input.as_str()).ok();
                let line = file
                    .as_deref()
                    .and_then(|s| s.lines().next())
                    .map(|l| {
                        l.split([' ', '\t', '\r', '\n'])
                            .next()
                            .unwrap_or("")
                            .to_string()
                    })
                    .unwrap_or_default();
                match crypto::pubkey_b64_decode(&line) {
                    Some(raw) if !line.is_empty() => (line, raw),
                    _ => {
                        cli::err(&format!(
                            "not an 88-char public key{} (the .public.b64, never the .private.b64)",
                            if file.is_some() { " in that file" } else { "" }
                        ));
                        continue;
                    }
                }
            }
        };
        cli::kv("fingerprint", &crypto::key_fingerprint(&raw));
        if cli::ask_yes("use this key?", true) {
            return key;
        }
    }
}

/// A hub's pinned key for a summary line: the fingerprint of an 88-char
/// combined key, or a 44-char Ed25519 key shortened.
fn wizard_hub_key_label(input: &str) -> String {
    match crypto::pubkey_b64_decode(input) {
        Some(raw) => format!("key {}", crypto::key_fingerprint(&raw)),
        None => format!("key {}", cli::short(input)),
    }
}

/// -setup: can the bot dial out from `vhost`?  An IPv4 or IPv6 literal
/// (what irc_client binds) of this host: a throwaway socket is bound to it
/// on port 0 and dropped.  Err gets the reason.
fn wizard_test_vhost(vhost: &str) -> Result<(), String> {
    let Ok(ip) = vhost.parse::<std::net::IpAddr>() else {
        return Err("not an IP address (a hostname is not accepted)".to_string());
    };
    match std::net::TcpListener::bind(std::net::SocketAddr::new(ip, 0)) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
            Err("not an address of this host".to_string())
        }
        Err(e) => {
            let t = e.to_string();
            Err(t.split(" (os error").next().unwrap_or(&t).to_string())
        }
    }
}

fn run_config_wizard() -> io::Result<()> {
    let poll = Poll::new()?;
    cli::header("ircbot", BOT_VERSION, "setup");
    cli::note(&format!(
        "No {CONFIG_FILE} here yet: these steps write one, encrypted with a config password."
    ));

    let (mut state, config_pass, server, chan, hub_managed, admin) = loop {
        let mut state = BotState::new(poll.registry().try_clone()?);
        let mut step = 0;
        let mut hub_keys: Vec<Zeroizing<String>> = Vec::new();

        step += 1;
        cli::step(step, "Config password");
        let config_pass = loop {
            let p = cli::ask_secret("password", MAX_PASS);
            let c = cli::ask_secret("confirm", MAX_PASS);
            if !p.is_empty() && *p == *c {
                cli::ok("the passwords match");
                break p;
            }
            cli::err("the passwords do not match, or are empty: again");
        };

        // Identity is generated here up front: the summary shows the exact
        // 'bot add' line for the hub console.  The private key never leaves
        // this machine.
        step += 1;
        cli::step(step, "Identity (generated here, Curve25519)");
        let Some((priv_key, pub_key)) = crypto::generate_combined_keypair() else {
            cli::err("could not generate the bot's keypair");
            return Ok(());
        };
        let Some(uuid) = crypto::gen_uuid_v4() else {
            cli::err("RAND_bytes failed");
            return Ok(());
        };
        state.bot_uuid = uuid;
        *state.hub_key = crypto::b64_encode(priv_key.as_ref());
        state.hub_key_raw.set(&priv_key);
        drop(priv_key);
        let id_fp = crypto::key_fingerprint(&pub_key);
        let pub_b64 = crypto::b64_encode(&pub_key);
        cli::kv("uuid", &state.bot_uuid);
        cli::kv("public key", &pub_b64);
        cli::kv("fingerprint", &id_fp);
        cli::note("The summary at the end has the 'bot add' line for the hub console.");

        step += 1;
        cli::step(step, "On IRC");
        loop {
            state.target_nick = cli::ask("nick", MAX_NICK).to_string();
            if is_rfc_nick(&state.target_nick) {
                state.current_nick = state.target_nick.clone();
                break;
            }
            if state.target_nick.contains('|') {
                cli::err("a nick cannot hold '|' (it delimits the records)");
            } else if !is_valid_bot_nick(&state.target_nick) {
                cli::err(&format!("a nick is 1-{} characters", MAX_NICK - 1));
            } else {
                cli::err(
                    "not an IRC nick: start with a letter or one of []\\`_^{}, then letters, digits, those or '-'",
                );
            }
        }
        state.user = cli::ask("ident", 64).to_string();
        state.gecos = cli::ask("real name", 128).to_string();
        // Optional: most bots dial out from the host's default address.
        cli::note(
            "A vhost is optional: a local IP address the bot dials IRC from (for a host with several).",
        );
        state.vhost.clear();
        if cli::ask_yes("do you have a vhost?", false) {
            loop {
                state.vhost = cli::ask("vhost ip (empty = none)", 128).to_string();
                if state.vhost.is_empty() || cli::eof() {
                    break;
                }
                match wizard_test_vhost(&state.vhost) {
                    Ok(()) => {
                        cli::ok(&format!("{} can be bound", state.vhost));
                        break;
                    }
                    Err(why) => {
                        cli::err(&format!("cannot use {}: {why}", state.vhost));
                        state.vhost.clear();
                    }
                }
            }
        }
        if state.vhost.is_empty() {
            cli::note("no vhost: the system's default address");
        }

        let mut server = String::new();

        // A hub-managed bot owns none of the hub-authoritative records, so
        // they are not asked for.
        step += 1;
        cli::step(step, "Management");
        cli::note(
            "hub-managed: admins, usermasks, channels and IRC servers live on the hub and are managed on its console; this bot needs only the hubs' addresses and keys.",
        );
        cli::note("standalone: this bot keeps its own IRC server, admin and channel.");
        let hub_managed = cli::ask_yes("hub-managed?", true);

        let mut chan = String::new();
        let mut admin: Option<(String, String, Vec<String>)> = None;
        if hub_managed {
            step += 1;
            cli::step(step, "Hubs");
            cli::note(
                "Each hub's address and public key: './irchub -id' on its host prints both (the '+hub' line), and so does 'hub show' on its console.",
            );
            while state.hubs.len() < MAX_HUBS {
                println!();
                let addr = loop {
                    let a = cli::ask(&format!("hub {}", state.hubs.len() + 1), 256);
                    let ok = a.rfind(':').is_some_and(|c| {
                        c > 0 && c + 1 < a.len() && (1..65536).contains(&cstr::atoi(&a[c + 1..]))
                    });
                    if ok {
                        break a.to_string();
                    }
                    cli::err("give host:port (e.g. 127.0.0.1:6000)");
                };
                if state.hubs.iter().any(|h| h.addr == addr) {
                    cli::err(&format!("{addr} is already in the list: skipped"));
                } else {
                    let (ed_pub, typed) = loop {
                        let k = cli::ask("public key", 256);
                        let k = k.trim_end_matches([' ', '\r', '\n', '\t']).to_string();
                        match crypto::b64_decode(&k) {
                            Some(d) if d.len() == HUB_KEY_RAW_LEN => {
                                // The Ed25519 half is what the handshake verifies.
                                let mut p = [0u8; 32];
                                p.copy_from_slice(&d[..32]);
                                break (p, k);
                            }
                            _ => cli::err(
                                "expected the hub's 88-char public key (./irchub -id or hub show)",
                            ),
                        }
                    };
                    state.hubs.push(HubEntry {
                        addr: addr.clone(),
                        ed_pub,
                        ed_pub_set: true,
                    });
                    hub_keys.push(Zeroizing::new(typed));
                    cli::ok(&format!("hub {}: {addr}", state.hubs.len()));
                }
                if state.hubs.len() >= MAX_HUBS {
                    cli::note(&format!("That is the most hubs a bot keeps ({MAX_HUBS})."));
                    break;
                }
                if !cli::ask_yes("another hub?", false) {
                    break;
                }
            }
            if state.hubs.is_empty() {
                cli::err("a hub-managed bot needs at least one hub: starting over");
                continue;
            }
        } else {
            step += 1;
            cli::step(step, "IRC server");
            server = loop {
                let s = cli::ask("server", MAX_BUFFER);
                if s.contains('.') && pool_rec::hostport_parse(&s).is_some() {
                    break s.to_string();
                }
                cli::err("give host or host:port (e.g. irc.efnet.org:6697)");
            };

            step += 1;
            cli::step(step, "First admin");
            let name = loop {
                let n = cli::ask("name", 64);
                if !n.is_empty() && !n.contains(' ') && !n.contains('|') {
                    break n.to_string();
                }
                cli::err("a name with no spaces or '|' (e.g. admin)");
            };
            cli::note(&format!(
                "The admin signs in with a Curve25519 key, not a password: on the admin's own machine run 'utils/keygen {name}' (or see 'help +admin' for an openssl recipe) and give its .public.b64 here.  The .private.b64 stays with the admin (chmod 600) for their IRC script."
            ));
            let pubkey = wizard_read_pubkey(&name);
            cli::note(
                "Usermasks the admin is known by (e.g. nick!*@*.example.com); an empty line ends the list, at least one.",
            );
            let mut masks: Vec<String> = Vec::new();
            while masks.len() < 20 {
                let m = cli::ask(&format!("usermask {}", masks.len() + 1), MAX_MASK_LEN);
                if cli::eof() {
                    break;
                }
                if m.is_empty() {
                    if masks.is_empty() {
                        cli::err("at least one usermask");
                        continue;
                    }
                    break;
                }
                if !m.contains('!') || !m.contains('@') {
                    cli::err("a usermask holds '!' and '@' (nick!user@host)");
                    continue;
                }
                masks.push(m.to_string());
            }

            step += 1;
            cli::step(step, "First channel");
            loop {
                chan = cli::ask("channel", MAX_CHAN).to_string();
                if chan.is_empty() {
                    cli::note("none: add channels later with 'join' from IRC");
                    break;
                }
                if chan.starts_with('#') && chan.len() > 1 {
                    break;
                }
                cli::err("a channel starts with '#' (or leave it empty)");
            }
            admin = Some((name, pubkey, masks));
        }

        // The summary: every answer, and what to paste on the other side.
        cli::summary("Summary");
        if hub_managed {
            cli::skv(
                "mode",
                &format!(
                    "hub-managed {} {} hub{}",
                    cli::g(cli::Glyph::Dot),
                    state.hubs.len(),
                    if state.hubs.len() == 1 { "" } else { "s" }
                ),
            );
        } else {
            cli::skv("mode", "standalone");
        }
        cli::skv("nick", &state.target_nick);
        cli::skv(
            "ident",
            if state.user.is_empty() {
                "(the nick)"
            } else {
                &state.user
            },
        );
        cli::skv(
            "real name",
            if state.gecos.is_empty() {
                "(none)"
            } else {
                &state.gecos
            },
        );
        cli::skv(
            "vhost",
            if state.vhost.is_empty() {
                "(none)"
            } else {
                &state.vhost
            },
        );
        if hub_managed {
            for (i, h) in state.hubs.iter().enumerate() {
                let label = wizard_hub_key_label(hub_keys.get(i).map_or("", |k| k.as_str()));
                cli::skv(
                    if i == 0 { "hubs" } else { "" },
                    &format!("{}  {label}", h.addr),
                );
            }
            cli::skv("irc servers", "from the hub's pool");
        } else if let Some((name, key, masks)) = &admin {
            cli::skv("irc server", &server);
            let fp = crypto::pubkey_b64_decode(key)
                .map(|r| crypto::key_fingerprint(&r))
                .unwrap_or_else(|| "?".to_string());
            cli::skv(
                "admin",
                &format!("{name} {} key {fp}", cli::g(cli::Glyph::Dot)),
            );
            for (i, m) in masks.iter().enumerate() {
                cli::skv(if i == 0 { "usermasks" } else { "" }, m);
            }
            cli::skv("channel", if chan.is_empty() { "(none)" } else { &chan });
        }
        cli::skv("uuid", &state.bot_uuid);
        cli::skv("key", &id_fp);
        if hub_managed {
            cli::skv("on the hub", "paste this on ONE hub's console:");
            print!(
                "\n   bot add {} {} {pub_b64}\n\n",
                state.target_nick, state.bot_uuid
            );
            cli::note("Once is enough: every linked hub learns the bot through the mesh.");
        } else {
            cli::skv("other bots", "trust this one with:");
            print!(
                "\n   +bot {}!{}@<host> {} {pub_b64}\n\n",
                state.target_nick,
                if state.user.is_empty() {
                    &state.target_nick
                } else {
                    &state.user
                },
                state.bot_uuid
            );
        }
        cli::rule();
        if !cli::ask_yes(&format!("write {CONFIG_FILE}?"), true) {
            cli::note("Starting over.");
            continue;
        }
        break (state, config_pass, server, chan, hub_managed, admin);
    };

    // Standalone only: the hub is authoritative for a|/m| records and would
    // replace them on the first sync.
    if !hub_managed && let Some((name, key, masks)) = admin {
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
            state.mask_records.push(MaskRecord {
                uuid: uuid.clone(),
                mask: m,
                is_active: true,
                last_used: 0,
                timestamp: t,
                act_pending: 0,
            });
        }
    }
    // Standalone: its one local server.  Hub-managed: none -- the hub's pool
    // arrives with the first sync (server pool plan §5.5a).
    if !hub_managed && !server.is_empty() {
        state.local_servers.push(server);
    }
    if !chan.is_empty()
        && let Some(ci) = channel::add(&mut state, &chan)
    {
        let c = &mut state.chans[ci];
        c.is_managed = true;
        c.timestamp = now();
        c.status = ChanStatus::Out;
    }

    config::write(&mut state, &config_pass);
    config::key_forget();
    println!();
    cli::ok(&format!("wrote {CONFIG_FILE}"));
    cli::kv("next", "./ircbot -p, then ./ircbot");
    cli::note(
        "-p writes a machine-bound password file, so the bot starts without typing the password; ./ircbot alone asks for it.",
    );
    if hub_managed {
        cli::note(
            "The bot joins IRC once its first hub sync brings the server pool: if the hub has no servers yet, add one on its console ('server add <host[:port]>').",
        );
    }
    println!();
    Ok(())
}

// ---- Daemon ------------------------------------------------------------------------------------

/// Detach: new session, stdio to /dev/null, umask 077.  The working
/// directory stays (config and log paths are relative).
fn daemonize() {
    if let Err(e) = nix::unistd::daemon(true, false) {
        eprintln!("daemon: {e}");
        std::process::exit(1);
    }
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
}

/// The pid file, flock'd: the lock is what marks this bot as running.
fn lock_pid_file() -> Option<fs::File> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PID_FILE)
        .ok()?;
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

/// Instance directory: .ircbot.cnf/.pass/.pid/.log/.upgrade all live beside the binary, so the bot behaves the same
/// whatever the caller's cwd -- cron starts jobs in $HOME.  One binary per bot.  Our own
/// path comes from /proc/self/exe (`current_exe`; argv[0] has no directory when launched
/// through PATH); returns it after chdir()ing to its directory.  That directory holds the
/// binary an upgrade replaces, its .prev and the upgrade script, so refuse one another user
/// owns and chmod go-w one group/other can write -- they could swap any of them.  Mirrors
/// `instance_dir_enter()` in ircbot/main.c.
fn instance_dir_enter() -> Option<String> {
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("Cannot resolve my own path (/proc/self/exe)");
        return None;
    };
    let Some(dir) = exe.parent() else {
        eprintln!("Cannot resolve my own directory from {}", exe.display());
        return None;
    };
    let md = match fs::metadata(dir) {
        Ok(md) if md.is_dir() => md,
        _ => {
            eprintln!("Cannot stat my own directory {}", dir.display());
            return None;
        }
    };
    if md.uid() != nix::unistd::geteuid().as_raw() {
        eprintln!(
            "Refusing to run from {}: it must be owned by this user",
            dir.display()
        );
        return None;
    }
    // Group/other write (a 002 umask makes 0775 directories): we own it, so close the hole
    // rather than refuse -- refusing turned every upgrade on such a host into a watchdog
    // rollback and a fresh install into a dead start.  Nothing is weakened: the directory
    // was open before we ran.
    if md.mode() & 0o022 != 0 {
        let m = md.mode() & 0o7777 & !0o022;
        if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(m)) {
            eprintln!(
                "Refusing to run from {}: group/other can write it and chmod go-w failed ({e})",
                dir.display()
            );
            return None;
        }
        eprintln!(
            "Removed group/other write from {} (now {m:04o})",
            dir.display()
        );
    }
    if std::env::set_current_dir(dir).is_err() {
        eprintln!("Cannot change to my own directory {}", dir.display());
        return None;
    }
    Some(exe.to_string_lossy().into_owned())
}

fn main() {
    harden_process();
    logging::install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    // -checkupdate [variant]: verify the release channel and exit; needs no
    // config, no password and no PID lock.
    if let Some(i) = args.iter().skip(1).position(|a| a == "-checkupdate") {
        std::process::exit(updater::check_cli(args.get(i + 2).map(String::as_str)));
    }
    // -selftest: could this build run here?  Loads the config exactly as a
    // start would, then exits — no daemon, no PID lock, no network.  A hub-
    // driven upgrade runs the staged new build with it before swapping.
    if args.iter().skip(1).any(|a| a == "-selftest") {
        std::process::exit(selftest());
    }
    // -selftest (above) stays in the caller's directory: the updater runs a
    // staged build from a scratch subdirectory, against this bot's config.
    let Some(self_exe) = instance_dir_enter() else {
        std::process::exit(1)
    };
    let do_setup = args.iter().skip(1).any(|a| a == "-setup");
    let do_passfile = args.iter().skip(1).any(|a| a == "-p");
    let do_identity = args.iter().skip(1).any(|a| a == "-id");

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
        cli::header("ircbot", BOT_VERSION, "password file");
        cli::note(&format!(
            "{PASS_FILE} holds the config password, bound to this machine, so the bot starts without typing it."
        ));
        println!();
        let pass = loop {
            let p1 = cli::ask_secret("password", MAX_PASS);
            if p1.is_empty() {
                cli::err("the password cannot be empty");
                std::process::exit(1);
            }
            let p2 = cli::ask_secret("confirm", MAX_PASS);
            if *p1 == *p2 {
                break p1;
            }
            cli::err("the passwords do not match: again");
        };
        if passfile_create(PASS_FILE, &pass) {
            cli::ok(&format!("wrote {PASS_FILE} (0600, bound to this machine)"));
            cli::kv("next", "./ircbot");
            println!();
            return;
        }
        cli::err(&format!("could not write {PASS_FILE}"));
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

    if do_identity {
        std::process::exit(identity(password));
    }

    println!("{BOT_NAME} {BOT_VERSION}");
    if updater::install_in_progress() {
        eprintln!("An upgrade is installing here; not starting");
        return;
    }
    updater::stage_boot_clean();
    daemonize();

    let Some(pid_file) = lock_pid_file() else {
        std::process::exit(1)
    };
    let code = run(password, pid_file, self_exe);
    config::key_forget();
    std::process::exit(code);
}

/// `ircbot -selftest`: prints `selftest: OK ircbot <version> <variant>` and
/// returns 0, or `selftest: FAIL <reason>` and 1.  Never writes the config
/// (config::READ_ONLY): the running build still owns it.
fn selftest() -> i32 {
    let fail = |why: &str| {
        println!("selftest: FAIL {why}");
        1
    };
    if let Some(why) = updater::tls_unusable_reason() {
        return fail(&why);
    }
    // The swap happens in this directory: one another user owns is refused at start (a
    // group/other-writable one we own is tightened there).
    if !fs::metadata(".").is_ok_and(|m| m.uid() == nix::unistd::geteuid().as_raw()) {
        return fail("this directory is not owned by this user");
    }
    if fs::metadata(CONFIG_FILE).is_err() {
        return fail(&format!("no {CONFIG_FILE}"));
    }
    // 2.5.1 reads only the 600k key; a pass file 2.5.0 never got to rewrite
    // is refused here so the upgrade reports it instead of leaving a bot that
    // cannot start.
    let Some(password) = passfile_load(PASS_FILE) else {
        return fail(&format!(
            "cannot read {PASS_FILE} (written before 2.5.0? restart once on 2.5.0, or rewrite it with -p)"
        ));
    };
    let registry = match Poll::new().and_then(|p| p.registry().try_clone()) {
        Ok(r) => r,
        Err(e) => return fail(&format!("poll: {e}")),
    };
    let mut state = BotState::new(registry);
    config::READ_ONLY.store(true, Ordering::Relaxed);
    if !config::load(&mut state, &password, CONFIG_FILE) {
        return fail("the config did not load (see the log)");
    }
    println!(
        "selftest: OK ircbot {BOT_VERSION} {}",
        updater::host_variant()
    );
    0
}

/// `ircbot -id`: print this bot's uuid, public key and fingerprint — what the
/// hub console's `bot add` (or a standalone peer's +bot) needs — from the
/// config, and exit.  Read-only: no daemon, no PID lock, no config rewrite.
fn identity(password: Zeroizing<String>) -> i32 {
    let registry = match Poll::new().and_then(|p| p.registry().try_clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("poll: {e}");
            return 1;
        }
    };
    let mut state = BotState::new(registry);
    config::READ_ONLY.store(true, Ordering::Relaxed);
    if !config::load(&mut state, &password, CONFIG_FILE) {
        eprintln!("Cannot load {CONFIG_FILE} (wrong password?).");
        return 1;
    }
    drop(password);
    if !state.self_pub_set || state.bot_uuid.is_empty() {
        eprintln!("{CONFIG_FILE} has no identity key or uuid; re-run -setup.");
        return 1;
    }
    let pub_b64 = crypto::b64_encode(&state.self_pub);
    cli::header("ircbot", BOT_VERSION, "identity");
    println!();
    cli::skv("nick", &state.target_nick);
    cli::skv("uuid", &state.bot_uuid);
    cli::skv("public key", &pub_b64);
    cli::skv("fingerprint", &crypto::key_fingerprint(&state.self_pub));
    cli::skv("on the hub", "paste this on ONE hub's console:");
    print!(
        "\n   bot add {} {} {pub_b64}\n\n",
        state.target_nick, state.bot_uuid
    );
    cli::note("Once is enough: every linked hub learns the bot through the mesh.");
    cli::rule();
    0
}

/// Load the config and run the poll loop until `die` or a signal.
fn run(password: Zeroizing<String>, pid_file: fs::File, self_exe: String) -> i32 {
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
    state.executable_path = self_exe;

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
        commands::activity_tick(&mut state, now());
        chanenf::tick(&mut state);

        // Debounced flush of last_seen / last_used (set on every successful
        // admin auth): at most once per CONFIG_WRITE_DEBOUNCE_S, local only.
        // The times reach the hub as CMD_ACTIVITY instead, once per record per
        // clock hour (auth::mark_used).
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
            hub_client::user_chan_tick(&mut state); // unanswered person requests -> ~B2
            channel::own_tick(&mut state); // our own unanswered requests -> ~B2
            channel::invite_check_tick(&mut state); // invites whose WHO never came back
        }
        hub_client::upgrade_ready_tick(&mut state);
        let exe = state.executable_path.clone();
        if updater::cron_tick(&exe) {
            hub_client::send_presence(&mut state, true);
        }
        updater::standalone_tick(&mut state);
        hub_client::stage_tick(&mut state);

        // Lines wait in the send queue and pacing will allow one: wake as soon
        // as it may go.  Otherwise the 1 s timeout is the tick.
        let mut timeout = Duration::from_secs(1);
        if state.irc.is_some() {
            let wait_ms = sendq::next_ms(&mut state);
            if (0..1000).contains(&wait_ms) {
                timeout = Duration::from_millis(wait_ms as u64);
            }
        }
        match poll.poll(&mut events, Some(timeout)) {
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

        // Paced output: whatever the queue may send now.  The poll timeout
        // above is sized to the next credit, so lines leave on time.
        if state.irc.is_some() {
            sendq::drain(&mut state);
        }
    }

    // Cleanup.  The pid file is unlinked while its flock is still held, then
    // released: a replacement that starts in between is refused.
    updater::stage_kill_build(); // a stage's build does not outlive the daemon
    dcc::close_all(&mut state, "Bot shutting down.");
    config::write_with_state_pass(&mut state);
    irc_client::disconnect(&mut state);
    hub_client::disconnect(&mut state);
    let _ = fs::remove_file(PID_FILE);
    state.pid_file = None;
    0
}
