//! The encrypted config file and the record codecs shared with the hub
//! (config.c).
//!
//! On disk: salt(16) || iv(12) || tag(16) || AES-256-GCM(ciphertext) under
//! PBKDF2-HMAC-SHA256(password, salt).  The plaintext is one record per
//! line, `X|fields...`, the same shapes irchub sends in CMD_CONFIG_DATA.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use zeroize::Zeroizing;

use crate::consts::*;
use crate::crypto;
use crate::cstr::{atoll, has_uuid_dashes, is_uuid, now, split_fields, strtoll, trunc, trunc_string, Scan};
use crate::state::{BotState, ChanStatus, HubEntry, MaskRecord, TrustedBot, UserLine, UserRecord};
use crate::{channel, hub_client, logm};

/// A key-shaped field: Some(b64) only if it is exactly a valid key.
fn field_pubkey(f: &str) -> Option<String> {
    if f.len() != COMBINED_KEY_B64 {
        return None;
    }
    crypto::pubkey_b64_decode(f).map(|_| f.to_string())
}

/// a|/o| body codec (irchub/docs/passwordless.md 3.1):
///   new     uuid|name|pubkey|add/del|last_seen|ts|<reserved, empty>
///   legacy  uuid|name|password|add/del|last_seen|ts[|pubkey]
/// Field 3 decides: a valid key there means the new format; anything else is
/// a legacy password, never copied anywhere, and the key (if any) is field 7.
pub fn parse_user_line(data: &str) -> Option<UserLine> {
    let f = split_fields(data, 8);
    if f.len() < 6 || !is_uuid(f[0]) {
        return None;
    }
    if f[1].is_empty() || f[1].len() >= USER_NAME_BUF {
        return None;
    }
    let mut out = UserLine {
        uuid: f[0].to_string(),
        name: f[1].to_string(),
        ..UserLine::default()
    };
    if let Some(k) = field_pubkey(f[2]) {
        out.pubkey_b64 = k;
        out.has_pubkey = true;
    } else {
        out.legacy = true;
        if let Some(k) = f.get(6).and_then(|x| field_pubkey(x)) {
            out.pubkey_b64 = k;
            out.has_pubkey = true;
        }
    }
    out.is_active = f[3] == "add";
    out.last_seen = atoll(f[4]);
    out.timestamp = atoll(f[5]);
    Some(out)
}

/// One user record as a full "a|...\n" / "o|...\n" line.
pub fn format_user_line(u: &UserRecord) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|\n",
        u.typ,
        u.uuid,
        u.name,
        if u.has_pubkey { u.pubkey_b64.as_str() } else { "" },
        if u.is_active { "add" } else { "del" },
        u.last_seen,
        u.timestamp
    )
}

/// b| body codec (passwordless.md 3.2):
///   new     mask|uuid|pubkey|ts       (pubkey may be empty)
///   legacy  mask|uuid|ts
///   bare    mask                       (hand-typed; no uuid, no key)
/// Oversized fields are refused rather than truncated.
pub fn parse_bot_line(data: &str) -> Option<TrustedBot> {
    let f = split_fields(data, 5);
    if f[0].is_empty() || f[0].len() >= MAX_MASK_LEN {
        return None;
    }
    let mut out = TrustedBot { mask: f[0].to_string(), ..TrustedBot::default() };
    if f.len() == 1 {
        return Some(out);
    }
    if f[1].len() >= UUID_BUF {
        return None;
    }
    out.uuid = f[1].to_string();
    if f.len() == 2 {
        return Some(out);
    }
    if f.len() == 3 {
        out.ts = atoll(f[2]);
        return Some(out);
    }
    if !f[2].is_empty()
        && let Some(k) = field_pubkey(f[2]).and_then(|b| crypto::pubkey_b64_decode(&b)) {
        out.pub_key = k;
        out.has_pub = true;
    }
    out.ts = atoll(f[3]);
    Some(out)
}

/// One trusted bot as a full "b|...\n" line (new format).
pub fn format_bot_line(tb: &TrustedBot) -> String {
    let pb = if tb.has_pub { crypto::b64_encode(&tb.pub_key) } else { String::new() };
    format!("b|{}|{}|{}|{}\n", tb.mask, tb.uuid, pb, tb.ts)
}

/// "m|uuid|mask|add/del|last_used|ts\n".
pub fn format_mask_line(m: &MaskRecord) -> String {
    format!(
        "m|{}|{}|{}|{}|{}\n",
        m.uuid,
        m.mask,
        if m.is_active { "add" } else { "del" },
        m.last_used,
        m.timestamp
    )
}

/// Keep only [a-zA-Z0-9] of an opt-flag string, at most MAX_OPT_FLAGS.
pub fn clean_opt_flags(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric()).take(MAX_OPT_FLAGS).collect()
}

/// Parse "O|<flags>|<ts>" data (also the hub's form).  "O||<ts>" is a
/// persisted clear.  None when sscanf would have matched nothing.
pub fn parse_opt_line(data: &str) -> Option<(String, i64)> {
    if let Some(rest) = data.strip_prefix('|') {
        let (v, used) = strtoll(rest);
        return (used > 0).then(|| (String::new(), v));
    }
    let mut sc = Scan::new(data);
    let flags = sc.set_not(MAX_OPT_FLAGS, b"|")?;
    let ts = if sc.lit(b'|') { sc.int().unwrap_or(0) } else { 0 };
    Some((clean_opt_flags(flags), ts))
}

/// Parse a c| body from the config: channel|key|add/del|timestamp, or
/// channel||add/del|timestamp.  Returns (chan, key, op, ts) when at least
/// the channel and op matched (sscanf count >= 2 on either form).
fn parse_cfg_chan(data: &str) -> Option<(String, String, String, i64)> {
    let mut chan = String::new();
    let mut key = String::new();
    let mut op = String::new();
    let mut ts = 0i64;
    let mut parsed = 0;
    {
        let mut sc = Scan::new(data);
        if let Some(c) = sc.set_not(64, b"|") {
            chan = c.to_string();
            parsed = 1;
            if sc.lit(b'|')
                && let Some(k) = sc.set_not(30, b"|") {
                key = k.to_string();
                parsed = 2;
                if sc.lit(b'|')
                    && let Some(o) = sc.set_not(15, b"|") {
                    op = o.to_string();
                    parsed = 3;
                    if sc.lit(b'|')
                        && let Some(t) = sc.int() {
                        ts = t;
                        parsed = 4;
                    }
                }
            }
        }
    }
    if parsed < 3 {
        // Fallback for an empty key.
        key.clear();
        parsed = 0;
        let mut sc = Scan::new(data);
        if let Some(c) = sc.set_not(64, b"|") {
            chan = c.to_string();
            parsed = 1;
            if sc.lit(b'|') && sc.lit(b'|')
                && let Some(o) = sc.set_not(15, b"|") {
                op = o.to_string();
                parsed = 2;
                if sc.lit(b'|')
                    && let Some(t) = sc.int() {
                    ts = t;
                    parsed = 3;
                }
            }
        }
    }
    (parsed >= 2).then_some((chan, key, op, ts))
}

/// Read and decrypt the config file; returns the plaintext and whether the
/// legacy (pre-PBKDF2) key had to be used.
fn decrypt_file(state: &BotState, password: &str, filename: &str) -> Option<(Zeroizing<Vec<u8>>, bool)> {
    let mut f = fs::File::open(filename).ok()?;
    let mut data = Vec::new();
    if f.read_to_end(&mut data).is_err() {
        logm!(state, L_INFO, "[CFG] Error: Could not read the full contents of the config file.\n");
        return None;
    }
    if data.len() < SALT_SIZE {
        logm!(state, L_INFO, "[CFG] Failed to read Salt from config.\n");
        return None;
    }
    if data.len() < SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN {
        logm!(state, L_INFO, "[CFG] Failed to read IV/Tag from config.\n");
        return None;
    }
    let salt = &data[..SALT_SIZE];
    let iv = &data[SALT_SIZE..SALT_SIZE + GCM_IV_LEN];
    let tag = &data[SALT_SIZE + GCM_IV_LEN..SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN];
    let ct = &data[SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN..];
    if ct.is_empty() || ct.len() > MAX_CONFIG_SIZE {
        logm!(state, L_INFO, "[CFG] Error: Config file is empty or too large (Max 1MB).\n");
        return None;
    }
    let key = crypto::derive_config_key(password.as_bytes(), salt);
    if let Some(pt) = crypto::gcm_decrypt_detached(key.as_ref(), iv, &[], ct, tag) {
        return Some((pt, false));
    }
    // Configs written before the PBKDF2 upgrade: migrate once.
    let legacy = crypto::legacy_config_key(password.as_bytes(), salt);
    if let Some(pt) = crypto::gcm_decrypt_detached(legacy.as_ref(), iv, &[], ct, tag) {
        return Some((pt, true));
    }
    logm!(state, L_INFO, "[CFG] Decryption failed (wrong password?).\n");
    None
}

/// config_load(): false when the file is missing, does not decrypt, or lacks
/// a nick, server or ident.
pub fn load(state: &mut BotState, password: &str, filename: &str) -> bool {
    if let Ok(md) = fs::metadata(filename) {
        let mode = md.permissions().mode();
        if mode & 0o177 != 0 {
            logm!(state, L_INFO, "[CFG] WARN: {} has insecure permissions {:04o} — should be 0600\n", filename, mode & 0o777);
        }
    }
    let Some((plaintext, migrated_from_legacy)) = decrypt_file(state, password, filename) else {
        return false;
    };
    let text = Zeroizing::new(String::from_utf8_lossy(&plaintext).into_owned());
    drop(plaintext);

    let mut legacy_user_lines = 0;
    let mut dropped_botpass = false;
    // MIGRATE sentinel records carry the old oper mask in `name` until the
    // migration pass below.
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let line = crate::cstr::until_nul(line);
        if line.len() < 2 || line.starts_with('#') || line.as_bytes()[1] != b'|' {
            continue;
        }
        let typ = line.as_bytes()[0];
        let data = &line[2..];
        match typ {
            b'n' => state.target_nick = trunc_string(data, MAX_NICK),
            b's' => {
                if state.server_list.len() < MAX_SERVERS {
                    state.server_list.push(data.to_string());
                }
            }
            b'c' => {
                if let Some((chan, key, op, ts)) = parse_cfg_chan(data)
                    && let Some(ci) = channel::add(state, &chan) {
                    let c = &mut state.chans[ci];
                    if !key.is_empty() {
                        c.key = trunc_string(&key, MAX_KEY);
                    }
                    c.is_managed = op != "del";
                    c.timestamp = if ts > 0 { ts } else { now() };
                    if !c.is_managed {
                        c.status = ChanStatus::Out;
                    }
                }
            }
            b'm' => load_mask_line(state, data),
            b'a' | b'o' => {
                if state.user_records.len() >= MAX_USER_RECORDS {
                    continue;
                }
                let f = split_fields(data, 5);
                if is_uuid(f[0]) {
                    let Some(ul) = parse_user_line(data) else {
                        logm!(state, L_INFO, "[CFG] Malformed {}| record ignored.\n", typ as char);
                        continue;
                    };
                    if ul.legacy {
                        legacy_user_lines += 1;
                    }
                    state.user_records.push(UserRecord {
                        uuid: ul.uuid,
                        name: ul.name,
                        pubkey_b64: ul.pubkey_b64,
                        has_pubkey: ul.has_pubkey,
                        typ: typ as char,
                        is_active: ul.is_active,
                        last_seen: ul.last_seen,
                        timestamp: ul.timestamp,
                        last_auth_reply: 0,
                    });
                } else {
                    // Pre-UUID shapes, tagged for migration; their password is
                    // never copied:  a|<password>|<ts>
                    //                o|<mask>|<password>|<add/del>|<ts>
                    let mut u = UserRecord { typ: typ as char, ..UserRecord::default() };
                    if typ == b'a' {
                        u.uuid = "MIGRATE".into();
                        let ts = f.get(1).map_or(0, |x| atoll(x));
                        u.is_active = true;
                        u.timestamp = if ts > 0 { ts } else { now() };
                    } else {
                        if f.len() < 3 || f[0].is_empty() || f[0].len() >= MAX_MASK_LEN {
                            continue;
                        }
                        u.uuid = "MIGRATE_O".into();
                        u.name = f[0].to_string(); // the old mask, full length
                        u.is_active = f[2] != "del";
                        let ts = f.get(3).map_or(0, |x| atoll(x));
                        u.timestamp = if ts > 0 { ts } else { now() };
                    }
                    state.user_records.push(u);
                    legacy_user_lines += 1;
                }
            }
            // Retired shared bot password (p|<pass>|<ts>): dropped.
            b'p' => dropped_botpass = true,
            b'b' => {
                if state.trusted_bots.len() < MAX_TRUSTED_BOTS {
                    match parse_bot_line(data) {
                        Some(tb) => state.trusted_bots.push(tb),
                        None => logm!(state, L_INFO, "[CFG] Malformed or oversized b| line ignored.\n"),
                    }
                }
            }
            b'l' => state.log.level = crate::cstr::atoi(data) as u32,
            b'u' => state.user = trunc_string(data, 64),
            b'g' => state.gecos = trunc_string(data, 128),
            b'v' => state.vhost = trunc_string(data, 128),
            b'h' => load_hub_line(state, data),
            b'k' => match crypto::b64_decode(data) {
                Some(dec) if dec.len() == HUB_KEY_RAW_LEN => {
                    *state.hub_key = trunc_string(data, MAX_HUB_KEY_SIZE);
                    let mut raw = [0u8; HUB_KEY_RAW_LEN];
                    raw.copy_from_slice(&dec);
                    state.hub_key_raw.set(&raw);
                    crypto::wipe(&mut raw);
                }
                _ => logm!(
                    state,
                    L_INFO,
                    "[CFG] Bot key in config is not a valid 64-byte Curve25519 key (legacy RSA?). Re-run 'ircbot -setup' to regenerate the bot's identity.\n"
                ),
            },
            b'j' => match crypto::b64_decode(data) {
                // Legacy single global hub pubkey; migrated into h| below.
                Some(dec) if dec.len() == 32 => {
                    state.hub_remote_ed_pub.copy_from_slice(&dec);
                    state.hub_remote_ed_pub_set = true;
                }
                _ => logm!(
                    state,
                    L_INFO,
                    "[CFG] Legacy 'j|' hub pubkey is not 32 raw bytes — ignored. Pin per-hub keys with '+hub <host:port> <pubkey>'.\n"
                ),
            },
            b'i' => state.bot_uuid = trunc_string(data, 64),
            b'D' => state.admin_delta_pending = data == "1",
            b'O' => {
                if let Some((flags, ts)) = parse_opt_line(data) {
                    state.opt_flags = flags;
                    state.opt_flags_ts = if ts > 0 { ts } else { now() };
                }
            }
            _ => {}
        }
    }
    drop(text);

    // A legacy j| key applies to every hub without its own pin.
    if state.hub_remote_ed_pub_set {
        let k = state.hub_remote_ed_pub;
        for h in state.hubs.iter_mut().filter(|h| !h.ed_pub_set) {
            h.ed_pub = k;
            h.ed_pub_set = true;
        }
    }

    let needs_migration = state.user_records.iter().any(|u| u.uuid.starts_with("MIGRATE"))
        || state.mask_records.iter().any(|m| m.uuid == "MIGRATE");
    if needs_migration {
        migrate_legacy_records(state);
    }
    if migrated_from_legacy {
        logm!(state, L_INFO, "[CFG] Config re-encrypted with PBKDF2 (legacy migration).\n");
    }

    // Identity key: a standalone config from before bots had keys gets one
    // minted here.  A hub-managed bot without one must re-run -setup.
    let mut identity_minted = false;
    if state.hub_key.is_empty() && state.hubs.is_empty() {
        match crypto::generate_combined_keypair() {
            Some((priv_key, _)) => {
                *state.hub_key = crypto::b64_encode(priv_key.as_ref());
                state.hub_key_raw.set(&priv_key);
                identity_minted = true;
            }
            None => logm!(state, L_INFO, "[CFG] Could not generate an identity key.\n"),
        }
    }
    if state.bot_uuid.is_empty() && state.hubs.is_empty()
        && let Some(u) = crypto::gen_uuid_v4() {
        state.bot_uuid = u;
        identity_minted = true;
    }
    if !hub_client::self_pub_refresh(state) {
        logm!(
            state,
            L_INFO,
            "[CFG] No usable identity key (k|): admin commands and bot-to-bot messages cannot be decrypted. Re-run -setup.\n"
        );
    } else if identity_minted {
let fp = crypto::key_fingerprint(&state.self_pub);
eprintln!(
    "[CFG] Generated this bot's identity key. Public key: {} (fp {})",
            crypto::b64_encode(&state.self_pub),
            fp
        );
        logm!(state, L_INFO, "[CFG] Generated identity key, fp {}\n", fp);
    }

    for i in 0..state.user_records.len() {
        let u = &state.user_records[i];
        if u.is_active && !u.has_pubkey {
            logm!(
                state,
                L_INFO,
                "[CFG] {} '{}' has no public key and cannot authenticate until given one (chkey, or hub_admin 'Change user public key').\n",
                if u.typ == 'a' { "Admin" } else { "Oper" },
                u.name
            );
        }
    }
    if legacy_user_lines > 0 {
        logm!(state, L_INFO, "[CFG] Migrated {} password-era user record(s); passwords dropped.\n", legacy_user_lines);
    }
    if dropped_botpass {
        logm!(state, L_INFO, "[CFG] Dropped the retired bot password (p|); bots use public keys now.\n");
    }

    // Rewrite once if anything above changed the on-disk shape.
    if needs_migration || migrated_from_legacy || legacy_user_lines > 0 || dropped_botpass || identity_minted {
        write(state, password);
    }

    if state.target_nick.is_empty() || state.server_list.is_empty() || state.user.is_empty() {
        logm!(state, L_INFO, "[CFG] Config file is missing required fields (Nick, Server, or Ident).\n");
        return false;
    }
    true
}

/// m| line: new uuid|mask|add/del|last_used|ts, or old mask|add/del|ts
/// (tagged MIGRATE).
fn load_mask_line(state: &mut BotState, data: &str) {
    if state.mask_records.len() >= MAX_USER_MASKS {
        return;
    }
    let first = data.find('|').map(|p| &data[..p]).filter(|f| f.len() < 40).unwrap_or("");
    if has_uuid_dashes(first) {
        let f: Vec<&str> = data.splitn(5, '|').collect();
        if f.len() == 5 {
            state.mask_records.push(MaskRecord {
                uuid: trunc_string(f[0], UUID_BUF),
                mask: trunc_string(f[1], MAX_MASK_LEN),
                is_active: f[2].starts_with("add"),
                last_used: atoll(f[3]),
                timestamp: atoll(f[4]),
            });
        }
    } else {
        let mut sc = Scan::new(data);
        let Some(mask) = sc.set_not(255, b"|") else { return };
        if !sc.lit(b'|') {
            return;
        }
        let Some(op) = sc.set_not(15, b"|") else { return };
        let ts = if sc.lit(b'|') { sc.int().unwrap_or(0) } else { 0 };
        state.mask_records.push(MaskRecord {
            uuid: "MIGRATE".into(),
            mask: mask.to_string(),
            is_active: op != "del",
            last_used: 0,
            timestamp: if ts > 0 { ts } else { now() },
        });
    }
}

/// h|<host:port>[|<pubkey_b64>]: the pin is the hub's Ed25519 key, 44-char
/// (32 raw bytes) or 88-char (combined key; first 32 bytes).
fn load_hub_line(state: &mut BotState, data: &str) {
    if state.hubs.len() >= MAX_SERVERS {
        return;
    }
    let mut he = HubEntry::default();
    match data.find('|') {
        Some(bar) => {
            he.addr = trunc_string(&data[..bar], 256);
            match crypto::b64_decode(&data[bar + 1..]) {
                Some(dec) if dec.len() == 32 || dec.len() == HUB_KEY_RAW_LEN => {
                    he.ed_pub.copy_from_slice(&dec[..32]);
                    he.ed_pub_set = true;
                }
                _ => logm!(
                    state,
                    L_INFO,
                    "[CFG] Hub '{}' pubkey is not a valid Ed25519/Curve25519 key — re-add with '+hub {} <pubkey>'.\n",
                    he.addr,
                    he.addr
                ),
            }
        }
        None => he.addr = trunc_string(data, 256),
    }
    state.hubs.push(he);
}

/// Convert MIGRATE sentinel records (pre-UUID admin and oper lines) into
/// UUID-keyed user and mask records.
fn migrate_legacy_records(state: &mut BotState) {
    let now = now();
    let admin_uuid = crypto::gen_uuid_v4().unwrap_or_default();
    let mut new_users: Vec<UserRecord> = Vec::new();
    let mut new_masks: Vec<MaskRecord> = Vec::new();

    if let Some(u) = state.user_records.iter().find(|u| u.uuid == "MIGRATE" && u.typ == 'a') {
        new_users.push(UserRecord {
            uuid: admin_uuid.clone(),
            name: "admin".into(),
            typ: 'a',
            is_active: true,
            timestamp: if u.timestamp != 0 { u.timestamp } else { now },
            ..UserRecord::default()
        });
    }
    for m in state.mask_records.iter().filter(|m| m.uuid == "MIGRATE") {
        if new_masks.len() >= MAX_USER_MASKS {
            break;
        }
        new_masks.push(MaskRecord {
            uuid: admin_uuid.clone(),
            mask: m.mask.clone(),
            is_active: m.is_active,
            last_used: 0,
            timestamp: m.timestamp,
        });
    }
    for (i, u) in state.user_records.iter().enumerate() {
        if u.uuid != "MIGRATE_O" || new_users.len() >= MAX_USER_RECORDS {
            continue;
        }
        let ouuid = crypto::gen_uuid_v4().unwrap_or_default();
        // Name from the nick part of the old mask (held in `name`).
        let derived = match u.name.find('!') {
            Some(b) => trunc_string(&u.name[..b], USER_NAME_BUF),
            None => format!("oper{i}"),
        };
        let mut try_name = derived.clone();
        let mut suffix = 2;
        while new_users.iter().any(|n| n.name == try_name) {
            // Room for "_<suffix>" so a long name cannot push it out.
            try_name = format!("{}_{}", trunc(&derived, USER_NAME_BUF - 11), suffix);
            suffix += 1;
        }
        let ts = if u.timestamp != 0 { u.timestamp } else { now };
        new_users.push(UserRecord {
            uuid: ouuid.clone(),
            name: try_name,
            typ: 'o',
            is_active: u.is_active,
            timestamp: ts,
            ..UserRecord::default()
        });
        if new_masks.len() < MAX_USER_MASKS {
            new_masks.push(MaskRecord {
                uuid: ouuid,
                mask: trunc_string(&u.name, MAX_MASK_LEN),
                is_active: u.is_active,
                last_used: 0,
                timestamp: ts,
            });
        }
    }
    for u in state.user_records.iter().filter(|u| !u.uuid.starts_with("MIGRATE")) {
        if new_users.len() >= MAX_USER_RECORDS {
            break;
        }
        new_users.push(u.clone());
    }
    for m in state.mask_records.iter().filter(|m| m.uuid != "MIGRATE") {
        if new_masks.len() >= MAX_USER_MASKS {
            break;
        }
        new_masks.push(m.clone());
    }
    state.user_records = new_users;
    state.mask_records = new_masks;
}

/// Serialize the state.  None if the result would exceed MAX_CONFIG_SIZE
/// (a truncated write would silently drop records).
fn serialize(state: &BotState) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(4096));
    let mut push = |s: &str| out.push_str(s);
    push(&format!("n|{}\n", state.target_nick));
    for s in &state.server_list {
        push(&format!("s|{s}\n"));
    }
    for c in &state.chans {
        push(&format!("c|{}|{}|{}|{}\n", c.name, c.key, if c.is_managed { "add" } else { "del" }, c.timestamp));
    }
    for u in &state.user_records {
        let l = format_user_line(u);
        if l.len() >= CFG_USER_LINE_MAX {
            return None;
        }
        push(&l);
    }
    for m in &state.mask_records {
        push(&format_mask_line(m));
    }
    for tb in &state.trusted_bots {
        let l = format_bot_line(tb);
        if l.len() >= CFG_BLINE_MAX {
            return None;
        }
        push(&l);
    }
    if state.log.level != DEFAULT_LOG_LEVEL {
        push(&format!("l|{}\n", state.log.level as i32));
    }
    push(&format!("u|{}\n", state.user));
    push(&format!("g|{}\n", state.gecos));
    if !state.vhost.is_empty() {
        push(&format!("v|{}\n", state.vhost));
    }
    // Per-hub pins; the legacy global j| line is no longer written.
    for h in &state.hubs {
        if h.ed_pub_set {
            push(&format!("h|{}|{}\n", h.addr, crypto::b64_encode(&h.ed_pub)));
        } else {
            push(&format!("h|{}\n", h.addr));
        }
    }
    if !state.hub_key.is_empty() {
        let mut k = Zeroizing::new(String::from("k|"));
        k.push_str(&state.hub_key);
        k.push('\n');
        push(&k);
    }
    if !state.bot_uuid.is_empty() {
        push(&format!("i|{}\n", state.bot_uuid));
    }
    // Written with a timestamp even when empty, so a clear survives restart.
    if !state.opt_flags.is_empty() || state.opt_flags_ts > 0 {
        push(&format!("O|{}|{}\n", state.opt_flags, state.opt_flags_ts));
    }
    if state.admin_delta_pending {
        push("D|1\n");
    }
    (out.len() < MAX_CONFIG_SIZE).then_some(out)
}

/// Serialize and encrypt to CONFIG_FILE through a 0600 temp file and a
/// rename.  Does NOT push to the hub.
fn write_file(state: &BotState, password: &str) {
    if password.len() >= MAX_PASS {
        return;
    }
    let Some(plaintext) = serialize(state) else {
        eprintln!("[CFG] Config exceeds {MAX_CONFIG_SIZE} bytes; NOT written (old config kept).");
        return;
    };
    if plaintext.is_empty() {
        let _ = fs::remove_file(CONFIG_FILE);
        return;
    }
    let mut salt = [0u8; SALT_SIZE];
    let mut iv = [0u8; GCM_IV_LEN];
    if !crypto::random_bytes(&mut salt) || !crypto::random_bytes(&mut iv) {
        eprintln!("[CFG] RNG/KDF failure; aborting config write.");
        return;
    }
    let key = crypto::derive_config_key(password.as_bytes(), &salt);
    let Some((ct, tag)) = crypto::gcm_encrypt_detached(key.as_ref(), &iv, &[], plaintext.as_bytes()) else {
        return;
    };
    drop(plaintext);

    let temp_file = format!("{CONFIG_FILE}.tmp");
    let mut f = match OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temp_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[CFG] Failed to open {temp_file} for writing: {e}");
            return;
        }
    };
    let ok = f.write_all(&salt).is_ok()
        && f.write_all(&iv).is_ok()
        && f.write_all(&tag).is_ok()
        && f.write_all(&ct).is_ok()
        && f.flush().is_ok()
        && f.sync_all().is_ok();
    drop(f);
    if !ok {
        eprintln!("[CFG] Failed to write config, keeping old config intact");
        let _ = fs::remove_file(&temp_file);
        return;
    }
    if let Err(e) = fs::rename(&temp_file, CONFIG_FILE) {
        eprintln!("[CFG] Failed to rename {temp_file} to {CONFIG_FILE}: {e}");
        let _ = fs::remove_file(&temp_file);
    }
}

/// config_write(): save, then push to the hub when authenticated.
pub fn write(state: &mut BotState, password: &str) {
    write_file(state, password);
    if !state.hubs.is_empty() && state.hub_authenticated {
        hub_client::push_config(state);
    }
}

/// config_write_local(): save only -- for data received FROM the hub, which
/// must not be echoed back.
pub fn write_local(state: &BotState, password: &str) {
    write_file(state, password);
}

pub fn write_with_state_pass(state: &mut BotState) {
    let pass = state.startup_pass();
    write(state, &pass);
}

pub fn write_local_with_state_pass(state: &BotState) {
    let pass = state.startup_pass();
    write_local(state, &pass);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_line_new_and_legacy() {
        let (_, p) = crypto::generate_combined_keypair().unwrap();
        let k = crypto::b64_encode(&p);
        let uuid = "12345678-1234-4234-8234-123456789abc";
        let ul = parse_user_line(&format!("{uuid}|bob|{k}|add|5|6|")).unwrap();
        assert!(ul.has_pubkey && !ul.legacy && ul.is_active);
        assert_eq!((ul.last_seen, ul.timestamp), (5, 6));
        let ul = parse_user_line(&format!("{uuid}|bob|secret|del|0|9|{k}")).unwrap();
        assert!(ul.legacy && ul.has_pubkey && !ul.is_active);
        assert!(parse_user_line("nope|bob|x|add|0|0").is_none());
    }

    #[test]
    fn bot_line_shapes() {
        let tb = parse_bot_line("n!u@h").unwrap();
        assert!(tb.uuid.is_empty());
        let tb = parse_bot_line("n!u@h|uuid|42").unwrap();
        assert_eq!(tb.ts, 42);
        let (_, p) = crypto::generate_combined_keypair().unwrap();
        let tb = parse_bot_line(&format!("n!u@h|uuid|{}|7", crypto::b64_encode(&p))).unwrap();
        assert!(tb.has_pub && tb.ts == 7);
        assert_eq!(format_bot_line(&tb), format!("b|n!u@h|uuid|{}|7\n", crypto::b64_encode(&p)));
    }

    #[test]
    fn chan_and_opt_lines() {
        assert_eq!(parse_cfg_chan("#a|k|add|5"), Some(("#a".into(), "k".into(), "add".into(), 5)));
        assert_eq!(parse_cfg_chan("#a||del|7"), Some(("#a".into(), String::new(), "del".into(), 7)));
        assert_eq!(parse_opt_line("|12"), Some((String::new(), 12)));
        assert_eq!(parse_opt_line("h-x|3"), Some(("hx".into(), 3)));
    }
}
