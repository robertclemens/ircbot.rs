//! Compile-time settings, limits and the wire contract shared with irchub.
//! Mirrors bot.h: every `CMD_*` opcode, label and size here must match
//! irchub/hub.h byte for byte.

// ---- Identity / files (the "only edit this section" block of bot.h) -------
pub const BOT_NAME: &str = "ircbot.rs by trojanman";
/// Overridable at build time (`IRCBOT_VERSION=2.4.0 cargo build --release`)
/// so a release build can stamp its own version without editing the tree —
/// the testnet builds a bumped-version artifact this way.  Mirrors the
/// `#ifndef BOT_VERSION` guard in bot.h.  This is the version the bot
/// reports in CMD_BOT_PRESENCE, and the one every upgrade comparison is
/// made against.
pub const BOT_VERSION: &str = match option_env!("IRCBOT_VERSION") {
    Some(v) => v,
    None => "2.4.3",
};
pub const PASS_FILE: &str = ".ircbot.pass"; // machine-bound password file
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const VERSION_RESPONSE: &str = "A robot may not injure a human being";
pub const CONFIG_FILE: &str = ".ircbot.cnf";
pub const PID_FILE: &str = ".ircbot.pid";
pub const SALT_SIZE: usize = 16;
pub const DEFAULT_LOG_LEVEL: u32 = 63;
pub const LOGFILE: &str = ".ircbot.log";
pub const BOT_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;
/// Hand-off note written just before a hub-driven upgrade execs the new
/// binary: the restarted process reads the upgrade id from here and
/// answers CMD_UPGRADE_RESULT (bot.h UPGRADE_MARKER_FILE).
pub const UPGRADE_MARKER_FILE: &str = ".ircbot.upgrade";
/// Retained previous binary/config, kept (not deleted) after a hub-driven
/// upgrade so CMD_UPGRADE_ABORT can put the node back.
pub const UPGRADE_PREV_SUFFIX: &str = ".prev";
/// How long a CMD_UPGRADE_PREPARE stays commitable.
pub const UPGRADE_PREPARE_TTL: i64 = 900;
/// The release tree ROOT; one variant subdirectory below it holds that build's
/// manifest.  Keeping the root separate is what lets a hub-driven upgrade flip
/// a node between the C and Rust builds: `updater::hub_commit` appends the
/// variant it was told to install, so one network-wide run can leave each node
/// on its own kind of build, or move it across.  Mirrors `BOT_UPDATE_BASE` in
/// bot.h.
pub const BOT_UPDATE_BASE: &str =
    "https://raw.githubusercontent.com/robertclemens/ircbot-releases/main/ircbot";
/// The variant THIS build is: the standalone `update` command stays on it.
pub const BOT_UPDATE_VARIANT: &str = "rs";
pub const BOT_UPDATE_URL: &str =
    "https://raw.githubusercontent.com/robertclemens/ircbot-releases/main/ircbot/rs/releases.txt";
pub const BOT_UPDATE_SIG_URL: &str =
    "https://raw.githubusercontent.com/robertclemens/ircbot-releases/main/ircbot/rs/releases.sig";
/// Base64 of the raw Ed25519 public key that signs releases.txt.  Empty
/// disables the self-updater (fail closed).
pub const BOT_UPDATE_PUBKEY_B64: &str = "qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBU=";

// ---- Timeouts (seconds) ----------------------------------------------------
pub const JOIN_RETRY_TIME: i64 = 10;
pub const NICK_TAKE_TIME: i64 = 20;
pub const NICK_RETRY_TIME: i64 = 10;
pub const DEAD_SERVER_TIMEOUT: i64 = 120;
pub const CHECK_LAG_TIMEOUT: i64 = 60;
pub const ROSTER_REFRESH_INTERVAL: i64 = 120;
pub const HUB_RECONNECT_DELAY: i64 = 30;
pub const IRC_RECONNECT_MIN_INTERVAL: i64 = 10;
pub const IRC_THROTTLE_BACKOFF: i64 = 60;
pub const IRC_THROTTLE_BACKOFF_MAX: i64 = 1800;
pub const IRC_BAN_BACKOFF: i64 = 900;
pub const IRC_BAN_BACKOFF_MAX: i64 = 86400;
pub const IRC_BAN_STATED_MAX: i64 = 2_592_000;
pub const IRC_BAN_GRACE: i64 = 30;
/// Connect timeout for IRC and hub links (the C select() wait).
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

// ---- Limits ------------------------------------------------------------------
pub const MAX_SERVERS: usize = 10;
pub const MAX_USER_RECORDS: usize = 40;
pub const MAX_USER_MASKS: usize = 200;
pub const MAX_CHAN: usize = 65; // buffer size incl. NUL: names up to 64 bytes
pub const MAX_BUFFER: usize = 16384;
pub const MAX_NICK: usize = 10; // 9 chars + NUL
pub const MAX_PASS: usize = 128;
pub const MAX_KEY: usize = 31; // channel key: up to 30 bytes
pub const MAX_MASK_LEN: usize = 256;
pub const MAX_TRUSTED_BOTS: usize = 200;
pub const UUID_BUF: usize = 37; // 36 chars + NUL
pub const USER_NAME_BUF: usize = 64;

pub const CFG_GLOBAL_LINE_MAX: usize = 1088;
pub const CFG_BOT_FIELD_LINE: usize = 320;
pub const CFG_USER_LINE_MAX: usize = 384;
pub const CFG_MASK_LINE_MAX: usize = 352;
pub const CFG_BLINE_MAX: usize = 448;
pub const CFG_MAX_GLOBALS: usize = 64;
pub const CFG_BOT_SYNC_FIELDS: usize = 8;
pub const CFG_PAYLOAD_SLACK: usize = 8192;
pub const MAX_CONFIG_PAYLOAD: usize = CFG_MAX_GLOBALS * CFG_GLOBAL_LINE_MAX
    + MAX_USER_RECORDS * CFG_USER_LINE_MAX
    + MAX_USER_MASKS * CFG_MASK_LINE_MAX
    + CFG_BOT_SYNC_FIELDS * CFG_BOT_FIELD_LINE
    + MAX_TRUSTED_BOTS * CFG_BLINE_MAX
    + CFG_PAYLOAD_SLACK;
/// Largest inbound hub frame = envelope(5) + payload + GCM tag, plus margin.
pub const MAX_HUB_FRAME: usize = MAX_CONFIG_PAYLOAD + 64;
pub const MAX_ROSTER_SIZE: usize = 50;
pub const MAX_SEEN_HASHES: usize = 4096;
pub const NONCE_CACHE_SIZE: usize = 4096;
pub const NONCE_TTL_SECONDS: i64 = 60;
pub const CONFIG_WRITE_DEBOUNCE_S: i64 = 5;

// ---- Passwordless transport labels (shared with utils/ and irchub) ---------
pub const A2A_LABEL: &str = "ircbot-A2A-v1";
pub const A2K_LABEL: &str = "ircbot-A2K-v1";
pub const A2_LABEL: &str = "ircbot-A2-v1";
pub const A2S_LABEL: &str = "ircbot-A2S-v1";
pub const A2R_LABEL: &str = "ircbot-A2R-v1";
pub const B2_LABEL: &str = "ircbot-B2-v1";
pub const A2_TS_SKEW: i64 = 30;
pub const B2_TS_SKEW: i64 = 60;
pub const A2_AUTH_REPLY_MIN_INTERVAL: i64 = 3;
pub const A2_AUTH_REPLY_GLOBAL_INTERVAL: i64 = 1;
pub const SEAL_OVERHEAD: usize = 32 + 12 + 16;
pub const SEAL_MAX_PLAINTEXT: usize = 1024;
pub const A2_NICK_MAX: usize = 64;
pub const A2_B64_MAX: usize = 4 * (SEAL_MAX_PLAINTEXT + SEAL_OVERHEAD).div_ceil(3);
pub const A2_LINE_MAX: usize = 5 + A2_B64_MAX;
#[cfg(test)]
pub const A2R_OVERHEAD: usize = 12 + 16;
pub const A2R_TEXT_MAX: usize = 240;
pub const A2R_PT_MAX: usize = A2R_TEXT_MAX + 24;

// ---- DCC CHAT (outbound only) ----------------------------------------------
pub const DCC_MAX_SESSIONS: usize = 4;
pub const DCC_OFFER_TIMEOUT: i64 = 120;
pub const DCC_CONNECT_TIMEOUT: i64 = 20;
pub const DCC_IDLE_TIMEOUT: i64 = 3600;
pub const DCC_MIN_PORT: u32 = 1024;
pub const DCC_OUTBUF_MAX: usize = 512 * 1024;

pub const BOT_PROTO_VERSION: i32 = 2;

// ---- Crypto sizes --------------------------------------------------------------
pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;
pub const HUB_KEY_RAW_LEN: usize = 64; // Ed25519(32) || X25519(32)
pub const COMBINED_KEY_B64: usize = 88;
pub const MAX_HUB_KEY_SIZE: usize = 128;
pub const MAX_OPT_FLAGS: usize = 32;
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;

// ---- Logging --------------------------------------------------------------------
pub const NUM_LOG_LEVELS: usize = 6;
pub const LOG_BUFFER_LINES: usize = 50;
pub const MAX_LOG_LINE_LEN: usize = 256;
pub const DEFAULT_LOG_LINES: i32 = 10;
pub const MAX_LOG_LINES: i32 = 20;
pub const BOT_STATUS_MAX_LINES: usize = 30;
/// Keep IRC PING/PONG and hub CMD_PING out of the RAW/DEBUG logs.
pub const HIDEPINGPONG: bool = true;

pub const L_MSG: u32 = 1;
pub const L_CTCP: u32 = 2;
pub const L_INFO: u32 = 4;
pub const L_CMD: u32 = 8;
pub const L_RAW: u32 = 16;
pub const L_DEBUG: u32 = 32;

pub const OP_REQUEST_MIN_INTERVAL: i64 = 5;
/// Network option: refuse local mutations of hub-authoritative records.
pub const OPT_HUB_ONLY_MUTATIONS: char = 'h';

// ---- Hub protocol opcodes (must match irchub/hub.h) -------------------------
pub const CMD_PING: u8 = 0x01;
pub const CMD_CONFIG_PUSH: u8 = 0x02;
pub const CMD_CONFIG_PULL: u8 = 0x03;
pub const CMD_CONFIG_DATA: u8 = 0x04;
pub const CMD_UPDATE_PUBKEY: u8 = 0x05;
pub const CMD_INVITE_REQUEST: u8 = 0x09;
pub const CMD_BOT_KEY_UPDATE: u8 = 0x40;
pub const CMD_BOT_DELTA: u8 = 0x45;
pub const CMD_OP_REQUEST: u8 = 0x28;
pub const CMD_OP_GRANT: u8 = 0x29;
pub const CMD_OP_FAILED: u8 = 0x2A;
pub const CMD_BOT_RELAY: u8 = 0x50;
pub const CMD_BOT_MSG: u8 = 0x51;
pub const CMD_BOT_PRESENCE: u8 = 0x56;
pub const CMD_BOT_TREE: u8 = 0x58;
pub const CMD_CHAN_REQUEST: u8 = 0x59;
pub const CMD_CHAN_ACTION: u8 = 0x5A;
pub const CMD_CHAN_REPLY: u8 = 0x5B;
// Network-wide upgrade coordination (mirrors irchub/hub.h + ircbot/bot.h).
pub const CMD_UPGRADE_PREPARE: u8 = 0x5E;
pub const CMD_UPGRADE_READY: u8 = 0x5F;
pub const CMD_UPGRADE_COMMIT: u8 = 0x60;
pub const CMD_UPGRADE_RESULT: u8 = 0x61;
pub const CMD_UPGRADE_ABORT: u8 = 0x62;

// ---- Channel-access requests (unban / invite / key) -----------------------------
pub const CHAN_REQUEST_MIN_INTERVAL: i64 = 5;
pub const CHAN_REQUEST_RETRY_TIME: i64 = 60;
pub const CHAN_REQUEST_MAX_RETRIES: i32 = 5;
pub const CHAN_REQUEST_COOLOFF: i64 = 300;
pub const CHAN_REPLY_ACCEPT_WINDOW: i64 = 45;
pub const MAX_UNBAN_JOBS: usize = 8;
pub const UNBAN_JOB_TTL: i64 = 30;
pub const UNBAN_MAX_REMOVALS: i32 = 6;

// ---- Bot tree ('bots') ------------------------------------------------------------
pub const MAX_BOT_TREE_ROWS: usize = 256;
pub const TREE_VERSION_MAX: usize = 15;
/// "c" / "rs" -- the code base a node runs (bot_tree_row_t.variant).
pub const TREE_VARIANT_MAX: usize = 7;
pub const TREE_SERVER_MAX: usize = 63;
pub const TREE_NAME_MAX: usize = 64;
pub const BOT_TREE_STALE_AFTER: i64 = 660;
pub const BOT_PRESENCE_REPORT_INTERVAL: i64 = 120;

pub const IRC_REFUSAL_LEN: usize = 256;
