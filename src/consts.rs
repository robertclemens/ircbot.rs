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
    None => "2.4.8",
};
pub const PASS_FILE: &str = ".ircbot.pass"; // machine-bound password file
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const VERSION_RESPONSE: &str = "A robot may not injure a human being";
pub const CONFIG_FILE: &str = ".ircbot.cnf";
pub const PID_FILE: &str = ".ircbot.pid";
pub const SALT_SIZE: usize = 16;
/// The log FILE is off by default: a production bot writes nothing to disk
/// until `setlog` (l| in the config) turns it on.  The in-memory ring that
/// `getlog` reads is fed at every level.
pub const DEFAULT_LOG_LEVEL: u32 = 0;
/// Every log type (L_MSG..L_DEBUG): the largest mask `setlog` takes.
pub const LOG_LEVEL_MAX: u32 = 63;
pub const LOGFILE: &str = ".ircbot.log";
/// Default LOGFILE cap; the config's L|<bytes> line overrides it.
pub const BOT_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;
/// Bounds on L| ('setlog <level> <maxbytes>'): the hub's SET_LOG_SIZE range.
pub const BOT_LOG_SIZE_MIN: u64 = 1024;
pub const BOT_LOG_SIZE_MAX: u64 = 1024 * 1024 * 1024;
/// Hand-off note written just before a hub-driven upgrade execs the new
/// binary: the restarted process reads the upgrade id from here and
/// answers CMD_UPGRADE_RESULT (bot.h UPGRADE_MARKER_FILE).
pub const UPGRADE_MARKER_FILE: &str = ".ircbot.upgrade";
/// Retained previous binary/config, kept (not deleted) after a hub-driven
/// upgrade so CMD_UPGRADE_ABORT can put the node back.
pub const UPGRADE_PREV_SUFFIX: &str = ".prev";
/// How long a CMD_UPGRADE_PREPARE stays commitable.
pub const UPGRADE_PREPARE_TTL: i64 = 900;
/// Per-transfer budget (seconds) for the manifest read a PREPARE answer
/// makes: the bot serves nothing else while it blocks.
pub const UPGRADE_QUICK_TIMEOUT: u64 = 8;
/// The updater's ordinary transfer budget (seconds), COMMIT's download
/// included (bot.h UPDATE_FETCH_TIMEOUT).
pub const UPDATE_FETCH_TIMEOUT: u64 = 300;
/// The upgrade script's startup watchdog: how long the new build's daemon
/// has to be up before the script keeps it (bot.h UPGRADE_WATCH_SECS).
pub const UPGRADE_WATCH_SECS: u32 = 20;
/// After an upgrade restart the bot holds its "ok" until it is back in every
/// channel it held ops in before, opped — at most this long (seconds), then
/// it reports "ok" anyway with what is missing (bot.h UPGRADE_OPS_WAIT).
pub const UPGRADE_OPS_WAIT: i64 = 180;
/// The first bot version with `-selftest`: an older build would not know the
/// flag and would start a second daemon instead (bot.h SELFTEST_MIN_BOT).
pub const SELFTEST_MIN_BOT: &str = "2.4.5";
/// How long a staged build's `-selftest` may run before it is killed.
pub const SELFTEST_TIMEOUT: u64 = 15;
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
/// Connected but no 001 by then: drop, try the next server.
pub const IRC_REGISTER_TIMEOUT: i64 = 90;
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
pub const OP_GRANT_HOLD_MAX: usize = 8; // OP_GRANTs held per channel until our own +o
pub const OP_GRANT_HOLD_SECS: i64 = 15; // ...and for at most this long
/// Other people's nicks (roster, flood tracking): the server's NICKLEN, which
/// is 30 and more on today's networks, not this bot's own 9-character limit.
pub const MAX_MEMBER_NICK: usize = 32;
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
// modes.md section 2: C| (per channel), D| (one) and B| (bans) lines.  The
// ceiling stays derived from these macros, so the C| / D| / B| ingest caps
// below are what make it a hard bound.
pub const C_MODES_MAX: usize = 64; // modes field of C| / D|
pub const C_SETTINGS_MAX: usize = 512; // settings field of C|
pub const D_SETTINGS_MAX: usize = 512; // settings field of D|
pub const BAN_REASON_MAX: usize = 120;
pub const BAN_MASK_MAX: usize = 120;
pub const BAN_SETTER_MAX: usize = 63; // admin name or bot uuid
pub const MAX_BANS_PER_CHAN: usize = 100;
pub const MAX_GLOBAL_BANS: usize = 100; // bans with channel "*"
pub const CFG_MAX_CHANNELS: usize = CFG_MAX_GLOBALS;
pub const C_LINE_MAX: usize = 2 + MAX_CHAN + 1 + C_MODES_MAX + 1 + C_SETTINGS_MAX + 24;
pub const D_LINE_MAX: usize = 2 + C_MODES_MAX + 1 + D_SETTINGS_MAX + 24;
pub const B_LINE_MAX: usize =
    2 + MAX_CHAN + 1 + BAN_MASK_MAX + 1 + 24 + 8 + BAN_SETTER_MAX + 1 + BAN_REASON_MAX + 40;
pub const CFG_MAX_BANS: usize = MAX_GLOBAL_BANS + CFG_MAX_CHANNELS * MAX_BANS_PER_CHAN;
pub const MAX_CONFIG_PAYLOAD: usize = CFG_MAX_GLOBALS * CFG_GLOBAL_LINE_MAX
    + CFG_MAX_CHANNELS * C_LINE_MAX
    + D_LINE_MAX
    + CFG_MAX_BANS * B_LINE_MAX
    + MAX_USER_RECORDS * CFG_USER_LINE_MAX
    + MAX_USER_MASKS * CFG_MASK_LINE_MAX
    + CFG_BOT_SYNC_FIELDS * CFG_BOT_FIELD_LINE
    + MAX_TRUSTED_BOTS * CFG_BLINE_MAX
    + CFG_PAYLOAD_SLACK;
/// Largest inbound hub frame = envelope(5) + payload + GCM tag, plus margin.
pub const MAX_HUB_FRAME: usize = MAX_CONFIG_PAYLOAD + 64;
pub const MAX_ROSTER_SIZE: usize = 500;
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
// Channel-request election (irchub docs/plans/2026-10-07_chan_election_plan.md).
// The hub asks whether we could do a channel request right now (PROBE; we
// answer at once from our own state), then hands it to ONE bot that said yes
// (DO), which reports back (DONE).  A hub that predates this never sends
// PROBE and keeps using CMD_OP_GRANT / CMD_CHAN_ACTION.  Mirrors ircbot/bot.h.
//   PROBE      hub->bot  eid|kind|channel
//   PROBE_ACK  bot->hub  eid|1| or eid|0|reason
//   DO         hub->bot  eid|kind|channel|requester|nick|hostmask
//   DONE       bot->hub  eid|ok|detail or eid|fail|detail
// kind = op / invite / unban / key.
pub const CMD_CHAN_PROBE: u8 = 0x6D;
pub const CMD_CHAN_PROBE_ACK: u8 = 0x6E;
pub const CMD_CHAN_DO: u8 = 0x6F;
pub const CMD_CHAN_DONE: u8 = 0x70;
/// A nick the hub hands us, any network.
pub const CHAN_DO_NICK_MAX: usize = 30;
// ---- Channel modes / settings / bans / floods (irchub docs/modes.md) -----------
// The 0x76-0x7A ops are console->hub only; a bot never sends or handles them
// and they are declared so the numbers stay reserved on both sides.
// CMD_CHAN_EVENT is the one bot-originated frame: one enforcement action
// (D42), `#chan|<action>|<target>|<detail>`, rate-limited by the bot
// (hub_client::chan_event) and logged by the hub.  Mirrors irchub/hub.h.
#[allow(dead_code)]
pub const CMD_ADMIN_CHAN_MODE: u8 = 0x76; // console -> hub: channel mode
#[allow(dead_code)]
pub const CMD_ADMIN_CHAN_SET: u8 = 0x77; // console -> hub: channel set
#[allow(dead_code)]
pub const CMD_ADMIN_BAN: u8 = 0x78; // console -> hub: ban list / add / del
#[allow(dead_code)]
pub const CMD_ADMIN_NET_SET: u8 = 0x79; // console -> hub: network set
#[allow(dead_code)]
pub const CMD_ADMIN_SET_SSH: u8 = 0x7A; // console -> hub: hub set ssh / conn
pub const CMD_CHAN_EVENT: u8 = 0x7B; // bot -> hub: #chan|action|target|detail
pub const CHAN_EVENT_TARGET_MAX: usize = 120;
pub const CHAN_EVENT_DETAIL_MAX: usize = 160;
pub const CHAN_EVENT_DEDUPE_SECS: i64 = 10; // per (chan, action, target)
pub const CHAN_EVENT_WINDOW_SECS: i64 = 60; // total-rate window
pub const CHAN_EVENT_WINDOW_MAX: usize = 20; // events per window
pub const CHAN_EVENT_TRACK: usize = 32; // dedupe slots (oldest replaced)

// 005 (RPL_ISUPPORT) values this bot uses; reset on every disconnect.
pub const ISUPPORT_MODES_DEFAULT: i32 = 3;
pub const ISUPPORT_MODES_MAX: i32 = 12;
pub const NICKLEN_DEFAULT: i32 = 30;
pub const MAXLIST_DEFAULT: i32 = 100;
pub const BAN_LIST_CAP: i32 = 200; // our own ceiling on a stored list

// In-channel elections and set-option enforcement (chanenf.rs, modes.md
// sections 4, 6, 7).  The five jobs, in deal order:
pub const JOB_KICK: usize = 0;
pub const JOB_BAN: usize = 1;
pub const JOB_OP: usize = 2;
pub const JOB_MODE: usize = 3;
pub const JOB_LIMIT: usize = 4;
pub const JOB_COUNT: usize = 5;
pub const JOB_STEP_MS: i64 = 1500; // backup delay = backup index x this
pub const MAX_PENDING_JOBS: usize = 32;
pub const JOB_MIN_VERSION: &str = "2.4.7"; // older bots are left out of the deal
pub const JOB_MAX_AGE_MS: i64 = 30000; // a pending job older than this is dropped
pub const ENF_SWEEP_SECS: i64 = 5; // per-channel state sweep when nothing happened
/// Idle clocks (ban_track, grown on demand): one per channel x listed ban, so a
/// network ban on "*" costs one per channel.  The ceiling covers every
/// channel's own bans plus every global ban in every channel; the table is
/// pruned by minute_sweep and only the oldest-matched clock goes if it is
/// ever full.
pub const MAX_BAN_TRACK: usize = CFG_MAX_BANS + MAX_GLOBAL_BANS * CFG_MAX_CHANNELS;
pub const ENF_RESWEEP_MS: i64 = 2000; // a dirty channel is swept at most this often
pub const ENF_KICKS_PER_SWEEP: usize = 4; // kicks queued per channel per ban sweep
pub const MAX_OFFENCES: usize = 64;
pub const ENF_RECENT: usize = 32;
pub const ENF_CYCLE_MIN_SECS: i64 = 600; // +cycle: at most one part/rejoin per this

// Flood counters (chanflood.rs, botflood.rs; modes.md sections 8, 9.1).
pub const MAX_FLOOD_TRACK: usize = 64; // sources tracked per channel, oldest replaced
pub const MAX_IGNORES: usize = 64; // bot ignore table (runtime only)
pub const MAX_HOST_TRACK: usize = 64; // hosts tracked for the bot msg / ctcp floods
pub const FLOOD_HOST_MAX: usize = 128; // a tracked host (cut, lower-cased), buffer size
pub const QUIET_FILL_MS: i64 = 60000; // a table full within this -> quiet mode

// Output send queue (sendq.rs): three lanes, drained by pacing.
pub const MAX_SENDQ: usize = 256; // lines held, all lanes together
pub const SENDQ_LANES: usize = 3;
pub const SENDQ_LANE_PROTO: usize = 0; // PONG, registration
pub const SENDQ_LANE_PROT: usize = 1; // MODE / KICK
pub const SENDQ_LANE_REST: usize = 2; // everything else (dropped first)
pub const SENDQ_DEF_BURST: i64 = 10; // lines sent back to back (D| sendq B)
pub const SENDQ_DEF_INTERVAL_MS: i64 = 100; // then one line per this (D| sendq I)
pub const SENDQ_MIN_BURST: i64 = 1;
pub const SENDQ_MAX_BURST: i64 = 100;
pub const SENDQ_MIN_INTERVAL_MS: i64 = 0; // 0 = unpaced
pub const SENDQ_MAX_INTERVAL_MS: i64 = 10000;
pub const SENDQ_LINE_MAX: usize = 510; // IRC line body; CR LF is added after

// Network-wide upgrade coordination (mirrors irchub/hub.h + ircbot/bot.h).
pub const CMD_UPGRADE_PREPARE: u8 = 0x5E;
pub const CMD_UPGRADE_READY: u8 = 0x5F;
pub const CMD_UPGRADE_COMMIT: u8 = 0x60;
pub const CMD_UPGRADE_RESULT: u8 = 0x61;
pub const CMD_UPGRADE_ABORT: u8 = 0x62;

// ---- Activity (last seen / last used), mirrors ircbot/bot.h + irchub/hub.h.
// last_seen / last_used are max-merged outside LWW.  auth::mark_used stores
// the exact time and, on a record's first use within an ACTIVITY_BUCKET (a
// clock hour), reports that time to the hub as CMD_ACTIVITY; with no hub link
// the latest such time waits per record and goes out after the next hub
// authentication.  admins / opers / match ask the hub for the network-wide
// times (CMD_ACTIVITY_QUERY), park the command for up to
// ACTIVITY_QUERY_TIMEOUT seconds, and show max(hub, local) per row; with no
// hub or no answer they show the local times.
//   CMD_ACTIVITY        a|<user_uuid>|<ts>  /  m|<user_uuid>|<mask>|<ts>
//   CMD_ACTIVITY_QUERY  <req_id>|users  /  <req_id>|masks|<user_uuid or *>
//   CMD_ACTIVITY_REPLY  <req_id>|<more>, then a|/m| lines; more=0 last
pub const CMD_ACTIVITY: u8 = 0x69;
pub const CMD_ACTIVITY_QUERY: u8 = 0x6A;
pub const CMD_ACTIVITY_REPLY: u8 = 0x6B;
pub const ACTIVITY_BUCKET: i64 = 3600;
/// Hub times further ahead than this are refused.
pub const ACTIVITY_MAX_FUTURE: i64 = 300;
pub const ACTIVITY_QUERY_TIMEOUT: i64 = 3;
pub const MAX_ACTIVITY_QUERIES: usize = 4;
pub const ACTIVITY_REQ_ID_MAX: usize = 32;

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
/// Deepest row we draw.  A hub hangs every hub further out beneath the hub
/// that links to it, so a chain of N hubs is N levels deep (plus its bots);
/// a deeper row is drawn at this depth rather than dropped.
pub const MAX_TREE_DEPTH: i32 = 32;
pub const TREE_VERSION_MAX: usize = 15;
/// "c" / "rs" -- the code base a node runs (bot_tree_row_t.variant).
pub const TREE_VARIANT_MAX: usize = 7;
pub const TREE_SERVER_MAX: usize = 63;
pub const TREE_NAME_MAX: usize = 64;
pub const BOT_TREE_STALE_AFTER: i64 = 660;
pub const BOT_PRESENCE_REPORT_INTERVAL: i64 = 120;

pub const IRC_REFUSAL_LEN: usize = 256;
