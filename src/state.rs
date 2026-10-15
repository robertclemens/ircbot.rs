//! The bot's state (bot_state_t and the records it holds) and the small
//! inline rules from bot.h (LWW acceptance, nick validation).

use std::cell::Cell;
use std::collections::VecDeque;

use mio::Registry;
use zeroize::Zeroizing;

use crate::consts::*;
use crate::cstr::now;
use crate::dcc::DccSession;
use crate::hub_client::HubConn;
use crate::irc_client::IrcConn;
use crate::logging::Logger;
use crate::secret::Locked;

pub const S_CONNECTED: u32 = 1 << 0;
pub const S_AUTHED: u32 = 1 << 1;
pub const S_DIE: u32 = 1 << 2;

pub const M_K: u32 = 64;
pub const M_I: u32 = 128;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ChanStatus {
    #[default]
    None,
    Out,
    In,
}

/// chan_req_kind_t: one in-flight request per kind per channel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChanReq {
    Unban = 0,
    Invite = 1,
    Key = 2,
}

pub const CHAN_REQ_KIND_COUNT: usize = 3;

impl ChanReq {
    pub fn token(self) -> &'static str {
        match self {
            ChanReq::Unban => "unban",
            ChanReq::Invite => "invite",
            ChanReq::Key => "key",
        }
    }

    pub fn from_token(tok: &str) -> Option<ChanReq> {
        [ChanReq::Unban, ChanReq::Invite, ChanReq::Key]
            .into_iter()
            .find(|k| tok.eq_ignore_ascii_case(k.token()))
    }
}

/// An admin ('a') or oper ('o') record.
#[derive(Clone, Debug, Default)]
pub struct UserRecord {
    pub uuid: String,
    pub name: String,
    /// Combined Curve25519 public key, base64 (88 chars); the user's only
    /// credential.  Empty when has_pubkey is false.
    pub pubkey_b64: String,
    pub has_pubkey: bool,
    pub typ: char,
    pub is_active: bool,
    pub last_seen: i64,
    pub timestamp: i64,
    /// Runtime only: ~A2K rate limit.
    pub last_auth_reply: i64,
    /// Runtime only: CMD_ACTIVITY time not yet sent.
    pub act_pending: i64,
}

/// A parsed a|/o| line body.  `legacy` is true when field 3 carried a
/// password (never copied anywhere).
#[derive(Clone, Debug, Default)]
pub struct UserLine {
    pub uuid: String,
    pub name: String,
    pub pubkey_b64: String,
    pub has_pubkey: bool,
    pub is_active: bool,
    pub legacy: bool,
    pub last_seen: i64,
    pub timestamp: i64,
}

/// One trusted peer bot (b| line).
#[derive(Clone, Debug)]
pub struct TrustedBot {
    pub mask: String,
    pub uuid: String,
    pub pub_key: [u8; HUB_KEY_RAW_LEN],
    pub has_pub: bool,
    pub ts: i64,
}

impl Default for TrustedBot {
    fn default() -> Self {
        TrustedBot {
            mask: String::new(),
            uuid: String::new(),
            pub_key: [0; HUB_KEY_RAW_LEN],
            has_pub: false,
            ts: 0,
        }
    }
}

impl TrustedBot {
    /// Nick part of the mask (auth_trusted_bot_nick), bounded to MAX_NICK.
    pub fn nick(&self) -> &str {
        crate::cstr::mask_nick(&self.mask, MAX_NICK)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MaskRecord {
    pub uuid: String,
    pub mask: String,
    pub is_active: bool,
    pub last_used: i64,
    pub timestamp: i64,
    /// Runtime only: CMD_ACTIVITY time not yet sent.
    pub act_pending: i64,
}

#[derive(Clone, Debug, Default)]
pub struct RosterEntry {
    pub nick: String,
    pub hostmask: String,
    pub is_op: bool,
    /// PREFIX 'h' (D41); false on a server without it.
    pub is_halfop: bool,
    pub is_voice: bool,
    /// chanenf.rs: cached "authorised" verdict for `hostmask`, valid while
    /// `auth_gen` equals the state's (0 = never computed).  Cells, as the
    /// cache is filled through a shared borrow (C casts the const away).
    pub authorised: Cell<bool>,
    pub auth_gen: Cell<u32>,
}

/// Settings that live in a C| / D| `settings` field as name=value.  The
/// first ten are flags (0/1), the rest numbers with the ranges in chancfg.rs.
/// `Ignoretime` is network-only (D|).  Discriminants index `ChanSettings`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CsetId {
    EnforceModes = 0,
    Bitch,
    ProtectOps,
    Revenge,
    StopNetHack,
    EnforceBans,
    DynamicBans,
    DontKickOps,
    Cycle,
    DynamicLimit,
    BanTime,
    BanType,
    BanIdle,
    LimitGap,
    LimitDelay,
    IgnoreTime,
}

pub const CS_COUNT: usize = 16;

impl CsetId {
    /// Every setting, in discriminant order (the `chanset` listing walks it).
    pub const ALL: [CsetId; CS_COUNT] = [
        CsetId::EnforceModes,
        CsetId::Bitch,
        CsetId::ProtectOps,
        CsetId::Revenge,
        CsetId::StopNetHack,
        CsetId::EnforceBans,
        CsetId::DynamicBans,
        CsetId::DontKickOps,
        CsetId::Cycle,
        CsetId::DynamicLimit,
        CsetId::BanTime,
        CsetId::BanType,
        CsetId::BanIdle,
        CsetId::LimitGap,
        CsetId::LimitDelay,
        CsetId::IgnoreTime,
    ];
}

/// Flood settings: the seven channel types (`flood <type>`), then the three
/// bot floods (`bflood cmd|msg|ctcp`, D| only).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FloodKind {
    Chan = 0,
    Ctcp,
    Join,
    Nick,
    Deop,
    Kick,
    Ban,
    BotCmd,
    BotMsg,
    BotCtcp,
    /// `sendq` B:I (D| only; n = burst 1..100, s = interval ms 0..10000, never `off`).
    Sendq,
}

pub const FL_COUNT: usize = 11;

impl FloodKind {
    /// Every flood, in discriminant order.
    pub const ALL: [FloodKind; FL_COUNT] = [
        FloodKind::Chan,
        FloodKind::Ctcp,
        FloodKind::Join,
        FloodKind::Nick,
        FloodKind::Deop,
        FloodKind::Kick,
        FloodKind::Ban,
        FloodKind::BotCmd,
        FloodKind::BotMsg,
        FloodKind::BotCtcp,
        FloodKind::Sendq,
    ];
}
/// FL_CHAN..FL_BAN are per-channel.
pub const FL_CHAN_COUNT: usize = 7;

#[derive(Clone, Copy, Debug, Default)]
pub struct FloodSpec {
    /// An override is set.
    pub present: bool,
    /// `off`.
    pub off: bool,
    /// More than n events in s seconds trips it.
    pub n: i32,
    pub s: i32,
}

/// A parsed settings field: only the overrides it names.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChanSettings {
    /// Bit per `CsetId`.
    pub present: u32,
    pub val: [i64; CS_COUNT],
    pub fl: [FloodSpec; FL_COUNT],
    /// A sendq=... token was present but invalid.
    pub bad_sendq: bool,
}

/// One counting window: the first event opens it, more than n events before
/// s seconds have passed from its start trip it.  Checked on arrival only.
#[derive(Clone, Copy, Debug, Default)]
pub struct FloodWindow {
    /// Monotonic ms; only meaningful while `count` > 0.
    pub start_ms: i64,
    pub count: i32,
}

/// One source host in one channel: a window per channel flood type.  An
/// empty `host` is a free slot.
#[derive(Clone, Debug, Default)]
pub struct FloodSrc {
    /// Lower-cased, cut to FLOOD_HOST_MAX.
    pub host: String,
    /// Last counted event (the oldest is replaced when the tracker is full).
    pub last_ms: i64,
    pub w: [FloodWindow; FL_CHAN_COUNT],
    /// Bit per kind: a victim was authorised (+revenge).
    pub victim_auth: u8,
}

/// One ignore-table entry (botflood.rs); an empty `key` is a free slot.  The
/// key is a lower-cased host, or "u:<uuid>" for a user over the cmd limit.
#[derive(Clone, Debug, Default)]
pub struct IgnoreEnt {
    pub key: String,
    pub since_ms: i64,
    pub until_ms: i64,
}

/// One host tracked for the bot msg / ctcp floods; empty `host` = free slot.
#[derive(Clone, Debug, Default)]
pub struct HostFlood {
    pub host: String,
    pub last_ms: i64,
    pub msg: FloodWindow,
    pub ctcp: FloodWindow,
}

/// One user record tracked for the cmd flood; empty `uuid` = free slot.
#[derive(Clone, Debug, Default)]
pub struct CmdFlood {
    pub uuid: String,
    pub last_ms: i64,
    pub w: FloodWindow,
    /// The "slow down" notice went out in this window.
    pub notified: bool,
}

/// Runtime flood state of the bot itself (botflood.rs): never persisted or
/// shared.  Every table is a fixed number of slots, as in C.
#[derive(Clone, Debug)]
pub struct BotFlood {
    pub ignores: Vec<IgnoreEnt>,
    /// 0 / past = not quiet.
    pub quiet_until_ms: i64,
    /// The episode's one log line went out.
    pub quiet_logged: bool,
    pub host_flood: Vec<HostFlood>,
    pub cmd_flood: Vec<CmdFlood>,
}

impl Default for BotFlood {
    fn default() -> Self {
        BotFlood {
            ignores: vec![IgnoreEnt::default(); MAX_IGNORES],
            quiet_until_ms: 0,
            quiet_logged: false,
            host_flood: vec![HostFlood::default(); MAX_HOST_TRACK],
            cmd_flood: vec![CmdFlood::default(); MAX_USER_RECORDS],
        }
    }
}

/// One server-side ban in a channel's ban list (367 + MODE +b/-b).
#[derive(Clone, Debug, Default)]
pub struct LiveBan {
    pub mask: String,
    /// Setter as the server printed it, cut.
    #[allow(dead_code)] // read by the enforcement code of a later phase
    pub setter: String,
    /// Server's ts, 0 if unknown.
    #[allow(dead_code)]
    pub when: i64,
}

/// One B| record (a network ban).  chan "*" = every managed channel.
#[derive(Clone, Debug, Default)]
pub struct CfgBan {
    pub chan: String,
    pub mask: String,
    /// "s" sticky, "" none.
    pub flags: String,
    pub setter: String,
    pub reason: String,
    /// Absolute unix time, 0 = permanent.
    pub expires: i64,
    pub ts: i64,
    /// False = tombstone (op "del").
    pub active: bool,
    /// Bot-written, not yet pushed to a hub.
    pub push_pending: bool,
}

/// 005 (RPL_ISUPPORT) values this bot uses; reset on every disconnect.
#[derive(Clone, Debug)]
pub struct Isupport {
    /// MODES=: changes per MODE line.
    pub modes: i32,
    /// MAXLIST for 'b' (or MAXBANS), 0 = unknown.
    pub maxlist_b: i32,
    /// PREFIX=(ohv)@%+ -> "ohv"
    pub prefix_modes: String,
    /// ... -> "@%+"
    pub prefix_syms: String,
    /// CHANMODES=A,B,C,D
    pub cm_a: String,
    pub cm_b: String,
    pub cm_c: String,
    pub cm_d: String,
    /// NICKLEN=, default 30.
    pub nicklen: i32,
}

impl Default for Isupport {
    /// isupport_reset(): what a server that says nothing is assumed to have.
    fn default() -> Self {
        Isupport {
            modes: ISUPPORT_MODES_DEFAULT,
            maxlist_b: 0,
            prefix_modes: "ov".into(),
            prefix_syms: "@+".into(),
            cm_a: "beI".into(),
            cm_b: "k".into(),
            cm_c: "l".into(),
            cm_d: "imnpst".into(),
            nicklen: NICKLEN_DEFAULT,
        }
    }
}

/// Output send queue (sendq.rs): three lanes, drained by pacing.  Lines are
/// bytes, as in C: a line cut at SENDQ_LINE_MAX may end inside a character.
#[derive(Debug)]
pub struct SendQ {
    /// One ring per lane; each line holds its CRLF.
    pub q: [VecDeque<Vec<u8>>; SENDQ_LANES],
    pub total: usize,
    /// Live D| sendq burst (lines).
    pub burst: i64,
    /// Live D| sendq interval in ms; 0 = unpaced.
    pub interval_ms: i64,
    /// Send credit, capped at burst * interval.
    pub credit_ms: i64,
    /// Monotonic ms of the last refill.
    pub last_ms: i64,
    /// Lines dropped because the queue was full.
    #[allow(dead_code)] // counted like C's sendq_t.dropped, shown by a later phase
    pub dropped: u64,
    /// sendq::hold depth: >0 queues without draining.
    pub hold: u32,
}

impl Default for SendQ {
    /// sendq_clear(): empty, with a full burst of credit.
    fn default() -> Self {
        SendQ {
            q: Default::default(),
            total: 0,
            burst: SENDQ_DEF_BURST,
            interval_ms: SENDQ_DEF_INTERVAL_MS,
            credit_ms: SENDQ_DEF_BURST * SENDQ_DEF_INTERVAL_MS,
            last_ms: crate::sendq::mono_ms(),
            dropped: 0,
            hold: 0,
        }
    }
}

/// One dedupe slot of the CMD_CHAN_EVENT limiter.
#[derive(Clone, Debug, Default)]
pub struct ChanEventSeen {
    pub key: String,
    pub when: i64,
}

/// Rate-limit memory for CMD_CHAN_EVENT (hub_client::chan_event).
#[derive(Clone, Debug)]
pub struct ChanEventLim {
    pub seen: Vec<ChanEventSeen>,
    /// Send times, ring.
    pub window: [i64; CHAN_EVENT_WINDOW_MAX],
    pub widx: usize,
    /// Dropped since the last summary.
    pub suppressed: u32,
    /// Channel of the latest suppressed event.
    pub sup_chan: String,
    pub sup_action: String,
}

impl Default for ChanEventLim {
    fn default() -> Self {
        ChanEventLim {
            seen: vec![ChanEventSeen::default(); CHAN_EVENT_TRACK],
            window: [0; CHAN_EVENT_WINDOW_MAX],
            widx: 0,
            suppressed: 0,
            sup_chan: String::new(),
            sup_action: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Chan {
    pub name: String,
    pub key: String,
    pub status: ChanStatus,
    pub modes: u32,
    pub is_managed: bool,
    pub timestamp: i64,
    pub last_who_request: i64,
    pub roster: Vec<RosterEntry>,
    pub last_join_attempt: i64,
    /// 405 received: stop retrying this channel this session.
    pub join_disabled: bool,
    pub i_am_opped: bool,
    pub op_request_pending: bool,
    pub last_op_request_time: i64,
    pub op_request_retry_count: i32,
    /// OP_GRANTs (nick, when) that came in before our own +o (a channel just
    /// created, every bot joining at once): granted when the +o lands,
    /// dropped after OP_GRANT_HOLD_SECS.  Without it the asker waits out its
    /// 60 s timeout.  At most OP_GRANT_HOLD_MAX.
    pub op_grant_held: Vec<(String, i64)>,
    pub last_access_request: [i64; CHAN_REQ_KIND_COUNT],
    pub access_retry_count: [i32; CHAN_REQ_KIND_COUNT],
    /// C| record (modes.md section 2): the stored modes string, the raw
    /// settings field (unknown names kept verbatim) and its parse.  Written
    /// only by the console; cfg_ts 0 = never seen.
    pub cfg_modes: String,
    pub cfg_settings: String,
    pub cfg_set: ChanSettings,
    pub cfg_ts: i64,
    pub cfg_active: bool,
    /// chanenf.rs runtime: sweep at the next tick.
    pub enf_dirty: bool,
    /// Gained ops / settings changed: +bitch sweep.
    pub enf_ops_check: bool,
    /// -dynamicbans overflow warning logged.
    pub ban_cap_warned: bool,
    /// Monotonic ms of the last sweep.
    pub enf_last_sweep_ms: i64,
    pub enf_last_limit: i64,
    pub enf_last_cycle: i64,
    /// Live state (never persisted): modes from 324 + MODE, the ban list
    /// from 367 + MODE.  `live_flags` has a bit per mode letter
    /// (chanlive::live_bit).
    pub live_flags: u64,
    pub live_key: String,
    /// 0 = none.
    pub live_limit: i64,
    /// A 324 (or our own MODE echo) was seen.
    pub live_known: bool,
    /// 329.
    pub live_created: i64,
    pub bans: Vec<LiveBan>,
    /// Between the first 367 and the 368.
    pub ban_list_open: bool,
    /// A full list was received.
    pub ban_list_known: bool,
    pub ban_overflow_logged: bool,
    /// The channel WHO finished (315) this stay.
    pub who_done: bool,
    /// A key / mode this bot learned and has not yet got to a hub: pushed in
    /// a full config push even under opt 'h' (D43).
    pub enf_pending: bool,
    /// chanflood.rs: per-source flood windows, MAX_FLOOD_TRACK slots,
    /// allocated on the first counted event (empty until then) and freed by
    /// `chanlive::live_reset`.
    pub flood: Vec<FloodSrc>,
}

/// What a pending job does when it falls due (each is re-checked first).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum JobAct {
    #[default]
    Deop,
    Dehalf,
    Reop,
    Kick,
    BanNuh,
    BanMask,
    Unban,
    Mode,
    Limit,
}

/// A queued piece of in-channel work (chanenf.rs); `used` slots are scanned
/// in index order, as in C.
#[derive(Clone, Debug, Default)]
pub struct PendingJob {
    pub used: bool,
    pub act: JobAct,
    pub chan: String,
    /// Nick, nick!user@host or ban mask.
    pub target: String,
    pub reason: String,
    /// Monotonic.
    pub created_ms: i64,
}

/// Idle clock of a listed ban on a channel (+dynamicbans / banidle); an
/// empty `chan` is a free slot.
#[derive(Clone, Debug, Default)]
pub struct BanTrack {
    pub chan: String,
    pub mask: String,
    /// Last time an unauthorised member matched.
    pub last_match: i64,
    /// When this bot last sent +b for it.
    pub set_at: i64,
    /// Last section 6.2 overlap check (cached 60 s).
    pub checked_at: i64,
    /// Its result.
    pub overlap_ok: bool,
}

/// Repeat-offence memory for +revenge and the flood ladder (runtime only);
/// an empty `key` is a free slot.
#[derive(Clone, Debug, Default)]
pub struct Offence {
    /// lower(chan) '|' lower(host)
    pub key: String,
    pub when: i64,
    pub count: u32,
}

/// One "same action again" memory slot (chanenf.rs recent_seen).
#[derive(Clone, Debug, Default)]
pub struct EnfRecent {
    pub key: String,
    pub when_ms: i64,
}

/// An unban being serviced for another bot (367 walk, closed by 368).
#[derive(Clone, Debug, Default)]
pub struct UnbanJob {
    pub channel: String,
    pub hostmask: String,
    pub started: i64,
    pub removed: i32,
    pub active: bool,
}

/// One row of the hub-pushed bot tree (display only).
#[derive(Clone, Debug, Default)]
pub struct BotTreeRow {
    pub kind: char,
    pub depth: i32,
    pub name: String,
    pub uuid: String,
    pub version: String,
    /// Code base ("c" / "rs"); empty when the hub did not say.
    pub variant: String,
    pub server: String,
    pub uptime: i64,
    /// Absolute start time, 0 = unknown.
    pub started: i64,
    /// The hub sent `started`: the uptime is ours to work out.
    pub has_started: bool,
    pub online: bool,
}

/// A configured hub and its pinned Ed25519 key.
#[derive(Clone, Debug, Default)]
pub struct HubEntry {
    pub addr: String,
    pub ed_pub: [u8; 32],
    pub ed_pub_set: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ServerBlockKind {
    #[default]
    None,
    Throttled,
    Banned,
    BannedTemp,
    BannedPerm,
}

/// Per-server ban/throttle hold, parallel to server_list (runtime only).
#[derive(Clone, Debug, Default)]
pub struct ServerBlock {
    pub kind: ServerBlockKind,
    pub until: i64,
    pub strikes: i32,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NonceEntry {
    pub nonce: u64,
    pub ts: i64,
}

/// Replay cache: a ring of (nonce, time) with a TTL.
pub struct NonceCache {
    entries: Vec<NonceEntry>,
    idx: usize,
}

impl NonceCache {
    pub fn new(size: usize) -> Self {
        NonceCache {
            entries: vec![NonceEntry::default(); size],
            idx: 0,
        }
    }

    pub fn seen(&self, nonce: u64, now: i64) -> bool {
        self.entries
            .iter()
            .any(|e| e.nonce == nonce && now - e.ts <= NONCE_TTL_SECONDS)
    }

    pub fn record(&mut self, nonce: u64, now: i64) {
        let n = self.entries.len();
        self.entries[self.idx] = NonceEntry { nonce, ts: now };
        self.idx = (self.idx + 1) % n;
    }
}

/// Reply sealing context while a ~A2S command runs (wiped right after).
#[derive(Default)]
pub struct A2rCtx {
    pub active: bool,
    pub key: Zeroizing<[u8; 32]>,
    pub aad: Vec<u8>,
    pub nick: String,
    pub seq: u64,
}

/// Which listing a parked activity query answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActqKind {
    Admins,
    Opers,
    Match,
}

/// One admins / opers / match command parked on CMD_ACTIVITY_QUERY, with
/// everything needed to answer it later: the asker, the DCC chat it came in
/// on (slot + dcc_token, so a reused slot is not mistaken for it) and a ~A2S
/// command's reply key (wiped as soon as the command is answered).
pub struct ActivityQuery {
    pub id: String,
    pub kind: ActqKind,
    /// match: the name, or "*".
    pub arg: String,
    pub nick: String,
    pub dcc: Option<(usize, u32)>,
    pub a2r: A2rCtx,
    pub deadline: i64,
}

/// Hub handshake progress.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HubAuthState {
    #[default]
    None,
    SentUuid,
    SentSignature,
    Complete,
}

pub struct BotState {
    pub registry: Registry,
    /// Bumped for every socket registered with the poller; tokens carry it so
    /// an event for a closed socket never reaches its replacement.
    pub next_gen: usize,

    /// The locked pid file; its flock marks this bot as running.
    pub pid_file: Option<std::fs::File>,
    pub executable_path: String,
    pub status: u32,
    pub current_nick: String,
    pub target_nick: String,
    pub user: String,
    pub gecos: String,
    pub vhost: String,
    pub server_list: Vec<String>,
    pub actual_server_name: String,
    pub actual_hostname: String,
    pub actual_hostname_ts: i64,
    pub current_nick_ts: i64,
    pub current_server_index: usize,
    pub server_blocks: Vec<ServerBlock>,
    /// server_list slot of the current/last attempt (None: no slot).
    pub irc_server_idx: Option<usize>,
    pub last_irc_attempt: i64,
    pub irc_refusal_ban: bool,
    pub irc_refusal: String,
    pub irc_blocked_logged: bool,
    pub nick_generation_attempt: usize,
    pub bot_start_time: i64,
    pub connection_time: i64,
    pub last_pong_time: i64,
    pub nick_release_time: i64,
    pub last_nick_attempt: i64,
    pub nick_refused: String,
    pub pong_pending: bool,
    pub nick_change_pending: bool,
    pub irc: Option<IrcConn>,
    pub log: Logger,
    pub chans: Vec<Chan>,

    /// Plaintext config password for the life of the process (every config
    /// write needs it); mlock'd and wiped on drop.
    pub startup_password: Locked<MAX_PASS>,
    pub trusted_bots: Vec<TrustedBot>,
    pub last_auth_reply_any: i64,
    /// Local user/mask changes still to be pushed to the hub (config "D|1").
    pub admin_delta_pending: bool,
    pub dcc: Vec<DccSession>,
    /// Index of the DCC chat whose command is being dispatched: replies to
    /// its owner go down the chat instead of to IRC.
    pub dcc_reply: Option<usize>,
    pub a2r: A2rCtx,
    /// admins / opers / match waiting on a CMD_ACTIVITY_REPLY (commands).
    pub activity_queries: Vec<ActivityQuery>,
    pub recent_nonces: NonceCache,
    pub admin_nonces: NonceCache,

    pub user_records: Vec<UserRecord>,
    pub mask_records: Vec<MaskRecord>,
    pub config_dirty: bool,
    pub last_config_write: i64,

    pub opt_flags: String,
    pub opt_flags_ts: i64,

    pub bot_uuid: String,
    /// Base64 of the identity private key: config serialization only.
    pub hub_key: Zeroizing<String>,
    /// The decoded identity key (ed_seed || x_priv), mlock'd.
    pub hub_key_raw: Locked<HUB_KEY_RAW_LEN>,
    pub self_pub: [u8; HUB_KEY_RAW_LEN],
    pub self_pub_set: bool,
    /// Pinned key of the hub being connected to (copied from hubs[] at
    /// connect time), or the legacy global j| key while loading.
    pub hub_remote_ed_pub: [u8; 32],
    pub hub_remote_ed_pub_set: bool,
    pub hubs: Vec<HubEntry>,
    pub hub: Option<HubConn>,
    pub hub_auth_state: HubAuthState,
    pub current_hub: String,
    pub hub_connecting: bool,
    pub hub_connected: bool,
    pub hub_authenticated: bool,
    pub hub_session_key: Locked<32>,
    pub last_hub_connect_attempt: i64,
    pub last_hub_ping_time: i64,
    pub last_hub_activity: i64,
    pub last_hub_pong_sent: i64,
    pub last_op_request_sent: i64,
    pub last_chan_request_sent: i64,
    pub chan_req_fallback_idx: usize,
    pub unban_jobs: Vec<UnbanJob>,
    pub hub_connect_time: i64,

    pub bot_tree: Vec<BotTreeRow>,
    pub bot_tree_ts: i64,
    pub presence_server: String,
    pub last_presence_sent: i64,
    /// The hub-driven upgrade this bot has acknowledged (CMD_UPGRADE_PREPARE).
    /// COMMIT carries only the id and the version, so the release base the hub
    /// named at PREPARE time is remembered here; an id that never went through
    /// PREPARE, or one older than UPGRADE_PREPARE_TTL, is refused.  Volatile:
    /// never written to the config, and the upgrade itself hands over through
    /// UPGRADE_MARKER_FILE because exec() takes all of this with it.
    pub upgrade_id: String,
    pub upgrade_target: String,
    pub upgrade_variant: String,
    pub upgrade_base: String,
    pub upgrade_prepared: i64,
    /// The run whose build this process IS, from UPGRADE_MARKER_FILE when the
    /// upgraded binary first reports in.  An ABORT rolls back to `<exe>.prev`
    /// only for this run — `.prev` otherwise holds the build from before some
    /// earlier, completed run, and a bot that refused a COMMIT never moved.
    pub upgrade_installed_id: String,
    /// An upgrade's "ok" not sent yet: held until this bot is back in every
    /// channel it held ops in before the restart, opped, or UPGRADE_OPS_WAIT
    /// has passed (hub_client::upgrade_ready_tick).  Volatile.
    pub upgrade_report: Option<UpgradeReport>,

    // ---- modes.md ----
    /// Output queue (sendq.rs).
    pub sendq: SendQ,
    /// This server's 005 (chanlive.rs).
    pub isup: Isupport,
    /// D| network defaults: stored modes, raw settings, parse.
    pub net_modes: String,
    pub net_settings: String,
    pub net_set: ChanSettings,
    pub net_ts: i64,
    /// B| records, grown on demand up to CFG_MAX_BANS.
    pub cfg_bans: Vec<CfgBan>,
    pub chan_event: ChanEventLim,
    /// chanenf.rs: bumped when a C| / D| / B| record changes.
    pub cfg_gen: u32,
    pub enf_seen_gen: u32,
    /// Pending in-channel jobs (MAX_PENDING_JOBS slots).
    pub jobs: Vec<PendingJob>,
    /// Ban idle clocks, grown on demand up to MAX_BAN_TRACK (an emptied slot
    /// has an empty `chan`).
    pub ban_track: Vec<BanTrack>,
    /// chanenf.rs: bumped when cfg_gen or the auth records change; retires
    /// every roster entry's cached verdict.  Cells like RosterEntry's cache.
    pub auth_gen: Cell<u32>,
    pub auth_seen_cfg_gen: Cell<u32>,
    /// Fingerprint of trusted bots / users / masks, and when it was taken.
    pub auth_fp: Cell<u64>,
    pub auth_fp_ms: Cell<i64>,
    /// Offence memory (MAX_OFFENCES slots).
    pub offences: Vec<Offence>,
    /// Recent-action ring (ENF_RECENT slots) and its write index.
    pub enf_recent: Vec<EnfRecent>,
    pub enf_recent_idx: usize,
    pub enf_last_minute: i64,
    /// botflood.rs: ignore table, quiet mode, host and per-user windows.
    pub flood: BotFlood,
}

/// A held upgrade "ok" (see BotState::upgrade_report).
#[derive(Clone, Debug, Default)]
pub struct UpgradeReport {
    pub id: String,
    /// Channels to be back in, opped, before reporting.
    pub ops: Vec<String>,
    /// When the restarted build first had a hub to report to.
    pub since: i64,
}

impl BotState {
    /// state_init().
    pub fn new(registry: Registry) -> Self {
        let t = now();
        BotState {
            registry,
            next_gen: 1,
            pid_file: None,
            executable_path: String::new(),
            status: 0,
            current_nick: String::new(),
            target_nick: String::new(),
            user: String::new(),
            gecos: String::new(),
            vhost: String::new(),
            server_list: Vec::new(),
            actual_server_name: String::new(),
            actual_hostname: String::new(),
            actual_hostname_ts: 0,
            current_nick_ts: t,
            current_server_index: 0,
            server_blocks: vec![ServerBlock::default(); MAX_SERVERS],
            irc_server_idx: None,
            last_irc_attempt: 0,
            irc_refusal_ban: false,
            irc_refusal: String::new(),
            irc_blocked_logged: false,
            nick_generation_attempt: 0,
            bot_start_time: t,
            connection_time: 0,
            last_pong_time: t,
            nick_release_time: t - NICK_TAKE_TIME,
            last_nick_attempt: 0,
            nick_refused: String::new(),
            pong_pending: false,
            nick_change_pending: false,
            irc: None,
            log: Logger::new(DEFAULT_LOG_LEVEL),
            chans: Vec::new(),
            startup_password: Locked::new(),
            trusted_bots: Vec::new(),
            last_auth_reply_any: 0,
            admin_delta_pending: false,
            dcc: (0..DCC_MAX_SESSIONS)
                .map(|_| DccSession::default())
                .collect(),
            dcc_reply: None,
            a2r: A2rCtx::default(),
            activity_queries: Vec::new(),
            recent_nonces: NonceCache::new(NONCE_CACHE_SIZE),
            admin_nonces: NonceCache::new(MAX_SEEN_HASHES),
            user_records: Vec::new(),
            mask_records: Vec::new(),
            config_dirty: false,
            last_config_write: 0,
            opt_flags: String::new(),
            opt_flags_ts: 0,
            bot_uuid: String::new(),
            hub_key: Zeroizing::new(String::new()),
            hub_key_raw: Locked::new(),
            self_pub: [0; HUB_KEY_RAW_LEN],
            self_pub_set: false,
            hub_remote_ed_pub: [0; 32],
            hub_remote_ed_pub_set: false,
            hubs: Vec::new(),
            hub: None,
            hub_auth_state: HubAuthState::None,
            current_hub: String::new(),
            hub_connecting: false,
            hub_connected: false,
            hub_authenticated: false,
            hub_session_key: Locked::new(),
            last_hub_connect_attempt: 0,
            last_hub_ping_time: 0,
            last_hub_activity: 0,
            last_hub_pong_sent: 0,
            last_op_request_sent: 0,
            last_chan_request_sent: 0,
            chan_req_fallback_idx: 0,
            unban_jobs: vec![UnbanJob::default(); MAX_UNBAN_JOBS],
            hub_connect_time: 0,
            bot_tree: Vec::new(),
            bot_tree_ts: 0,
            presence_server: String::new(),
            last_presence_sent: 0,
            upgrade_id: String::new(),
            upgrade_target: String::new(),
            upgrade_variant: String::new(),
            upgrade_base: String::new(),
            upgrade_prepared: 0,
            upgrade_installed_id: String::new(),
            upgrade_report: None,
            sendq: SendQ::default(),
            isup: Isupport::default(),
            net_modes: String::new(),
            net_settings: String::new(),
            net_set: ChanSettings::default(),
            net_ts: 0,
            cfg_bans: Vec::new(),
            chan_event: ChanEventLim::default(),
            cfg_gen: 0,
            enf_seen_gen: 0,
            jobs: vec![PendingJob::default(); MAX_PENDING_JOBS],
            ban_track: Vec::new(),
            auth_gen: Cell::new(0),
            auth_seen_cfg_gen: Cell::new(0),
            auth_fp: Cell::new(0),
            auth_fp_ms: Cell::new(0),
            offences: vec![Offence::default(); MAX_OFFENCES],
            enf_recent: vec![EnfRecent::default(); ENF_RECENT],
            enf_recent_idx: 0,
            enf_last_minute: 0,
            flood: BotFlood::default(),
        }
    }

    /// A connected-looking state for unit tests: no sockets, and the send
    /// queue holds its lines (no credit, so nothing is written).
    #[cfg(test)]
    pub fn for_test() -> Self {
        let poll = mio::Poll::new().expect("poll");
        let mut s = BotState::new(poll.registry().try_clone().expect("registry"));
        s.status |= S_CONNECTED;
        s.sendq.credit_ms = 0;
        s.sendq.last_ms = i64::MAX;
        s.bot_uuid = "11111111-1111-4111-8111-111111111111".into();
        s.current_nick = "me".into();
        s
    }

    /// A fresh poll token for `slot` (see net::Slot).
    pub fn new_token(&mut self, slot: usize) -> mio::Token {
        self.next_gen = self.next_gen.wrapping_add(1).max(1);
        mio::Token((self.next_gen << 4) | slot)
    }

    /// is_opt_set(): network option letter present (case-sensitive).
    pub fn is_opt_set(&self, c: char) -> bool {
        self.opt_flags.contains(c)
    }

    /// bot_set_startup_pass().
    pub fn set_startup_pass(&mut self, pass: &str) {
        self.startup_password.set_str(pass);
    }

    /// bot_get_startup_pass(): a wiped-on-drop copy.
    pub fn startup_pass(&self) -> Zeroizing<String> {
        self.startup_password.get_str()
    }
}

/// Timestamp for changing an existing replicated record: now, but always
/// past its previous stamp (hubs and bots accept only a strictly newer one).
pub fn lww_next_ts(prev: i64) -> i64 {
    let t = now();
    if t > prev { t } else { prev + 1 }
}

/// LWW acceptance for an add/del record: newer wins; on a tie a delete beats
/// an add.  Mirrors irchub hub_lww_accepts.
pub fn lww_accepts(in_ts: i64, in_active: bool, cur_ts: i64, cur_active: bool) -> bool {
    in_ts > cur_ts || (in_ts == cur_ts && cur_active && !in_active)
}

/// LWW acceptance for the hub-pushed opt flags: newer wins; on a tie the
/// byte-wise greater flag string wins.  Mirrors irchub hub_opt_accepts.
pub fn opt_accepts(in_ts: i64, in_flags: &str, cur_ts: i64, cur_flags: &str) -> bool {
    in_ts > cur_ts || (in_ts == cur_ts && in_flags.as_bytes() > cur_flags.as_bytes())
}

pub fn is_valid_bot_nick(nick: &str) -> bool {
    !nick.is_empty() && nick.len() < MAX_NICK && !nick.contains('|')
}

/// A nick every ircd accepts (RFC 2812), within is_valid_bot_nick's length.
pub fn is_rfc_nick(nick: &str) -> bool {
    if !is_valid_bot_nick(nick) {
        return false;
    }
    nick.bytes().enumerate().all(|(i, c)| {
        let letter = c.is_ascii_alphabetic();
        let special = b"[]\\`_^{}".contains(&c);
        let later = c.is_ascii_digit() || c == b'-';
        letter || special || (later && i != 0)
    })
}

/// True if any C0 control byte or DEL is present.
pub fn has_control_bytes(buf: &[u8]) -> bool {
    buf.iter().any(|&b| b < 0x20 || b == 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_nicks() {
        assert!(is_rfc_nick("bot1"));
        assert!(is_rfc_nick("[x]-y"));
        assert!(!is_rfc_nick("1bot"));
        assert!(!is_rfc_nick("-bot"));
        assert!(!is_rfc_nick("bot|x"));
        assert!(!is_rfc_nick("abcdefghij"));
    }

    #[test]
    fn lww_rules() {
        assert!(lww_accepts(2, true, 1, false));
        assert!(lww_accepts(1, false, 1, true));
        assert!(!lww_accepts(1, true, 1, false));
        assert!(opt_accepts(5, "h", 5, ""));
        assert!(!opt_accepts(5, "", 5, "h"));
    }
}
