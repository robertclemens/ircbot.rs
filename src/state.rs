//! The bot's state (bot_state_t and the records it holds) and the small
//! inline rules from bot.h (LWW acceptance, nick validation).

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
}

#[derive(Clone, Debug, Default)]
pub struct RosterEntry {
    pub nick: String,
    pub hostmask: String,
    pub is_op: bool,
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
    pub last_access_request: [i64; CHAN_REQ_KIND_COUNT],
    pub access_retry_count: [i32; CHAN_REQ_KIND_COUNT],
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
    pub server: String,
    pub uptime: i64,
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
        }
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
