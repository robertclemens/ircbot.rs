"""ircbot_hexchat_auth.py — v2 (~A2/~A2A/~A2K) key-based admin-command client
for ircbot, HexChat edition.  There are no passwords: each admin/oper has an
Ed25519+X25519 keypair (ircbot/utils/keygen), and the bot only ever learns
the *public* half.

Protocol (must match commands.c / crypto.c exactly — see
irchub/docs/passwordless.md #4): on the first command to a bot this script
signs a "~A2A <sig> <ts>:<nonce>" request with your Ed25519 key; the bot
replies with a NOTICE "~A2K <b64>" carrying its own public key, sealed
(X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to your X25519 key and bound to
that request's ts:nonce.  Once that lockbox is opened and cached, every admin
command travels as a fresh "~A2 <b64>" PRIVMSG: a per-command X25519
ephemeral key is mixed with your static key so the bot can both decrypt and
authenticate the sender.  ~A2K notices are protocol traffic and are always
hidden from the chat window.

Dependency:  pip install cryptography      (or: apt install python3-cryptography)
All crypto runs in-process: your private key material never reaches a
command line, an environment variable, or a temp file, and this script never
shells out to openssl(1) or any other external program.

Install:
    cp ircbot_hexchat_auth.py ~/.config/hexchat/addons/

Setup:
    1. Make a keypair with ircbot/utils/keygen (or irchub/bin/keygen); give
       the bot admin the .public.b64 contents, keep the .private.b64 to
       yourself and `chmod 600` it -- this script warns (but still runs) if
       it is not.
    2. /BOTCMD keyfile /home/you/NAME.private.b64
    3. Optionally pin bots to their key:
       /BOTCMD pinfile /home/you/.ircbot_bot_pins    (chmod 600 on first write)
       /BOTCMD pinfile off                            (disable pinning; default)
    4. /BOTCMD <bot_nick> <command> [args...]

Usage:
    /BOTCMD   <bot_nick> <command> [args...]   - auto-authenticates, then sends
    /BOTAUTH  <bot_nick>                       - drop the cached key, re-auth now
    /BOTFORGET <bot_nick>                      - drop the cached key (and pin)
    /BOTUNLOCK                                 - enter the key's passphrase now
    /BOTLOCK                                   - forget the unlocked key now

Passphrase-protected keys (keygen asks for one; irchub/docs/console.md §9):
the first /BOTCMD that needs the key asks for the passphrase and waits.  Type
it and press Enter: the keys never reach the input box (it shows stars) or
its history, and nothing is sent (Escape or an empty line cancels; pasting is
not taken).  The key then stays unlocked for passwd_expire from the unlock,
then the script asks again:
    /BOTCMD passwd_expire 6h     (default 1h; 0 = ask for every command;
                                  30m, 2d, a number of seconds, or never =
                                  until /BOTLOCK or the script is unloaded)
Three wrong passphrases in a row lock the prompt for 30 s.  Changing keyfile
or passwd_expire locks the key.

Sealed replies (on by default): commands go out as "~A2S <b64>", which asks
the bot to seal its answers too ("~A2R <b64>", only this command's sender can
open them).  They are shown in place, decrypted, behind a lock marker:
    /BOTCMD marker <text|off>    (default U+1F512)
    /BOTCMD sealed off           (plain ~A2 / plaintext replies, for bots
                                  older than ~A2S)
A marked line provably came from the bot; an unmarked "reply" did not go
through this protection.

DCC chat: `/BOTCMD <bot> dcc` makes the bot offer a passive DCC chat; accept
it in HexChat.  HexChat then listens (open its DCC port range in your
firewall, and set its DCC IP to your public address if you are behind NAT)
and the bot connects to it.  While that chat is open, /BOTCMD sends each
sealed command down the chat instead of by PRIVMSG, and the bot answers there.
Plain text typed into the bot's dialog while the chat is open is sealed the
same way before it is sent (never sent as typed).

Compare a bot's key fingerprint (printed here on every successful auth)
against that bot's own 'status' output or the hub console's 'bot list' before
trusting it for the first time.
"""

import base64
import hashlib
import os
import re
import time
from collections import namedtuple

import hexchat
# Imported defensively so a missing dependency shows one actionable line in the
# client instead of an ImportError traceback at load time.
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

CRYPTO_HINT = ("bot_auth: the 'cryptography' module is not installed — this "
               "script cannot do the Curve25519/AES-GCM handshake without it. "
               "Install one of:  sudo apt install python3-cryptography  |  "
               "pip install cryptography")

__module_name__ = "ircbot_hexchat_auth"
__module_version__ = "6.2.0"
__module_description__ = "Sends ~A2 admin commands to ircbot (Curve25519 + AES-256-GCM, passwordless)"

AUTH_TIMEOUT = 60     # seconds a pending ~A2A stays valid
MAX_QUEUE = 5         # queued commands per bot while authenticating

PASSWD_EXPIRE_DEFAULT = 3600
PASS_MAX = 1024       # passphrase bytes, as keygen
PROMPT_TIMEOUT = 120  # seconds the passphrase prompt waits
FAIL_LIMIT = 3        # wrong passphrases before the prompt pauses
FAIL_PAUSE = 30       # seconds of that pause

ClientKey = namedtuple("ClientKey",
                        ["ed_priv", "x_priv", "ed_pub", "x_pub", "pub64", "warning",
                         "plain"])

# irckey-v2 (a passphrase-protected .private.b64, irchub/docs/console.md §9):
# "irckey-v2 scrypt <log2N> <r> <p> <salt> <nonce> <ct>".  Reader bounds as
# in keygen: a hostile file costs at most 128 * r * N = 256 MB.
IRCKEY_TAG = "irckey-v2"
IRCKEY_LOG2N = (14, 18)
IRCKEY_R = (1, 8)
IRCKEY_P = (1, 4)


class KeyLocked(Exception):
    """The keyfile is passphrase-protected and no passphrase was given."""


# =============================================================================
# Pure protocol functions — no `hexchat` calls anywhere below this line down
# to the "HexChat glue" section.  Callable standalone by a test harness that
# has stubbed `hexchat` into sys.modules before import.
#
# Note on memory hygiene: Python `bytes` are immutable, so shared secrets,
# derived keys, and decrypted plaintext returned by the `cryptography`
# library cannot be reliably zeroed in-process the way the Perl/C
# implementations do (a `bytearray` copy could be wiped, but the original
# immutable object handed back by the library would still linger until the
# garbage collector reclaims it).  This is a known limitation of doing crypto
# in pure Python; keep the process lifetime short and the keyfile chmod 600.
# =============================================================================

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_LC_TABLE = str.maketrans(_UPPER, _LOWER)


def _lc(s):
    """ASCII-only lowercase: A-Z -> a-z, every other character unchanged."""
    return s.translate(_LC_TABLE)


def _b64_exact(text, n):
    raw = base64.b64decode(text, validate=True)
    if len(raw) != n or len(text) != 4 * ((n + 2) // 3):
        raise ValueError("bad field")
    return raw


def irckey_open(line, passphrase):
    """The 64-byte private key inside an irckey-v2 line.  The scrypt settings
    are bounds-checked before any work; ValueError on a malformed line, a
    wrong passphrase or any edit to the line."""
    if len(line) >= 512 or "  " in line or line.endswith(" "):
        raise ValueError("malformed irckey-v2 line")
    f = line.split(" ")
    if len(f) != 8 or f[0] != IRCKEY_TAG or f[1] != "scrypt":
        raise ValueError("malformed irckey-v2 line")
    nums = []
    for v, (lo, hi) in zip(f[2:5], (IRCKEY_LOG2N, IRCKEY_R, IRCKEY_P)):
        if not v.isdigit() or len(v) > 3 or not lo <= int(v) <= hi:
            raise ValueError("irckey-v2 scrypt settings out of range")
        nums.append(int(v))
    log2n, r, p = nums
    try:
        salt, nonce, ct = _b64_exact(f[5], 16), _b64_exact(f[6], 12), _b64_exact(f[7], 80)
    except Exception as exc:
        raise ValueError("malformed irckey-v2 line") from exc
    key = hashlib.scrypt(passphrase, salt=salt, n=1 << log2n, r=r, p=p,
                         maxmem=128 * r * (1 << log2n) + (2 << 20), dklen=32)
    try:
        return AESGCM(key).decrypt(nonce, ct, line[:line.rindex(" ")].encode("ascii"))
    except Exception as exc:
        raise ValueError("wrong passphrase (or a damaged key file)") from exc


def key_is_protected(path):
    """True if the keyfile at path is an irckey-v2 (passphrase) key."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.readline().startswith(IRCKEY_TAG + " ")


def load_key(path, passphrase=None):
    """Load the combined Ed25519+X25519 private key from `path`: either the
    plain first line (standard base64 with padding, decoding to exactly 64
    bytes: ed_priv(32) || x_priv(32)) or an irckey-v2 line, which needs
    `passphrase` (bytes) and raises KeyLocked without it.  Returns a
    ClientKey.  Raises ValueError/OSError on any failure.  `.warning` is a
    mode-permission message, or None; `.plain` is True for a key without a
    passphrase.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw_line = fh.readline()
    line = raw_line.rstrip("\r\n")
    if line.startswith(IRCKEY_TAG + " "):
        if passphrase is None:
            raise KeyLocked(path)
        raw, plain = irckey_open(line, passphrase), False
    else:
        raw_b64 = raw_line.strip()
        if not raw_b64:
            raise ValueError("keyfile '%s' is empty" % path)
        try:
            raw = base64.b64decode(raw_b64, validate=True)
        except Exception as exc:
            raise ValueError("keyfile '%s': invalid base64 (%s)" % (path, exc)) from exc
        plain = True
    if len(raw) != 64:
        raise ValueError("keyfile '%s': decoded key must be 64 bytes, got %d"
                          % (path, len(raw)))

    ed_priv, x_priv = raw[:32], raw[32:64]
    ed_pub = Ed25519PrivateKey.from_private_bytes(ed_priv).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    x_pub = X25519PrivateKey.from_private_bytes(x_priv).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    pub64 = base64.b64encode(ed_pub + x_pub).decode("ascii")

    warning = None
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            warning = ("keyfile '%s' is mode %04o — chmod 600 it"
                       % (path, st.st_mode & 0o7777))
    except OSError:
        pass

    return ClientKey(ed_priv=ed_priv, x_priv=x_priv, ed_pub=ed_pub, x_pub=x_pub,
                     pub64=pub64, warning=warning, plain=plain)


def parse_expire(text):
    """passwd_expire: "1h", "30m", "90s", "2d", "3600" -> seconds; "never"
    -> -1; None if unreadable.  0 = ask for every command."""
    text = (text or "").strip().lower()
    if text == "never":
        return -1
    m = re.fullmatch(r"(\d{1,12})([smhd]?)", text)
    if not m:
        return None
    secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return secs if secs <= 366 * 86400 else None


def fingerprint(pub64):
    """"ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64), where pub64 is
    the raw 64-byte combined public key (ed_pub(32) || x_pub(32))."""
    h = hashlib.sha256(pub64).digest()[:8]
    hexstr = h.hex()
    return ":".join(hexstr[i:i + 4] for i in range(0, 16, 4))


def build_auth(key, botnick, mynick):
    """Build one ~A2A auth request.  Returns (line, tsn)."""
    nonce = os.urandom(8).hex()   # 16 lowercase hex chars
    tsn = "%d:%s" % (int(time.time()), nonce)
    msg = (b"ircbot-A2A-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8") + b"\0" + tsn.encode("ascii"))
    sig = Ed25519PrivateKey.from_private_bytes(key.ed_priv).sign(msg)
    line = "~A2A " + base64.b64encode(sig).decode("ascii") + " " + tsn
    return line, tsn


def open_lockbox(key, botnick, mynick, tsn, b64):
    """Open a ~A2K lockbox.  `tsn` must be the ts:nonce of the pending request
    this reply answers.  Returns the bot's raw 64-byte combined public key on
    success, or None on any failure (malformed frame, bad point, wrong tag).
    """
    try:
        frame = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    if len(frame) != 124:
        return None
    eph, iv, ct, tag = frame[0:32], frame[32:44], frame[44:108], frame[108:124]

    try:
        ss = X25519PrivateKey.from_private_bytes(key.x_priv).exchange(
            X25519PublicKey.from_public_bytes(eph))
    except Exception:
        return None
    if ss == b"\x00" * 32:   # reject a low-order point
        return None

    info = b"ircbot-A2K-v1" + key.x_pub
    km = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph, info=info).derive(ss)

    aad = (b"ircbot-A2K-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8") + b"\0" + tsn.encode("ascii"))
    try:
        pt = AESGCM(km).decrypt(iv, ct + tag, aad)
    except Exception:
        return None
    if len(pt) != 64:
        return None
    return pt


def _seal_command(key, bot_pub64, botnick, mynick, command, sealed):
    """(line, reply_key): a ~A2S frame and its reply key when `sealed`, else a
    ~A2 frame and None.  Raises ValueError if the command must be refused
    (control byte, or the finished line would exceed the 400-char budget)."""
    if any(b < 0x20 or b == 0x7F for b in command.encode("utf-8")):
        raise ValueError("command contains a control character")
    label = b"ircbot-A2S-v1" if sealed else b"ircbot-A2-v1"

    nonce = os.urandom(8).hex()
    pt = ("%d:%s:%s" % (int(time.time()), nonce, command)).encode("utf-8")

    bot_x_pub = bot_pub64[32:64]
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    dh1 = eph_priv.exchange(X25519PublicKey.from_public_bytes(bot_x_pub))
    dh2 = X25519PrivateKey.from_private_bytes(key.x_priv).exchange(
        X25519PublicKey.from_public_bytes(bot_x_pub))
    if dh1 == b"\x00" * 32 or dh2 == b"\x00" * 32:
        raise ValueError("key exchange produced a degenerate shared secret")

    def kdf(lbl):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub,
                    info=lbl + key.x_pub + bot_x_pub).derive(dh1 + dh2)
    km = kdf(label)
    rk = kdf(b"ircbot-A2R-v1") if sealed else None

    iv = os.urandom(12)
    aad = (label + b"\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8"))
    ct_tag = AESGCM(km).encrypt(iv, pt, aad)

    frame = eph_pub + iv + ct_tag
    line = ("~A2S " if sealed else "~A2 ") + base64.b64encode(frame).decode("ascii")
    if len(line) > 400:
        raise ValueError("command is too long (%d > 400 chars on the wire)" % len(line))
    return line, rk


def build_command(key, bot_pub64, botnick, mynick, command):
    """Build one ~A2 sealed command.  `bot_pub64` is the bot's raw 64-byte
    combined public key (as returned by open_lockbox).  Returns the line to
    send.  Raises ValueError if the command must be refused (control byte,
    or the finished line would exceed the 400-char budget)."""
    return _seal_command(key, bot_pub64, botnick, mynick, command, False)[0]


def build_sealed_command(key, bot_pub64, botnick, mynick, command):
    """Build one ~A2S command: like ~A2, but the bot seals its replies to it
    (~A2R).  Returns (line, reply_key), the key being HKDF(same ikm, eph_pub,
    "ircbot-A2R-v1" || my_x || bot_x).  Raises ValueError like build_command."""
    return _seal_command(key, bot_pub64, botnick, mynick, command, True)


def open_reply(reply_key, botnick, mynick, b64):
    """Open one ~A2R reply to a ~A2S command, with that command's reply key and
    context nicks.  Returns (seq, more, text): text is one piece of a reply
    line, continued in the next frame when more is 1.  None on any failure."""
    try:
        frame = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    if len(frame) < 28 or len(frame) > 28 + 264:
        return None
    aad = (b"ircbot-A2R-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8"))
    try:
        pt = AESGCM(reply_key).decrypt(frame[:12], frame[12:], aad)
    except Exception:
        return None
    head, sep, text = pt.partition(b":")
    more, sep2, text = text.partition(b":")
    if (not sep or not sep2 or not head.isdigit() or len(head) > 19
            or more not in (b"0", b"1")):
        return None
    return int(head), more == b"1", text.decode("utf-8", errors="replace")


# =============================================================================
# Pin-file helpers.  Plain file I/O, no `hexchat` calls.
# =============================================================================

def pin_lookup(pinfile, bot_lc):
    try:
        with open(pinfile, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0] == bot_lc:
                    return parts[1]
    except OSError:
        pass
    return None


def pin_add(pinfile, bot_lc, pub_b64):
    is_new = not os.path.exists(pinfile)
    fd = os.open(pinfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write("%s %s\n" % (bot_lc, pub_b64))
    if is_new:
        try:
            os.chmod(pinfile, 0o600)
        except OSError:
            pass


def pin_remove(pinfile, bot_lc):
    try:
        with open(pinfile, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    kept = [ln for ln in lines if ln.strip().split(" ", 1)[:1] != [bot_lc]]
    if len(kept) != len(lines):
        with open(pinfile, "w", encoding="utf-8") as fh:
            fh.writelines(kept)


# =============================================================================
# HexChat glue.  Everything below touches `hexchat`.
# =============================================================================

_KEY_CACHE = {}   # (network, bot_lc) -> bot_pub64 (raw 64 bytes)
_PENDING = {}     # same key          -> (tsn, send_time)
_QUEUE = {}       # same key          -> [command_line, ...]
_DCC_NICK = {}    # same key          -> our nick when we asked for the DCC chat
_REPLY_KEYS = {}  # same key          -> [{rk, bot, me, t, next, part}, ...] newest first
_NOTED = {}       # same key          -> time of the last "could not open" note
_EMITTING = [False]

DCC_CHAT_TYPES = (2, 3)   # get_list("dcc") type: chat receive / chat send
DCC_ACTIVE = 1            # get_list("dcc") status: active
REPLY_KEY_TTL = 600       # seconds a ~A2S reply key lives after its last use
MAX_REPLY_KEYS = 8        # reply keys kept per bot
DEFAULT_MARKER = "\U0001F512"


def _sealed_on():
    return (hexchat.get_pluginpref("bot_auth_sealed_replies") or "on") != "off"


def _marked(text):
    m = hexchat.get_pluginpref("bot_auth_sealed_marker")
    m = DEFAULT_MARKER if m is None else ("" if m == "off" else m)
    return "%s %s" % (m, text) if m else text


def _remember_reply_key(ck, rk, bot, me):
    """A ~A2S command's reply key, with the nicks its replies are bound to."""
    keys = _REPLY_KEYS.setdefault(ck, [])
    keys.insert(0, {"rk": rk, "bot": bot, "me": me, "t": time.time(),
                    "next": 0, "part": ""})
    del keys[MAX_REPLY_KEYS:]


def _reply_text(ck, b64):
    """One ~A2R frame from a bot, tried against the keys of the commands we
    sealed to it (newest first): ("show", line) for a complete reply line,
    ("hold", None) for a piece of a longer line or a repeat, ("bad", None) if
    no key opens it.  A missing piece is marked "[...]" in the joined line."""
    now = time.time()
    keys = [e for e in _REPLY_KEYS.get(ck, []) if now - e["t"] <= REPLY_KEY_TTL]
    _REPLY_KEYS[ck] = keys
    for e in keys:
        got = open_reply(e["rk"], e["bot"], e["me"], b64)
        if got is None:
            continue
        seq, more, text = got
        if seq < e["next"]:
            return "hold", None
        if seq > e["next"] and e["part"]:
            e["part"] += " [...] "
        e["next"], e["t"] = seq + 1, now
        e["part"] += text
        if more:
            return "hold", None
        line, e["part"] = e["part"], ""
        return "show", line
    return "bad", None


def _note_unopened(ck, nick):
    if time.time() - _NOTED.get(ck, 0) < 30:
        return
    _NOTED[ck] = time.time()
    hexchat.prnt("bot_auth: a sealed reply from %s could not be opened (it answers a "
                 "command this session did not send); hidden." % nick)


def _net_key():
    return hexchat.get_info("network") or hexchat.get_info("server") or ""


# The unlocked passphrase-protected key: {"key", "path", "until" (None =
# never), "once" (passwd_expire 0: lock after this command)}.  Python cannot
# wipe the key's bytes (see the note at the top); locking drops every
# reference.
_UNLOCKED = {}
# The passphrase prompt while it waits: {"path", "t", "typed": [...],
# "saved": input box text, "pending": [...]}.
_CAPTURE = {}
_FAILS = {"n": 0, "until": 0.0}
_WARNED = set()   # keyfiles already warned about having no passphrase
LOCKED = "locked"  # _load_key_pref() error: ask for the passphrase
KEY_ENTER = ("65293", "65421")   # GDK Return, KP_Enter
KEY_BACKSPACE = "65288"
KEY_ESCAPE = "65307"
MOD_CTRL_ALT = 4 | 8             # GDK control / mod1 masks


def _expire_secs():
    v = hexchat.get_pluginpref("bot_auth_passwd_expire") or "1h"
    secs = parse_expire(v)
    if secs is None:
        hexchat.prnt("bot_auth: passwd_expire '%s' is not e.g. 30m, 1h, 6h, 1d, 0 or "
                     "never; using 1h" % v)
        return PASSWD_EXPIRE_DEFAULT
    return secs


def _lock(why=None):
    had = bool(_UNLOCKED)
    _UNLOCKED.clear()
    if had and why:
        hexchat.prnt("bot_auth: %s" % why)


def _load_key_pref():
    path = hexchat.get_pluginpref("bot_auth_keyfile")
    if not path:
        return None, "no keyfile set — /BOTCMD keyfile <path>"
    try:
        if key_is_protected(path):
            u = _UNLOCKED
            if u and u["path"] == path and (u["until"] is None or time.time() < u["until"]):
                return u["key"], None
            _lock("key locked again (passwd_expire)" if u else None)
            return None, LOCKED
        key = load_key(path)
    except Exception as exc:                      # noqa: BLE001 - report to user
        return None, "keyfile error: %s" % exc
    if path not in _WARNED:
        _WARNED.add(path)
        hexchat.prnt("bot_auth: keyfile '%s' has no passphrase — add one with: "
                     "keygen --passwd %s" % (path, path))
    return key, None


def _used_once():
    """passwd_expire 0: lock once nothing more is waiting for the key."""
    if _UNLOCKED.get("once") and not _PENDING and not _CAPTURE:
        _lock()


def _ask_passphrase(pending=None):
    """Arm the passphrase prompt; `pending` (a /BOTCMD's bot and command)
    runs after a successful unlock."""
    path = hexchat.get_pluginpref("bot_auth_keyfile")
    now = time.time()
    if now < _FAILS["until"]:
        hexchat.prnt("bot_auth: too many wrong passphrases; try again in %d s."
                     % (_FAILS["until"] - now + 1))
        return
    if _CAPTURE:
        if pending and len(_CAPTURE["pending"]) < MAX_QUEUE:
            _CAPTURE["pending"].append(pending)
        hexchat.prnt("bot_auth: still waiting for the passphrase (Escape cancels).")
        return
    _CAPTURE.update(path=path, t=now, typed=[], pending=[pending] if pending else [],
                    saved=hexchat.get_info("inputbox") or "")
    hexchat.command("SETTEXT ")
    hexchat.prnt("bot_auth: passphrase for %s: type it and press Enter — it never "
                 "reaches the input box or its history and is never sent (Escape "
                 "cancels)." % path)


def _end_capture():
    """The prompt's state, the prompt closed and the input box restored."""
    cap = dict(_CAPTURE)
    _CAPTURE.clear()
    hexchat.command("SETTEXT %s" % cap.get("saved", ""))
    return cap


def _cancel_capture(why):
    if _CAPTURE:
        cap = _end_capture()
        n = len(cap["pending"])
        hexchat.prnt("bot_auth: %s%s" % (why, "; dropped %d command(s)" % n if n else ""))


def _try_unlock(cap, passphrase):
    if not passphrase:
        n = len(cap["pending"])
        hexchat.prnt("bot_auth: passphrase prompt cancelled%s"
                     % ("; dropped %d command(s)" % n if n else ""))
        return
    pw = passphrase.encode("utf-8")
    if len(pw) > PASS_MAX:
        hexchat.prnt("bot_auth: passphrase too long.")
        return
    try:
        key = load_key(cap["path"], pw)
    except Exception as exc:                      # noqa: BLE001 - report to user
        _FAILS["n"] += 1
        if _FAILS["n"] >= FAIL_LIMIT:
            _FAILS.update(n=0, until=time.time() + FAIL_PAUSE)
        hexchat.prnt("bot_auth: %s%s" % (exc, "; dropped %d command(s)" % len(cap["pending"])
                                         if cap["pending"] else ""))
        return
    _FAILS.update(n=0, until=0.0)
    secs = _expire_secs()
    now = time.time()
    _UNLOCKED.clear()
    _UNLOCKED.update(key=key, path=cap["path"], once=secs == 0,
                     until=None if secs < 0 else now + max(secs, AUTH_TIMEOUT if secs == 0 else 0))
    if secs < 0:
        hexchat.prnt("bot_auth: key unlocked until /BOTLOCK.")
    elif secs == 0:
        hexchat.prnt("bot_auth: key unlocked for this command.")
    else:
        hexchat.prnt("bot_auth: key unlocked until %s (passwd_expire)."
                     % time.strftime("%H:%M:%S", time.localtime(now + secs)))
    for p in cap["pending"]:
        _handle_botcmd(*p)
    _used_once()


def cb_keypress(word, word_eol, userdata):
    """While the passphrase prompt waits, every key goes to it: the input box
    only ever shows stars, and nothing reaches its history or the server."""
    if not _CAPTURE:
        return hexchat.EAT_NONE
    keyval = word[0] if word else ""
    try:
        state = int(word[1]) if len(word) > 1 else 0
    except ValueError:
        state = 0
    typed = _CAPTURE["typed"]
    if keyval in KEY_ENTER:
        cap = _end_capture()
        _try_unlock(cap, "".join(cap["typed"]))
        cap["typed"][:] = []
        return hexchat.EAT_ALL
    if keyval == KEY_ESCAPE:
        _cancel_capture("passphrase prompt cancelled")
        return hexchat.EAT_ALL
    if keyval == KEY_BACKSPACE:
        if typed:
            typed.pop()
    elif not state & MOD_CTRL_ALT and len(word) > 2 and word[2] and word[2].isprintable():
        if len(typed) < PASS_MAX:
            typed.append(word[2])
    hexchat.command("SETTEXT %s" % ("*" * len(typed)))
    return hexchat.EAT_ALL


def _expire_pending(ck):
    pend = _PENDING.get(ck)
    if not pend or time.time() - pend[1] <= AUTH_TIMEOUT:
        return
    del _PENDING[ck]
    q = _QUEUE.pop(ck, None)
    if q:
        hexchat.prnt("bot_auth: auth with %s timed out; dropped %d queued command(s)."
                     % (ck[1], len(q)))


def _send_auth(network, bot_nick, mynick, key):
    try:
        line, tsn = build_auth(key, bot_nick, mynick)
    except Exception as exc:                      # noqa: BLE001 - report to user
        hexchat.prnt("bot_auth: failed to build auth request: %s" % exc)
        return
    _PENDING[(network, _lc(bot_nick))] = (tsn, time.time())
    hexchat.command("QUOTE PRIVMSG %s :%s" % (bot_nick, line))
    hexchat.prnt("bot_auth: authenticating with %s..." % bot_nick)


def _dcc_chat_open(bot_nick):
    for d in hexchat.get_list("dcc") or []:
        if (d.type in DCC_CHAT_TYPES and d.status == DCC_ACTIVE
                and _lc(d.nick) == _lc(bot_nick)):
            return True
    return False


def _send_command(network, bot_nick, mynick, key, bot_pub64, command_line):
    """A command goes down the bot's DCC chat when one is open, else by
    PRIVMSG.  On the chat the bot takes the sender nick to be the one that
    asked for it.  Sealed replies on (the default): a ~A2S frame, and its
    reply key is kept to open the answers.  True once sent."""
    ck = (network, _lc(bot_nick))
    dcc = _dcc_chat_open(bot_nick)
    as_nick = _DCC_NICK.get(ck, mynick) if dcc else mynick
    try:
        line, rk = _seal_command(key, bot_pub64, bot_nick, as_nick, command_line,
                                 _sealed_on())
    except ValueError as exc:
        hexchat.prnt("bot_auth: %s" % exc)
        return False
    if rk:
        _remember_reply_key(ck, rk, bot_nick, as_nick)
    if dcc:
        hexchat.command("MSG =%s %s" % (bot_nick, line))
        return True
    if (command_line.split(None, 1) or [""])[0].lower() == "dcc":
        _DCC_NICK[ck] = mynick
    hexchat.command("QUOTE PRIVMSG %s :%s" % (bot_nick, line))
    return True


def _handle_botcmd(bot_nick, command_line):
    network = _net_key()
    mynick = hexchat.get_info("nick") or ""

    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase((bot_nick, command_line))
        return
    if err:
        hexchat.prnt("bot_auth: %s" % err)
        return
    if key.warning:
        hexchat.prnt("bot_auth: %s" % key.warning)

    ck = (network, _lc(bot_nick))
    _expire_pending(ck)

    bot_pub64 = _KEY_CACHE.get(ck)
    if bot_pub64:
        _send_command(network, bot_nick, mynick, key, bot_pub64, command_line)
        _used_once()
        return

    q = _QUEUE.setdefault(ck, [])
    if len(q) >= MAX_QUEUE:
        hexchat.prnt("bot_auth: queue for %s is full (max %d); dropping oldest."
                     % (bot_nick, MAX_QUEUE))
        q.pop(0)
    q.append(command_line)

    if ck in _PENDING:
        hexchat.prnt("bot_auth: already authenticating with %s; command queued." % bot_nick)
        return
    _send_auth(network, bot_nick, mynick, key)


def cb_botcmd(word, word_eol, userdata):
    if not CRYPTO_OK:
        hexchat.prnt(CRYPTO_HINT)
        return hexchat.EAT_ALL

    if len(word) < 2:
        hexchat.prnt("Usage: /BOTCMD <bot_nick> <command> [args...]")
        hexchat.prnt("       /BOTCMD keyfile <path>   |   /BOTCMD pinfile <path|off>")
        return hexchat.EAT_ALL

    if word[1].lower() == "keyfile":
        if len(word) < 3 or not word_eol[2].strip():
            hexchat.prnt("Usage: /BOTCMD keyfile <path>")
            return hexchat.EAT_ALL
        hexchat.set_pluginpref("bot_auth_keyfile", word_eol[2])
        hexchat.prnt("bot_auth: keyfile set to %s" % word_eol[2])
        _cancel_capture("keyfile changed: passphrase prompt cancelled")
        _lock("keyfile changed: key locked.")
        return hexchat.EAT_ALL

    if word[1].lower() == "pinfile":
        if len(word) < 3 or not word_eol[2].strip():
            hexchat.prnt("Usage: /BOTCMD pinfile <path|off>")
            return hexchat.EAT_ALL
        val = word_eol[2].strip()
        if val.lower() == "off":
            val = ""
        hexchat.set_pluginpref("bot_auth_pinfile", val)
        hexchat.prnt("bot_auth: pinfile %s" % (("set to %s" % val) if val else "disabled"))
        return hexchat.EAT_ALL

    if word[1].lower() == "passwd_expire":
        val = word[2].strip() if len(word) > 2 else ""
        if parse_expire(val) is None:
            hexchat.prnt("Usage: /BOTCMD passwd_expire <0|30m|1h|6h|1d|secs|never>   (now %s)"
                         % (hexchat.get_pluginpref("bot_auth_passwd_expire") or "1h"))
            return hexchat.EAT_ALL
        hexchat.set_pluginpref("bot_auth_passwd_expire", val)
        hexchat.prnt("bot_auth: passwd_expire %s" % val)
        _cancel_capture("passwd_expire changed: passphrase prompt cancelled")
        _lock("passwd_expire changed: key locked.")
        return hexchat.EAT_ALL

    if word[1].lower() == "sealed":
        val = word[2].lower() if len(word) > 2 else ""
        if val not in ("on", "off"):
            hexchat.prnt("Usage: /BOTCMD sealed <on|off>   (now %s)"
                         % ("on" if _sealed_on() else "off"))
            return hexchat.EAT_ALL
        hexchat.set_pluginpref("bot_auth_sealed_replies", val)
        hexchat.prnt("bot_auth: sealed replies %s" % val)
        return hexchat.EAT_ALL

    if word[1].lower() == "marker":
        if len(word) < 3 or not word_eol[2].strip():
            hexchat.prnt("Usage: /BOTCMD marker <text|off>")
            return hexchat.EAT_ALL
        val = word_eol[2].strip()
        hexchat.set_pluginpref("bot_auth_sealed_marker", "off" if val.lower() == "off" else val)
        hexchat.prnt("bot_auth: sealed-reply marker %s" % ("off" if val.lower() == "off" else val))
        return hexchat.EAT_ALL

    if len(word) < 3:
        hexchat.prnt("Usage: /BOTCMD <bot_nick> <command> [args...]")
        return hexchat.EAT_ALL

    _handle_botcmd(word[1], word_eol[2])
    return hexchat.EAT_ALL


def cb_botauth(word, word_eol, userdata):
    if not CRYPTO_OK:
        hexchat.prnt(CRYPTO_HINT)
        return hexchat.EAT_ALL
    if len(word) < 2 or not word[1]:
        hexchat.prnt("Usage: /BOTAUTH <bot_nick>")
        return hexchat.EAT_ALL

    bot_nick = word[1]
    network = _net_key()
    mynick = hexchat.get_info("nick") or ""

    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase()
        hexchat.prnt("bot_auth: run /BOTAUTH %s again once the key is unlocked." % bot_nick)
        return hexchat.EAT_ALL
    if err:
        hexchat.prnt("bot_auth: %s" % err)
        return hexchat.EAT_ALL

    _KEY_CACHE.pop((network, _lc(bot_nick)), None)
    _send_auth(network, bot_nick, mynick, key)
    return hexchat.EAT_ALL


def cb_botforget(word, word_eol, userdata):
    if len(word) < 2 or not word[1]:
        hexchat.prnt("Usage: /BOTFORGET <bot_nick>")
        return hexchat.EAT_ALL

    bot_nick = word[1]
    network = _net_key()
    ck = (network, _lc(bot_nick))
    had = _KEY_CACHE.pop(ck, None) is not None
    _PENDING.pop(ck, None)
    _QUEUE.pop(ck, None)
    _DCC_NICK.pop(ck, None)
    _REPLY_KEYS.pop(ck, None)

    pinfile = hexchat.get_pluginpref("bot_auth_pinfile")
    if pinfile:
        pin_remove(pinfile, _lc(bot_nick))

    hexchat.prnt("bot_auth: forgot %s%s." % (bot_nick, "" if had else " (was not cached)"))
    return hexchat.EAT_ALL


def cb_notice(word, word_eol, userdata):
    if len(word) < 4:
        return hexchat.EAT_NONE
    prefix = word[0]
    text = word_eol[3]
    if text.startswith(":"):
        text = text[1:]
    if not text.startswith("~A2K "):
        return hexchat.EAT_NONE

    # Protocol traffic: always hidden, whether or not we can process it.
    nick = prefix[1:] if prefix.startswith(":") else prefix
    nick = nick.split("!", 1)[0]

    if not CRYPTO_OK:
        return hexchat.EAT_ALL

    network = _net_key()
    mynick = hexchat.get_info("nick") or ""
    ck = (network, _lc(nick))
    _expire_pending(ck)

    pend = _PENDING.pop(ck, None)
    if not pend:
        return hexchat.EAT_ALL   # no matching request: drop silently
    tsn, _sent = pend

    key, err = _load_key_pref()
    if err:
        hexchat.prnt("bot_auth: %s" % ("the key locked before %s answered; /BOTUNLOCK "
                                       "and try again" % nick if err == LOCKED else err))
        _QUEUE.pop(ck, None)
        return hexchat.EAT_ALL

    b64 = text[5:]
    bot_pub64 = open_lockbox(key, nick, mynick, tsn, b64)
    if bot_pub64 is None:
        hexchat.prnt("bot_auth: ~A2K from %s failed to decrypt/verify; ignored." % nick)
        return hexchat.EAT_ALL

    pinfile = hexchat.get_pluginpref("bot_auth_pinfile")
    if pinfile:
        bot_lc = _lc(nick)
        existing = pin_lookup(pinfile, bot_lc)
        got_b64 = base64.b64encode(bot_pub64).decode("ascii")
        if existing is None:
            pin_add(pinfile, bot_lc, got_b64)
        elif existing != got_b64:
            try:
                existing_raw = base64.b64decode(existing)
            except Exception:
                existing_raw = None
            hexchat.prnt(
                "bot_auth: WARNING pinned-key mismatch for %s! pinned %s got %s "
                "-- possible man-in-the-middle, or the bot was rekeyed. "
                "Run /BOTFORGET %s to accept the new key."
                % (nick, fingerprint(existing_raw) if existing_raw else "?",
                   fingerprint(bot_pub64), nick))
            return hexchat.EAT_ALL   # do NOT cache on a pin mismatch

    _KEY_CACHE[ck] = bot_pub64
    hexchat.prnt("bot_auth: authenticated with %s — key %s" % (nick, fingerprint(bot_pub64)))

    q = _QUEUE.pop(ck, [])
    for cmd in q:
        _send_command(network, nick, mynick, key, bot_pub64, cmd)
    _used_once()
    return hexchat.EAT_ALL


def cb_msg_send(word, word_eol, userdata):
    # "/MSG =bot <frame>" (a command sent down a DCC chat) echoes the frame
    # as "Message Send"; it is protocol traffic, so hide it.
    if len(word) >= 2 and word[1].startswith(("~A2 ", "~A2S ")):
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


def _show_reply(ck, nick, text, show):
    """A bot's ~A2R frame shown in place, decrypted and marked as sealed via
    show(marked_line); pieces of a longer line wait for the last one; a frame
    no key opens is hidden.  False if text is not a ~A2R frame."""
    if not text.startswith("~A2R "):
        return False
    st, line = _reply_text(ck, text[5:].strip()) if CRYPTO_OK else ("bad", None)
    if st == "show":
        _EMITTING[0] = True
        try:
            show(_marked(line))
        finally:
            _EMITTING[0] = False
    elif st == "bad":
        _note_unopened(ck, nick)
    return True


def cb_reply_print(word, word_eol, event):
    """"Private Message", "Private Message to Dialog", "Notice": word[0] is the
    nick, word[1] the text."""
    if _EMITTING[0] or len(word) < 2:
        return hexchat.EAT_NONE
    nick = word[0]
    if _show_reply((_net_key(), _lc(hexchat.strip(nick))), nick, word[1],
                   lambda line: hexchat.emit_print(event, nick, line)):
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


def cb_dcc_text(word, word_eol, userdata):
    """"DCC Chat Text": address, port, nick, text.  Eating it also stops
    HexChat's own display of the line in the nick's dialog, so the decrypted
    line is shown there instead."""
    if _EMITTING[0] or len(word) < 4:
        return hexchat.EAT_NONE
    nick = word[2]
    ctx = hexchat.find_context(channel=nick) or hexchat.get_context()
    if _show_reply((_net_key(), _lc(nick)), nick, word[3],
                   lambda line: ctx.emit_print("Private Message to Dialog", nick, line)):
        return hexchat.EAT_ALL
    return hexchat.EAT_NONE


def _is_dialog():
    ctx = hexchat.get_context()
    for c in hexchat.get_list("channels") or []:
        if c.context == ctx:
            return c.type == 3
    return False


def cb_say(word, word_eol, userdata):
    """Text typed into the dialog of a bot we asked for a DCC chat, while that
    chat is open: the chat only carries sealed frames (the bot closes it on
    anything else), so seal it like /BOTCMD and show it as typed.  If it
    cannot be sealed it is not sent.  Dialogs with anyone else pass."""
    if not word_eol or not _is_dialog():
        return hexchat.EAT_NONE
    bot = hexchat.get_info("channel") or ""
    network = _net_key()
    ck = (network, _lc(bot))
    if ck not in _DCC_NICK or not _dcc_chat_open(bot):
        return hexchat.EAT_NONE
    text = word_eol[0]
    if not CRYPTO_OK:
        hexchat.prnt(CRYPTO_HINT)
        return hexchat.EAT_ALL
    key, err = _load_key_pref()
    bot_pub64 = _KEY_CACHE.get(ck)
    if err == LOCKED:
        hexchat.prnt("bot_auth: the key is locked -- not sent; /BOTUNLOCK first")
        return hexchat.EAT_ALL
    if err or not bot_pub64:
        hexchat.prnt("bot_auth: %s -- not sent"
                     % (err or "no key for %s this session (/BOTAUTH %s)" % (bot, bot)))
        return hexchat.EAT_ALL
    mynick = hexchat.get_info("nick") or ""
    if _send_command(network, bot, mynick, key, bot_pub64, text):
        hexchat.emit_print("Your Message", mynick, text)
    _used_once()
    return hexchat.EAT_ALL


def cb_botunlock(word, word_eol, userdata):
    if not CRYPTO_OK:
        hexchat.prnt(CRYPTO_HINT)
        return hexchat.EAT_ALL
    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase()
    elif err:
        hexchat.prnt("bot_auth: %s" % err)
    elif key.plain:
        hexchat.prnt("bot_auth: the keyfile has no passphrase; nothing to unlock.")
    else:
        u = _UNLOCKED
        hexchat.prnt("bot_auth: already unlocked%s." % (
            " until /BOTLOCK" if u["until"] is None else
            " for %d more s" % max(0, u["until"] - time.time())))
    return hexchat.EAT_ALL


def cb_botlock(word, word_eol, userdata):
    _cancel_capture("passphrase prompt cancelled")
    had = bool(_UNLOCKED)
    _lock()
    hexchat.prnt("bot_auth: key locked." if had else "bot_auth: key was not unlocked.")
    return hexchat.EAT_ALL


def cb_timer(userdata):
    for ck in list(_PENDING.keys()):
        _expire_pending(ck)
    now = time.time()
    if _UNLOCKED and _UNLOCKED["until"] is not None and now >= _UNLOCKED["until"]:
        _lock("key locked again (passwd_expire); the next /BOTCMD asks for the passphrase.")
    if _CAPTURE and now - _CAPTURE["t"] > PROMPT_TIMEOUT:
        _cancel_capture("passphrase prompt timed out")
    return 1   # keep repeating


hexchat.hook_command("BOTCMD", cb_botcmd,
                     help="/BOTCMD <bot_nick> <command> [args...]  |  "
                          "/BOTCMD keyfile <path>  |  /BOTCMD pinfile <path|off>  |  "
                          "/BOTCMD sealed <on|off>  |  /BOTCMD marker <text|off>  |  "
                          "/BOTCMD passwd_expire <0|30m|1h|6h|1d|secs|never>")
hexchat.hook_command("BOTAUTH", cb_botauth,
                     help="/BOTAUTH <bot_nick> - drop the cached key and re-authenticate")
hexchat.hook_command("BOTFORGET", cb_botforget,
                     help="/BOTFORGET <bot_nick> - drop the cached key (and pin) for a bot")
hexchat.hook_command("BOTUNLOCK", cb_botunlock,
                     help="/BOTUNLOCK - enter the keyfile's passphrase (next keys, masked); "
                          "it stays unlocked for /BOTCMD passwd_expire (default 1h)")
hexchat.hook_command("BOTLOCK", cb_botlock,
                     help="/BOTLOCK - forget the unlocked key (and cancel a waiting prompt)")
hexchat.hook_print("Key Press", cb_keypress, priority=hexchat.PRI_HIGHEST)
hexchat.hook_server("NOTICE", cb_notice)
hexchat.hook_print("Message Send", cb_msg_send)
for _ev in ("Private Message", "Private Message to Dialog", "Notice"):
    hexchat.hook_print(_ev, cb_reply_print, _ev)
hexchat.hook_print("DCC Chat Text", cb_dcc_text)
hexchat.hook_command("", cb_say)
hexchat.hook_timer(5000, cb_timer)

hexchat.prnt("%s %s loaded (~A2 / key-based, passwordless)."
             % (__module_name__, __module_version__))
if not CRYPTO_OK:
    hexchat.prnt(CRYPTO_HINT)
    hexchat.prnt("/BOTCMD stays registered but will refuse to send until then.")
else:
    hexchat.prnt("Set /BOTCMD keyfile <path> to your .private.b64, then "
                 "/BOTCMD <bot> <command>.")
