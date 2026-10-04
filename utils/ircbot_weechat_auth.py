"""ircbot_weechat_auth.py — v2 (~A2/~A2A/~A2K) key-based admin-command client
for ircbot, WeeChat edition.  There are no passwords: each admin/oper has an
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
    cp ircbot_weechat_auth.py ~/.weechat/python/     (or ~/.local/share/weechat/python/)
    /python load ircbot_weechat_auth.py

Setup:
    1. Make a keypair with ircbot/utils/keygen (or irchub/bin/keygen); give
       the bot admin the .public.b64 contents, keep the .private.b64 to
       yourself and `chmod 600` it -- this script warns (but still runs) if
       it is not.
    2. /set plugins.var.python.ircbot_weechat_auth.keyfile /home/you/NAME.private.b64
    3. Optionally pin bots to their key:
       /set plugins.var.python.ircbot_weechat_auth.pinfile /home/you/.ircbot_bot_pins
       (chmod 600 on first write; leaving this empty, the default, disables pinning)
    4. From a buffer on the bot's network: /botcmd <bot_nick> <command> [args...]

Usage:
    /botcmd   <bot_nick> <command> [args...]   - auto-authenticates, then sends
    /botauth  <bot_nick>                       - drop the cached key, re-auth now
    /botforget <bot_nick>                      - drop the cached key (and pin)
    /botunlock                                 - enter the key's passphrase now
    /botlock                                   - forget the unlocked key now

Passphrase-protected keys (keygen asks for one; irchub/docs/console.md §9):
the first /botcmd that needs the key asks for the passphrase and waits.  The
next line you type is taken as the passphrase: it is masked in the input bar,
kept out of the input history, and never sent or shown (an empty line
cancels).  The key then stays unlocked for passwd_expire from the unlock,
then the script asks again:
    /set plugins.var.python.ircbot_weechat_auth.passwd_expire 6h
         (default 1h; 0 = ask for every command; 30m, 2d, a number of
          seconds, or never = until /botlock or the script is unloaded)
Three wrong passphrases in a row lock the prompt for 30 s.  Changing keyfile
or passwd_expire locks the key.

Sealed replies (on by default): commands go out as "~A2S <b64>", which asks
the bot to seal its answers too ("~A2R <b64>", only this command's sender can
open them).  They are shown in place, decrypted, behind a lock marker:
    /set plugins.var.python.ircbot_weechat_auth.sealed_marker <text|off>
         (default U+1F512)
    /set plugins.var.python.ircbot_weechat_auth.sealed_replies off
         (plain ~A2 / plaintext replies, for bots older than ~A2S)
A marked line provably came from the bot; an unmarked "reply" did not go
through this protection.

DCC chat: `/botcmd <bot> dcc` makes the bot offer a passive DCC chat.  The
bot never accepts connections: it connects to a port your client listens on,
so open WeeChat's DCC port range (xfer.network.port_range) in your firewall
and set xfer.network.own_ip if you are behind NAT.  WeeChat cannot take a
passive offer, so this script answers the bot's with a /dcc chat of its own
(WeeChat listens, the bot connects out).  While the chat is open, /botcmd
sends each sealed command down the chat instead of by PRIVMSG, and the bot
answers there.  Plain text typed into the chat buffer is sealed the same way
before it is sent (never sent as typed).

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

import weechat
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

SCRIPT_NAME = "ircbot_weechat_auth"
SCRIPT_AUTHOR = "rclemens"
SCRIPT_VERSION = "6.2.0"
SCRIPT_LICENSE = "Public Domain"
SCRIPT_DESC = "Sends ~A2 admin commands to ircbot (Curve25519 + AES-256-GCM, passwordless)"

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
# Pure protocol functions — no `weechat` calls anywhere below this line down
# to the "Pin-file helpers" section. Callable standalone by a test harness
# that has stubbed `weechat` into sys.modules before import.
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
# Pin-file helpers.  Plain file I/O, no `weechat` calls.
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
# WeeChat glue.  Everything below touches `weechat`.  WeeChat callbacks are
# registered (and invoked) by function *name*, not by reference.
# =============================================================================

_KEY_CACHE = {}   # (server, bot_lc) -> bot_pub64 (raw 64 bytes)
_PENDING = {}     # same key         -> (tsn, send_time)
_QUEUE = {}       # same key         -> [command_line, ...]
_DCC_NICK = {}    # same key         -> our nick when we asked for the DCC chat
_REPLY_KEYS = {}  # same key         -> [{rk, bot, me, t, next, part}, ...] newest first
_NOTED = {}       # same key         -> time of the last "could not open" note
_OWN_ECHO = {}    # frame typed for us into a bot chat -> the text as typed

REPLY_KEY_TTL = 600       # seconds a ~A2S reply key lives after its last use
MAX_REPLY_KEYS = 8        # reply keys kept per bot
DEFAULT_MARKER = "\U0001F512"


def _sealed_on():
    return weechat.config_get_plugin("sealed_replies") != "off"


def _marked(text):
    m = weechat.config_get_plugin("sealed_marker")
    m = "" if m == "off" else m
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
    weechat.prnt("", "bot_auth: a sealed reply from %s could not be opened (it "
                     "answers a command this session did not send); hidden." % nick)


def _reply_for(ck, nick, text):
    """A ~A2R frame as the marked line to show, or None to show nothing (a
    piece of a longer line, a repeat, or a frame no key opens)."""
    st, line = _reply_text(ck, text[5:].strip()) if CRYPTO_OK else ("bad", None)
    if st == "bad":
        _note_unopened(ck, nick)
    return _marked(line) if st == "show" else None


# The unlocked passphrase-protected key: {"key", "path", "until" (None =
# never), "once" (passwd_expire 0: lock after this command)}.  Python cannot
# wipe the key's bytes (see the note at the top); locking drops every
# reference.
_UNLOCKED = {}
# The passphrase prompt while it waits: {"path", "t", "pending": [...]}.
_CAPTURE = {}
_FAILS = {"n": 0, "until": 0.0}
_WARNED = set()   # keyfiles already warned about having no passphrase
LOCKED = "locked"  # _load_key_pref() error: ask for the passphrase


def _expire_secs():
    secs = parse_expire(weechat.config_get_plugin("passwd_expire"))
    if secs is None:
        weechat.prnt("", "bot_auth: passwd_expire '%s' is not e.g. 30m, 1h, 6h, 1d, "
                         "0 or never; using 1h"
                     % weechat.config_get_plugin("passwd_expire"))
        return PASSWD_EXPIRE_DEFAULT
    return secs


def _lock(why=None):
    had = bool(_UNLOCKED)
    _UNLOCKED.clear()
    if had and why:
        weechat.prnt("", "bot_auth: %s" % why)


def _load_key_pref():
    path = weechat.config_get_plugin("keyfile")
    if not path:
        return None, ("no keyfile set — /set plugins.var.python.%s.keyfile <path>"
                      % SCRIPT_NAME)
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
        weechat.prnt("", "bot_auth: keyfile '%s' has no passphrase — add one with: "
                         "keygen --passwd %s" % (path, path))
    return key, None


def _used_once():
    """passwd_expire 0: lock once nothing more is waiting for the key."""
    if _UNLOCKED.get("once") and not _PENDING and not _CAPTURE:
        _lock()


def _ask_passphrase(pending=None):
    """Arm the passphrase prompt; `pending` (a /botcmd's arguments) runs
    after a successful unlock."""
    path = weechat.config_get_plugin("keyfile")
    now = time.time()
    if now < _FAILS["until"]:
        weechat.prnt("", "bot_auth: too many wrong passphrases; try again in %d s."
                     % (_FAILS["until"] - now + 1))
        return
    if _CAPTURE:
        if pending and len(_CAPTURE["pending"]) < MAX_QUEUE:
            _CAPTURE["pending"].append(pending)
        weechat.prnt("", "bot_auth: still waiting for the passphrase (an empty line cancels).")
        return
    _CAPTURE.update(path=path, t=now, pending=[pending] if pending else [])
    weechat.prnt("", "bot_auth: passphrase for %s: type it and press Enter — it is "
                     "masked, never sent and kept out of the history (an empty line "
                     "cancels)." % path)


def _cancel_capture(why):
    if _CAPTURE:
        n = len(_CAPTURE["pending"])
        _CAPTURE.clear()
        weechat.prnt("", "bot_auth: %s%s" % (why, "; dropped %d command(s)" % n if n else ""))


def _try_unlock(passphrase):
    cap = dict(_CAPTURE)
    _CAPTURE.clear()
    if not passphrase:
        _CAPTURE.update(cap)
        _cancel_capture("passphrase prompt cancelled")
        return
    pw = passphrase.encode("utf-8")
    if len(pw) > PASS_MAX:
        weechat.prnt("", "bot_auth: passphrase too long.")
        return
    try:
        key = load_key(cap["path"], pw)
    except Exception as exc:                      # noqa: BLE001 - report to user
        _FAILS["n"] += 1
        if _FAILS["n"] >= FAIL_LIMIT:
            _FAILS.update(n=0, until=time.time() + FAIL_PAUSE)
        weechat.prnt("", "bot_auth: %s%s" % (exc, "; dropped %d command(s)" % len(cap["pending"])
                                             if cap["pending"] else ""))
        return
    _FAILS.update(n=0, until=0.0)
    secs = _expire_secs()
    now = time.time()
    _UNLOCKED.clear()
    _UNLOCKED.update(key=key, path=cap["path"], once=secs == 0,
                     until=None if secs < 0 else now + max(secs, AUTH_TIMEOUT if secs == 0 else 0))
    if secs < 0:
        weechat.prnt("", "bot_auth: key unlocked until /botlock.")
    elif secs == 0:
        weechat.prnt("", "bot_auth: key unlocked for this command.")
    else:
        weechat.prnt("", "bot_auth: key unlocked until %s (passwd_expire)."
                     % time.strftime("%H:%M:%S", time.localtime(now + secs)))
    for p in cap["pending"]:
        _handle_botcmd(*p)
    _used_once()


def _expire_pending(ck):
    pend = _PENDING.get(ck)
    if not pend or time.time() - pend[1] <= AUTH_TIMEOUT:
        return
    del _PENDING[ck]
    q = _QUEUE.pop(ck, None)
    if q:
        weechat.prnt("", "bot_auth: auth with %s timed out; dropped %d queued command(s)."
                     % (ck[1], len(q)))


def _send_line(buffer, server, bot_nick, line):
    weechat.command(buffer or "", "/quote -server %s PRIVMSG %s :%s" % (server, bot_nick, line))


def _send_auth(buffer, server, mynick, bot_nick, key):
    try:
        line, tsn = build_auth(key, bot_nick, mynick)
    except Exception as exc:                      # noqa: BLE001 - report to user
        weechat.prnt("", "bot_auth: failed to build auth request: %s" % exc)
        return
    _PENDING[(server, _lc(bot_nick))] = (tsn, time.time())
    _send_line(buffer, server, bot_nick, line)
    weechat.prnt("", "bot_auth: authenticating with %s..." % bot_nick)


def _dcc_chat_buffer(server, bot_nick):
    """The buffer of the open DCC chat with bot_nick on server, or ""."""
    found = ""
    il = weechat.infolist_get("xfer", "", "")
    if il:
        while not found and weechat.infolist_next(il):
            if (weechat.infolist_string(il, "type_string") in ("chat_recv", "chat_send")
                    and weechat.infolist_string(il, "status_string") == "active"
                    and weechat.infolist_string(il, "plugin_id") == server
                    and _lc(weechat.infolist_string(il, "remote_nick")) == _lc(bot_nick)):
                found = weechat.infolist_pointer(il, "buffer") or ""
        weechat.infolist_free(il)
    return found


def _xfer_chat_of(buffer):
    """(server, remote nick) of the open DCC chat shown in buffer, or None."""
    found = None
    il = weechat.infolist_get("xfer", "", "")
    if il:
        while not found and weechat.infolist_next(il):
            if (weechat.infolist_pointer(il, "buffer") == buffer
                    and weechat.infolist_string(il, "type_string") in ("chat_recv", "chat_send")
                    and weechat.infolist_string(il, "status_string") == "active"):
                found = (weechat.infolist_string(il, "plugin_id"),
                         weechat.infolist_string(il, "remote_nick"))
        weechat.infolist_free(il)
    return found


def _seal_for(ck, bot_nick, as_nick, key, bot_pub64, command_line):
    """The frame for one command (~A2S with its reply key kept, or ~A2 when
    sealed replies are off), or None if it must be refused (printed)."""
    try:
        line, rk = _seal_command(key, bot_pub64, bot_nick, as_nick, command_line,
                                 _sealed_on())
    except ValueError as exc:
        weechat.prnt("", "bot_auth: %s" % exc)
        return None
    if rk:
        _remember_reply_key(ck, rk, bot_nick, as_nick)
    return line


def _send_command(buffer, server, mynick, key, bot_nick, bot_pub64, command_line):
    """A command goes down the bot's DCC chat when one is open, else by
    PRIVMSG.  On the chat the bot takes the sender nick to be the one that
    asked for it."""
    ck = (server, _lc(bot_nick))
    chat = _dcc_chat_buffer(server, bot_nick)
    as_nick = _DCC_NICK.get(ck, mynick) if chat else mynick
    line = _seal_for(ck, bot_nick, as_nick, key, bot_pub64, command_line)
    if not line:
        return
    if chat:
        weechat.command(chat, line)   # text, not a /command: sent down the chat
        return
    if (command_line.split(None, 1) or [""])[0].lower() == "dcc":
        _DCC_NICK[ck] = mynick
    _send_line(buffer, server, bot_nick, line)


def _handle_botcmd(buffer, server, mynick, bot_nick, command_line):
    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase((buffer, server, mynick, bot_nick, command_line))
        return
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return
    if key.warning:
        weechat.prnt("", "bot_auth: %s" % key.warning)

    ck = (server, _lc(bot_nick))
    _expire_pending(ck)

    bot_pub64 = _KEY_CACHE.get(ck)
    if bot_pub64:
        _send_command(buffer, server, mynick, key, bot_nick, bot_pub64, command_line)
        _used_once()
        return

    q = _QUEUE.setdefault(ck, [])
    if len(q) >= MAX_QUEUE:
        weechat.prnt("", "bot_auth: queue for %s is full (max %d); dropping oldest."
                     % (bot_nick, MAX_QUEUE))
        q.pop(0)
    q.append(command_line)

    if ck in _PENDING:
        weechat.prnt("", "bot_auth: already authenticating with %s; command queued." % bot_nick)
        return
    _send_auth(buffer, server, mynick, bot_nick, key)


def cb_botcmd(data, buffer, args):
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return weechat.WEECHAT_RC_OK

    parts = args.split(None, 1)
    if len(parts) < 2:
        weechat.prnt("", "Usage: /botcmd <bot_nick> <command> [args...]")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server")
    if not server:
        weechat.prnt("", "bot_auth: run /botcmd from a buffer on the bot's network.")
        return weechat.WEECHAT_RC_OK

    mynick = weechat.info_get("irc_nick", server) or ""
    _handle_botcmd(buffer, server, mynick, parts[0], parts[1])
    return weechat.WEECHAT_RC_OK


def cb_botauth(data, buffer, args):
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return weechat.WEECHAT_RC_OK

    bot_nick = args.strip()
    if not bot_nick:
        weechat.prnt("", "Usage: /botauth <bot_nick>")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server")
    if not server:
        weechat.prnt("", "bot_auth: run /botauth from a buffer on the bot's network.")
        return weechat.WEECHAT_RC_OK

    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase()
        weechat.prnt("", "bot_auth: run /botauth %s again once the key is unlocked." % bot_nick)
        return weechat.WEECHAT_RC_OK
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return weechat.WEECHAT_RC_OK

    mynick = weechat.info_get("irc_nick", server) or ""
    _KEY_CACHE.pop((server, _lc(bot_nick)), None)
    _send_auth(buffer, server, mynick, bot_nick, key)
    return weechat.WEECHAT_RC_OK


def cb_botforget(data, buffer, args):
    bot_nick = args.strip()
    if not bot_nick:
        weechat.prnt("", "Usage: /botforget <bot_nick>")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server") or ""
    ck = (server, _lc(bot_nick))
    had = _KEY_CACHE.pop(ck, None) is not None
    _PENDING.pop(ck, None)
    _QUEUE.pop(ck, None)
    _DCC_NICK.pop(ck, None)
    _REPLY_KEYS.pop(ck, None)

    pinfile = weechat.config_get_plugin("pinfile")
    if pinfile:
        pin_remove(pinfile, _lc(bot_nick))

    weechat.prnt("", "bot_auth: forgot %s%s." % (bot_nick, "" if had else " (was not cached)"))
    return weechat.WEECHAT_RC_OK


def cb_botunlock(data, buffer, args):
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return weechat.WEECHAT_RC_OK
    key, err = _load_key_pref()
    if err == LOCKED:
        _ask_passphrase()
    elif err:
        weechat.prnt("", "bot_auth: %s" % err)
    elif key.plain:
        weechat.prnt("", "bot_auth: the keyfile has no passphrase; nothing to unlock.")
    else:
        u = _UNLOCKED
        weechat.prnt("", "bot_auth: already unlocked%s." % (
            " until /botlock" if u["until"] is None else
            " for %d more s" % max(0, u["until"] - time.time())))
    return weechat.WEECHAT_RC_OK


def cb_botlock(data, buffer, args):
    _cancel_capture("passphrase prompt cancelled")
    had = bool(_UNLOCKED)
    _lock()
    weechat.prnt("", "bot_auth: key locked." if had else "bot_auth: key was not unlocked.")
    return weechat.WEECHAT_RC_OK


def cb_history_add(data, modifier, modifier_data, string):
    """While the passphrase prompt waits, the line typed is not history."""
    return "" if _CAPTURE else string


def cb_input_display(data, modifier, modifier_data, string):
    """While the passphrase prompt waits, the input bar shows stars."""
    if not _CAPTURE:
        return string
    return "*" * len(weechat.string_remove_color(string, ""))


def cb_config(data, option, value):
    _cancel_capture("keyfile/passwd_expire changed: passphrase prompt cancelled")
    _lock("keyfile/passwd_expire changed: key locked.")
    return weechat.WEECHAT_RC_OK


def _parse_in_line(line, verb):
    """Parse a raw irc_in2_<verb> line into (nick, text), or None.  Handles
    an optional leading IRCv3 "@tags " prefix.  Not a `weechat` call."""
    s = line
    if s.startswith("@"):
        sp = s.find(" ")
        if sp == -1:
            return None
        s = s[sp + 1:]
    if not s.startswith(":"):
        return None
    sp = s.find(" ")
    if sp == -1:
        return None
    prefix = s[1:sp]
    rest = s[sp + 1:]
    parts = rest.split(" ", 2)
    if len(parts) < 3 or parts[0].upper() != verb:
        return None
    text = parts[2]
    if text.startswith(":"):
        text = text[1:]
    nick = prefix.split("!", 1)[0]
    return nick, text


def _in_reply(server, string, nick, text):
    """A ~A2R PRIVMSG/NOTICE: the raw line with the frame replaced by the
    marked plaintext, or "" to drop it (see _reply_for)."""
    line = _reply_for((server, _lc(nick)), nick, text)
    i = string.find(" :~A2R ")
    return string[:i + 2] + line if line is not None and i >= 0 else ""


def cb_notice(data, modifier, modifier_data, string):
    parsed = _parse_in_line(string, "NOTICE")
    if not parsed:
        return string
    nick, text = parsed
    if text.startswith("~A2R "):
        return _in_reply(modifier_data, string, nick, text)
    if not text.startswith("~A2K "):
        return string

    # Protocol traffic: always hidden, whether or not we can process it.
    if not CRYPTO_OK:
        return ""

    server = modifier_data
    mynick = weechat.info_get("irc_nick", server) or ""
    ck = (server, _lc(nick))
    _expire_pending(ck)

    pend = _PENDING.pop(ck, None)
    if not pend:
        return ""   # no matching request: drop silently
    tsn, _sent = pend

    key, err = _load_key_pref()
    if err:
        weechat.prnt("", "bot_auth: %s" % ("the key locked before %s answered; /botunlock "
                                           "and try again" % nick if err == LOCKED else err))
        _QUEUE.pop(ck, None)
        return ""

    b64 = text[5:]
    bot_pub64 = open_lockbox(key, nick, mynick, tsn, b64)
    if bot_pub64 is None:
        weechat.prnt("", "bot_auth: ~A2K from %s failed to decrypt/verify; ignored." % nick)
        return ""

    pinfile = weechat.config_get_plugin("pinfile")
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
            weechat.prnt(
                "", "bot_auth: WARNING pinned-key mismatch for %s! pinned %s got %s "
                    "-- possible man-in-the-middle, or the bot was rekeyed. "
                    "Run /botforget %s to accept the new key."
                    % (nick, fingerprint(existing_raw) if existing_raw else "?",
                       fingerprint(bot_pub64), nick))
            return ""   # do NOT cache on a pin mismatch

    _KEY_CACHE[ck] = bot_pub64
    weechat.prnt("", "bot_auth: authenticated with %s — key %s" % (nick, fingerprint(bot_pub64)))

    q = _QUEUE.pop(ck, [])
    for cmd in q:
        _send_command("", server, mynick, key, nick, bot_pub64, cmd)
    _used_once()
    return ""


def cb_privmsg(data, modifier, modifier_data, string):
    """WeeChat cannot take a passive DCC chat offer (it would dial port 0).
    When a bot we asked with `dcc` sends one, hide it and make an ordinary
    /dcc chat offer instead: WeeChat listens, and the bot -- whose offer is
    still open -- connects out to it."""
    parsed = _parse_in_line(string, "PRIVMSG")
    if not parsed:
        return string
    nick, text = parsed
    if text.startswith("~A2R "):
        return _in_reply(modifier_data, string, nick, text)
    f = text.strip("\x01").split()
    if (not (text.startswith("\x01DCC ") and len(f) == 6 and f[1].upper() == "CHAT"
             and f[4] == "0") or (modifier_data, _lc(nick)) not in _DCC_NICK):
        return string
    weechat.command(weechat.buffer_search("irc", "server." + modifier_data),
                    "/dcc chat " + nick)
    return ""


def cb_print(data, modifier, modifier_data, string):
    """Lines of a DCC chat.  A command sent down it is echoed as our own line:
    the frame is protocol traffic, so it is hidden -- or, for text typed into
    the chat (cb_input_text), shown as typed.  A bot's ~A2R reply is shown
    decrypted and marked.  modifier_data is "<buffer pointer>;<tags>" (older
    WeeChat: "<plugin>;<buffer name>;<tags>")."""
    prefix, sep, msg = string.partition("\t")
    if not sep or not msg.startswith(("~A2 ", "~A2S ", "~A2R ")):
        return string
    first = modifier_data.split(";", 1)[0]
    plugin = weechat.buffer_get_string(first, "plugin") if first.startswith("0x") else first
    if plugin != "xfer":
        return string
    if msg.startswith("~A2R "):
        chat = _xfer_chat_of(first) if first.startswith("0x") else None
        line = _reply_for((chat[0], _lc(chat[1])), chat[1], msg) if chat else None
        return prefix + "\t" + line if line is not None else ""
    typed = _OWN_ECHO.pop(msg, None)
    return prefix + "\t" + typed if typed is not None else ""


def cb_input_text(data, modifier, modifier_data, string):
    """Text typed into the chat buffer of a bot we asked for a DCC chat: the
    chat only carries sealed frames (the bot closes it on anything else), so
    the text is sealed like /botcmd -- and shown as typed (cb_print).  If it
    cannot be sealed it is not sent.  Commands, frames and chats with anyone
    else pass untouched."""
    if _CAPTURE:
        # The passphrase prompt takes this line whole: never sent or shown.
        _try_unlock(string)
        return ""
    text = weechat.string_input_for_buffer(string)
    if not text or text.startswith(("~A2 ", "~A2S ")):
        return string
    if weechat.buffer_get_string(modifier_data, "plugin") != "xfer":
        return string
    chat = _xfer_chat_of(modifier_data)
    if not chat or (chat[0], _lc(chat[1])) not in _DCC_NICK:
        return string
    server, bot_nick = chat
    ck = (server, _lc(bot_nick))
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return ""
    key, err = _load_key_pref()
    bot_pub64 = _KEY_CACHE.get(ck)
    if err == LOCKED:
        weechat.prnt("", "bot_auth: the key is locked -- not sent; /botunlock first")
        return ""
    if err or not bot_pub64:
        weechat.prnt("", "bot_auth: %s -- not sent"
                     % (err or "no key for %s this session (/botauth %s)" % (bot_nick, bot_nick)))
        return ""
    line = _seal_for(ck, bot_nick, _DCC_NICK[ck], key, bot_pub64, text)
    _used_once()
    if not line:
        return ""
    if len(_OWN_ECHO) > 32:
        _OWN_ECHO.clear()
    _OWN_ECHO[line] = text
    return line


def cb_timer(data, remaining_calls):
    for ck in list(_PENDING.keys()):
        _expire_pending(ck)
    now = time.time()
    if _UNLOCKED and _UNLOCKED["until"] is not None and now >= _UNLOCKED["until"]:
        _lock("key locked again (passwd_expire); the next /botcmd asks for the passphrase.")
    if _CAPTURE and now - _CAPTURE["t"] > PROMPT_TIMEOUT:
        _cancel_capture("passphrase prompt timed out")
    return weechat.WEECHAT_RC_OK


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", ""):
    if not weechat.config_is_set_plugin("keyfile"):
        weechat.config_set_plugin("keyfile", "")
    if not weechat.config_is_set_plugin("pinfile"):
        weechat.config_set_plugin("pinfile", "")
    if not weechat.config_is_set_plugin("sealed_replies"):
        weechat.config_set_plugin("sealed_replies", "on")
    if not weechat.config_is_set_plugin("sealed_marker"):
        weechat.config_set_plugin("sealed_marker", DEFAULT_MARKER)
    if not weechat.config_is_set_plugin("passwd_expire"):
        weechat.config_set_plugin("passwd_expire", "1h")

    weechat.hook_command(
        "botcmd",
        "Send an encrypted (~A2) admin command to an ircbot (passwordless, key-based)",
        "<bot_nick> <command> [args...]",
        "  bot_nick: the bot's current nick on this network\n"
        "   command: the admin command, e.g. 'die' or '+admin ...'\n\n"
        "Set your key first:\n"
        "  /set plugins.var.python.%s.keyfile /path/to/NAME.private.b64  (chmod 600)\n"
        "  /set plugins.var.python.%s.pinfile /path/to/pinfile           (optional)"
        % (SCRIPT_NAME, SCRIPT_NAME),
        "", "cb_botcmd", "")
    weechat.hook_command(
        "botauth",
        "Drop the cached key for a bot and send a fresh ~A2A auth request",
        "<bot_nick>", "", "", "cb_botauth", "")
    weechat.hook_command(
        "botforget",
        "Drop the cached key (and pin) for a bot",
        "<bot_nick>", "", "", "cb_botforget", "")
    weechat.hook_command(
        "botunlock",
        "Enter the passphrase of a passphrase-protected keyfile (next line, masked)",
        "", "The key stays unlocked for plugins.var.python.%s.passwd_expire "
        "(default 1h; 0, 30m, 6h, 1d or never)." % SCRIPT_NAME, "", "cb_botunlock", "")
    weechat.hook_command(
        "botlock",
        "Forget the unlocked key (and cancel a waiting passphrase prompt)",
        "", "", "", "cb_botlock", "")

    weechat.hook_modifier("irc_in2_notice", "cb_notice", "")
    weechat.hook_modifier("irc_in2_privmsg", "cb_privmsg", "")
    weechat.hook_modifier("weechat_print", "cb_print", "")
    weechat.hook_modifier("input_text_for_buffer", "cb_input_text", "")
    weechat.hook_modifier("history_add", "cb_history_add", "")
    weechat.hook_modifier("input_text_display", "cb_input_display", "")
    weechat.hook_modifier("input_text_display_with_cursor", "cb_input_display", "")
    weechat.hook_config("plugins.var.python.%s.keyfile" % SCRIPT_NAME, "cb_config", "")
    weechat.hook_config("plugins.var.python.%s.passwd_expire" % SCRIPT_NAME, "cb_config", "")
    weechat.hook_timer(5000, 0, 0, "cb_timer", "")

    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        weechat.prnt("", "/botcmd stays registered but will refuse to send "
                         "until then.")
    else:
        weechat.prnt("", "Set /set plugins.var.python.%s.keyfile <path> to your "
                         ".private.b64, then /botcmd <bot> <command>." % SCRIPT_NAME)
