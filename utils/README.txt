ircbot/utils — client tools
===========================

Admins and opers command the bot with a Curve25519 keypair.  There are no
admin, oper or bot passwords any more; the only password left is your bot's
config-file password.  Design: irchub/docs/passwordless.md.



/* keygen :: make a keypair — built by `cargo build --release` (target/release/keygen) */

    ./keygen robert          # or just ./keygen and type the name when asked

It asks for an optional passphrase (twice, echo off; empty = none) and
writes, in the current directory or in -d <dir> (never overwriting a file):

    YYYYMMDDHHMMSS_robert.private.b64   0600 — yours alone: your IRC script and
                                        bot-auth use it
    YYYYMMDDHHMMSS_robert.public.b64    give this to an admin
    YYYYMMDDHHMMSS_robert_ed25519       0600 — the SSH key for the hub console
    YYYYMMDDHHMMSS_robert_ed25519.pub        (admins; PuTTYgen imports it)

Both private files are under the same passphrase (the IRC key as an
"irckey-v2 scrypt ..." line, the SSH key as a standard encrypted OpenSSH
key).  keygen prints the public key, its fingerprint (e.g.
763e:58a6:2dfd:ae02) and a ~/.ssh/config block; the private key is never
printed.  Later:

    ./keygen --passwd YYYYMMDDHHMMSS_robert.private.b64
        add / change / remove the passphrase (rewrites the SSH pair too; the
        public key stays the same, so nothing on the hubs or bots changes)

Scripts: --no-passphrase, --passphrase-file <0600 file>,
--old-passphrase-file <0600 file>.  keygen (utils/keygen.rs) is the Rust
port of the shared C keygen.c, byte-identical to irchub.rs/src/bin/keygen.rs:
same files, same output.
Formats: irchub/docs/console.md §9.

Without keygen (OpenSSL 1.1.1 or newer; a key without a passphrase):

    umask 077
    openssl genpkey -algorithm ED25519 -out ed.pem
    openssl genpkey -algorithm X25519  -out x.pem
    ( openssl pkey -in ed.pem -outform DER | tail -c 32
      openssl pkey -in x.pem  -outform DER | tail -c 32 ) | openssl base64 -A > NAME.private.b64
    ( openssl pkey -in ed.pem -pubout -outform DER | tail -c 32
      openssl pkey -in x.pem  -pubout -outform DER | tail -c 32 ) | openssl base64 -A > NAME.public.b64
    shred -u ed.pem x.pem      # or rm -f — the .pem files hold the private key

An admin then adds you with your PUBLIC key: the hub console's "admin add" /
"oper add", or on
IRC (when the network is not in hub-only-mutation mode, opt 'h'):

    +admin <name> <pubkey> <nick!user@host>
    +oper  <name> <pubkey> <nick!user@host>
    chkey  <name> <pubkey>          (replace a key; opers may change their own)



// How a client talks to the bot

    you -> bot   PRIVMSG  ~A2A <signature> <ts>:<nonce>    auth request, signed with your key
    bot -> you   NOTICE   ~A2K <lockbox>                   the bot's public key, sealed to you
    you -> bot   PRIVMSG  ~A2 <sealed command>             every command after that

The scripts below do this automatically: the first /botcmd to a bot
authenticates (the lockbox notice is hidden and the bot key's fingerprint is
printed), later commands go straight through.  The bot key is kept in memory
for the session; restarting the IRC client means one fresh auth.  Compare the
fingerprint once with the bot's 'status' (Pubkey line) or the hub console's
'bot list'.

Optional pin file: once set, each bot's key is remembered and a DIFFERENT key
for the same nick is refused with a loud warning (possible man-in-the-middle,
or the bot was rekeyed — /botforget <bot> accepts the new key).

Old password-based scripts (~A1 / ~A1c) no longer work: the bot ignores them.



// Passphrase-protected keys: unlock once, for a while

A key made with a passphrase is locked until you unlock it.  The scripts ask
the first time a command needs the key (the command waits), or on
/botunlock; you type the passphrase into the input line, where it is masked
(irssi and HexChat: the keys never reach the input line, it shows stars;
WeeChat: the bar shows stars and the line stays out of the history).  It is
never sent or shown; an empty line cancels.  The key then stays unlocked
for passwd_expire from the moment you unlocked it (default 1h), then the
script asks again; /botlock forgets it at once:

    irssi     /set bot_auth_passwd_expire 6h
    HexChat   /BOTCMD passwd_expire 6h
    WeeChat   /set plugins.var.python.ircbot_weechat_auth.passwd_expire 6h
    mIRC      /set %bot_auth_passwd_expire 6h

    values: 0 (ask for every command), 30m, 6h, 1d, a number of seconds, or
    never (until /botlock or the client exits) — your call on the risk.

Three wrong passphrases in a row pause the prompt for 30 s.  Changing the
keyfile or passwd_expire locks the key.  A key without a passphrase still
works; the scripts say once per session that it has none.



// Sealed replies: the bot's answers are encrypted too

    you -> bot   PRIVMSG  ~A2S <sealed command>            "and seal your answer"
    bot -> you   PRIVMSG  ~A2R <sealed reply>              one per reply line (long lines: several)

The irssi, HexChat and WeeChat scripts send ~A2S by default.  Only the
sender of that one command can open the answers, and the script shows each
one in place of the frame, decrypted, behind a lock:

    <pwbot1> 🔒 | Pubkey   : H4Z+...

A marked line provably came from the bot (only the bot and you can make it);
an unmarked "reply" did not go through this protection.  Settings:

    irssi     /set bot_auth_sealed_marker <text>     (empty = no marker)
              /set bot_auth_sealed_replies OFF        (plain ~A2 again)
    HexChat   /BOTCMD marker <text|off>     /BOTCMD sealed <on|off>
    WeeChat   /set plugins.var.python.ircbot_weechat_auth.sealed_marker <text|off>
              /set plugins.var.python.ircbot_weechat_auth.sealed_replies off

Turn it off only for a bot older than ~A2S (it ignores ~A2S, so you would
get no answer at all).  A plain ~A2 is still answered in plaintext, which is
what mIRC (bot-auth.mrc) sends.  CLI: bot-auth cmd ... --sealed / bot-auth
reply, below.



// DCC chat (admins): long replies without IRC's flood pacing

    /botcmd <bot_nick> dcc

The bot never accepts a connection.  It answers `dcc` with a passive offer
(PRIVMSG you :\1DCC CHAT chat <ip> 0 <token>\1); your client listens on a
port from its own DCC range and replies with it, and the bot connects out.
So: open your client's DCC port range in your firewall, and set its DCC
address to your public IP if you are behind NAT.  The bot refuses ports
below 1024 and unusable addresses (0.0.0.0, link-local, multicast,
broadcast), and gives up after 120 s without a reply or 20 s of connecting.

    irssi     accept with /dcc chat <bot_nick>   (dcc_port range, dcc_own_ip)
    HexChat   accept the chat request            (DCC ports / DCC IP in Preferences;
              not yet tried in HexChat)
    WeeChat   nothing to do: WeeChat cannot take a passive offer, so the script
              answers it with /dcc chat <bot_nick>, which the bot takes while
              its offer is open  (xfer.network.port_range, xfer.network.own_ip)
    mIRC      accept the chat request            (not yet tried in mIRC)
    other     any client: /dcc chat <bot_nick> while the bot's offer is open

While the chat is open, /botcmd <bot_nick> ... sends each sealed command down
the chat instead of by PRIVMSG, and the bot answers on the chat.  With the
irssi, HexChat or WeeChat script you can also just type commands into the
chat window: the script seals each line before it is sent and shows it as
typed, and the (sealed) answers show decrypted -- the chat reads like any
other.  If the script cannot seal a line (no key cached, key file error) it
does not send it.  A command sent by PRIVMSG is still answered by PRIVMSG.
The chat is only a transport: every line on it must be a sealed ~A2/~A2S
frame from the admin who asked, for the nicks the chat was opened under (a
later nick change on either side does not matter).  Anything else -- typed
text without the script, a replay, another user's key -- closes the chat, as
does an hour without a command.  The CLI (bot-auth cmd) makes frames that
work on a chat too: paste the line into the chat window.



/* ircbot_irssi_auth.pl  (Irssi, requires CryptX) */

    cpan CryptX            (or: apt install libcryptx-perl)
    cp ircbot_irssi_auth.pl ~/.irssi/scripts/ && /script load ircbot_irssi_auth.pl
    /set bot_auth_keyfile /home/you/20260914120000_you.private.b64
    /set bot_auth_pinfile /home/you/.ircbot_bot_pins        (optional)
    /botcmd <bot_nick> <command> [args]
    /botauth <bot_nick>      re-authenticate      /botforget <bot_nick>   drop key (and pin)
    /botunlock               enter the passphrase /botlock                forget the unlocked key
    /set bot_auth_passwd_expire 1h                   (passphrase keys, see above)



/* ircbot_hexchat_auth.py  (HexChat, requires python3-cryptography) */

    pip install cryptography       (or: apt install python3-cryptography)
    cp ircbot_hexchat_auth.py ~/.config/hexchat/addons/
    /BOTCMD keyfile /home/you/20260914120000_you.private.b64
    /BOTCMD pinfile /home/you/.ircbot_bot_pins                (optional; "off" disables)
    /BOTCMD <bot_nick> <command> [args]
    /BOTAUTH <bot_nick>      /BOTFORGET <bot_nick>      /BOTUNLOCK      /BOTLOCK
    /BOTCMD passwd_expire 1h                                (passphrase keys, see above)



/* ircbot_weechat_auth.py  (WeeChat, requires python3-cryptography) */

    cp ircbot_weechat_auth.py ~/.local/share/weechat/python/   (or ~/.weechat/python/)
    /python load ircbot_weechat_auth.py
    /set plugins.var.python.ircbot_weechat_auth.keyfile /home/you/20260914120000_you.private.b64
    /set plugins.var.python.ircbot_weechat_auth.pinfile /home/you/.ircbot_bot_pins   (optional)
    /botcmd <bot_nick> <command> [args]       (run it from a buffer on the bot's network)
    /botauth <bot_nick>      /botforget <bot_nick>      /botunlock      /botlock
    /set plugins.var.python.ircbot_weechat_auth.passwd_expire 1h   (passphrase keys)



/* bot-auth  (command-line client; also the engine behind bot-auth.mrc) */

    cargo build --release            -> target/release/bot-auth  (utils/bot_auth.rs)
    Windows (bot-auth.exe for mIRC), from a Rust toolchain with the target added:
        rustup target add x86_64-pc-windows-gnu
        cargo build --release --bin bot-auth --target x86_64-pc-windows-gnu

Three steps, by hand (any client that can send a raw line works, e.g. repartee):

    ./bot-auth auth KEY.private.b64 <botnick> <yournick>
        -> ~A2A ... 1789326450:9f1c2e3a4b5c6d7e        send it:  /msg <botnick> <that line>
    ./bot-auth open KEY.private.b64 <botnick> <yournick> 1789326450:9f1c2e3a4b5c6d7e "~A2K <reply>" [--pin FILE]
        -> <bot pubkey> <fingerprint>
    echo "op #chan" | ./bot-auth cmd KEY.private.b64 <botnick> <yournick> <bot pubkey>
        -> ~A2 ...                                     send it:  /quote PRIVMSG <botnick> :<that line>
    ./bot-auth fp <pubkey|file>                        print a key's fingerprint

Sealed replies from the command line:

    echo "status" | ./bot-auth cmd KEY.private.b64 <botnick> <yournick> <bot pubkey> --sealed RK
        -> ~A2S ...      (and RK, created 0600, holds that command's reply key)
    ./bot-auth reply RK <botnick> <yournick> < lines-with-~A2R
        -> the answer in plaintext, one line per reply line; delete RK afterwards

Passphrase-protected keys: the key holder

    ./bot-auth unlock KEY.private.b64 [--expire 1h|30m|6h|1d|secs|never]
        asks for the passphrase (echo off) and starts a background key holder
        that keeps the key in locked memory until the expiry (default 1h)
    ./bot-auth status KEY.private.b64      "unlocked <secs|never>" or "locked"
    ./bot-auth lock KEY.private.b64        end it now (the key is wiped)

While it runs, auth / open / cmd use it: it signs and does the X25519 step,
and the private key never leaves it.  It listens on a 0600 socket in a 0700
directory ($XDG_RUNTIME_DIR/bot-auth, else /tmp/bot-auth-<uid>) and answers
only your own user; on Windows a named pipe only you can open.  The C and
Rust bot-auth share it.  Without it, a passphrase-protected key makes
bot-auth ask for the passphrase on the terminal for that one call (never on
Windows), or print "bot-auth: LOCKED: ..." and exit 4.

The command is read from stdin, never from the command line (ps(1) would show
it).  Exit status: 1 usage/IO error, 2 verification failure, 3 pinned key
changed, 4 the key is locked.  Commands must fit one IRC line (about 200
characters).



/* bot-auth.mrc  (mIRC; drives bot-auth.exe) */

    /load -rs C:\path\to\bot-auth.mrc
    /set %bot_auth_exe     C:\path\to\bot-auth.exe
    /set %bot_auth_keyfile C:\path\to\20260914120000_you.private.b64
    /set %bot_auth_pinfile C:\path\to\bot_pins.txt       (optional)
    /set %bot_auth_passwd_expire 1h                     (optional, passphrase keys)
    /botcmd <bot_nick> <command> [args]      /botauth <bot_nick>      /botforget <bot_nick>
    /botunlock      /botlock

With a passphrase-protected key, the first command opens a bot-auth window
that asks for the passphrase and closes itself once the key holder runs;
the waiting commands are then sent.  The passphrase never passes through
mIRC.

mIRC has no Curve25519 or AES-GCM, so every crypto step runs in bot-auth.exe;
the command text reaches it through a temp file that is deleted right away
(set %bot_auth_tmpdir to a private folder if your temp dir is shared).  This
script has not been exercised in mIRC by the developers — report problems.

repartee: its sandboxed Lua has no crypto binding, no clock and no CSPRNG, so
a native script is not possible; use bot-auth by hand (above) and repartee's
raw-line command.



// Starting the bot

See ../README.md: run ./ircbot and type the config password, or create a machine-bound password file once with
./ircbot -p for unattended starts (crontab).
