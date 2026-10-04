use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use MIME::Base64 qw(encode_base64 decode_base64);   # core

# CryptX is loaded at runtime, not with `use`, so a missing dependency reports
# one actionable line in the irssi window instead of aborting the script with a
# compile error and an @INC dump.  Functions are called fully qualified, so
# nothing needs importing into this script's package.
our $CRYPTX_OK = eval {
    require Crypt::PK::Ed25519;     # sign / verify
    require Crypt::PK::X25519;      # ECDH
    require Crypt::KeyDerivation;   # hkdf
    require Crypt::AuthEnc::GCM;    # gcm_encrypt_authenticate / gcm_decrypt_verify
    require Crypt::PRNG;            # random_bytes
    require Crypt::Digest::SHA256;  # sha256 (fingerprints)
    1;
};
our $CRYPTX_ERR = $CRYPTX_OK ? '' : "$@";

sub cryptx_hint {
    return 'bot_auth: CryptX is not installed — this script cannot do the '
         . 'Curve25519/AES-GCM handshake without it.  Install one of:  '
         . 'sudo apt install libcryptx-perl  |  cpan CryptX  |  cpanm CryptX';
}

# ircbot_irssi_auth.pl — v2 (~A2/~A2A/~A2K) key-based admin-command client for
# ircbot, Irssi edition.  There are no passwords: each admin/oper has an
# Ed25519+X25519 keypair (ircbot/utils/keygen), and the bot only ever learns
# the *public* half.
#
# Protocol (must match commands.c / crypto.c exactly — see
# irchub/docs/passwordless.md §4): on the first command to a bot this script
# signs a "~A2A <sig> <ts>:<nonce>" request with your Ed25519 key; the bot
# replies with a NOTICE "~A2K <b64>" carrying its own public key, sealed
# (X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to your X25519 key and bound to
# that request's ts:nonce.  Once that lockbox is opened and cached, every
# admin command travels as a fresh "~A2 <b64>" PRIVMSG: a per-command X25519
# ephemeral key is mixed with your static key so the bot can both decrypt and
# authenticate the sender.  ~A2K notices are protocol traffic and are always
# hidden from the chat window.
#
# Dependency: CryptX only (cpan CryptX, or: apt install libcryptx-perl).
# All crypto runs in-process: your private key material never appears in a
# command line, an environment variable, or a temp file, and this script
# never shells out to openssl(1) or any other external program.
#
# Setup:
#   1. Make a keypair with ircbot/utils/keygen (or irchub/bin/keygen); give
#      the bot admin the .public.b64 contents, keep the .private.b64 to
#      yourself and `chmod 600` it — this script warns (but still runs) if it
#      is not.
#   2. /set bot_auth_keyfile /home/you/NAME.private.b64
#   3. Optionally pin bots to their key:
#      /set bot_auth_pinfile /home/you/.ircbot_bot_pins   (chmod 600 on first write)
#      Leaving this empty (the default) disables pinning.
#   4. /botcmd <bot_nick> <command> [args...]
#
# Usage:
#   /botcmd   <bot_nick> <command> [args...]   - auto-authenticates, then sends
#   /botauth  <bot_nick>                       - drop the cached key, re-auth now
#   /botforget <bot_nick>                      - drop the cached key (and pin)
#   /botunlock                                 - enter the key's passphrase now
#   /botlock                                   - forget the unlocked key now
#
# Passphrase-protected keys (keygen asks for one; irchub/docs/console.md §9):
# the first /botcmd that needs the key asks for the passphrase and waits.
# Type it and press Enter: the keys never reach the input line (it shows
# stars) or its history, and nothing is sent (an empty line cancels; a pasted
# line is taken too).  The key then stays unlocked for bot_auth_passwd_expire
# from the unlock, then the script asks again:
#   /set bot_auth_passwd_expire 6h    (default 1h; 0 = ask for every command;
#                                      30m, 2d, a number of seconds, or never
#                                      = until /botlock or /script unload)
# Three wrong passphrases in a row lock the prompt for 30 s.  Changing
# bot_auth_keyfile or bot_auth_passwd_expire locks the key.
#
# Sealed replies (on by default): commands go out as "~A2S <b64>", which asks
# the bot to seal its answers too ("~A2R <b64>", only this command's sender
# can open them).  They are shown in place, decrypted, behind a lock marker:
#   /set bot_auth_sealed_marker <text>     (default U+1F512; empty = no marker)
#   /set bot_auth_sealed_replies OFF       (plain ~A2 / plaintext replies, for
#                                           bots older than ~A2S)
# A marked line provably came from the bot; an unmarked "reply" did not go
# through this protection.
#
# DCC chat: `/botcmd <bot> dcc` makes the bot offer a passive DCC chat; accept
# it with /dcc chat <bot>.  irssi then listens (open its dcc_port range in
# your firewall, and set dcc_own_ip if you are behind NAT) and the bot
# connects to it.  While that chat is open, /botcmd sends each sealed command
# down the chat instead of by PRIVMSG, and the bot answers there.  Plain text
# typed into the =<bot> window is sealed the same way before it is sent (never
# sent as typed), so the chat reads like any other.
#
# Compare a bot's key fingerprint (printed here on every successful auth)
# against that bot's own 'status' output or the hub console's 'bot list' before
# trusting it for the first time.

our $VERSION = '6.2.0';
our %IRSSI = (
    authors     => 'rclemens',
    contact     => '',
    name        => 'Bot Authenticator (v2 / key-based, passwordless)',
    description => 'Sends ~A2 admin commands to ircbot via Curve25519 + AES-256-GCM. No passwords.',
    license     => 'Public Domain',
);

# =============================================================================
# Pure protocol functions — no Irssi:: calls anywhere below this line down to
# the "Client-side state" section.  These are callable standalone after
# `do "ircbot_irssi_auth.pl"` against a stub Irssi package, for testing.
# =============================================================================

# ASCII-only lowercase: A-Z -> a-z, every other byte unchanged.
sub lc_ascii {
    my $s = shift;
    $s = '' unless defined $s;
    (my $t = $s) =~ tr/A-Z/a-z/;
    return $t;
}

# "ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64), where pub64 is the
# raw 64-byte combined public key (ed_pub(32) || x_pub(32)).
sub fingerprint {
    my ($pub64) = @_;
    my $h   = Crypt::Digest::SHA256::sha256($pub64);
    my $hex = unpack('H*', substr($h, 0, 8));
    return join(':', $hex =~ /(....)/g);
}

# irckey-v2 (a passphrase-protected .private.b64, irchub/docs/console.md §9):
# "irckey-v2 scrypt <log2N> <r> <p> <salt> <nonce> <ct>".  Reader bounds as in
# keygen: a hostile file costs at most 128 * r * N = 256 MB.
use constant IRCKEY_TAG => 'irckey-v2';

sub _b64_exact {
    my ($text, $n) = @_;
    die "malformed irckey-v2 line\n"
        if length($text) != 4 * int(($n + 2) / 3) || $text !~ m{\A[A-Za-z0-9+/]+={0,2}\z};
    my $raw = decode_base64($text);
    die "malformed irckey-v2 line\n" if length($raw) != $n;
    return $raw;
}

# The 64-byte private key inside an irckey-v2 line; dies on a malformed line,
# out-of-range scrypt settings (checked before any work), a wrong passphrase
# or any edit to the line.
sub irckey_open {
    my ($line, $pass) = @_;
    die "malformed irckey-v2 line\n"
        if length($line) >= 512 || $line =~ /  / || $line =~ / \z/;
    my @f = split / /, $line, -1;
    die "malformed irckey-v2 line\n"
        if @f != 8 || $f[0] ne IRCKEY_TAG || $f[1] ne 'scrypt';
    my @lim = ([14, 18], [1, 8], [1, 4]);
    for my $i (0 .. 2) {
        my $v = $f[2 + $i];
        die "irckey-v2 scrypt settings out of range\n"
            if $v !~ /\A\d{1,3}\z/ || $v < $lim[$i][0] || $v > $lim[$i][1];
    }
    my ($log2n, $r, $p) = @f[2 .. 4];
    my $salt  = _b64_exact($f[5], 16);
    my $nonce = _b64_exact($f[6], 12);
    my $ct    = _b64_exact($f[7], 80);
    my $aad   = substr($line, 0, rindex($line, ' '));
    my $key = Crypt::KeyDerivation::scrypt_pbkdf($pass, $salt, 1 << $log2n, $r, $p, 32);
    my ($body, $tag) = (substr($ct, 0, 64), substr($ct, 64));   # plain scalars for the XS
    my $pt = eval { Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $key, $nonce, $aad,
                                                             $body, $tag) };
    substr($key, 0, 32, "\0" x 32);
    die "wrong passphrase (or a damaged key file)\n" if !defined $pt || length($pt) != 64;
    return $pt;
}

# True if the keyfile at $path is an irckey-v2 (passphrase) key.
sub key_is_protected {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "keyfile '$path': $!\n";
    my $line = <$fh>;
    close($fh);
    return defined $line && index($line, IRCKEY_TAG . ' ') == 0;
}

# bot_auth_passwd_expire: "1h", "30m", "90s", "2d", "3600" -> seconds;
# "never" -> -1; undef if unreadable.  0 = ask for every command.
sub parse_expire {
    my ($t) = @_;
    $t = lc($t // '');
    $t =~ s/^\s+|\s+$//g;
    return -1 if $t eq 'never';
    return undef unless $t =~ /\A(\d{1,12})([smhd]?)\z/;
    my $secs = $1 * { '' => 1, s => 1, m => 60, h => 3600, d => 86400 }->{$2};
    return $secs <= 366 * 86400 ? $secs : undef;
}

# Load the combined Ed25519+X25519 private key from $path: the plain first
# line (standard base64 with padding, decoding to exactly 64 bytes:
# ed_priv(32) || x_priv(32)), or an irckey-v2 line opened with $pass (dies
# "locked" without one).  Returns a hashref { ed_priv, x_priv, ed_pub, x_pub,
# pub64, warning, plain }; dies with a one-line message on any failure.
# `warning` is a mode-permission message (or undef) — the caller decides how
# to show it; `plain` is true for a key without a passphrase.
sub load_key {
    my ($path, $pass) = @_;
    open(my $fh, '<', $path) or die "keyfile '$path': $!\n";
    my $line = <$fh>;
    close($fh);
    die "keyfile '$path' is empty\n" if !defined $line;
    my $plain = index($line, IRCKEY_TAG . ' ') != 0;
    my $raw;
    if ($plain) {
        $line =~ s/^\s+|\s+$//g;
        die "keyfile '$path' is empty\n" if !length $line;
        $raw = eval { decode_base64($line) };
        die "keyfile '$path': invalid base64\n" if !defined $raw || !length $raw;
    } else {
        die "locked\n" if !defined $pass;
        $line =~ s/[\r\n]+\z//;
        $raw = irckey_open($line, $pass);
    }
    die "keyfile '$path': decoded key must be 64 bytes, got " . length($raw) . "\n"
        if length($raw) != 64;

    my $ed_priv = substr($raw, 0, 32);
    my $x_priv  = substr($raw, 32, 32);
    substr($raw, 0, length($raw), "\0" x length($raw));

    my $ed = Crypt::PK::Ed25519->new;
    $ed->import_key_raw($ed_priv, 'private');
    my $ed_pub = $ed->export_key_raw('public');

    my $x = Crypt::PK::X25519->new;
    $x->import_key_raw($x_priv, 'private');
    my $x_pub = $x->export_key_raw('public');

    my $pub64 = encode_base64($ed_pub . $x_pub, '');

    my $warning;
    my @st = stat($path);
    if (@st) {
        my $mode = $st[2] & 07777;
        $warning = sprintf("keyfile '%s' is mode %04o — chmod 600 it", $path, $mode)
            if $mode & 077;
    }

    return {
        ed_priv => $ed_priv,
        x_priv  => $x_priv,
        ed_pub  => $ed_pub,
        x_pub   => $x_pub,
        pub64   => $pub64,
        warning => $warning,
        plain   => $plain,
    };
}

# Build one ~A2A auth request.  Returns ($line, $tsn).
sub build_auth {
    my ($key, $botnick, $mynick) = @_;

    my $nonce = unpack('H*', Crypt::PRNG::random_bytes(8));   # 16 lowercase hex chars
    my $tsn   = sprintf('%d:%s', time(), $nonce);

    my $msg = "ircbot-A2A-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick) . "\0" . $tsn;

    my $ed = Crypt::PK::Ed25519->new;
    $ed->import_key_raw($key->{ed_priv}, 'private');
    my $sig = $ed->sign_message($msg);   # 64 bytes

    my $line = '~A2A ' . encode_base64($sig, '') . ' ' . $tsn;
    return ($line, $tsn);
}

# Open a ~A2K lockbox.  $tsn must be the ts:nonce of the pending request this
# reply answers.  Returns the bot's raw 64-byte combined public key on
# success, or undef on any failure (malformed frame, bad point, wrong tag).
sub open_lockbox {
    my ($key, $botnick, $mynick, $tsn, $b64) = @_;

    my $frame = eval { decode_base64($b64) };
    return undef if !defined $frame || length($frame) != 124;

    my $eph = substr($frame, 0, 32);
    my $iv  = substr($frame, 32, 12);
    my $ct  = substr($frame, 44, 64);
    my $tag = substr($frame, 108, 16);

    my $x = Crypt::PK::X25519->new;
    $x->import_key_raw($key->{x_priv}, 'private');
    my $peer = Crypt::PK::X25519->new;
    eval { $peer->import_key_raw($eph, 'public'); 1 } or return undef;

    my $ss = eval { $x->shared_secret($peer) };
    return undef if !defined $ss || $ss eq ("\0" x 32);   # reject a low-order point

    my $info = "ircbot-A2K-v1" . $key->{x_pub};
    my $kmat = eval { Crypt::KeyDerivation::hkdf($ss, $eph, 'SHA256', 32, $info) };
    substr($ss, 0, length($ss), "\0" x length($ss));
    return undef if !defined $kmat;

    my $aad = "ircbot-A2K-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick) . "\0" . $tsn;
    my $pt = eval { Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $kmat, $iv, $aad, $ct, $tag) };
    substr($kmat, 0, length($kmat), "\0" x length($kmat));
    return undef if !defined $pt || length($pt) != 64;
    return $pt;
}

# Build one sealed command.  $bot_pub64 is the bot's raw 64-byte combined
# public key (as returned by open_lockbox).  With $sealed it is a ~A2S frame
# (the bot then seals its replies, §4.7) and, in list context, the reply key
# HKDF(same ikm, eph_pub, "ircbot-A2R-v1" || my_x || bot_x) comes back too:
# ($line, $reply_key).  Otherwise a ~A2 frame.  Dies with a one-line message
# if the command must be refused (control byte, or the finished line would
# exceed the 400-char budget).
sub build_command {
    my ($key, $bot_pub64, $botnick, $mynick, $command, $sealed) = @_;
    my $label = $sealed ? 'ircbot-A2S-v1' : 'ircbot-A2-v1';

    die "command contains a control character\n" if $command =~ /[\x00-\x1f\x7f]/;

    my $nonce = unpack('H*', Crypt::PRNG::random_bytes(8));
    my $pt    = sprintf('%d:%s:%s', time(), $nonce, $command);

    my $bot_x_pub = substr($bot_pub64, 32, 32);

    my $ephk = Crypt::PK::X25519->new;
    $ephk->generate_key;
    my $eph_pub = $ephk->export_key_raw('public');

    my $botpk = Crypt::PK::X25519->new;
    $botpk->import_key_raw($bot_x_pub, 'public');

    my $dh1 = $ephk->shared_secret($botpk);

    my $myx = Crypt::PK::X25519->new;
    $myx->import_key_raw($key->{x_priv}, 'private');
    my $dh2 = $myx->shared_secret($botpk);

    if ($dh1 eq ("\0" x 32) || $dh2 eq ("\0" x 32)) {
        substr($dh1, 0, length($dh1), "\0" x length($dh1));
        substr($dh2, 0, length($dh2), "\0" x length($dh2));
        die "key exchange produced a degenerate shared secret\n";
    }

    my $info = $label . $key->{x_pub} . $bot_x_pub;
    my $kmat = Crypt::KeyDerivation::hkdf($dh1 . $dh2, $eph_pub, 'SHA256', 32, $info);
    my $rk = $sealed
        ? Crypt::KeyDerivation::hkdf($dh1 . $dh2, $eph_pub, 'SHA256', 32,
                                     'ircbot-A2R-v1' . $key->{x_pub} . $bot_x_pub)
        : undef;
    substr($dh1, 0, length($dh1), "\0" x length($dh1));
    substr($dh2, 0, length($dh2), "\0" x length($dh2));

    my $iv  = Crypt::PRNG::random_bytes(12);
    my $aad = "$label\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick);
    my ($ct, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES', $kmat, $iv, $aad, $pt);

    substr($pt, 0, length($pt), "\0" x length($pt));
    substr($kmat, 0, length($kmat), "\0" x length($kmat));

    my $frame = $eph_pub . $iv . $ct . $tag;
    my $line  = ($sealed ? '~A2S ' : '~A2 ') . encode_base64($frame, '');
    if (length($line) > 400) {
        substr($rk, 0, length($rk), "\0" x length($rk)) if defined $rk;
        die "command is too long (" . length($line) . " > 400 chars on the wire)\n";
    }
    return wantarray ? ($line, $rk) : $line;
}

# Open one ~A2R reply to a ~A2S command, with that command's reply key and
# its context nicks.  Returns ($seq, $more, $text) -- text is one piece of a
# reply line, continued in the next frame when $more is 1 -- or () on any
# failure (not ours, tampered, malformed).
sub open_reply {
    my ($rk, $botnick, $mynick, $b64) = @_;
    my $frame = eval { decode_base64($b64) };
    return () if !defined $frame || length($frame) < 28 || length($frame) > 28 + 264;
    my $iv  = substr($frame, 0, 12);
    my $ct  = substr($frame, 12, length($frame) - 28);
    my $tag = substr($frame, -16);
    my $aad = "ircbot-A2R-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick);
    my $pt = eval { Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $rk, $iv, $aad, $ct, $tag) };
    return () if !defined $pt;
    my ($seq, $more, $text) = $pt =~ /\A(\d{1,19}):([01]):(.*)\z/s or return ();
    substr($pt, 0, length($pt), "\0" x length($pt));
    return ($seq + 0, $more + 0, $text);
}

# =============================================================================
# Client-side state and Irssi glue.  Everything below touches Irssi::.
# =============================================================================

use constant AUTH_TIMEOUT   => 60;    # seconds a pending ~A2A stays valid
use constant MAX_QUEUE      => 5;     # queued commands per bot while authenticating
use constant REPLY_KEY_TTL  => 600;   # seconds a ~A2S reply key lives after last use
use constant MAX_REPLY_KEYS => 8;     # reply keys kept per bot (newest first)

our %KEY_CACHE;   # "$net\x1e$bot_lc" => bot_pub64 (raw 64 bytes)
our %PENDING;     # same key         => [$tsn, $send_time]
our %QUEUE;       # same key         => [ $command_line, ... ]
our %DCC_NICK;    # same key         => our nick when we asked for the DCC chat
our %REPLY_KEYS;  # same key         => [ {rk, bot, me, t, next, part}, ... ]
our %NOTED;       # same key         => last "could not open" note (time)

sub _ck { my ($net, $bot) = @_; return (defined $net ? $net : '') . "\x1e" . lc_ascii($bot); }

sub _wipe_reply_key {
    my ($e) = @_;
    substr($e->{rk}, 0, length($e->{rk}), "\0" x length($e->{rk})) if defined $e->{rk};
    $e->{part} = '';
}

# A ~A2S command's reply key, with the nicks its replies are bound to.
sub _remember_reply_key {
    my ($ck, $rk, $bot, $me) = @_;
    my $l = ($REPLY_KEYS{$ck} //= []);
    unshift @$l, { rk => $rk, bot => $bot, me => $me, t => time(), next => 0, part => '' };
    _wipe_reply_key(pop @$l) while @$l > MAX_REPLY_KEYS;
}

sub _forget_reply_keys {
    my ($ck) = @_;
    my $l = delete $REPLY_KEYS{$ck};
    _wipe_reply_key($_) for @{ $l || [] };
}

# One ~A2R frame from a bot, tried against the keys of the commands we sealed
# to it (newest first).  Returns ('show', $line) for a complete reply line,
# ('hold') for a piece of a longer line or a repeat, ('bad') if no key opens
# it.  A missing piece is marked "[...]" in the joined line.
sub _reply_text {
    my ($ck, $b64) = @_;
    my $now = time();
    my $l = $REPLY_KEYS{$ck} or return ('bad');
    for my $e (grep { $now - $_->{t} > REPLY_KEY_TTL } @$l) { _wipe_reply_key($e); }
    @$l = grep { $now - $_->{t} <= REPLY_KEY_TTL } @$l;
    for my $e (@$l) {
        my ($seq, $more, $text) = open_reply($e->{rk}, $e->{bot}, $e->{me}, $b64);
        next unless defined $seq;
        return ('hold') if $seq < $e->{next};
        $e->{part} .= ' [...] ' if $seq > $e->{next} && length $e->{part};
        $e->{next} = $seq + 1;
        $e->{t} = $now;
        $e->{part} .= $text;
        return ('hold') if $more;
        my $line = $e->{part};
        $e->{part} = '';
        return ('show', $line);
    }
    return ('bad');
}

sub _marked {
    my ($text) = @_;
    my $m = Irssi::settings_get_str('bot_auth_sealed_marker');
    return (defined $m && length $m) ? "$m $text" : $text;
}

sub _note_unopened {
    my ($ck, $nick) = @_;
    return if time() - ($NOTED{$ck} // 0) < 30;
    $NOTED{$ck} = time();
    Irssi::print("bot_auth: a sealed reply from $nick could not be opened (it answers "
               . 'a command this session did not send); hidden.');
}

sub _expire_pending {
    my ($ck) = @_;
    my $p = $PENDING{$ck};
    return unless $p;
    return unless time() - $p->[1] > AUTH_TIMEOUT;
    delete $PENDING{$ck};
    my $q = delete $QUEUE{$ck};
    if ($q && @$q) {
        my (undef, $bot_lc) = split /\x1e/, $ck, 2;
        Irssi::print("bot_auth: auth with $bot_lc timed out; dropped "
                   . scalar(@$q) . ' queued command(s).');
    }
}

use constant PASSWD_EXPIRE_DEFAULT => 3600;
use constant PASS_MAX       => 1024;  # passphrase bytes, as keygen
use constant PROMPT_TIMEOUT => 120;   # seconds the passphrase prompt waits
use constant FAIL_LIMIT     => 3;     # wrong passphrases before the prompt pauses
use constant FAIL_PAUSE     => 30;    # seconds of that pause
use constant LOCKED         => 'locked';  # _load_key() error: ask for the passphrase

# The unlocked passphrase-protected key: { key, path, until (undef = never),
# once (passwd_expire 0: lock after this command) }.  Locking wipes the key.
our %UNLOCKED;
# The passphrase prompt while it waits: { path, t, typed => [chars], esc
# (inside an escape sequence), pending => [...] }.
our %CAPTURE;
our %FAILS = (n => 0, until => 0);
our %WARNED;      # keyfiles already warned about having no passphrase
our %SETTINGS_SEEN;

# The input line (Irssi::TextUI; absent under a test stub).
sub _input_set {
    my ($t) = @_;
    Irssi::gui_input_set($t) if defined &Irssi::gui_input_set;
}

sub _wipe_key {
    my ($k) = @_;
    return if !$k;
    for (qw(ed_priv x_priv)) {
        substr($k->{$_}, 0, length $k->{$_}, "\0" x length $k->{$_}) if defined $k->{$_};
    }
}

sub _lock {
    my ($why) = @_;
    my $had = %UNLOCKED ? 1 : 0;
    _wipe_key($UNLOCKED{key});
    %UNLOCKED = ();
    Irssi::print("bot_auth: $why") if $had && defined $why;
}

sub _expire_secs {
    my $v = Irssi::settings_get_str('bot_auth_passwd_expire');
    my $secs = parse_expire($v);
    if (!defined $secs) {
        Irssi::print("bot_auth: bot_auth_passwd_expire '$v' is not e.g. 30m, 1h, 6h, 1d, "
                   . '0 or never; using 1h');
        return PASSWD_EXPIRE_DEFAULT;
    }
    return $secs;
}

sub _load_key {
    my $path = Irssi::settings_get_str('bot_auth_keyfile');
    return (undef, 'no keyfile set — /set bot_auth_keyfile <path>')
        if !defined $path || !length $path;
    my $prot = eval { key_is_protected($path) };
    if ($@) {
        (my $e = $@) =~ s/\n\z//;
        return (undef, "keyfile error: $e");
    }
    if ($prot) {
        return ($UNLOCKED{key}, undef)
            if %UNLOCKED && $UNLOCKED{path} eq $path
            && (!defined $UNLOCKED{until} || time() < $UNLOCKED{until});
        _lock(%UNLOCKED ? 'key locked again (passwd_expire)' : undef);
        return (undef, LOCKED);
    }
    my $key = eval { load_key($path) };
    if ($@) {
        (my $e = $@) =~ s/\n\z//;
        return (undef, "keyfile error: $e");
    }
    if (!$WARNED{$path}++) {
        Irssi::print("bot_auth: keyfile '$path' has no passphrase — add one with: "
                   . "keygen --passwd $path");
    }
    return ($key, undef);
}

# passwd_expire 0: lock once nothing more is waiting for the key.
sub _used_once {
    _lock() if $UNLOCKED{once} && !%PENDING && !%CAPTURE;
}

# Arm the passphrase prompt; $pending (a /botcmd's server tag, bot and
# command) runs after a successful unlock.
sub _ask_passphrase {
    my ($pending) = @_;
    my $path = Irssi::settings_get_str('bot_auth_keyfile');
    my $now  = time();
    if ($now < $FAILS{until}) {
        return Irssi::print('bot_auth: too many wrong passphrases; try again in '
                          . ($FAILS{until} - $now + 1) . ' s.');
    }
    if (%CAPTURE) {
        push @{ $CAPTURE{pending} }, $pending
            if $pending && @{ $CAPTURE{pending} } < MAX_QUEUE;
        return Irssi::print('bot_auth: still waiting for the passphrase (an empty line cancels).');
    }
    %CAPTURE = (path => $path, t => $now, typed => [], esc => 0,
                pending => [$pending ? $pending : ()]);
    _input_set('');
    Irssi::print("bot_auth: passphrase for $path: type it and press Enter — it never "
               . 'reaches the input line or its history and is never sent (an empty '
               . 'line cancels).');
}

# The prompt's state, the prompt closed and the input line cleared.
sub _end_capture {
    my %cap = %CAPTURE;
    %CAPTURE = ();
    _input_set('');
    return \%cap;
}

sub _cancel_capture {
    my ($why) = @_;
    return if !%CAPTURE;
    my $cap = _end_capture();
    my $n = @{ $cap->{pending} };
    $_ = "\0" for @{ $cap->{typed} };
    Irssi::print("bot_auth: $why" . ($n ? "; dropped $n command(s)" : ''));
}

sub _try_unlock {
    my ($cap) = @_;
    my $pass = join('', @{ $cap->{typed} });
    $_ = "\0" for @{ $cap->{typed} };
    my $n = @{ $cap->{pending} };
    if (!length $pass) {
        return Irssi::print('bot_auth: passphrase prompt cancelled'
                          . ($n ? "; dropped $n command(s)" : ''));
    }
    utf8::encode($pass) if utf8::is_utf8($pass);
    my $key = length($pass) <= PASS_MAX ? eval { load_key($cap->{path}, $pass) } : undef;
    my $err = $@ || (length($pass) > PASS_MAX ? "passphrase too long\n" : '');
    substr($pass, 0, length $pass, "\0" x length $pass);
    if (!$key) {
        $err =~ s/\n\z//;
        if (++$FAILS{n} >= FAIL_LIMIT) {
            %FAILS = (n => 0, until => time() + FAIL_PAUSE);
        }
        return Irssi::print("bot_auth: $err" . ($n ? "; dropped $n command(s)" : ''));
    }
    %FAILS = (n => 0, until => 0);
    my $secs = _expire_secs();
    my $now  = time();
    _lock();
    %UNLOCKED = (key => $key, path => $cap->{path}, once => $secs == 0,
                 until => $secs < 0 ? undef
                        : $now + ($secs == 0 ? AUTH_TIMEOUT : $secs));
    if ($secs < 0) {
        Irssi::print('bot_auth: key unlocked until /botlock.');
    } elsif ($secs == 0) {
        Irssi::print('bot_auth: key unlocked for this command.');
    } else {
        my @t = localtime($now + $secs);
        Irssi::print(sprintf('bot_auth: key unlocked until %02d:%02d:%02d (passwd_expire).',
                             @t[2, 1, 0]));
    }
    for my $p (@{ $cap->{pending} }) {
        my $server = Irssi::server_find_tag($p->[0]);
        if (!$server || !$server->{connected}) {
            Irssi::print("bot_auth: not connected to $p->[0] any more; dropped a command.");
            next;
        }
        _handle_botcmd($server, $p->[1], $p->[2]);
    }
    _used_once();
}

# While the passphrase prompt waits, every key goes to it: the input line only
# ever shows stars, and nothing reaches its history or the server.  Escape
# sequences (arrows, function keys) are skipped.
sub sig_gui_key {
    my ($key) = @_;
    return if !%CAPTURE;
    Irssi::signal_stop();
    my $typed = $CAPTURE{typed};
    if ($CAPTURE{esc}) {
        # ESC [ ... final byte, or ESC O x, or ESC x
        if ($CAPTURE{esc} == 1 && ($key == 91 || $key == 79)) { $CAPTURE{esc} = 2; return; }
        $CAPTURE{esc} = 0 if $CAPTURE{esc} == 1 || ($key >= 0x40 && $key <= 0x7e);
        return;
    }
    if ($key == 10 || $key == 13) {
        _try_unlock(_end_capture());
        return;
    }
    if ($key == 27) { $CAPTURE{esc} = 1; return; }
    if ($key == 127 || $key == 8) {
        pop @$typed;
    } elsif ($key >= 32 && @$typed < PASS_MAX) {
        my $ch = chr($key);
        utf8::encode($ch);
        push @$typed, $ch;
    }
    _input_set('*' x scalar(@$typed));
}

# The active window's input history, oldest first (Irssi 1.2+; undef when
# this Irssi cannot list or delete entries).
sub _history {
    return undef if !defined &Irssi::active_win;
    my $win = Irssi::active_win() or return undef;
    return undef if !$win->can('get_history_entries') || !$win->can('delete_history_entries');
    return ($win, [ $win->get_history_entries() ]);
}

# A paste holding a newline never raises "gui key pressed": Irssi adds the
# line to the input history and emits "send command" itself.  While the
# prompt waits, that line is the passphrase: it is taken, dropped from the
# history and never sent.
sub sig_send_command {
    my ($line) = @_;
    return if !%CAPTURE;
    my ($win, $hist) = _history();
    if ($win) {
        # Commands from scripts (ours included) skip the history: let them by.
        return if !@$hist || ($hist->[-1]{text} // '') ne $line;
        $win->delete_history_entries(grep { ($_->{text} // '') eq $line } @$hist);
    } else {
        Irssi::print('bot_auth: this Irssi cannot delete history entries; '
                   . 'the pasted passphrase is still in the input history.');
    }
    Irssi::signal_stop();
    my $typed = $CAPTURE{typed};
    my $n = @$typed;
    # The input line held one star per key typed before the paste.
    my $pasted = substr($line, 0, $n) eq '*' x $n ? substr($line, $n) : $line;
    $pasted =~ tr/\x00-\x1f\x7f//d;
    utf8::encode($pasted) if utf8::is_utf8($pasted);
    push @$typed, $pasted if length $pasted;
    substr($pasted, 0, length $pasted, "\0" x length $pasted);
    _try_unlock(_end_capture());
}

sub pin_lookup {
    my ($pinfile, $bot_lc) = @_;
    open(my $fh, '<', $pinfile) or return undef;
    while (my $line = <$fh>) {
        chomp $line;
        my ($nick, $val) = split ' ', $line, 2;
        next unless defined $nick && defined $val;
        return $val if $nick eq $bot_lc;
    }
    return undef;
}

sub pin_add {
    my ($pinfile, $bot_lc, $pub_b64) = @_;
    my $is_new = !-e $pinfile;
    open(my $fh, '>>', $pinfile) or return;
    print $fh "$bot_lc $pub_b64\n";
    close($fh);
    chmod(0600, $pinfile) if $is_new;
}

sub pin_remove {
    my ($pinfile, $bot_lc) = @_;
    open(my $fh, '<', $pinfile) or return;
    my @lines = <$fh>;
    close($fh);
    my @kept = grep {
        my ($nick) = split ' ', $_, 2;
        !(defined $nick && $nick eq $bot_lc);
    } @lines;
    if (@kept != @lines) {
        open(my $out, '>', $pinfile) or return;
        print $out @kept;
        close($out);
    }
}

sub _send_auth {
    my ($server, $bot_nick, $mynick, $key) = @_;
    my ($line, $tsn) = eval { build_auth($key, $bot_nick, $mynick) };
    if ($@ || !defined $line) {
        (my $e = $@) =~ s/\n\z//;
        Irssi::print("bot_auth: failed to build auth request: $e");
        return;
    }
    $PENDING{_ck($server->{tag}, $bot_nick)} = [$tsn, time()];
    $server->command("QUOTE PRIVMSG $bot_nick :$line");
    Irssi::print("bot_auth: authenticating with $bot_nick...");
}

# The open DCC chat with $bot_nick on this network, if any.
sub _dcc_chat {
    my ($server, $bot_nick) = @_;
    for my $dcc (Irssi::Irc::dccs()) {
        next unless $dcc->{type} eq 'CHAT' && $dcc->{starttime};
        next unless lc_ascii($dcc->{nick}) eq lc_ascii($bot_nick);
        next if $server && $dcc->{servertag} && $dcc->{servertag} ne $server->{tag};
        return $dcc;
    }
    return undef;
}

# A command goes down the bot's DCC chat when one is open, else by PRIVMSG.
# On the chat the bot takes the sender nick to be the one that asked for it.
# With bot_auth_sealed_replies (the default) it is a ~A2S frame and the reply
# key is kept to open the answers.  Returns true once sent.
sub _send_command {
    my ($server, $bot_nick, $mynick, $key, $bot_pub64, $command_line) = @_;
    my $ck  = _ck($server->{tag}, $bot_nick);
    my $dcc = _dcc_chat($server, $bot_nick);
    return _seal_and_send($ck, $server, $dcc, $bot_nick,
                          $dcc ? ($DCC_NICK{$ck} // $mynick) : $mynick,
                          $key, $bot_pub64, $command_line);
}

sub _seal_and_send {
    my ($ck, $server, $dcc, $bot_nick, $as, $key, $bot_pub64, $command_line) = @_;
    my $sealed = Irssi::settings_get_bool('bot_auth_sealed_replies');
    my ($line, $rk) = eval {
        build_command($key, $bot_pub64, $bot_nick, $as, $command_line, $sealed) };
    if ($@) {
        (my $e = $@) =~ s/\n\z//;
        Irssi::print("bot_auth: $e");
        return 0;
    }
    _remember_reply_key($ck, $rk, $bot_nick, $as) if defined $rk;
    if ($dcc) {
        Irssi::Irc::dcc_chat_send($dcc, $line);
        return 1;
    }
    $DCC_NICK{$ck} = $as if $command_line =~ /^dcc(?:\s|$)/i;
    $server->command("QUOTE PRIVMSG $bot_nick :$line");
    return 1;
}

sub _handle_botcmd {
    my ($server, $bot_nick, $command_line) = @_;

    my ($key, $err) = _load_key();
    return _ask_passphrase([$server->{tag}, $bot_nick, $command_line])
        if $err && $err eq LOCKED;
    return Irssi::print("bot_auth: $err") if $err;
    Irssi::print("bot_auth: " . $key->{warning}) if $key->{warning};

    my $ck = _ck($server->{tag}, $bot_nick);
    _expire_pending($ck);

    my $bot_pub64 = $KEY_CACHE{$ck};
    if (defined $bot_pub64) {
        _send_command($server, $bot_nick, $server->{nick}, $key, $bot_pub64, $command_line);
        _used_once();
        return;
    }

    my $q = ($QUEUE{$ck} //= []);
    if (@$q >= MAX_QUEUE) {
        Irssi::print("bot_auth: queue for $bot_nick is full (max " . MAX_QUEUE . '); dropping oldest.');
        shift @$q;
    }
    push @$q, $command_line;

    if ($PENDING{$ck}) {
        Irssi::print("bot_auth: already authenticating with $bot_nick; command queued.");
        return;
    }
    _send_auth($server, $bot_nick, $server->{nick}, $key);
}

sub cmd_botcmd {
    my ($data, $server, $witem) = @_;
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;

    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print('bot_auth: not connected to a server.')
            if !$server || !$server->{connected};
    }

    my ($bot_nick, @rest) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botcmd <bot_nick> <command> [args...]')
        if !defined $bot_nick || !length $bot_nick || !@rest;

    _handle_botcmd($server, $bot_nick, join(' ', @rest));
}

sub cmd_botauth {
    my ($data, $server, $witem) = @_;
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;

    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print('bot_auth: not connected to a server.')
            if !$server || !$server->{connected};
    }

    my ($bot_nick) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botauth <bot_nick>')
        if !defined $bot_nick || !length $bot_nick;

    my ($key, $err) = _load_key();
    if ($err && $err eq LOCKED) {
        _ask_passphrase();
        return Irssi::print("bot_auth: run /botauth $bot_nick again once the key is unlocked.");
    }
    return Irssi::print("bot_auth: $err") if $err;

    delete $KEY_CACHE{_ck($server->{tag}, $bot_nick)};
    _send_auth($server, $bot_nick, $server->{nick}, $key);
}

sub cmd_botforget {
    my ($data, $server, $witem) = @_;
    $server = $witem->{server} if !$server && $witem && $witem->{server};

    my ($bot_nick) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botforget <bot_nick>')
        if !defined $bot_nick || !length $bot_nick;

    my $net = $server ? $server->{tag} : '';
    my $ck  = _ck($net, $bot_nick);
    my $had = exists $KEY_CACHE{$ck};
    delete $KEY_CACHE{$ck};
    delete $PENDING{$ck};
    delete $QUEUE{$ck};
    delete $DCC_NICK{$ck};
    _forget_reply_keys($ck);

    my $pinfile = Irssi::settings_get_str('bot_auth_pinfile');
    pin_remove($pinfile, lc_ascii($bot_nick)) if defined $pinfile && length $pinfile;

    Irssi::print("bot_auth: forgot $bot_nick" . ($had ? '' : ' (was not cached)') . '.');
}

# "event notice" args: ($server, $data, $nick, $address) — $nick/$address are
# already split from the sender prefix by Irssi.  $data is "<target> :<text>".
sub sig_notice {
    my ($server, $data, $nick, $address) = @_;
    return if !defined $data;
    my ($target, $text) = $data =~ /^(\S+)\s+:(.*)$/s;
    return if !defined $text;
    return unless $text =~ /^~A2K /;

    # Protocol traffic: always hidden, whether or not we can process it.
    Irssi::signal_stop();
    return if !$CRYPTX_OK;
    return if !$server;

    my $mynick = $server->{nick};
    my $ck     = _ck($server->{tag}, $nick);
    _expire_pending($ck);

    my $pend = delete $PENDING{$ck};
    return if !$pend;   # no matching request: drop silently
    my ($tsn) = @$pend;

    my ($key, $err) = _load_key();
    if ($err) {
        delete $QUEUE{$ck};
        return Irssi::print('bot_auth: ' . ($err eq LOCKED
            ? "the key locked before $nick answered; /botunlock and try again" : $err));
    }

    my $b64 = substr($text, 5);
    my $bot_pub64 = open_lockbox($key, $nick, $mynick, $tsn, $b64);
    if (!defined $bot_pub64) {
        Irssi::print("bot_auth: ~A2K from $nick failed to decrypt/verify; ignored.");
        return;
    }

    my $pinfile = Irssi::settings_get_str('bot_auth_pinfile');
    if (defined $pinfile && length $pinfile) {
        my $bot_lc    = lc_ascii($nick);
        my $existing  = pin_lookup($pinfile, $bot_lc);
        my $got_b64   = encode_base64($bot_pub64, '');
        if (!defined $existing) {
            pin_add($pinfile, $bot_lc, $got_b64);
        } elsif ($existing ne $got_b64) {
            my $existing_raw = eval { decode_base64($existing) };
            Irssi::print(sprintf(
                "bot_auth: WARNING pinned-key mismatch for %s! pinned %s got %s "
              . "-- possible man-in-the-middle, or the bot was rekeyed. "
              . "Run /botforget %s to accept the new key.",
                $nick,
                (defined $existing_raw ? fingerprint($existing_raw) : '?'),
                fingerprint($bot_pub64), $nick));
            return;   # do NOT cache on a pin mismatch
        }
    }

    $KEY_CACHE{$ck} = $bot_pub64;
    Irssi::print("bot_auth: authenticated with $nick — key " . fingerprint($bot_pub64));

    my $q = delete $QUEUE{$ck};
    if ($q) {
        _send_command($server, $nick, $mynick, $key, $bot_pub64, $_) for @$q;
    }
    _used_once();
}

# A bot's ~A2R reply shown in place of the frame, marked as sealed: "message
# private" / "message irc notice" ($server, $msg, $nick, $address, $target)
# and "message dcc" ($dcc, $msg) are continued with the plaintext.  Pieces of
# a longer line are held until the last one; a frame no key opens is hidden.
sub _sig_reply {
    my ($ck, $nick, $msg, $continue) = @_;
    return 0 unless defined $msg && $msg =~ /^~A2R (\S+)\s*$/;
    my ($st, $line) = $CRYPTX_OK ? _reply_text($ck, $1) : ('bad');
    if ($st eq 'show') {
        $continue->(_marked($line));
    } else {
        Irssi::signal_stop();
        _note_unopened($ck, $nick) if $st eq 'bad';
    }
    return 1;
}

sub sig_message_private {
    my ($server, $msg, $nick, $address, $target) = @_;
    return if !$server;
    _sig_reply(_ck($server->{tag}, $nick), $nick, $msg,
               sub { Irssi::signal_continue($server, $_[0], $nick, $address, $target) });
}

sub sig_message_dcc {
    my ($dcc, $msg) = @_;
    return if !$dcc;
    _sig_reply(_ck($dcc->{servertag}, $dcc->{nick}), $dcc->{nick}, $msg,
               sub { Irssi::signal_continue($dcc, $_[0]) });
}

# Text typed into the "=bot" window of a DCC chat we asked a bot for: the chat
# only carries sealed frames (the bot closes it on anything else), so the text
# is sealed like /botcmd and shown as typed.  If it cannot be sealed it is not
# sent.  Chats with anyone else are left alone.
sub sig_send_text {
    my ($text, $server, $witem) = @_;
    return unless $witem && $witem->{type} eq 'QUERY' && $witem->{name} =~ /^=(.+)\z/;
    my $bot = $1;
    my $dcc = _dcc_chat(undef, $bot) or return;
    my $ck  = _ck($dcc->{servertag}, $bot);
    return unless exists $DCC_NICK{$ck};
    Irssi::signal_stop();
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;
    my ($key, $err) = _load_key();
    return Irssi::print('bot_auth: the key is locked -- not sent; /botunlock first')
        if $err && $err eq LOCKED;
    return Irssi::print("bot_auth: $err -- not sent") if $err;
    my $bot_pub64 = $KEY_CACHE{$ck};
    return Irssi::print("bot_auth: no key for $bot this session (/botauth $bot) -- not sent")
        if !defined $bot_pub64;
    my $srv = Irssi::server_find_tag($dcc->{servertag});
    Irssi::signal_emit('message dcc own', $dcc, $text)
        if _seal_and_send($ck, $srv, $dcc, $bot, $DCC_NICK{$ck}, $key, $bot_pub64, $text);
    _used_once();
}

sub cmd_botunlock {
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;
    my ($key, $err) = _load_key();
    if ($err && $err eq LOCKED) {
        _ask_passphrase();
    } elsif ($err) {
        Irssi::print("bot_auth: $err");
    } elsif ($key->{plain}) {
        Irssi::print('bot_auth: the keyfile has no passphrase; nothing to unlock.');
    } else {
        Irssi::print('bot_auth: already unlocked' . (defined $UNLOCKED{until}
            ? ' for ' . ($UNLOCKED{until} > time() ? $UNLOCKED{until} - time() : 0) . ' more s'
            : ' until /botlock') . '.');
    }
}

sub cmd_botlock {
    _cancel_capture('passphrase prompt cancelled');
    my $had = %UNLOCKED ? 1 : 0;
    _lock();
    Irssi::print($had ? 'bot_auth: key locked.' : 'bot_auth: key was not unlocked.');
}

# Changing bot_auth_keyfile or bot_auth_passwd_expire locks the key.
sub sig_setup_changed {
    my $now = join("\x1e", map { Irssi::settings_get_str($_) }
                                 qw(bot_auth_keyfile bot_auth_passwd_expire));
    my $was = $SETTINGS_SEEN{v};
    $SETTINGS_SEEN{v} = $now;
    return if !defined $was || $was eq $now;
    _cancel_capture('keyfile/passwd_expire changed: passphrase prompt cancelled');
    _lock('keyfile/passwd_expire changed: key locked.');
}

sub timer_check {
    _expire_pending($_) for keys %PENDING;
    my $now = time();
    _lock('key locked again (passwd_expire); the next /botcmd asks for the passphrase.')
        if %UNLOCKED && defined $UNLOCKED{until} && $now >= $UNLOCKED{until};
    _cancel_capture('passphrase prompt timed out')
        if %CAPTURE && $now - $CAPTURE{t} > PROMPT_TIMEOUT;
}

# Registration is guarded so this file can be `do`-loaded under a minimal
# stub Irssi package (a test harness) without dying before the pure functions
# above (load_key/build_auth/open_lockbox/build_command/fingerprint) exist.
eval { require Irssi::TextUI; 1 };   # gui_input_set for the passphrase prompt
eval {
    Irssi::settings_add_str('bot_auth', 'bot_auth_keyfile', '');
    Irssi::settings_add_str('bot_auth', 'bot_auth_pinfile', '');
    Irssi::settings_add_bool('bot_auth', 'bot_auth_sealed_replies', 1);
    Irssi::settings_add_str('bot_auth', 'bot_auth_sealed_marker', "\xF0\x9F\x94\x92");  # U+1F512
    Irssi::settings_add_str('bot_auth', 'bot_auth_passwd_expire', '1h');
    sig_setup_changed();
    Irssi::command_bind('botcmd',    \&cmd_botcmd);
    Irssi::command_bind('botauth',   \&cmd_botauth);
    Irssi::command_bind('botforget', \&cmd_botforget);
    Irssi::command_bind('botunlock', \&cmd_botunlock);
    Irssi::command_bind('botlock',   \&cmd_botlock);
    Irssi::signal_add_first('gui key pressed', \&sig_gui_key);
    Irssi::signal_add_first('send command', \&sig_send_command);
    Irssi::signal_add('setup changed', \&sig_setup_changed);
    Irssi::signal_add_first('event notice', \&sig_notice);
    Irssi::signal_add_first('message private', \&sig_message_private);
    Irssi::signal_add_first('message irc notice', \&sig_message_private);
    Irssi::signal_add_first('message dcc', \&sig_message_dcc);
    Irssi::signal_add_first('send text', \&sig_send_text);
    Irssi::timeout_add(5000, \&timer_check, undef);

    Irssi::print("Bot Authenticator v$VERSION (~A2 / key-based, passwordless) loaded.");
    if ($CRYPTX_OK) {
        Irssi::print('Set /set bot_auth_keyfile <path> to your .private.b64, '
                   . 'then /botcmd <bot> <command>.');
    } else {
        Irssi::print(cryptx_hint());
        Irssi::print('/botcmd stays registered but will refuse to send until then.');
    }
    1;
} or warn "bot_auth: registration under a limited Irssi stub: $@";

1;
