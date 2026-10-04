; bot-auth.mrc — mIRC client for ircbot's key-based admin/oper protocol
;                (~A2A auth request, ~A2K lockbox, ~A2 sealed command).
;
; mIRC cannot do Curve25519 / AES-GCM itself, so every crypto step runs in
; bot-auth.exe (utils/bot_auth.rs; build it with cargo, see utils/README.txt).
; No password exists anywhere.  Nothing secret goes on a command line: the
; private key stays in its file (read by bot-auth.exe), and the command text is
; handed over through a short-lived temp file that is deleted right after.
; The bot's public key is kept only in memory (a hash table) for this mIRC
; session; optionally it is pinned to a file so a changed key is refused.
;
; Setup (once, in mIRC):
;   /set %bot_auth_exe     C:\path\to\bot-auth.exe
;   /set %bot_auth_keyfile C:\path\to\20260914120000_robert.private.b64
;   /set %bot_auth_pinfile C:\path\to\bot_pins.txt      ; optional
;   /set %bot_auth_tmpdir  C:\path\to\a\private\tempdir ; optional, default $sysdir(temp)
;   /set %bot_auth_passwd_expire 1h                     ; optional, see below
; Keep the .private.b64 readable only by you (file Properties > Security).
;
; Passphrase-protected keys (keygen asks for one; irchub/docs/console.md §9):
; when bot-auth.exe reports the key LOCKED, this script opens a bot-auth
; window ("bot-auth.exe unlock") that asks for the passphrase with echo off
; and then keeps the key in a background key holder for %bot_auth_passwd_expire
; (default 1h; 30m, 6h, 1d, a number of seconds, never, or 0 = lock again
; right after the waiting commands are sent).  The window closes by itself.
; The waiting commands are sent once the key is unlocked.  The passphrase
; never passes through mIRC, a temp file or a command line.
;
; Usage:
;   /botcmd <bot_nick> <command> [arguments...]   authenticates once, then sends
;   /botauth <bot_nick>                           drop the cached key, re-auth
;   /botforget <bot_nick>                         drop the cached key (and pin)
;   /botunlock                                    unlock the key now
;   /botlock                                      forget the unlocked key now
; On first contact the bot's key fingerprint is echoed; compare it once with
; the bot's 'status' output or the hub console's 'bot list'.
;
; DCC chat: /botcmd <bot> dcc makes the bot offer a passive DCC chat; accept
; it.  mIRC then listens (open its DCC port range in your firewall; set its
; DCC IP to your public address if you are behind NAT) and the bot connects
; to it.  While that chat is open, /botcmd sends each sealed command down the
; chat instead of by PRIVMSG, and the bot answers there.

alias -l ba.net { return $iif($network != $null, $network, $server) }
alias -l ba.key { return $+($ba.net, ., $lower($1)) }
alias -l ba.tmp { return $+($iif(%bot_auth_tmpdir != $null, %bot_auth_tmpdir, $sysdir(temp)), \botauth-, $1, -, $ticks, -, $rand(1,999999), .txt) }
alias -l ba.q { return "" $+ $1- $+ "" }

alias -l ba.ready {
  if (%bot_auth_exe == $null) { echo -a bot_auth: /set % $+ bot_auth_exe C:\path\to\bot-auth.exe | return $false }
  if (%bot_auth_keyfile == $null) { echo -a bot_auth: /set % $+ bot_auth_keyfile C:\path\to\NAME.private.b64 | return $false }
  if (!$isfile(%bot_auth_exe)) { echo -a bot_auth: %bot_auth_exe not found | return $false }
  if (!$isfile(%bot_auth_keyfile)) { echo -a bot_auth: %bot_auth_keyfile not found | return $false }
  return $true
}

; ---- passphrase-protected keys: the bot-auth key holder -------------------
; bot-auth.exe prints "bot-auth: LOCKED: ..." (exit 4) for an irckey-v2 key
; with no key holder running.  What was being done is kept as a retry
; ("auth <bot>" or "cmd <bot> <command>", $chr(1)-separated) and replayed once
; `bot-auth.exe status` says unlocked.
alias -l ba.islocked { return $iif(($gettok($1-, 1, 32) == bot-auth:) && ($gettok($1-, 2, 32) == LOCKED:), $true, $false) }
alias -l ba.exp {
  var %e = $iif(%bot_auth_passwd_expire != $null, %bot_auth_passwd_expire, 1h)
  ; 0 = lock again right after the waiting commands (see ba.sendpoll)
  return $iif(%e == 0, 120, %e)
}
alias -l ba.warnplain {
  if ($hget(botauth, warnedplain) != $null) return
  hadd -m botauth warnedplain 1
  if ($gettok($read(%bot_auth_keyfile, n, 1), 1, 32) != irckey-v2) echo -a bot_auth: %bot_auth_keyfile has no passphrase — add one with: keygen --passwd <file>
}
alias -l ba.retry {
  ; $1- = "auth <bot>" or "cmd <bot> <command>"
  var %r = $hget(botauth, retry)
  if ($numtok(%r, 1) < 5) hadd -m botauth retry $addtok(%r, $1-, 1)
  ba.startunlock
}
alias -l ba.startunlock {
  if ($hget(botauth, unlocking) != $null) return
  hadd -m botauth unlocking $ctime
  ; not hidden: its own console window asks for the passphrase, then closes
  .run $ba.q(%bot_auth_exe) unlock $ba.q(%bot_auth_keyfile) --expire $ba.exp
  echo -a bot_auth: the key is passphrase-protected — type the passphrase in the bot-auth window.
  .timer 1 2 ba.unlockpoll 1 $null
}
alias -l ba.unlockpoll {
  ; $1 = try, $2 = the previous status output file
  var %try = $1, %prev = $2, %line
  if ((%prev != $null) && ($isfile(%prev))) { var %line = $read(%prev, n, 1) | .remove %prev }
  if ($gettok(%line, 1, 32) == unlocked) {
    hdel botauth unlocking
    echo -a bot_auth: key unlocked ( $+ $ba.exp $+ ).
    var %r = $hget(botauth, retry), %i = 1
    hdel botauth retry
    while (%i <= $numtok(%r, 1)) {
      var %t = $gettok(%r, %i, 1)
      if ($gettok(%t, 1, 32) == auth) ba.auth $gettok(%t, 2, 32)
      else botcmd $gettok(%t, 2-, 32)
      inc %i
    }
    return
  }
  if (%try >= 60) {
    hdel botauth unlocking
    hdel botauth retry
    echo -a bot_auth: the key was not unlocked; dropped the waiting commands.
    return
  }
  var %out = $ba.tmp(status)
  .run -nh cmd /c $ba.q($ba.q(%bot_auth_exe) status $ba.q(%bot_auth_keyfile) > $ba.q(%out) 2>&1)
  .timer 1 2 ba.unlockpoll $calc(%try + 1) %out
}
alias -l ba.lockrun {
  .run -nh $ba.q(%bot_auth_exe) lock $ba.q(%bot_auth_keyfile)
}

alias botunlock {
  if (!$ba.ready) return
  ba.startunlock
}

alias botlock {
  if (!$ba.ready) return
  ba.lockrun
  echo -a bot_auth: key locked.
}

alias botcmd {
  if ($0 < 2) { echo -a Usage: /botcmd <bot_nick> <command> [arguments] | return }
  if (!$ba.ready) return
  ba.warnplain
  var %bot = $1, %k = $ba.key($1)
  var %pub = $hget(botauth, $+(key., %k))
  if (%pub != $null) { ba.send %bot %pub $2- | return }
  ; queue until the lockbox arrives (control characters cannot occur in
  ; commands, so $chr(1) is a safe separator); at most 5 queued commands
  var %q = $hget(botauth, $+(q., %k))
  if ($numtok(%q, 1) >= 5) { var %q = $deltok(%q, 1, 1) | echo -a bot_auth: queue for %bot full; dropped the oldest }
  hadd -m botauth $+(q., %k) $addtok(%q, $2-, 1)
  var %pt = $hget(botauth, $+(pendt., %k))
  if ((%pt != $null) && ($calc($ctime - %pt) < 60)) { echo -a bot_auth: already authenticating with %bot $+ ; command queued | return }
  ba.auth %bot
}

alias botauth {
  if ($0 < 1) { echo -a Usage: /botauth <bot_nick> | return }
  if (!$ba.ready) return
  hdel botauth $+(key., $ba.key($1))
  ba.auth $1
}

alias botforget {
  if ($0 < 1) { echo -a Usage: /botforget <bot_nick> | return }
  var %k = $ba.key($1)
  hdel botauth $+(key., %k)
  hdel botauth $+(pend., %k)
  hdel botauth $+(pendt., %k)
  hdel botauth $+(q., %k)
  hdel botauth $+(dnick., %k)
  if ((%bot_auth_pinfile != $null) && ($isfile(%bot_auth_pinfile))) {
    ; remove the "<lc botnick> <pubkey>" line so a rekeyed bot can be learned
    var %n = $lines(%bot_auth_pinfile)
    while (%n > 0) {
      if ($gettok($read(%bot_auth_pinfile, n, %n), 1, 32) == $lower($1)) write -dl $+ %n $ba.q(%bot_auth_pinfile)
      dec %n
    }
  }
  echo -a bot_auth: forgot $1
}

; ---- step 1: ~A2A auth request -------------------------------------------
alias -l ba.auth {
  var %bot = $1, %k = $ba.key($1), %out = $ba.tmp(auth)
  hadd -m botauth $+(pendt., %k) $ctime
  .run -nh cmd /c $ba.q($ba.q(%bot_auth_exe) auth $ba.q(%bot_auth_keyfile) %bot $me > $ba.q(%out) 2>&1)
  echo -a bot_auth: authenticating with %bot $+ ...
  .timer 1 1 ba.authpoll %bot %out 1
}

alias -l ba.authpoll {
  var %bot = $1, %out = $2, %try = $3, %k = $ba.key($1)
  var %line = $iif($isfile(%out), $read(%out, n, 1))
  if ($gettok(%line, 1, 32) == ~A2A) {
    .remove %out
    hadd -m botauth $+(pend., %k) $gettok(%line, 3, 32)
    .quote PRIVMSG %bot : $+ %line
    return
  }
  if ($ba.islocked(%line)) {
    .remove %out
    hdel botauth $+(pendt., %k)
    ba.retry auth %bot
    return
  }
  if (%try < 10) { .timer 1 1 ba.authpoll %bot %out $calc(%try + 1) | return }
  echo -a bot_auth: bot-auth.exe gave no ~A2A line: %line
  if ($isfile(%out)) .remove %out
}

; ---- step 2: the bot's ~A2K lockbox (always hidden) ------------------------
on ^*:NOTICE:~A2K *:?: {
  haltdef
  var %k = $ba.key($nick), %tsn = $hget(botauth, $+(pend., %k))
  if (%tsn == $null) return
  hdel botauth $+(pend., %k)
  hdel botauth $+(pendt., %k)
  var %out = $ba.tmp(open), %pin
  if (%bot_auth_pinfile != $null) var %pin = --pin $ba.q(%bot_auth_pinfile)
  .run -nh cmd /c $ba.q($ba.q(%bot_auth_exe) open $ba.q(%bot_auth_keyfile) $nick $me %tsn $ba.q($1-) %pin > $ba.q(%out) 2>&1)
  .timer 1 1 ba.openpoll $nick %out 1
}

alias -l ba.openpoll {
  var %bot = $1, %out = $2, %try = $3, %k = $ba.key($1)
  var %line = $iif($isfile(%out), $read(%out, n, 1))
  if (($len($gettok(%line, 1, 32)) == 88) && ($numtok(%line, 32) == 2)) {
    .remove %out
    hadd -m botauth $+(key., %k) $gettok(%line, 1, 32)
    echo -a bot_auth: authenticated with %bot - key $gettok(%line, 2, 32)
    var %q = $hget(botauth, $+(q., %k)), %i = 1
    hdel botauth $+(q., %k)
    while (%i <= $numtok(%q, 1)) { ba.send %bot $gettok(%line, 1, 32) $gettok(%q, %i, 1) | inc %i }
    return
  }
  if ($ba.islocked(%line)) {
    ; the key locked between ~A2A and ~A2K: authenticate again once unlocked
    .remove %out
    ba.retry auth %bot
    return
  }
  if ((%line == $null) && (%try < 10)) { .timer 1 1 ba.openpoll %bot %out $calc(%try + 1) | return }
  ; bot-auth.exe prints the reason (wrong key, or a pinned-key mismatch)
  var %n = $iif($isfile(%out), $lines(%out), 0), %i = 1
  while (%i <= %n) { echo -a bot_auth: $read(%out, n, %i) | inc %i }
  if (%n == 0) echo -a bot_auth: lockbox from %bot could not be opened
  if ($isfile(%out)) .remove %out
}

; ---- step 3: ~A2 sealed command ------------------------------------------
alias -l ba.send {
  ; $1 = bot, $2 = bot pubkey, $3- = command.  It goes down the bot's DCC chat
  ; when one is open (sealed for the nick that asked for the chat), else by
  ; PRIVMSG.
  var %in = $ba.tmp(in), %out = $ba.tmp(cmd), %k = $ba.key($1), %via = irc, %as = $me
  if ($chat($1).status == active) {
    var %via = dcc
    if ($hget(botauth, $+(dnick., %k)) != $null) var %as = $v1
  }
  elseif ($3 == dcc) hadd -m botauth $+(dnick., %k) $me
  write -c $ba.q(%in) $3-
  .run -nh cmd /c $ba.q($ba.q(%bot_auth_exe) cmd $ba.q(%bot_auth_keyfile) $1 %as $2 < $ba.q(%in) > $ba.q(%out) 2>&1)
  .timer 1 1 ba.sendpoll $1 %in %out 1 %via
}

alias -l ba.sendpoll {
  var %bot = $1, %in = $2, %out = $3, %try = $4, %via = $5
  var %line = $iif($isfile(%out), $read(%out, n, 1))
  if ($gettok(%line, 1, 32) == ~A2) {
    .remove %in | .remove %out
    if (%via == dcc) .msg = $+ %bot %line
    else .quote PRIVMSG %bot : $+ %line
    ; passwd_expire 0: lock again 5 s after the last waiting command went out
    if (%bot_auth_passwd_expire == 0) .timerbotauthlock 1 5 ba.lockrun
    return
  }
  if ($ba.islocked(%line)) {
    var %cmd = $read(%in, n, 1)
    .remove %in | .remove %out
    ba.retry cmd %bot %cmd
    return
  }
  if ((%line == $null) && (%try < 10)) { .timer 1 1 ba.sendpoll %bot %in %out $calc(%try + 1) %via | return }
  echo -a bot_auth: bot-auth.exe refused the command: %line
  if ($isfile(%in)) .remove %in
  if ($isfile(%out)) .remove %out
}

on *:LOAD: {
  echo -a -- bot-auth.mrc (v5.2, key-based, uses bot-auth.exe) loaded --
  echo -a Required: /set % $+ bot_auth_exe C:\path\to\bot-auth.exe
  echo -a           /set % $+ bot_auth_keyfile C:\path\to\NAME.private.b64
  echo -a Optional: /set % $+ bot_auth_pinfile C:\path\to\bot_pins.txt
  echo -a           /set % $+ bot_auth_passwd_expire 1h   (passphrase keys: 0, 30m, 6h, 1d, never)
  echo -a Use: /botcmd <bot> <command> [args]   /botauth <bot>   /botforget <bot>   /botunlock   /botlock
}
