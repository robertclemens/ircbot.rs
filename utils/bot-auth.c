/* bot-auth.c — command-line client for ircbot's key-based admin/oper protocol
 * (~A2A auth request, ~A2K lockbox, ~A2 / ~A2S sealed command, ~A2R sealed
 * reply).  Also the backend
 * that bot-auth.mrc drives for mIRC (as bot-auth.exe).  Only dependency is
 * libcrypto.  Protocol: irchub/docs/passwordless.md §4; the bot side is
 * ircbot/commands.c (a2_handle_auth / a2_open_command).
 *
 * Build:   gcc -O2 -Wall -Wextra -o bot-auth bot-auth.c -lcrypto
 *          (Windows, MSYS2 MinGW 64-bit:
 *           gcc -O2 -Wall -o bot-auth.exe bot-auth.c -lcrypto -static)
 *
 * Usage (keyfile = your <ts>_<name>.private.b64, chmod 600):
 *   bot-auth auth <keyfile> <botnick> <yournick>
 *       -> prints "~A2A <sig> <ts>:<nonce>"; send it:  /msg <botnick> <line>
 *   bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply>
 *                 [--pin <pinfile>]
 *       -> the bot answers the auth with a NOTICE "~A2K <b64>"; pass it here
 *          with the <ts>:<nonce> of the ~A2A you sent.  Prints
 *          "<bot pubkey> <fingerprint>".  With --pin, the bot key is checked
 *          against / recorded in pinfile ("<lc botnick> <pubkey>" lines).
 *   bot-auth cmd <keyfile> <botnick> <yournick> <botpubkey|@file>
 *                [--sealed <replykeyfile>]
 *       -> reads ONE command line from stdin (never argv: ps(1) would show
 *          it) and prints "~A2 <b64>"; send it:  /quote PRIVMSG <bot> :<line>
 *          With --sealed it prints "~A2S <b64>" instead, which asks the bot
 *          to seal its replies, and writes that command's reply key to
 *          replykeyfile (created 0600; delete it when done).
 *   bot-auth reply <replykeyfile> <botnick> <yournick>
 *       -> reads the bot's reply lines (raw IRC lines or just "~A2R <b64>")
 *          from stdin and prints each reply in plaintext.
 *   bot-auth fp <pubkey|file>
 *       -> prints the key fingerprint (compare with the bot's 'status').
 *
 * Exit status: 0 ok, 1 usage/IO error, 2 crypto/verification failure,
 *              3 pinned key mismatch (possible MITM or a rekeyed bot).
 */

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifndef _WIN32
#include <sys/resource.h>
#include <unistd.h>
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define A2A_LABEL "ircbot-A2A-v1"
#define A2K_LABEL "ircbot-A2K-v1"
#define A2_LABEL  "ircbot-A2-v1"
#define A2S_LABEL "ircbot-A2S-v1"
#define A2R_LABEL "ircbot-A2R-v1"
#define A2R_PT_MAX 264           /* "<seq>:<more>:" + up to 240 bytes of text */
#define KEY_LEN 64               /* ed25519(32) || x25519(32) */
#define KEY_B64 88
#define LOCKBOX_LEN (32 + 12 + KEY_LEN + 16)
#define MAX_LINE 400             /* IRC line budget for the ~A2 text */
#define MAX_CMD 300

static void die(int rc, const char *msg) {
  fprintf(stderr, "bot-auth: %s\n", msg);
  exit(rc);
}

/* ---- small helpers ---------------------------------------------------- */

static int b64enc(const unsigned char *in, int n, char *out, size_t cap) {
  if (cap < (size_t)(4 * ((n + 2) / 3) + 1)) return -1;
  return EVP_EncodeBlock((unsigned char *)out, in, n);
}

/* Strict-ish base64 decode: returns decoded length or -1. */
static int b64dec(const char *in, unsigned char *out, int cap) {
  size_t n = strlen(in);
  if (n == 0 || n % 4 != 0 || (int)(n / 4 * 3) > cap + 2) return -1;
  unsigned char *tmp = malloc(n / 4 * 3 + 1);
  if (!tmp) return -1;
  int len = EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)n);
  if (len < 0) { free(tmp); return -1; }
  if (n >= 1 && in[n - 1] == '=') len--;
  if (n >= 2 && in[n - 2] == '=') len--;
  if (len > cap) { OPENSSL_cleanse(tmp, n / 4 * 3); free(tmp); return -1; }
  memcpy(out, tmp, (size_t)len);
  OPENSSL_cleanse(tmp, n / 4 * 3);
  free(tmp);
  return len;
}

static void lc_copy(char *out, size_t cap, const char *in) {
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++)
    out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] + 32) : in[i];
  out[i] = '\0';
}

static void fingerprint(const unsigned char pub[KEY_LEN], char out[20]) {
  unsigned char h[32];
  unsigned int hl = 0;
  if (EVP_Digest(pub, KEY_LEN, h, &hl, EVP_sha256(), NULL) != 1) {
    snprintf(out, 20, "????:????:????:????");
    return;
  }
  snprintf(out, 20, "%02x%02x:%02x%02x:%02x%02x:%02x%02x", h[0], h[1], h[2],
           h[3], h[4], h[5], h[6], h[7]);
}

/* First line of a file, whitespace-trimmed. */
static bool read_first_line(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "r");
  if (!f) return false;
  bool ok = fgets(out, (int)cap, f) != NULL;
  fclose(f);
  if (ok) out[strcspn(out, " \t\r\n")] = '\0';
  return ok && out[0];
}

/* X25519 with all-zero-result rejection. */
static bool x25519(const unsigned char priv[32], const unsigned char pub[32],
                   unsigned char out[32]) {
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
  EVP_PKEY *p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
  EVP_PKEY_CTX *c = k ? EVP_PKEY_CTX_new(k, NULL) : NULL;
  size_t l = 32;
  bool ok = p && c && EVP_PKEY_derive_init(c) == 1 &&
            EVP_PKEY_derive_set_peer(c, p) == 1 &&
            EVP_PKEY_derive(c, out, &l) == 1 && l == 32;
  EVP_PKEY_CTX_free(c);
  EVP_PKEY_free(k);
  EVP_PKEY_free(p);
  unsigned char acc = 0;
  for (int i = 0; ok && i < 32; i++) acc |= out[i];
  if (!ok || !acc) { OPENSSL_cleanse(out, 32); return false; }
  return true;
}

static bool hkdf(const unsigned char *ikm, size_t il, const unsigned char *salt,
                 size_t sl, const unsigned char *info, size_t nl,
                 unsigned char out[32]) {
  EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  size_t ol = 32;
  bool ok = c && EVP_PKEY_derive_init(c) == 1 &&
            EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_salt(c, salt, (int)sl) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_key(c, ikm, (int)il) == 1 &&
            EVP_PKEY_CTX_add1_hkdf_info(c, info, (int)nl) == 1 &&
            EVP_PKEY_derive(c, out, &ol) == 1 && ol == 32;
  EVP_PKEY_CTX_free(c);
  return ok;
}

static bool gcm(bool enc, const unsigned char key[32], const unsigned char iv[12],
                const unsigned char *aad, size_t al, const unsigned char *in,
                int n, unsigned char *out, unsigned char tag[16]) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int l = 0, f = 0;
  bool ok = c && EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
            EVP_CipherInit_ex(c, NULL, NULL, key, iv, enc) == 1 &&
            EVP_CipherUpdate(c, NULL, &l, aad, (int)al) == 1 &&
            EVP_CipherUpdate(c, out, &l, in, n) == 1;
  if (ok && !enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
  if (ok) ok = EVP_CipherFinal_ex(c, out + l, &f) == 1;
  if (ok && enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
  EVP_CIPHER_CTX_free(c);
  if (!ok) OPENSSL_cleanse(out, (size_t)n);
  return ok;
}

/* label "\0" lc(bot) "\0" lc(me) [ "\0" extra ] */
static size_t context(unsigned char *buf, size_t cap, const char *label,
                      const char *bot, const char *me, const char *extra) {
  char b[64], m[64];
  lc_copy(b, sizeof(b), bot);
  lc_copy(m, sizeof(m), me);
  int n = extra ? snprintf((char *)buf, cap, "%s%c%s%c%s%c%s", label, 0, b, 0, m, 0, extra)
                : snprintf((char *)buf, cap, "%s%c%s%c%s", label, 0, b, 0, m);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

/* ---- key material ----------------------------------------------------- */

typedef struct {
  unsigned char priv[KEY_LEN];  /* ed || x */
  unsigned char pub[KEY_LEN];
} userkey_t;

static void load_key(const char *path, userkey_t *k) {
  struct stat st;
  if (stat(path, &st) != 0) die(1, "cannot read the key file");
#ifndef _WIN32
  if (st.st_mode & 0077)
    fprintf(stderr, "bot-auth: warning: %s is readable by others — chmod 600 it\n",
            path);
#endif
  char line[256];
  if (!read_first_line(path, line, sizeof(line))) die(1, "cannot read the key file");
  int n = b64dec(line, k->priv, KEY_LEN);
  OPENSSL_cleanse(line, sizeof(line));
  if (n != KEY_LEN)
    die(1, "key file is not an 88-char private key (use the .private.b64)");
  EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, k->priv, 32);
  EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, k->priv + 32, 32);
  size_t l1 = 32, l2 = 32;
  bool ok = ep && xp && EVP_PKEY_get_raw_public_key(ep, k->pub, &l1) == 1 &&
            EVP_PKEY_get_raw_public_key(xp, k->pub + 32, &l2) == 1;
  EVP_PKEY_free(ep);
  EVP_PKEY_free(xp);
  if (!ok) die(2, "cannot derive the public key");
}

/* A bot public key given inline (88 chars) or as @file. */
static void load_pub(const char *arg, unsigned char pub[KEY_LEN]) {
  char line[256];
  if (arg[0] == '@') {
    if (!read_first_line(arg + 1, line, sizeof(line))) die(1, "cannot read the pubkey file");
  } else if (!read_first_line(arg, line, sizeof(line))) {
    snprintf(line, sizeof(line), "%s", arg);
  }
  if (strlen(line) != KEY_B64 || b64dec(line, pub, KEY_LEN) != KEY_LEN)
    die(1, "not an 88-char public key");
}

static void make_nonce(char out[17]) {
  unsigned char r[8];
  if (RAND_bytes(r, sizeof(r)) != 1) die(2, "RNG failure");
  for (int i = 0; i < 8; i++) snprintf(out + 2 * i, 3, "%02x", r[i]);
}

/* ---- subcommands ------------------------------------------------------ */

static int cmd_auth(const char *keyfile, const char *bot, const char *me) {
  userkey_t k;
  load_key(keyfile, &k);
  char nonce[17], tsn[40];
  make_nonce(nonce);
  snprintf(tsn, sizeof(tsn), "%lld:%s", (long long)time(NULL), nonce);
  unsigned char msg[256];
  size_t ml = context(msg, sizeof(msg), A2A_LABEL, bot, me, tsn);
  unsigned char sig[64];
  size_t sl = sizeof(sig);
  EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, k.priv, 32);
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  bool ok = ml && ep && md && EVP_DigestSignInit(md, NULL, NULL, NULL, ep) == 1 &&
            EVP_DigestSign(md, sig, &sl, msg, ml) == 1 && sl == 64;
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(ep);
  OPENSSL_cleanse(&k, sizeof(k));
  if (!ok) die(2, "signing failed");
  char sb[100];
  b64enc(sig, 64, sb, sizeof(sb));
  printf("~A2A %s %s\n", sb, tsn);
  return 0;
}

/* Pin file: "<lc botnick> <pubkey b64>" per line.  0 ok/recorded, 3 mismatch. */
static int pin_check(const char *pinfile, const char *bot,
                     const unsigned char pub[KEY_LEN]) {
  char want[100], lbot[64];
  b64enc(pub, KEY_LEN, want, sizeof(want));
  lc_copy(lbot, sizeof(lbot), bot);
  FILE *f = fopen(pinfile, "r");
  if (f) {
    char line[256];
    while (fgets(line, sizeof(line), f)) {
      char n[64] = {0}, k[128] = {0};
      if (sscanf(line, "%63s %127s", n, k) != 2 || strcmp(n, lbot) != 0) continue;
      fclose(f);
      if (strcmp(k, want) == 0) return 0;
      unsigned char old[KEY_LEN];
      char ofp[20] = "(unreadable)", nfp[20];
      if (b64dec(k, old, KEY_LEN) == KEY_LEN) fingerprint(old, ofp);
      fingerprint(pub, nfp);
      fprintf(stderr,
              "bot-auth: *** KEY CHANGED for %s: pinned %s, offered %s ***\n"
              "bot-auth: possible man-in-the-middle, or the bot was rekeyed.\n"
              "bot-auth: check the bot's 'status' / hub_admin, then remove its "
              "line from %s to accept.\n", bot, ofp, nfp, pinfile);
      return 3;
    }
    fclose(f);
  }
#ifndef _WIN32
  mode_t old = umask(077);
#endif
  f = fopen(pinfile, "a");
#ifndef _WIN32
  umask(old);
#endif
  if (!f) die(1, "cannot write the pin file");
  fprintf(f, "%s %s\n", lbot, want);
  fclose(f);
  return 0;
}

static int cmd_open(const char *keyfile, const char *bot, const char *me,
                    const char *tsn, const char *reply, const char *pinfile) {
  const char *b = strncmp(reply, "~A2K ", 5) == 0 ? reply + 5 : reply;
  unsigned char frame[LOCKBOX_LEN + 4];
  if (b64dec(b, frame, sizeof(frame)) != LOCKBOX_LEN) die(2, "not a ~A2K lockbox");
  userkey_t k;
  load_key(keyfile, &k);
  unsigned char ss[32], key[32], info[64], aad[256], pub[KEY_LEN];
  size_t il = strlen(A2K_LABEL);
  memcpy(info, A2K_LABEL, il);
  memcpy(info + il, k.pub + 32, 32);
  size_t al = context(aad, sizeof(aad), A2K_LABEL, bot, me, tsn);
  bool ok = al && x25519(k.priv + 32, frame, ss) &&
            hkdf(ss, 32, frame, 32, info, il + 32, key) &&
            gcm(false, key, frame + 32, aad, al, frame + 44, KEY_LEN, pub,
                frame + 44 + KEY_LEN);
  OPENSSL_cleanse(&k, sizeof(k));
  OPENSSL_cleanse(ss, sizeof(ss));
  OPENSSL_cleanse(key, sizeof(key));
  if (!ok) die(2, "lockbox did not verify (wrong key, bot nick, your nick, or ts:nonce)");
  if (pinfile) {
    int rc = pin_check(pinfile, bot, pub);
    if (rc) return rc;
  }
  char pb[100], fp[20];
  b64enc(pub, KEY_LEN, pb, sizeof(pb));
  fingerprint(pub, fp);
  printf("%s %s\n", pb, fp);
  return 0;
}

/* With rkfile: a ~A2S frame, and its reply key HKDF(ikm, eph_pub, A2R_LABEL ||
 * user_x || bot_x) written to rkfile (0600) for `bot-auth reply`. */
static int cmd_cmd(const char *keyfile, const char *bot, const char *me,
                   const char *botpub, const char *rkfile) {
  const char *label = rkfile ? A2S_LABEL : A2_LABEL;
  unsigned char bpub[KEY_LEN];
  load_pub(botpub, bpub);
  char line_in[MAX_CMD + 2];
  if (!fgets(line_in, sizeof(line_in), stdin)) die(1, "no command on stdin");
  size_t cl = strcspn(line_in, "\r\n");
  if (cl == strlen(line_in) && !feof(stdin)) die(1, "command too long");
  line_in[cl] = '\0';
  if (!cl) die(1, "empty command");
  for (size_t i = 0; i < cl; i++)
    if ((unsigned char)line_in[i] < 0x20 || line_in[i] == 0x7f)
      die(1, "control characters are not allowed in commands");

  userkey_t k;
  load_key(keyfile, &k);
  char nonce[17];
  make_nonce(nonce);
  char pt[MAX_CMD + 64];
  int pl = snprintf(pt, sizeof(pt), "%lld:%s:%s", (long long)time(NULL), nonce,
                    line_in);
  OPENSSL_cleanse(line_in, sizeof(line_in));

  unsigned char eph_priv[32], eph_pub[32], ikm[64], key[32], rk[32], info[96];
  unsigned char aad[160], frame[sizeof(pt) + 60], tag[16];
  EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *ek = NULL;
  size_t l1 = 32, l2 = 32;
  bool ok = kc && EVP_PKEY_keygen_init(kc) == 1 && EVP_PKEY_keygen(kc, &ek) == 1 &&
            EVP_PKEY_get_raw_private_key(ek, eph_priv, &l1) == 1 &&
            EVP_PKEY_get_raw_public_key(ek, eph_pub, &l2) == 1;
  EVP_PKEY_free(ek);
  EVP_PKEY_CTX_free(kc);
  size_t il = strlen(label);
  memcpy(info, label, il);
  memcpy(info + il, k.pub + 32, 32);
  memcpy(info + il + 32, bpub + 32, 32);
  size_t al = context(aad, sizeof(aad), label, bot, me, NULL);
  ok = ok && al && pl > 0 && pl < (int)sizeof(pt) &&
       x25519(eph_priv, bpub + 32, ikm) && x25519(k.priv + 32, bpub + 32, ikm + 32) &&
       hkdf(ikm, 64, eph_pub, 32, info, il + 64, key) &&
       RAND_bytes(frame + 32, 12) == 1 &&
       gcm(true, key, frame + 32, aad, al, (unsigned char *)pt, pl, frame + 44, tag);
  if (ok && rkfile) {
    il = strlen(A2R_LABEL);
    memcpy(info, A2R_LABEL, il);
    ok = hkdf(ikm, 64, eph_pub, 32, info, il + 64, rk);
  }
  OPENSSL_cleanse(&k, sizeof(k));
  OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
  OPENSSL_cleanse(ikm, sizeof(ikm));
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(pt, sizeof(pt));
  if (!ok) die(2, "sealing failed");
  memcpy(frame, eph_pub, 32);
  memcpy(frame + 44 + pl, tag, 16);
  int fl = 44 + pl + 16;
  char out[1024];
  if (b64enc(frame, fl, out, sizeof(out)) < 0) die(2, "encoding failed");
  if (strlen(out) + (rkfile ? 5 : 4) > MAX_LINE)
    die(1, "command too long for one IRC line (keep it under ~200 chars)");
  if (rkfile) {
    char rb[64];
    b64enc(rk, 32, rb, sizeof(rb));
    OPENSSL_cleanse(rk, sizeof(rk));
#ifndef _WIN32
    mode_t old = umask(077);
#endif
    FILE *f = fopen(rkfile, "w");
#ifndef _WIN32
    umask(old);
    if (f) (void)fchmod(fileno(f), 0600);
#endif
    bool wrote = f && fprintf(f, "%s\n", rb) > 0;
    if (f && fclose(f) != 0) wrote = false;
    OPENSSL_cleanse(rb, sizeof(rb));
    if (!wrote) die(1, "cannot write the reply key file");
  }
  printf("%s %s\n", rkfile ? "~A2S" : "~A2", out);
  return 0;
}

/* Open the bot's ~A2R replies to one ~A2S command (its reply key in rkfile):
 * "<seq>:<more>:<text>" pieces, seq rising (a repeat is dropped), pieces with
 * more = 1 joined to the next.  Control bytes are shown as '?'.  Exit 2 if any
 * ~A2R line did not open. */
static int cmd_reply(const char *rkfile, const char *bot, const char *me) {
  char line[2048];
  unsigned char rk[32];
  if (!read_first_line(rkfile, line, sizeof(line))) die(1, "cannot read the reply key file");
  int kl = b64dec(line, rk, sizeof(rk));
  OPENSSL_cleanse(line, sizeof(line));
  if (kl != 32) die(1, "not a reply key file (from bot-auth cmd --sealed)");
  unsigned char aad[160];
  size_t al = context(aad, sizeof(aad), A2R_LABEL, bot, me, NULL);
  if (!al) die(1, "bot nick or your nick too long");

  char joined[8192];
  size_t jl = 0;
  unsigned long next = 0;
  bool seen = false;
  int bad = 0;
  while (fgets(line, sizeof(line), stdin)) {
    char *p = strstr(line, "~A2R ");
    if (!p) continue;
    p += 5;
    p[strcspn(p, "\r\n \t")] = '\0';
    unsigned char fr[A2R_PT_MAX + 28 + 4], pt[A2R_PT_MAX + 1];
    int fl = b64dec(p, fr, sizeof(fr));
    int n = fl - 28;
    if (fl < 28 || n > A2R_PT_MAX ||
        !gcm(false, rk, fr, aad, al, fr + 12, n, pt, fr + fl - 16)) {
      fprintf(stderr, "bot-auth: an ~A2R line did not open (a reply to another "
                      "command, or the wrong nicks)\n");
      bad++;
      continue;
    }
    pt[n] = '\0';
    char *e;
    unsigned long seq = strtoul((char *)pt, &e, 10);
    if (e == (char *)pt || e[0] != ':' || (e[1] != '0' && e[1] != '1') || e[2] != ':') {
      OPENSSL_cleanse(pt, sizeof(pt));
      bad++;
      continue;
    }
    if (seen && seq < next) {  /* a repeat of a piece already shown */
      OPENSSL_cleanse(pt, sizeof(pt));
      continue;
    }
    if (seen && seq != next && jl) {  /* a piece went missing */
      printf("%.*s [...]\n", (int)jl, joined);
      jl = 0;
    }
    next = seq + 1;
    seen = true;
    for (char *t = e + 3; *t && jl < sizeof(joined) - 1; t++)
      joined[jl++] = ((unsigned char)*t < 0x20 || *t == 0x7f) ? '?' : *t;
    if (e[1] == '0') {
      printf("%.*s\n", (int)jl, joined);
      jl = 0;
    }
    OPENSSL_cleanse(pt, sizeof(pt));
  }
  if (jl) printf("%.*s [...]\n", (int)jl, joined);
  OPENSSL_cleanse(joined, sizeof(joined));
  OPENSSL_cleanse(rk, sizeof(rk));
  return bad ? 2 : 0;
}

static int cmd_fp(const char *arg) {
  unsigned char pub[KEY_LEN];
  load_pub(arg, pub);
  char fp[20];
  fingerprint(pub, fp);
  printf("%s\n", fp);
  return 0;
}

static void usage(void) {
  fprintf(stderr,
          "usage: bot-auth auth <keyfile> <botnick> <yournick>\n"
          "       bot-auth open <keyfile> <botnick> <yournick> <ts:nonce> <~A2K reply> [--pin <pinfile>]\n"
          "       bot-auth cmd  <keyfile> <botnick> <yournick> <botpubkey|@file> [--sealed <replykeyfile>]\n"
          "                     (command on stdin)\n"
          "       bot-auth reply <replykeyfile> <botnick> <yournick>   (~A2R lines on stdin)\n"
          "       bot-auth fp   <pubkey|file>\n"
          "keyfile is your <ts>_<name>.private.b64 (chmod 600). See utils/README.txt.\n");
  exit(1);
}

int main(int argc, char **argv) {
#ifndef _WIN32
  struct rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
#endif
  if (argc < 2) usage();
  const char *sub = argv[1];
  if (strcmp(sub, "auth") == 0 && argc == 5) return cmd_auth(argv[2], argv[3], argv[4]);
  if (strcmp(sub, "open") == 0 && (argc == 7 || argc == 9)) {
    const char *pin = NULL;
    if (argc == 9) {
      if (strcmp(argv[7], "--pin") != 0) usage();
      pin = argv[8];
    }
    return cmd_open(argv[2], argv[3], argv[4], argv[5], argv[6], pin);
  }
  if (strcmp(sub, "cmd") == 0 && argc == 6)
    return cmd_cmd(argv[2], argv[3], argv[4], argv[5], NULL);
  if (strcmp(sub, "cmd") == 0 && argc == 8 && strcmp(argv[6], "--sealed") == 0)
    return cmd_cmd(argv[2], argv[3], argv[4], argv[5], argv[7]);
  if (strcmp(sub, "reply") == 0 && argc == 5) return cmd_reply(argv[2], argv[3], argv[4]);
  if (strcmp(sub, "fp") == 0 && argc == 3) return cmd_fp(argv[2]);
  usage();
  return 1;
}
