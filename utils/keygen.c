/*
 * keygen — Curve25519 keypair generator for ircbot / irchub users and bots.
 *
 * SHARED FILE: kept byte-identical as irchub/keygen.c and
 * ircbot/utils/keygen.c.  Change both together (the test harness cmp's them).
 * Self-contained on purpose — OpenSSL (-lcrypto) only, no hub.h / bot.h — so
 * either tree can build it:
 *
 *     gcc -O2 -Wall -Wextra -std=c11 -o keygen keygen.c -lcrypto
 *
 * Usage:  keygen [name]      (asks for the name on stdin when omitted)
 *
 * Writes, in the current directory (never overwriting anything):
 *   YYYYMMDDHHMMSS_<name>.private.b64   mode 0600  base64(ed25519_priv || x25519_priv)
 *   YYYYMMDDHHMMSS_<name>.public.b64    mode 0644  base64(ed25519_pub  || x25519_pub)
 * and prints the public key and its fingerprint (first 8 bytes of
 * SHA-256(pub), "ab12:cd34:ef56:7890") — never the private key.
 *
 * The public key is what an admin adds with hub_admin / +admin / +oper; the
 * private key stays on the user's machine for hub_admin and the IRC client
 * scripts.  See irchub/docs/passwordless.md.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define KEYGEN_VERSION "1"
#define NAME_MAX_LEN 32

/* Keep the private key out of core dumps and away from same-uid ptrace. */
static void harden(void) {
  struct rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__) && defined(PR_SET_DUMPABLE)
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$ — safe as a filename component. */
static bool valid_name(const char *s) {
  size_t n = strlen(s);
  if (n == 0 || n > NAME_MAX_LEN) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' ||
              (i > 0 && (c == '.' || c == '-'));
    if (!ok) return false;
  }
  return true;
}

static bool b64(const unsigned char *in, int n, char *out, size_t cap) {
  /* 64 bytes -> 88 chars + NUL */
  if (cap < (size_t)(4 * ((n + 2) / 3) + 1)) return false;
  return EVP_EncodeBlock((unsigned char *)out, in, n) == 4 * ((n + 2) / 3);
}

static bool gen_combined(unsigned char priv[64], unsigned char pub[64]) {
  EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  EVP_PKEY_CTX *xc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *ep = NULL, *xp = NULL;
  size_t l = 32;
  bool ok =
      ec && EVP_PKEY_keygen_init(ec) > 0 && EVP_PKEY_keygen(ec, &ep) > 0 &&
      EVP_PKEY_get_raw_private_key(ep, priv, &l) > 0 && l == 32 &&
      (l = 32, EVP_PKEY_get_raw_public_key(ep, pub, &l) > 0) && l == 32 &&
      xc && EVP_PKEY_keygen_init(xc) > 0 && EVP_PKEY_keygen(xc, &xp) > 0 &&
      (l = 32, EVP_PKEY_get_raw_private_key(xp, priv + 32, &l) > 0) && l == 32 &&
      (l = 32, EVP_PKEY_get_raw_public_key(xp, pub + 32, &l) > 0) && l == 32;
  EVP_PKEY_free(ep);
  EVP_PKEY_free(xp);
  EVP_PKEY_CTX_free(ec);
  EVP_PKEY_CTX_free(xc);
  if (!ok) {
    OPENSSL_cleanse(priv, 64);
    memset(pub, 0, 64);
  }
  return ok;
}

/* Create path exclusively with `mode` and write text + "\n".  Refuses to
 * follow a symlink or replace an existing file. */
static bool write_new(const char *path, mode_t mode, const char *text) {
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
  if (fd < 0) {
    fprintf(stderr, "keygen: cannot create %s: %s\n", path, strerror(errno));
    return false;
  }
  (void)fchmod(fd, mode); /* independent of the caller's umask */
  size_t n = strlen(text);
  bool ok = write(fd, text, n) == (ssize_t)n && write(fd, "\n", 1) == 1 &&
            fsync(fd) == 0;
  if (close(fd) != 0) ok = false;
  if (!ok) {
    fprintf(stderr, "keygen: writing %s failed\n", path);
    unlink(path);
  }
  return ok;
}

int main(int argc, char *argv[]) {
  harden();

  if (argc > 2 || (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
                                 strcmp(argv[1], "--help") == 0))) {
    fprintf(stderr,
            "Usage: keygen [name]\n"
            "Generates a Curve25519 (Ed25519 + X25519) keypair as\n"
            "  YYYYMMDDHHMMSS_<name>.private.b64  (0600, keep it; used by\n"
            "                                      hub_admin and IRC scripts)\n"
            "  YYYYMMDDHHMMSS_<name>.public.b64   (give this to an admin)\n"
            "Without [name] it asks for one. Names: letters, digits, _ . -\n"
            "(max %d, not starting with . or -).\n", NAME_MAX_LEN);
    return argc > 2 ? 1 : 0;
  }

  char name[128] = {0};
  if (argc == 2) {
    snprintf(name, sizeof(name), "%s", argv[1]);
  } else {
    printf("Key name (e.g. your nick): ");
    fflush(stdout);
    if (!fgets(name, sizeof(name), stdin)) {
      fprintf(stderr, "keygen: no name given\n");
      return 1;
    }
    name[strcspn(name, "\r\n")] = '\0';
  }
  if (!valid_name(name)) {
    fprintf(stderr, "keygen: invalid name '%s' — use letters, digits, _ . - "
                    "(max %d, not starting with . or -)\n", name, NAME_MAX_LEN);
    return 1;
  }

  char stamp[32];
  time_t now = time(NULL);
  struct tm tmv;
  if (!localtime_r(&now, &tmv) ||
      strftime(stamp, sizeof(stamp), "%Y%m%d%H%M%S", &tmv) == 0) {
    fprintf(stderr, "keygen: cannot format the timestamp\n");
    return 1;
  }
  /* Sized from the parts so no compiler can see a truncation (valid_name
   * already caps the name at NAME_MAX_LEN); a short write is still fatal. */
  char priv_path[sizeof(stamp) + 1 + sizeof(name) + sizeof(".private.b64")];
  char pub_path[sizeof(priv_path)];
  int pl = snprintf(priv_path, sizeof(priv_path), "%s_%s.private.b64", stamp, name);
  int ql = snprintf(pub_path, sizeof(pub_path), "%s_%s.public.b64", stamp, name);
  if (pl < 0 || (size_t)pl >= sizeof(priv_path) ||
      ql < 0 || (size_t)ql >= sizeof(pub_path)) {
    fprintf(stderr, "keygen: file name too long\n");
    return 1;
  }

  unsigned char priv[64], pub[64];
  char priv_b64[89], pub_b64[89];
  (void)mlock(priv, sizeof(priv));
  (void)mlock(priv_b64, sizeof(priv_b64));

  int rc = 1;
  if (!gen_combined(priv, pub) || !b64(priv, 64, priv_b64, sizeof(priv_b64)) ||
      !b64(pub, 64, pub_b64, sizeof(pub_b64))) {
    fprintf(stderr, "keygen: key generation failed\n");
    goto out;
  }
  if (!write_new(priv_path, 0600, priv_b64)) goto out;
  if (!write_new(pub_path, 0644, pub_b64)) {
    unlink(priv_path); /* never leave half a pair behind */
    goto out;
  }

  unsigned char h[32];
  unsigned int hl = 0;
  char fp[20] = "????:????:????:????";
  if (EVP_Digest(pub, sizeof(pub), h, &hl, EVP_sha256(), NULL) == 1 && hl == 32)
    snprintf(fp, sizeof(fp), "%02x%02x:%02x%02x:%02x%02x:%02x%02x", h[0], h[1],
             h[2], h[3], h[4], h[5], h[6], h[7]);

  printf("Generated Curve25519 keypair (keygen v%s) for '%s':\n", KEYGEN_VERSION,
         name);
  printf("  private: %s  (mode 0600 — keep it secret, keep it here)\n", priv_path);
  printf("  public:  %s\n", pub_path);
  printf("  public key:  %s\n", pub_b64);
  printf("  fingerprint: %s\n\n", fp);
  printf("Next:\n");
  printf("  - Give the PUBLIC key to an admin: hub_admin 'Add Admin/Oper' or\n");
  printf("    'Change user public key', or IRC '+admin|+oper <name> <pubkey> <mask>'.\n");
  printf("  - Admins log into the hub with: hub_admin <ip> <port> %s\n", priv_path);
  printf("  - Point your IRC client script (ircbot/utils) at %s\n", priv_path);
  rc = 0;

out:
  OPENSSL_cleanse(priv, sizeof(priv));
  OPENSSL_cleanse(priv_b64, sizeof(priv_b64));
  (void)munlock(priv, sizeof(priv));
  (void)munlock(priv_b64, sizeof(priv_b64));
  return rc;
}
