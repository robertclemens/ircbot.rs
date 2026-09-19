/* encrypt_config.c -- encrypt a plaintext ircbot config.
 *
 * Usage: encrypt_config <plaintext_file> <encrypted_out>
 *
 * The password is prompted for after start-up, twice, with echo off -- or read
 * once as the first line of stdin when stdin is not a terminal.  It is never
 * taken from argv.  The output is written 0600 to a temp file and renamed into
 * place, as config_write_file() does, so a failure never leaves a truncated
 * config behind.
 *
 * Build: gcc -O2 -Wall -o encrypt_config encrypt_config.c -lcrypto */
#include "config_tool.h" /* first: sets the feature-test macro */

#include <openssl/rand.h>

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s <plaintext_file> <encrypted_out>\n"
          "Prompts for the config password (twice), then writes the "
          "encrypted config.\n"
          "With stdin not a terminal, the first line of stdin is the "
          "password.\n",
          argv0);
}

/* config_load() skips blank and '#' lines, but every usable config has "X|"
 * record lines (it requires n| and s|).  Ciphertext almost always contains a
 * NUL (large files) or has no such line (small ones), so together these catch
 * an already-encrypted input without rejecting any config the bot accepts. */
static bool looks_like_plain_config(const unsigned char *p, size_t len) {
  if (memchr(p, '\0', len)) return false;
  for (size_t i = 0; i + 1 < len; i++) {
    bool line_start = (i == 0 || p[i - 1] == '\n');
    bool alpha = (p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z');
    if (line_start && alpha && p[i + 1] == '|') return true;
  }
  return false;
}

/* Write buf to path atomically: mkstemp (0600) in the same directory, fsync,
 * rename.  The temp file is removed on any failure. */
static bool write_atomic(const char *path, const unsigned char *buf,
                         size_t len) {
  char tmp[PATH_MAX];
  if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >= (int)sizeof(tmp)) {
    fprintf(stderr, "Error: output path too long.\n");
    return false;
  }
  int fd = mkstemp(tmp);
  if (fd < 0) {
    fprintf(stderr, "Error: cannot create temp file for '%s': %s\n", path,
            strerror(errno));
    return false;
  }
  bool ok = fchmod(fd, 0600) == 0 && tool_write_all(fd, buf, len) &&
            fsync(fd) == 0;
  int saved = errno;
  if (close(fd) != 0) ok = false;
  if (ok && rename(tmp, path) != 0) {
    saved = errno;
    ok = false;
  }
  if (!ok) {
    fprintf(stderr, "Error: writing '%s': %s\n", path, strerror(saved));
    unlink(tmp);
  }
  return ok;
}

int main(int argc, char *argv[]) {
  tool_harden();

  if (argc != 3 || argv[1][0] == '-') {
    usage(argv[0]);
    return 1;
  }
  const char *in_path = argv[1];
  const char *out_path = argv[2];

  /* GCM ciphertext is the same length as the plaintext, and config_load()
   * refuses ciphertext > MAX_CONFIG_SIZE -- so refuse to produce one. */
  unsigned char *plain = NULL;
  size_t plain_len = 0;
  if (!tool_read_file(in_path, 1, MAX_CONFIG_SIZE, &plain, &plain_len))
    return 1;
  if (!looks_like_plain_config(plain, plain_len)) {
    fprintf(stderr, "Error: '%s' does not look like a plaintext config (no "
                    "\"x|\" record lines; already encrypted?).\n", in_path);
    tool_wipe_unlock(plain, plain_len);
    free(plain);
    return 1;
  }

  int rc = 1, len = 0, ct_len = 0;
  bool derived;
  char password[MAX_PASS], confirm[MAX_PASS];
  unsigned char key[CFG_KEY_LEN];
  unsigned char *out = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  tool_lock(password, sizeof(password));
  tool_lock(confirm, sizeof(confirm));
  tool_lock(key, sizeof(key));

  if (tool_read_password("New config password: ", password,
                         sizeof(password)) < 0)
    goto done;
  if (isatty(STDIN_FILENO)) {
    if (tool_read_password("Confirm password: ", confirm, sizeof(confirm)) < 0)
      goto done;
    if (strcmp(password, confirm) != 0) {
      fprintf(stderr, "Error: passwords do not match.\n");
      goto done;
    }
  }

  /* salt | iv | tag | ciphertext, assembled in one buffer. */
  out = malloc(CFG_HDR_LEN + plain_len);
  ctx = EVP_CIPHER_CTX_new();
  if (!out || !ctx) {
    fprintf(stderr, "Error: out of memory.\n");
    goto done;
  }
  unsigned char *salt = out;
  unsigned char *iv = salt + SALT_SIZE;
  unsigned char *tag = iv + GCM_IV_LEN;
  unsigned char *ct = tag + GCM_TAG_LEN;

  /* A fresh random salt and IV every run.  GCM IV reuse under one key is
   * catastrophic, so an RNG failure aborts rather than falling back. */
  if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, GCM_IV_LEN) != 1) {
    fprintf(stderr, "Error: RNG failure; nothing written.\n");
    goto done;
  }
  derived = tool_derive_key(password, salt, key);
  OPENSSL_cleanse(password, sizeof(password));
  OPENSSL_cleanse(confirm, sizeof(confirm));
  if (!derived) {
    fprintf(stderr, "Error: key derivation failed.\n");
    goto done;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
      EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
      EVP_EncryptUpdate(ctx, ct, &len, plain, (int)plain_len) != 1) {
    fprintf(stderr, "Error: encryption failed.\n");
    goto done;
  }
  ct_len = len;
  if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
    fprintf(stderr, "Error: encryption failed.\n");
    goto done;
  }
  ct_len += len;

  if (!write_atomic(out_path, out, CFG_HDR_LEN + (size_t)ct_len))
    goto done;
  fprintf(stderr, "Encrypted %zu bytes to '%s' (0600).\n", plain_len,
          out_path);
  rc = 0;

done:
  EVP_CIPHER_CTX_free(ctx);
  tool_wipe_unlock(key, sizeof(key));
  tool_wipe_unlock(password, sizeof(password));
  tool_wipe_unlock(confirm, sizeof(confirm));
  free(out);
  tool_wipe_unlock(plain, plain_len);
  free(plain);
  return rc;
}
