/* decrypt_config.c -- dump a decrypted ircbot config.
 *
 * Usage: decrypt_config [config_file]        (default: .ircbot.cnf)
 *
 * The password is prompted for after start-up (echo off), or read as the first
 * line of stdin when stdin is not a terminal -- never taken from argv.
 * stdout carries the raw plaintext and nothing else, byte for byte, so it can
 * be redirected or piped; the prompt goes to the terminal, errors to stderr.
 *
 * Build: gcc -O2 -Wall -o decrypt_config decrypt_config.c -lcrypto */
#include "config_tool.h" /* first: sets the feature-test macro */

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s [config_file]   (default: %s)\n"
          "Prompts for the config password, then writes the raw plaintext "
          "to stdout.\n"
          "With stdin not a terminal, the first line of stdin is the "
          "password.\n",
          argv0, CONFIG_FILE);
}

int main(int argc, char *argv[]) {
  tool_harden();

  if (argc > 2 || (argc == 2 && argv[1][0] == '-')) {
    usage(argv[0]);
    return 1;
  }
  const char *path = (argc == 2) ? argv[1] : CONFIG_FILE;

  /* Same bound as config_load(): the bot refuses ciphertext > MAX_CONFIG_SIZE.
   * Read the file first so a bad path fails before the user types anything. */
  unsigned char *file = NULL;
  size_t file_len = 0;
  if (!tool_read_file(path, CFG_HDR_LEN + 1, CFG_HDR_LEN + MAX_CONFIG_SIZE,
                      &file, &file_len))
    return 1;

  const unsigned char *salt = file;
  const unsigned char *iv = salt + SALT_SIZE;
  unsigned char tag[GCM_TAG_LEN];
  memcpy(tag, iv + GCM_IV_LEN, GCM_TAG_LEN);
  const unsigned char *ct = file + CFG_HDR_LEN;
  const int ct_len = (int)(file_len - CFG_HDR_LEN);

  int rc = 1, len = 0, plain_len = 0;
  bool derived;
  char password[MAX_PASS];
  unsigned char key[CFG_KEY_LEN];
  unsigned char *plain = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  tool_lock(password, sizeof(password));
  tool_lock(key, sizeof(key));

  if (tool_read_password("Config password: ", password, sizeof(password)) < 0)
    goto out;
  derived = tool_derive_key(password, salt, key);
  OPENSSL_cleanse(password, sizeof(password));
  if (!derived) {
    fprintf(stderr, "Error: key derivation failed.\n");
    goto out;
  }

  plain = malloc((size_t)ct_len);
  ctx = EVP_CIPHER_CTX_new();
  if (!plain || !ctx) {
    fprintf(stderr, "Error: out of memory.\n");
    goto out;
  }
  tool_lock(plain, (size_t)ct_len);

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL) != 1 ||
      EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
      EVP_DecryptUpdate(ctx, plain, &len, ct, ct_len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
    fprintf(stderr, "Error: decryption setup failed.\n");
    goto out;
  }
  plain_len = len;
  /* GCM authenticates here: nothing is released unless the tag verifies. */
  if (EVP_DecryptFinal_ex(ctx, plain + plain_len, &len) != 1) {
    fprintf(stderr, "Error: decryption failed (wrong password, or the file "
                    "is corrupt or not an ircbot config).\n");
    goto out;
  }
  plain_len += len;

  if (!tool_write_all(STDOUT_FILENO, plain, (size_t)plain_len)) {
    fprintf(stderr, "Error: writing to stdout: %s\n", strerror(errno));
    goto out;
  }
  rc = 0;

out:
  EVP_CIPHER_CTX_free(ctx);
  tool_wipe_unlock(key, sizeof(key));
  tool_wipe_unlock(password, sizeof(password));
  if (plain) {
    tool_wipe_unlock(plain, (size_t)ct_len);
    free(plain);
  }
  tool_wipe_unlock(file, file_len);
  free(file);
  return rc;
}
