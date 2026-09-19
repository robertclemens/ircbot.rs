/* config_tool.h -- helpers shared by utils/encrypt_config.c and
 * utils/decrypt_config.c.  Header-only so each tool still builds from one
 * command (see utils/README.txt).
 *
 * File format and KDF come straight from ../bot.h so they cannot drift from
 * config_load() / config_write_file():
 *   salt[SALT_SIZE] | iv[GCM_IV_LEN] | tag[GCM_TAG_LEN] | AES-256-GCM ciphertext
 *   key = PBKDF2-HMAC-SHA256(password, salt, PBKDF2_ITERATIONS), 32 bytes
 *
 * Secrets are never taken from argv (visible in ps(1) and shell history).
 * Every secret buffer is mlock'd best-effort and OPENSSL_cleanse'd before it
 * is released, and core dumps are disabled before any secret exists. */
#ifndef CONFIG_TOOL_H
#define CONFIG_TOOL_H

/* Must precede every system header.  Same scoping as the Makefile: needed on
 * glibc under -std=c11, left unset on BSD to keep __BSD_VISIBLE. */
#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <limits.h>

/* The bot's config-file contract; must match src/consts.rs. */
#define CONFIG_FILE ".ircbot.cnf"
#define SALT_SIZE 16
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define PBKDF2_ITERATIONS 100000
#define MAX_PASS 128
#define MAX_CONFIG_SIZE (1024 * 1024)

#define CFG_HDR_LEN (SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN)
#define CFG_KEY_LEN 32

/* Disable core dumps and same-uid ptrace attach before any secret is loaded,
 * and ignore SIGPIPE so a closed output pipe surfaces as EPIPE and the wipe
 * path still runs. */
static inline void tool_harden(void) {
  struct rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
  signal(SIGPIPE, SIG_IGN);
}

/* Best-effort: keep a secret out of swap.  Failure is not fatal. */
static inline void tool_lock(void *p, size_t n) {
  if (p && n) (void)mlock(p, n);
}

static inline void tool_wipe_unlock(void *p, size_t n) {
  if (!p || !n) return;
  OPENSSL_cleanse(p, n);
  (void)munlock(p, n);
}

/* ---- Password prompt ---------------------------------------------------- */

static volatile sig_atomic_t tool_tty_echo_off = 0;
static struct termios tool_tty_saved;

/* Put the terminal back before dying, or the user's shell is left with echo
 * off.  tcsetattr, signal and raise are all async-signal-safe. */
static void tool_tty_signal(int sig) {
  if (tool_tty_echo_off)
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tool_tty_saved);
  signal(sig, SIG_DFL);
  raise(sig);
}

/* Read one password line into buf (cap bytes including the NUL).
 *
 *  - stdin is a terminal: prompt on /dev/tty (stderr as a fallback) with echo
 *    off, so stdout stays clean for redirection.
 *  - stdin is not a terminal: read the first line of stdin with no prompt --
 *    the same convention as `echo <pw> | ./ircbot`.
 *
 * read(2) goes straight into buf; no stdio buffer ever holds the password.
 * Mirrors main.c get_password(): the line is cut at the first '\r' or '\n'.
 * Fails closed -- never truncates -- on a password longer than cap-1 bytes
 * (the daemon's MAX_PASS buffer), an empty one, or one containing a NUL.
 * Returns the length, or -1 with buf wiped. */
static inline int tool_read_password(const char *prompt, char *buf,
                                     size_t cap) {
  static const int sigs[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
  struct sigaction old_sa[sizeof(sigs) / sizeof(sigs[0])];
  const bool tty = isatty(STDIN_FILENO);
  int prompt_fd = -1;
  size_t n = 0;
  bool too_long = false, has_nul = false, io_error = false;

  memset(buf, 0, cap);
  if (tty) {
    if (tcgetattr(STDIN_FILENO, &tool_tty_saved) != 0) {
      perror("tcgetattr");
      return -1;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = tool_tty_signal;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
      sigaction(sigs[i], &sa, &old_sa[i]);

    struct termios noecho = tool_tty_saved;
    noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
    tool_tty_echo_off = 1;
    /* TCSAFLUSH drops typeahead entered (and echoed) before the prompt. */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);

    prompt_fd = open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    int out = prompt_fd >= 0 ? prompt_fd : STDERR_FILENO;
    if (write(out, prompt, strlen(prompt)) < 0) { /* prompt is cosmetic */ }
  }

  for (;;) {
    char c;
    ssize_t r = read(STDIN_FILENO, &c, 1);
    if (r < 0) {
      if (errno == EINTR) continue;
      io_error = true;
      break;
    }
    if (r == 0 || c == '\n') break;
    if (c == '\0') has_nul = true;
    /* Past the cap, keep draining to end of line: whatever is left in a tty
     * line buffer would otherwise be read by the shell as a command. */
    if (n + 1 < cap) buf[n++] = c;
    else too_long = true;
  }

  if (tty) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tool_tty_saved);
    tool_tty_echo_off = 0;
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
      sigaction(sigs[i], &old_sa[i], NULL);
    int out = prompt_fd >= 0 ? prompt_fd : STDERR_FILENO;
    if (write(out, "\n", 1) < 0) { /* cosmetic */ }
    if (prompt_fd >= 0) close(prompt_fd);
  }

  buf[strcspn(buf, "\r")] = '\0';
  const char *why = NULL;
  if (io_error) why = "error reading password";
  else if (too_long) why = "password too long";
  else if (has_nul) why = "password contains a NUL byte";
  else if (buf[0] == '\0') why = "empty password";
  if (why) {
    if (too_long)
      fprintf(stderr, "Error: %s (max %zu characters).\n", why, cap - 1);
    else
      fprintf(stderr, "Error: %s.\n", why);
    OPENSSL_cleanse(buf, cap);
    return -1;
  }
  return (int)strlen(buf);
}

/* ---- File I/O (no stdio, so no hidden buffer copies) --------------------- */

static inline bool tool_write_all(int fd, const unsigned char *p, size_t len) {
  while (len > 0) {
    ssize_t w = write(fd, p, len);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += w;
    len -= (size_t)w;
  }
  return true;
}

/* Read a whole regular file of min_len..max_len bytes into a fresh, mlock'd
 * heap buffer.  The size is checked before anything is allocated. */
static inline bool tool_read_file(const char *path, size_t min_len,
                                  size_t max_len, unsigned char **out,
                                  size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
    return false;
  }
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    fprintf(stderr, "Error: '%s' is not a regular file.\n", path);
    close(fd);
    return false;
  }
  if ((unsigned long long)st.st_size < min_len ||
      (unsigned long long)st.st_size > max_len) {
    fprintf(stderr, "Error: '%s' is %lld bytes; expected %zu..%zu.\n", path,
            (long long)st.st_size, min_len, max_len);
    close(fd);
    return false;
  }
  size_t len = (size_t)st.st_size;
  unsigned char *buf = malloc(len);
  if (!buf) {
    fprintf(stderr, "Error: out of memory.\n");
    close(fd);
    return false;
  }
  tool_lock(buf, len);
  size_t got = 0;
  while (got < len) {
    ssize_t r = read(fd, buf + got, len - got);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    got += (size_t)r;
  }
  close(fd);
  if (got != len) {
    fprintf(stderr, "Error: short read on '%s'.\n", path);
    tool_wipe_unlock(buf, len);
    free(buf);
    return false;
  }
  *out = buf;
  *out_len = len;
  return true;
}

static inline bool tool_derive_key(const char *password,
                                   const unsigned char *salt,
                                   unsigned char key[CFG_KEY_LEN]) {
  return PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_SIZE,
                           PBKDF2_ITERATIONS, EVP_sha256(), CFG_KEY_LEN,
                           key) == 1;
}

#endif /* CONFIG_TOOL_H */
