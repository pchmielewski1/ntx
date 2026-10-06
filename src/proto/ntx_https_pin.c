#include "ntx_https_pin.h"

#include "../ui/ntx_diag.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* 1 = match, 0 = no match. pattern: exact host or "*.suffix" (wildcard:
   matches any subdomain of the suffix — NOT the apex). */
static int host_match(const char *pattern, const char *host) {
  size_t hl = strlen(host);
  if (pattern[0] == '*' && pattern[1] == '.') {
    const char *suffix = pattern + 2;
    size_t sl = strlen(suffix);
    if (hl <= sl)
      return 0; /* apex or shorter — the wildcard does not match */
    if (strncasecmp(host + hl - sl, suffix, sl) != 0)
      return 0;
    return host[hl - sl - 1] == '.';
  }
  return strcasecmp(pattern, host) == 0;
}

/* Built-in pool: a single loopback test entry (dev) — pin =
   SHA-256(SPKI) of test/vectors/tls_spki/test_leaf.der (bytes from the script
   pin_from_der.py; never hand-typed hex). */
const ntx_https_pin_entry ntx_https_pin_pool[] = {
    {
        .host = "127.0.0.1",
        .sni = NULL,
        .npins = 1,
        .pins = {
            { 0x04, 0xca, 0xe0, 0x8b, 0xb4, 0xe1, 0xe4, 0x11,
              0x68, 0xc5, 0x7c, 0xe0, 0xed, 0xca, 0xf8, 0xdf,
              0xa8, 0xfa, 0x23, 0x0f, 0x6d, 0x36, 0xf4, 0x76,
              0xb1, 0x44, 0x87, 0xd2, 0xde, 0xa5, 0x50, 0x8c },
        },
    },
};
const int ntx_https_pin_pool_len = 1;

/* hex → bin: exactly 2*out_len hex chars → out_len bytes; 0 = ok, -1 = bad */
static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_to_bin(const char *hex, uint8_t *out, size_t out_len) {
  size_t i;
  for (i = 0; i < out_len; i++) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0)
      return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

/* bin → hex: 32 bytes → 64 chars + NUL */
static void pin_to_hex(char out[65], const uint8_t pin[32]) {
  static const char d[] = "0123456789abcdef";
  int i;
  for (i = 0; i < 32; i++) {
    out[2 * i] = d[pin[i] >> 4];
    out[2 * i + 1] = d[pin[i] & 0xfu];
  }
  out[64] = '\0';
}

#define NTX_PIN_FILE_MAX 16
static struct { char host[128]; uint8_t pin[32]; } pin_file[NTX_PIN_FILE_MAX];
static int n_pin_file;
static char pin_file_path[256];
static void pin_file_load(void);   /* open+parse; fail → n_pin_file=0 */

#define NTX_TOFU_MAX 32
typedef struct {
    char host[128];    /* zeropad */
    uint8_t pin[32];
    uint32_t seen;     /* LE on disk */
} ntx_tofu_rec;        /* sizeof == 164 */

static ntx_tofu_rec tofu[NTX_TOFU_MAX];
static int n_tofu;
static char tofu_path[256];
static int tofu_enabled = 1;

/* TOFU event log (test hook; "new:host;" / "evict:host;", max 4KB) */
#define TOFU_EV_MAX 4096
static char tofu_ev[TOFU_EV_MAX];
static size_t tofu_ev_n;

static void tofu_ev_add(const char *kind, const char *host) {
  size_t kl = strlen(kind), hl = strlen(host);
  if (tofu_ev_n + kl + hl + 1 > sizeof tofu_ev)
    return;
  memcpy(tofu_ev + tofu_ev_n, kind, kl);
  tofu_ev_n += kl;
  memcpy(tofu_ev + tofu_ev_n, host, hl);
  tofu_ev_n += hl;
  tofu_ev[tofu_ev_n++] = ';';
}

/* Load/save of the binary TOFU file (host[128] zero-padded +
   pin[32] + seen u32 LE; max 32 records). */
static void tofu_load(void) {
  FILE *f;
  long fsz;
  int n, i;
  n_tofu = 0;
  if (tofu_path[0] == '\0')
    return;
  f = fopen(tofu_path, "rb");
  if (!f)
    return;
  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return;
  }
  fsz = ftell(f);
  if (fsz < 0) {
    fclose(f);
    return;
  }
  n = (int)(fsz / (long)sizeof(ntx_tofu_rec));
  if (n > NTX_TOFU_MAX)
    n = NTX_TOFU_MAX;
  if (fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return;
  }
  for (i = 0; i < n; i++) {
    if (fread(&tofu[i], sizeof(ntx_tofu_rec), 1, f) != 1) {
      n_tofu = 0;
      break;
    }
    n_tofu++;
  }
  fclose(f);
  /* the file is user-writable data: never trust that a host name is NUL-terminated */
  for (i = 0; i < n_tofu; i++)
    tofu[i].host[127] = '\0';
}

static void tofu_save(void) {
  FILE *f;
  int i;
  char tmp[sizeof tofu_path + 8];
  int fd, ok = 1;
  if (tofu_path[0] == '\0')
    return;
  /* Write a private temp file and rename it over the old one: a crash or a full disk must not leave a
   * truncated pin store behind (the loader would drop every pin = a fresh TOFU window for an attacker). */
  snprintf(tmp, sizeof tmp, "%s.tmp", tofu_path);
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return;
  f = fdopen(fd, "wb");
  if (!f) {
    close(fd);
    unlink(tmp);
    return;
  }
  for (i = 0; i < n_tofu; i++) {
    uint8_t b[4];
    b[0] = (uint8_t)(tofu[i].seen & 0xffu);
    b[1] = (uint8_t)((tofu[i].seen >> 8) & 0xffu);
    b[2] = (uint8_t)((tofu[i].seen >> 16) & 0xffu);
    b[3] = (uint8_t)((tofu[i].seen >> 24) & 0xffu);
    if (fwrite(tofu[i].host, 1, 128, f) != 128 ||
        fwrite(tofu[i].pin, 1, 32, f) != 32 ||
        fwrite(b, 1, 4, f) != 4) {
      ok = 0;
      break;
    }
  }
  if (fflush(f) != 0 || fsync(fileno(f)) != 0)
    ok = 0;
  if (fclose(f) != 0)
    ok = 0;
  if (!ok || rename(tmp, tofu_path) != 0)
    unlink(tmp);
}

static void pin_file_load(void) {
  FILE *f;
  char line[256];
  n_pin_file = 0;
  if (pin_file_path[0] == '\0')
    return;
  f = fopen(pin_file_path, "r");
  if (!f)
    return;
  while (fgets(line, sizeof line, f)) {
    char *host, *hex;
    size_t hl;
    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0' || line[0] == '#')
      continue;
    host = line;
    hex = strchr(host, ' ');
    if (!hex)
      continue;
    *hex = '\0';
    hex++;
    while (*hex == ' ')
      hex++;
    hl = strlen(host);
    if (hl < 1 || hl > 127)
      continue;
    if (strlen(hex) != 64u)
      continue;
    if (hex_to_bin(hex, pin_file[n_pin_file].pin, 32) != 0)
      continue;
    memcpy(pin_file[n_pin_file].host, host, hl + 1);
    n_pin_file++;
    if (n_pin_file >= NTX_PIN_FILE_MAX)
      break;
  }
  fclose(f);
}

void ntx_https_pin_set_file(const char *path) {
  if (path) {
    snprintf(pin_file_path, sizeof pin_file_path, "%s", path);
    pin_file_load();
  } else {
    pin_file_path[0] = '\0';
    n_pin_file = 0;
  }
}

void ntx_https_set_tofu_path(const char *path) {
  if (path) {
    snprintf(tofu_path, sizeof tofu_path, "%s", path);
    tofu_load();
  } else {
    tofu_path[0] = '\0';
    n_tofu = 0;
  }
}

/* explicit marker for a new TOFU pin (stderr + verbose log + event) */
static void tofu_new_pin_marker(const char *host, const uint8_t pin[32]) {
  char hex[65];
  pin_to_hex(hex, pin);
  fprintf(stderr, "ntx: TOFU new pin: %s (spki=%s)\n", host, hex);
  ntx_diag("ntx: tofu new host=%s pin=%s\n", host, hex);
  tofu_ev_add("new:", host);
}

/* LRU (max 32; host exists →
   update + move to MRU end; a new host with a full pool → evict min seen). */
static int tofu_add(const char *host, const uint8_t pin[32],
    uint32_t seen) {
  size_t hl;
  int i, oldest;
  if (!host || !host[0])
    return -1;
  hl = strlen(host);
  if (hl > 127)
    return -1;
  for (i = 0; i < n_tofu; i++) {
    if (memcmp(tofu[i].host, host, hl + 1) == 0) {
      ntx_tofu_rec rec = tofu[i];
      memcpy(rec.pin, pin, 32);
      rec.seen = seen;
      if (i != n_tofu - 1)
        memmove(&tofu[i], &tofu[i + 1],
            sizeof(ntx_tofu_rec) * (size_t)(n_tofu - 1 - i));
      tofu[n_tofu - 1] = rec;
      return 1;
    }
  }
  if (n_tofu >= NTX_TOFU_MAX) {
    char victim[128];
    oldest = 0;
    for (i = 1; i < n_tofu; i++)
      if (tofu[i].seen < tofu[oldest].seen)
        oldest = i;
    memcpy(victim, tofu[oldest].host, 128);
    memmove(&tofu[oldest], &tofu[oldest + 1],
        sizeof(ntx_tofu_rec) * (size_t)(n_tofu - 1 - oldest));
    n_tofu--;
    ntx_diag("ntx: tofu evicted (lru) host=%s\n", victim);
    tofu_ev_add("evict:", victim);
  }
  memset(&tofu[n_tofu], 0, sizeof(ntx_tofu_rec));
  memcpy(tofu[n_tofu].host, host, hl);
  memcpy(tofu[n_tofu].pin, pin, 32);
  tofu[n_tofu].seen = seen;
  n_tofu++;
  tofu_new_pin_marker(host, pin);
  return 1;
}

/* test hook (same 1/-1 semantics as tofu_add) */
int ntx_https_tofu_test_add(const char *host, const uint8_t pin[32],
    uint32_t seen) {
  return tofu_add(host, pin, seen);
}

/* TOFU note after the handshake — seen = unix time */
int ntx_https_tofu_note(const char *host, const uint8_t pin[32]) {
  return tofu_add(host, pin, (uint32_t)time(NULL));
}

void ntx_https_tofu_test_save(void) { tofu_save(); }

int ntx_https_tofu_test_count(void) { return n_tofu; }

int ntx_https_tofu_test_get(int i, char host[128], uint8_t pin[32],
    uint32_t *seen) {
  if (i < 0 || i >= n_tofu)
    return -1;
  memcpy(host, tofu[i].host, 128);
  memcpy(pin, tofu[i].pin, 32);
  if (seen)
    *seen = tofu[i].seen;
  return 0;
}

/* TOFU events since the last reset ("new:host;evict:host;...") */
int ntx_https_tofu_test_events(char *buf, size_t n) {
  size_t c;
  if (!buf || n == 0 || tofu_ev_n == 0)
    return 0;
  c = tofu_ev_n;
  if (c > n - 1)
    c = n - 1;
  memcpy(buf, tofu_ev, c);
  buf[c] = '\0';
  return (int)c;
}

void ntx_https_tofu_test_events_reset(void) { tofu_ev_n = 0; }

void ntx_https_tofu_set_enabled(int on) { tofu_enabled = on ? 1 : 0; }

int ntx_https_tofu_enabled(void) { return tofu_enabled; }

/* test hook: virtual pool entries (in addition to the built-in pool) */
static ntx_https_pin_entry pin_test_pool[2];
static int pin_test_pool_n;

int ntx_https_pin_test_pool_add(const char *host, const uint8_t pin[32]) {
  if (pin_test_pool_n >= 2)
    return -1;
  pin_test_pool[pin_test_pool_n].host = host;
  pin_test_pool[pin_test_pool_n].sni = NULL;
  pin_test_pool[pin_test_pool_n].npins = 1;
  memcpy(pin_test_pool[pin_test_pool_n].pins[0], pin, 32);
  pin_test_pool_n++;
  return 1;
}

void ntx_https_pin_test_pool_clear(void) { pin_test_pool_n = 0; }

int ntx_https_pin_lookup(const char *host, uint16_t port,
    uint8_t out_pins[][32], int max_pins, int *out_npins) {
  int i, k, n;
  (void)port; /* pins are not per-port */
  if (out_npins)
    *out_npins = 0;
  /* 1. built-in pool — the first matching source wins;
     OR-match: several entries for the same host → accumulate up to max_pins */
  n = 0;
  for (i = 0; i < ntx_https_pin_pool_len; i++) {
    if (!host_match(ntx_https_pin_pool[i].host, host))
      continue;
    for (k = 0; k < ntx_https_pin_pool[i].npins && n < max_pins; k++)
      memcpy(out_pins[n++], ntx_https_pin_pool[i].pins[k], 32);
  }
  if (n > 0) {
    if (out_npins)
      *out_npins = n;
    return 0;
  }
  /* 2. test pool (hook) */
  n = 0;
  for (i = 0; i < pin_test_pool_n; i++) {
    if (!host_match(pin_test_pool[i].host, host))
      continue;
    for (k = 0; k < pin_test_pool[i].npins && n < max_pins; k++)
      memcpy(out_pins[n++], pin_test_pool[i].pins[k], 32);
  }
  if (n > 0) {
    if (out_npins)
      *out_npins = n;
    return 0;
  }
  /* 3. pin file */
  n = 0;
  for (i = 0; i < n_pin_file; i++) {
    if (!host_match(pin_file[i].host, host))
      continue;
    if (n < max_pins)
      memcpy(out_pins[n++], pin_file[i].pin, 32);
  }
  if (n > 0) {
    if (out_npins)
      *out_npins = n;
    return 0;
  }
  /* 4. TOFU (only when neither the pool nor the file gave a pin) */
  if (ntx_https_tofu_enabled()) {
    for (i = 0; i < n_tofu && n < max_pins; i++)
      if (memcmp(tofu[i].host, host, strlen(host) + 1) == 0)
        memcpy(out_pins[n++], tofu[i].pin, 32);
  }
  if (n > 0) {
    if (out_npins)
      *out_npins = n;
    return 0;
  }
  if (ntx_https_tofu_enabled()) {
    if (out_npins)
      *out_npins = 0;
    return 0; /* signal: no pin, TOFU after the certificate */
  }
  return -1; /* TOFU disabled + no pin → fail */
}
