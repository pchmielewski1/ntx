#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* read() wrapper: when g_short_read > 0, return at most that many bytes per
 * call (models a short read from /dev/urandom). Defined before the macro so
 * it calls the real read(). */
static int g_short_read = 0;
static int g_read_calls = 0;
static ssize_t test_read(int fd, void *buf, size_t n) {
  g_read_calls++;
  if (g_short_read > 0 && n > (size_t)g_short_read) n = (size_t)g_short_read;
  return read(fd, buf, n);
}
#define read test_read
#include "../src/crypto/ntx_rng.c"
#undef read
#include "../src/ui/ntx_diag.c"

static int any_nonzero(const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (b[i]) return 1;
  return 0;
}

int main(void) {
  if (ntx_rng_init() != 0) { fprintf(stderr, "FAIL init\n"); return 1; }
  printf("PASS init\n");

  uint8_t b1[256], b2[16], b3[16];
  ntx_rand_bytes(b1, 256);
  if (!any_nonzero(b1, 256)) { fprintf(stderr, "FAIL allzero\n"); return 1; }
  printf("PASS bytes-256\n");

  uint32_t v = ntx_rand_u32();
  (void)v;
  printf("PASS u32\n");

  ntx_rand_bytes(b2, 16);
  ntx_rand_bytes(b3, 16);
  if (memcmp(b2, b3, 16) == 0) { fprintf(stderr, "FAIL identical\n"); return 1; }
  printf("PASS distinct\n");

  /* Short reads: every refill must replace the WHOLE pool, not just the first
   * bytes returned by read() (regression: the tail kept already-served data). */
  uint8_t prev[256];
  ntx_rand_bytes(b1, 256);          /* pool is now in a known state */
  memcpy(prev, rng_buf, sizeof prev);
  g_short_read = 7;
  g_read_calls = 0;
  rng_refill();
  g_short_read = 0;
  if (g_read_calls < 37) { fprintf(stderr, "FAIL short-read-calls %d\n", g_read_calls); return 1; }
  if (rng_left != sizeof rng_buf) { fprintf(stderr, "FAIL short-read-left\n"); return 1; }
  if (memcmp(prev + 7, rng_buf + 7, 249) == 0) { fprintf(stderr, "FAIL short-read-stale-tail\n"); return 1; }
  printf("PASS short-read-refill\n");

  /* Backtracking resistance: bytes already handed out (keys, DH secrets) must not stay in
   * the pool, or a later memory disclosure would reveal them. */
  rng_refill();
  uint8_t served[100];
  ntx_rand_bytes(served, sizeof served);
  size_t off = sizeof rng_buf - rng_left - sizeof served; /* where this request started */
  for (size_t i = 0; i < sizeof served; i++)
    if (rng_buf[off + i] != 0) { fprintf(stderr, "FAIL served-bytes-left-in-pool\n"); return 1; }
  if (!any_nonzero(rng_buf + (sizeof rng_buf - rng_left), rng_left)) {
    fprintf(stderr, "FAIL unserved-bytes-wiped\n");
    return 1;
  }
  printf("PASS served-bytes-wiped\n");
  return 0;
}
