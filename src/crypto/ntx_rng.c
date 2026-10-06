#include "ntx_rng.h"
#include "ntx_ct.h"
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int rng_fd = -1;
static uint8_t rng_buf[256];
static size_t rng_left = 0;
static uint64_t rng_served = 0;

static void rng_die(const char *msg) {
  ssize_t r = write(2, msg, strlen(msg));
  (void)r;
  exit(1);
}

/* Refill the whole pool. read() may legitimately return fewer bytes than
 * requested (e.g. interrupted by a signal); accumulate until all 256 bytes are
 * fresh so the tail of the pool never holds bytes that were already served. */
static void rng_refill(void) {
  size_t got = 0;
  int eagain = 0;
  while (got < sizeof rng_buf) {
    ssize_t r = read(rng_fd, rng_buf + got, sizeof rng_buf - got);
    if (r > 0) { got += (size_t)r; eagain = 0; continue; }
    if (r == 0) continue;
    if (errno == EINTR) continue;
    if (errno == EIO || errno == EACCES) abort();
    if (errno == EAGAIN) {
      if (eagain >= 10) rng_die("ntx_rng: EAGAIN persistent\n");
      struct timespec ts = { 0, 100000L * (1L << eagain) };
      nanosleep(&ts, NULL);
      eagain++;
      continue;
    }
    rng_die("ntx_rng: read error\n");
  }
  rng_left = sizeof rng_buf;
}

int ntx_rng_init(void) {
  if (rng_fd >= 0) return 0;
  rng_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (rng_fd < 0) abort();
  return 0;
}

static void rng_ensure(void) {
  if (rng_fd < 0) ntx_rng_init();
}

void ntx_rand_bytes(void *buf, size_t n) {
  rng_ensure();
  uint8_t *s = buf;
  while (n > 0) {
    if (rng_left == 0) rng_refill();
    size_t take = rng_left < n ? rng_left : n;
    memcpy(s, rng_buf + (256 - rng_left), take);
    /* Backtracking resistance: what was handed out (keys, DH secrets, nonces) must not
     * linger in the pool where a later memory disclosure could read it. */
    ntx_wipe(rng_buf + (256 - rng_left), take);
    rng_left -= take; s += take; n -= take;
    rng_served += take;
    if (rng_served >= 65536) { rng_served = 0; rng_refill(); }
  }
}

uint32_t ntx_rand_u32(void) {
  uint32_t v;
  ntx_rand_bytes(&v, 4);
  return v;
}
