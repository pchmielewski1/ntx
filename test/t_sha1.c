#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void hex_to_bin(const char *hex, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++)
    out[i] = (uint8_t)((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1]));
}

static void check(const char *name, const uint8_t *data, size_t n, const char *exp_hex) {
  uint8_t out[20], exp[20];
  ntx_sha1(data, n, out);
  hex_to_bin(exp_hex, exp, 20);
  if (memcmp(out, exp, 20) != 0) {
    fprintf(stderr, "FAIL %s: ", name);
    for (int i = 0; i < 20; i++) printf("%02x", out[i]);
    printf("\n");
    exit(1);
  }
  printf("PASS %s\n", name);
}

static void check_stream(const char *name, const uint8_t *data, size_t n, size_t chunk, const char *exp_hex) {
  ntx_sha1_ctx c;
  ntx_sha1_init(&c);
  size_t off = 0;
  while (off < n) {
    size_t t = chunk < n - off ? chunk : n - off;
    ntx_sha1_update(&c, data + off, t);
    off += t;
  }
  uint8_t out[20], exp[20];
  ntx_sha1_final(&c, out);
  hex_to_bin(exp_hex, exp, 20);
  if (memcmp(out, exp, 20) != 0) { fprintf(stderr, "FAIL(stream) %s\n", name); exit(1); }
  printf("PASS %s-stream\n", name);
}

int main(void) {
  static const struct { const char *path, *name, *hex; } V[] = {
    { "test/vectors/sha1/empty.bin",     "empty",     "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "test/vectors/sha1/abc.bin",       "abc",       "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "test/vectors/sha1/v56.bin",       "v56",       "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { "test/vectors/sha1/v64.bin",       "v64",       "e0c094e867ef46c350ef54a7f59dd60bed92ae83" },
    { "test/vectors/sha1/v80.bin",       "v80",       "db9d100073836c9651690af5a74192fe6af1a2b6" },
    { "test/vectors/sha1/million_a.bin", "million_a", "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
  };
  for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
    size_t n;
    uint8_t *d = read_file(V[i].path, &n);
    check(V[i].name, d, n, V[i].hex);
    check_stream(V[i].name, d, n, 7, V[i].hex);
    if (n >= 1000) check_stream(V[i].name, d, n, 1000, V[i].hex);
    free(d);
  }
  return 0;
}
