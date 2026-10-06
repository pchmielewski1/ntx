#include "../src/crypto/ntx_sha256.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(const char *name, const uint8_t *data, size_t n, const char *exp_hex) {
  uint8_t out[32], exp[32];
  ntx_sha256(data, n, out);
  hex_to_bytes(exp_hex, exp, 32);
  if (memcmp(out, exp, 32) != 0) {
    fprintf(stderr, "FAIL %s: ", name);
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    exit(1);
  }
  printf("PASS %s\n", name);
}

static void check_stream(const char *name, const uint8_t *data, size_t n, size_t chunk, const char *exp_hex) {
  ntx_sha256_ctx c;
  ntx_sha256_init(&c);
  size_t off = 0;
  while (off < n) {
    size_t t = chunk < n - off ? chunk : n - off;
    ntx_sha256_update(&c, data + off, t);
    off += t;
  }
  uint8_t out[32], exp[32];
  ntx_sha256_final(&c, out);
  hex_to_bytes(exp_hex, exp, 32);
  if (memcmp(out, exp, 32) != 0) { fprintf(stderr, "FAIL(stream) %s\n", name); exit(1); }
  printf("PASS %s-stream\n", name);
}

int main(void) {
  check("empty", (const uint8_t *)"", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("abc", (const uint8_t *)"abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("v56", (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  static uint8_t ma[1000000];
  for (size_t i = 0; i < 1000000; i++) ma[i] = 'a';
  check("million_a", ma, 1000000,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  check_stream("million_a", ma, 1000000, 63,
               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

  check_stream("abc", (const uint8_t *)"abc", 3, 1,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  return 0;
}
