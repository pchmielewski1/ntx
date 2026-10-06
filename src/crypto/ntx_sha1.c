#include "ntx_sha1.h"
#include <string.h>

static uint32_t rotl(uint32_t x, int k) { return (x << k) | (x >> (32 - k)); }

static void sha1_block(ntx_sha1_ctx *ctx, const uint8_t *p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
           ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
  for (int i = 16; i < 80; i++)
    w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];
  for (int t = 0; t < 80; t++) {
    uint32_t f, k;
    if (t < 20)      { f = (b & c) | (~b & d);      k = 0x5A827999u; }
    else if (t < 40) { f = b ^ c ^ d;               k = 0x6ED9EBA1u; }
    else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
    else             { f = b ^ c ^ d;               k = 0xCA62C1D6u; }
    uint32_t tmp = rotl(a, 5) + f + e + k + w[t];
    e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
  }
  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e;
}

void ntx_sha1_init(ntx_sha1_ctx *c) {
  c->h[0] = 0x67452301u; c->h[1] = 0xEFCDAB89u; c->h[2] = 0x98BADCFEu;
  c->h[3] = 0x10325476u; c->h[4] = 0xC3D2E1F0u;
  c->n = 0; c->bufn = 0;
}

void ntx_sha1_update(ntx_sha1_ctx *c, const void *p, size_t n) {
  const uint8_t *s = p;
  c->n += n;
  while (n > 0) {
    size_t take = 64 - c->bufn;
    if (take > n) take = n;
    memcpy(c->buf + c->bufn, s, take);
    c->bufn += take; s += take; n -= take;
    if (c->bufn == 64) { sha1_block(c, c->buf); c->bufn = 0; }
  }
}

void ntx_sha1_final(ntx_sha1_ctx *c, uint8_t out[20]) {
  uint64_t bits = c->n * 8;
  uint8_t pad = 0x80, z = 0;
  ntx_sha1_update(c, &pad, 1);
  while (c->bufn != 56) ntx_sha1_update(c, &z, 1);
  uint8_t lenb[8];
  for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
  ntx_sha1_update(c, lenb, 8);
  for (int i = 0; i < 5; i++) {
    out[4 * i]     = (uint8_t)(c->h[i] >> 24);
    out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
    out[4 * i + 2] = (uint8_t)(c->h[i] >> 8);
    out[4 * i + 3] = (uint8_t)c->h[i];
  }
}

void ntx_sha1(const void *p, size_t n, uint8_t out[20]) {
  ntx_sha1_ctx c;
  ntx_sha1_init(&c);
  ntx_sha1_update(&c, p, n);
  ntx_sha1_final(&c, out);
}
