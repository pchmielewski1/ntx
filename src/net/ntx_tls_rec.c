#include "ntx_tls.h"

/* TLS record layer + PRF (rec_send/rec_recv, io_read/io_write, tls12_prf, ...)
   — split out of ntx_tls.c. */

#include "../crypto/ntx_ct.h"
#include "../crypto/ntx_hmac.h"
#include "../crypto/ntx_sha256.h"
#include "../proto/ntx_wire.h"
#include "../core/ntx_time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define VER12 0x0303u
#define REC_ALERT 21
#define MAX_PT 16384

int io_read(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t g = 0;
    while (g < n) {
        /* R38: a server that drips one byte per timeout would never trip the socket
         * timeout on its own, so the budget is re-checked (and re-armed) per read. */
        if (!ntx_tls_budget_arm(fd)) return -1;
        ssize_t r = read(fd, p + g, n - g);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        g += (size_t)r;
    }
    return 0;
}

int io_write(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t s = 0;
    while (s < n) {
        if (!ntx_tls_budget_arm(fd)) return -1;
        ssize_t w = write(fd, p + s, n - s);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        s += (size_t)w;
    }
    return 0;
}

/* TLS 1.2 PRF with SHA-256 (RFC 5246 sec. 5): P_SHA256(secret, label || seed).
 * Incremental HMAC, so there is no length limit on label/seed, no scratch buffer that
 * could overflow and no "return zeros on error" path: the key schedule of the secret
 * runs once and every intermediate value is wiped. */
void tls12_prf(const uint8_t *secret, size_t slen, const char *label,
                      const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len) {
    size_t llen = strlen(label);
    ntx_hmac_sha256_ctx base, c;
    uint8_t A[32], block[32];

    ntx_hmac_sha256_init(&base, secret, slen);
    c = base; /* A(1) = HMAC(secret, label || seed) */
    ntx_hmac_sha256_update(&c, label, llen);
    ntx_hmac_sha256_update(&c, seed, seed_len);
    ntx_hmac_sha256_final(&c, A);
    for (size_t filled = 0; filled < out_len;) {
        c = base;
        ntx_hmac_sha256_update(&c, A, 32);
        ntx_hmac_sha256_update(&c, label, llen);
        ntx_hmac_sha256_update(&c, seed, seed_len);
        ntx_hmac_sha256_final(&c, block);
        size_t take = out_len - filled < 32 ? out_len - filled : 32;
        memcpy(out + filled, block, take);
        filled += take;
        if (filled < out_len) { /* A(i+1) = HMAC(secret, A(i)) */
            c = base;
            ntx_hmac_sha256_update(&c, A, 32);
            ntx_hmac_sha256_final(&c, A);
        }
    }
    ntx_wipe(A, sizeof A);
    ntx_wipe(block, sizeof block);
    ntx_wipe(&base, sizeof base);
}

void to_hex(char *dst, size_t dstsz, const uint8_t *b, size_t n) {
    static const char *H = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < dstsz; i++) {
        dst[o++] = H[b[i] >> 4];
        dst[o++] = H[b[i] & 15];
    }
    if (o < dstsz) dst[o] = '\0';
}

void peer_ip_str(int fd, char *out, size_t outsz) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    out[0] = 0;
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) return;
    if (ss.ss_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)&ss)->sin_addr, out, (socklen_t)outsz);
    }
}

/* R38: wall-clock budget for one synchronous fetch. The TLS record layer is where a
 * tracker that accepts the connection and then answers nothing actually blocks, so the
 * budget lives here: the caller sets an absolute deadline and every read/write re-arms
 * the socket timeout to fit what is left, so no single fetch can run past it. 0 = no
 * bound (DoH, the golden TLS replay tests, everything that never sets one). */
static uint64_t g_io_deadline_ms;
static uint64_t g_pre_reply_ms; /* V01: tighter leg for resolve/connect/handshake, 0 = none */

/* The leg that is actually in force: the tighter of the two, 0 = unbounded. */
static uint64_t budget_deadline(void) {
    if (!g_io_deadline_ms) return 0;
    if (!g_pre_reply_ms || g_pre_reply_ms > g_io_deadline_ms) return g_io_deadline_ms;
    return g_pre_reply_ms;
}

void ntx_tls_set_io_deadline_ms(uint64_t abs_ms) {
    g_io_deadline_ms = abs_ms;
    g_pre_reply_ms = 0; /* a stale leg must not shorten the next fetch */
}

void ntx_tls_set_pre_reply_deadline_ms(uint64_t abs_ms) {
    if (!g_io_deadline_ms) return; /* nothing armed: the fetch has no budget to leg */
    g_pre_reply_ms = abs_ms;
}

void ntx_tls_enter_reply_phase(void) { g_pre_reply_ms = 0; }

long ntx_tls_budget_left_ms(void) {
    uint64_t d = budget_deadline();
    if (!d) return LONG_MAX; /* unbounded */
    int64_t left = (int64_t)d - (int64_t)ntx_mono_ms();
    return left > 0 ? (long)left : 0;
}

int ntx_tls_budget_arm(int fd) {
    uint64_t d = budget_deadline();
    if (!d) return 1;
    int64_t left = (int64_t)d - (int64_t)ntx_mono_ms();
    if (left <= 0) return 0;
    struct timeval tv = { .tv_sec = (time_t)(left / 1000), .tv_usec = (suseconds_t)(left % 1000 * 1000) };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return 1;
}

void sock_timeouts(int fd, int sec) {
    if (sec <= 0) sec = 15;
    long ms = (long)sec * 1000;
    /* R38: never arm a timeout that outlives the fetch's own budget, or the last
     * read of a dead tracker would still hold the loop for its full 15 s. */
    if (g_io_deadline_ms) {
        long left = ntx_tls_budget_left_ms();
        if (left < 1) left = 1;
        if (left < ms) ms = left;
    }
    struct timeval tv = { .tv_sec = (time_t)(ms / 1000), .tv_usec = (suseconds_t)(ms % 1000 * 1000) };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

int rec_send(ntx_tls *t, uint8_t type, const uint8_t *body, size_t body_len, tls_dir *d) {
    uint8_t hdr[5];
    hdr[0] = type;
    ntx_wire_wr16(hdr + 1, VER12);
    if (!d || !d->enc) {
        ntx_wire_wr16(hdr + 3, (uint16_t)body_len);
        if (io_write(t->fd, hdr, 5) != 0) return -1;
        if (body_len && io_write(t->fd, body, body_len) != 0) return -1;
        return 0;
    }
    if (body_len > MAX_PT) return -1;
    /* R4: the GCM nonce is (salt || seq); never seal under a sequence number that
     * was already used or is about to wrap. */
    if (*d->seq == UINT64_MAX) return -1;
    uint8_t nonce[12], expl[8], aad[13], tag[16];
    uint8_t ct[MAX_PT];
    memcpy(nonce, d->fixed_iv4, 4);
    uint64_t sq = *d->seq;
    for (int i = 7; i >= 0; i--) {
        expl[i] = (uint8_t)(sq & 0xff);
        sq >>= 8;
    }
    memcpy(nonce + 4, expl, 8);
    sq = *d->seq;
    for (int i = 7; i >= 0; i--) {
        aad[i] = (uint8_t)(sq & 0xff);
        sq >>= 8;
    }
    aad[8] = type;
    ntx_wire_wr16(aad + 9, VER12);
    ntx_wire_wr16(aad + 11, (uint16_t)body_len);
    if (!ntx_aes128_gcm_seal(d->gcm, nonce, aad, 13, body, body_len, ct, tag)) return -1;
    /* Consume the sequence number (= nonce) BEFORE any I/O: if a write fails
     * half-way, a later send must not reuse this nonce with different data. */
    (*d->seq)++;
    size_t frag = 8 + body_len + 16;
    ntx_wire_wr16(hdr + 3, (uint16_t)frag);
    if (io_write(t->fd, hdr, 5) != 0) return -1;
    if (io_write(t->fd, expl, 8) != 0) return -1;
    if (body_len && io_write(t->fd, ct, body_len) != 0) return -1;
    if (io_write(t->fd, tag, 16) != 0) return -1;
    return 0;
}

int rec_recv(ntx_tls *t, uint8_t *type_out, uint8_t *buf, size_t cap, size_t *out_len,
                    tls_dir *d) {
    uint8_t hdr[5];
    if (io_read(t->fd, hdr, 5) != 0) return -1;
    uint8_t typ = hdr[0];
    if (hdr[1] != 0x03) return -1; /* not a TLS record (minor version is left to the handshake) */
    uint16_t L = ntx_wire_rd16(hdr + 3);
    if (L > 18432) return -1;
    uint8_t raw[18432];
    if (L && io_read(t->fd, raw, L) != 0) return -1;
    if (typ == REC_ALERT) return -1;
    if (!d || !d->enc) {
        if (L > cap) return -1;
        memcpy(buf, raw, L);
        *type_out = typ;
        *out_len = L;
        return 0;
    }
    if (L < 24) return -1;
    size_t ct_len = (size_t)L - 24;
    if (ct_len > cap) return -1;
    uint8_t nonce[12], aad[13];
    memcpy(nonce, d->fixed_iv4, 4);
    memcpy(nonce + 4, raw, 8);
    uint64_t sq = *d->seq;
    for (int i = 7; i >= 0; i--) {
        aad[i] = (uint8_t)(sq & 0xff);
        sq >>= 8;
    }
    aad[8] = typ;
    ntx_wire_wr16(aad + 9, VER12);
    ntx_wire_wr16(aad + 11, (uint16_t)ct_len);
    if (!ntx_aes128_gcm_open(d->gcm, nonce, aad, 13, raw + 8, ct_len, buf, raw + 8 + ct_len))
        return -1;
    (*d->seq)++;
    *type_out = typ;
    *out_len = ct_len;
    return 0;
}
