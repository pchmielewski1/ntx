/* R4: the TLS 1.2 GCM record layer must never reuse a (key, nonce) pair. */
#include "../src/net/ntx_tls_rec.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>

static int fail(const char *w) { fprintf(stderr, "FAIL %s\n", w); return 1; }

int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return fail("socketpair");

    ntx_tls t;
    memset(&t, 0, sizeof t);
    t.fd = sv[0];

    uint8_t key[16], iv4[4] = {1, 2, 3, 4};
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);
    ntx_aes128_gcm gcm;
    ntx_aes128_gcm_init(&gcm, key);

    uint64_t seq = 5;
    tls_dir d = { .enc = 1, .seq = &seq, .gcm = &gcm, .fixed_iv4 = iv4 };
    const uint8_t msg[] = "hello record layer";

    /* 1. a normal send consumes exactly one sequence number */
    if (rec_send(&t, 23, msg, sizeof msg, &d) != 0) return fail("send");
    if (seq != 6) return fail("seq-advance");
    printf("PASS rec-seq-advance\n");

    /* 2. two sends of identical plaintext use different nonces (different ciphertext) */
    uint8_t a[256], b[256];
    ssize_t na = recv(sv[1], a, sizeof a, 0);               /* first record */
    if (rec_send(&t, 23, msg, sizeof msg, &d) != 0) return fail("send2");
    ssize_t nb = recv(sv[1], b, sizeof b, 0);
    if (na <= 13 || na != nb) return fail("record-size");
    if (memcmp(a + 13, b + 13, (size_t)na - 13) == 0) return fail("same-ciphertext-twice");
    printf("PASS rec-nonce-differs\n");

    /* 2b. the record header's major version must be 3 (TLS); minor is left to the handshake */
    {
        tls_dir plain = { 0, NULL, NULL, NULL };
        uint8_t typ, buf[16];
        size_t olen;
        const uint8_t bad[9] = { 22, 0x02, 0x00, 0x00, 0x04, 1, 2, 3, 4 };
        const uint8_t good[9] = { 22, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4 };
        const uint8_t old[9] = { 22, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4 };
        if (send(sv[1], bad, sizeof bad, 0) != (ssize_t)sizeof bad) return fail("send-bad-version");
        if (rec_recv(&t, &typ, buf, sizeof buf, &olen, &plain) == 0) return fail("record-major-version-2-accepted");
        (void)recv(sv[0], buf, 4, 0); /* the rejected record's body is still queued: drop it */
        if (send(sv[1], good, sizeof good, 0) != (ssize_t)sizeof good) return fail("send-good-version");
        if (rec_recv(&t, &typ, buf, sizeof buf, &olen, &plain) != 0 || olen != 4) return fail("record-version-0303-rejected");
        if (send(sv[1], old, sizeof old, 0) != (ssize_t)sizeof old) return fail("send-old-version");
        if (rec_recv(&t, &typ, buf, sizeof buf, &olen, &plain) != 0 || olen != 4) return fail("record-version-0301-rejected");
        printf("PASS rec-version-check\n");
    }

    /* 3. a sequence number at the wrap point is refused and nothing is written */
    seq = UINT64_MAX;
    int fl = fcntl(sv[1], F_GETFL);
    fcntl(sv[1], F_SETFL, fl | O_NONBLOCK);
    if (rec_send(&t, 23, msg, sizeof msg, &d) == 0) return fail("send-at-wrap-allowed");
    if (seq != UINT64_MAX) return fail("seq-moved-at-wrap");
    if (recv(sv[1], a, sizeof a, 0) > 0) return fail("bytes-written-at-wrap");
    printf("PASS rec-seq-wrap-guard\n");

    /* 4. a failed write still consumes the nonce (no reuse after a partial send) */
    seq = 100;
    fcntl(sv[1], F_SETFL, fl);
    close(sv[1]);                                            /* peer gone -> write fails */
    signal(SIGPIPE, SIG_IGN);
    (void)rec_send(&t, 23, msg, sizeof msg, &d);
    if (seq != 101) return fail("seq-not-consumed-on-failed-write");
    printf("PASS rec-seq-consumed-before-io\n");

    close(sv[0]);
    return 0;
}
