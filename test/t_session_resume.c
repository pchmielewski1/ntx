#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/proto/ntx_pe.c"
#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/proto/ntx_pex.c"
#include "../src/proto/ntx_http.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/core/ntx_session_stats.c"
#include "../src/core/ntx_pieceblk.c"
#include "../src/core/ntx_session_webseed.c"
#include "../src/core/ntx_session_pex.c"
#include "../src/core/ntx_session_meta.c"
#include "../src/core/ntx_session_vlog.c"
#include "../src/core/ntx_session_pe.c"
#include "../src/core/ntx_session_bt_hs.c"
#include "../src/proto/ntx_btmsg.c"
#include "../src/proto/ntx_utmeta.c"
#include "../src/proto/ntx_pe_vc.c"

#define PS 32768U

static int g_fail;

static void fail(const char *m) {
    printf("FAIL %s\n", m);
    g_fail = 1;
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t trk_rd64(const uint8_t *p) {
    return ((uint64_t)rd32(p) << 32) | (uint64_t)rd32(p + 4);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void trk_wr64(uint8_t *p, uint64_t v) {
    wr32(p, (uint32_t)(v >> 32));
    wr32(p + 4, (uint32_t)v);
}

static uint8_t *mk_pat(uint32_t seed) {
    uint8_t *p = malloc(PS);
    for (uint32_t i = 0; i < PS; i++)
        p[i] = (uint8_t)(i * 11 + 7 + seed);
    return p;
}

static int build_info(const char *name, uint32_t np, uint32_t ps, uint8_t ih[20],
                      const uint8_t *pat, uint32_t npat, char *out, size_t cap) {
    (void)npat;
    uint8_t *pieces = malloc((size_t)np * 20);
    if (!pieces) return -1;
    for (uint32_t i = 0; i < np; i++) {
        uint8_t h[20];
        ntx_sha1(pat + (size_t)(i % npat) * PS, PS, h);
        memcpy(pieces + (size_t)i * 20, h, 20);
    }
    uint64_t size = (uint64_t)np * ps;
    int in = snprintf(out, cap, "d6:lengthi%llue4:name%u:", (unsigned long long)size,
                      (unsigned)strlen(name));
    if (in <= 0) {
        free(pieces);
        return -1;
    }
    memcpy(out + in, name, strlen(name));
    in += (int)strlen(name);
    in += snprintf(out + in, cap - (size_t)in, "12:piece lengthi%ue6:pieces%u:", (unsigned)ps,
                   (unsigned)np * 20);
    if ((size_t)in + (size_t)np * 20 + 2 > cap) {
        free(pieces);
        return -1;
    }
    memcpy(out + in, pieces, (size_t)np * 20);
    in += (int)((size_t)np * 20);
    out[in++] = 'e';
    out[in] = 0;
    free(pieces);
    ntx_sha1((const uint8_t *)out, (size_t)in, ih);
    return in;
}

static int build_torrent(const char *name, uint32_t np, uint32_t ps, uint8_t ih[20],
                         const uint8_t *pat, uint32_t npat, char *out, size_t cap) {
    static char info[32768];
    int in = build_info(name, np, ps, ih, pat, npat, info, sizeof info);
    if (in <= 0) return -1;
    if ((size_t)in + 64 > cap) return -1;
    int n = snprintf(out, cap, "d8:announce20:http://127.0.0.1/ann4:info");
    memcpy(out + n, info, (size_t)in);
    n += in;
    out[n++] = 'e';
    out[n] = 0;
    return 0;
}

static void write_file(const char *path, const uint8_t *pat, uint32_t np) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    for (uint32_t i = 0; i < np; i++)
        if (write(fd, pat, PS) != (ssize_t)PS) break;
    close(fd);
}

static void trk_resp(uint8_t *b, uint32_t tid) {
    wr32(b, 1);
    wr32(b + 4, tid);
    wr32(b + 8, 1200);
    wr32(b + 12, 0);
    wr32(b + 16, 0);
}

static void sp_nonblock(int sv[2]) {
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl >= 0) {
        fcntl(sv[0], F_SETFL, fl | O_NONBLOCK);
        fcntl(sv[1], F_SETFL, fl | O_NONBLOCK);
    }
}

static uint32_t local_ip_net(void) {
    int p = socket(AF_INET, SOCK_DGRAM, 0);
    if (p < 0) return htonl(0x7f000001);
    struct sockaddr_in ext;
    memset(&ext, 0, sizeof ext);
    ext.sin_family = AF_INET;
    ext.sin_port = htons(53);
    ext.sin_addr.s_addr = htonl(0x08080808);
    if (connect(p, (struct sockaddr *)&ext, sizeof ext) != 0) {
        close(p);
        return htonl(0x7f000001);
    }
    struct sockaddr_in loc;
    socklen_t ll = sizeof loc;
    uint32_t ip = htonl(0x7f000001);
    if (getsockname(p, (struct sockaddr *)&loc, &ll) == 0)
        ip = loc.sin_addr.s_addr;
    close(p);
    return ip;
}

static void trk_url(char *out, size_t cap, uint16_t port) {
    uint32_t ip = local_ip_net(); /* network byte order */
    uint8_t b[4];
    memcpy(b, &ip, 4);
    snprintf(out, cap, "udp://%u.%u.%u.%u:%u", (unsigned)b[0], (unsigned)b[1],
             (unsigned)b[2], (unsigned)b[3], (unsigned)port);
}

static int trk_listen(int *fd, uint16_t *port) {
    int l = socket(AF_INET, SOCK_DGRAM, 0);
    if (l < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = 0;
    a.sin_port = 0;
    if (bind(l, (struct sockaddr *)&a, sizeof a) != 0) {
        close(l);
        return -1;
    }
    socklen_t alen = sizeof a;
    if (getsockname(l, (struct sockaddr *)&a, &alen) != 0) {
        close(l);
        return -1;
    }
    *fd = l;
    *port = ntohs(a.sin_port);
    int fl = fcntl(l, F_GETFL, 0);
    fcntl(l, F_SETFL, fl | O_NONBLOCK);
    return 0;
}

static int trk_rx(int fd, uint8_t *buf, size_t cap, struct sockaddr_in *src) {
    socklen_t alen = sizeof *src;
    ssize_t n = recvfrom(fd, buf, cap, 0, (struct sockaddr *)src, &alen);
    if (n < 0) return 0;
    return (int)n;
}

static void trk_pump(int fd, int *cid, int *ann, uint64_t *started_left, uint64_t *completed_left) {
    for (;;) {
        uint8_t b[256];
        struct sockaddr_in src;
        int n = trk_rx(fd, b, sizeof b, &src);
        if (n <= 0) break;
        if (n >= 16 && (int32_t)rd32(b + 8) == 0) {
            uint8_t r[16];
            wr32(r, 0);
            wr32(r + 4, rd32(b + 12));
            trk_wr64(r + 8, 0x1234567890ABCDL);
            sendto(fd, r, 16, 0, (struct sockaddr *)&src, sizeof src);
            *cid = 1;
            continue;
        }
        if (n >= 98 && (int32_t)rd32(b + 8) == 1) {
            *ann += 1;
            uint64_t left = trk_rd64(b + 64);
            int ev = (int)rd32(b + 80);
            if (ev == NTX_TRACKER_EVENT_STARTED) *started_left = left;
            if (ev == NTX_TRACKER_EVENT_COMPLETED) *completed_left = left;
            trk_resp(b, rd32(b + 12));
            sendto(fd, b, 20, 0, (struct sockaddr *)&src, sizeof src);
        }
    }
}

static ssize_t drain_peer_tx(ntx_session *s, int pi, int sv, uint8_t *buf, size_t cap) {
    ntx_session_peer_out_flush(s, pi);
    ssize_t total = 0;
    for (;;) {
        ssize_t r = recv(sv, buf + total, cap - (size_t)total, MSG_DONTWAIT);
        if (r <= 0) break;
        total += r;
        if ((size_t)total >= cap) break;
    }
    return total;
}

static int peer_send_have_all(ntx_session *s, int pi) {
    uint8_t m[9];
    wr32(m, 5);
    m[4] = (uint8_t)MSG_HAVE_ALL;
    memcpy(s->peer_buf[pi], m, 9);
    s->peer_buflen[pi] = 9;
    ntx_session_peer_process_inbuf(s, pi);
    return 0;
}

static int peer_send_request(ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    uint8_t m[17];
    wr32(m, 13);
    m[4] = (uint8_t)MSG_REQUEST;
    wr32(m + 5, idx);
    wr32(m + 9, off);
    wr32(m + 13, len);
    memcpy(s->peer_buf[pi], m, 17);
    s->peer_buflen[pi] = 17;
    ntx_session_peer_process_inbuf(s, pi);
    return 0;
}

static void t3a(void) {
    unlink("test/t3_store/fresh");
    unlink("test/t3_store/fresh.torrent");
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("fresh", 5, PS, ih, mk_pat(10), 1, tor, sizeof tor) != 0) {
        fail("t3a_build");
        return;
    }
    FILE *f = fopen("test/t3_store/fresh.torrent", "wb");
    if (!f) {
        fail("t3a_fopen");
        return;
    }
    if (fwrite(tor, 1, strlen(tor), f) != strlen(tor)) {
        fclose(f);
        fail("t3a_write");
        return;
    }
    fclose(f);
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3a_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    if (ntx_session_add_torrent_file(s, "test/t3_store/fresh.torrent") != 0) {
        fail("t3a_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_DL) {
        fail("t3a_state_dl");
        return;
    }
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    for (int k = 0; k < 40; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        if (ann >= 1) break;
    }
    if (ann != 1) {
        fail("t3a_started_ann");
        return;
    }
    if (started_left != (uint64_t)5 * PS) {
        fail("t3a_left");
        return;
    }
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    unlink("test/t3_store/fresh.torrent");
    unlink("test/t3_store/fresh");
    printf("PASS t3a_fresh_regression\n");
}

static void t3b(void) {
    unlink("test/t3_store/resume");
    unlink("test/t3_store/resume.torrent");
    uint8_t *pat = mk_pat(1);
    write_file("test/t3_store/resume", pat, 2);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("resume", 5, PS, ih, pat, 1, tor, sizeof tor) != 0) {
        fail("t3b_build");
        return;
    }
    FILE *f = fopen("test/t3_store/resume.torrent", "wb");
    if (!f) {
        fail("t3b_fopen");
        return;
    }
    if (fwrite(tor, 1, strlen(tor), f) != strlen(tor)) {
        fclose(f);
        fail("t3b_write");
        return;
    }
    fclose(f);
    if (ntx_session_add_torrent_file(s, "test/t3_store/resume.torrent") != 0) {
        fail("t3b_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_VERIFY) {
        fail("t3b_state_verify");
        return;
    }
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3b_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    for (int k = 0; k < 40; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        if (s->tts[0].state != NTX_TTS_VERIFY && ann >= 1) break;
    }
    if (s->tts[0].state != NTX_TTS_DL) {
        fail("t3b_state_dl");
        return;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fail("t3b_socketpair");
        return;
    }
    sp_nonblock(sv);
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000002));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) {
        fail("t3b_alloc");
        return;
    }
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);
    ntx_session_peer_on_rw(s, sv[0], (void *)(intptr_t)(pi + 1));
    if (s->tts[0].have_n != 2) {
        fail("t3b_have_n");
        return;
    }
    if (s->tts[0].verified_B != (uint64_t)2 * PS) {
        fail("t3b_verified_B");
        return;
    }
    if (ann != 1) {
        fail("t3b_started_ann");
        return;
    }
    if (started_left != (uint64_t)3 * PS) {
        fail("t3b_left");
        return;
    }
    if (completed_left != 0) {
        fail("t3b_completed_ann");
        return;
    }
    ntx_peer_set_phave(&s->peers[pi], 0, 1);
    ntx_peer_set_phave(&s->peers[pi], 1, 1);
    ntx_peer_set_phave(&s->peers[pi], 2, 1);
    ntx_peer_set_phave(&s->peers[pi], 3, 1);
    ntx_peer_set_phave(&s->peers[pi], 4, 1);
    ntx_session_data_update_peer_interest(s, pi);
    ntx_session_data_refill(s, 0);
    uint8_t rx[4096];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    int saw_bf = 0;
    int req_01 = 0, req_234 = 0;
    if (rn >= 9) {
        if (rd32(rx) == 5 + (size_t)1 && rx[4] == MSG_BITFIELD)
            saw_bf = 1;
        for (ssize_t off = 0; off + 8 <= rn;) {
            uint32_t ln = rd32(rx + off);
            if (off + (ssize_t)ln + 4 > rn) break;
            if (ln >= 1 && rx[off + 4] == MSG_BITFIELD)
                saw_bf = 1;
            if (ln == 13 && rx[off + 4] == MSG_REQUEST) {
                uint32_t idx = rd32(rx + off + 5);
                if (idx <= 1) req_01 = 1;
                if (idx >= 2) req_234 = 1;
            }
            off += (ssize_t)ln + 4;
        }
    }
    if (!saw_bf) {
        fail("t3b_bitfield");
        return;
    }
    if (req_01) {
        fail("t3b_req_have_pieces");
        return;
    }
    if (!req_234) {
        fail("t3b_req_missing");
        return;
    }
    close(sv[0]);
    close(sv[1]);
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    free(pat);
    unlink("test/t3_store/resume.torrent");
    unlink("test/t3_store/resume");
    printf("PASS t3b_resume\n");
}

static void t3c(void) {
    unlink("test/t3_store/partial");
    unlink("test/t3_store/partial.torrent");
    uint8_t *pat = mk_pat(2);
    write_file("test/t3_store/partial", pat, 1);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("partial", 5, PS, ih, pat, 1, tor, sizeof tor) != 0) {
        fail("t3c_build");
        return;
    }
    FILE *f = fopen("test/t3_store/partial.torrent", "wb");
    if (!f) {
        fail("t3c_fopen");
        return;
    }
    if (fwrite(tor, 1, strlen(tor), f) != strlen(tor)) {
        fclose(f);
        fail("t3c_write");
        return;
    }
    fclose(f);
    if (ntx_session_add_torrent_file(s, "test/t3_store/partial.torrent") != 0) {
        fail("t3c_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_VERIFY) {
        fail("t3c_state_verify");
        return;
    }
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3c_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    for (int k = 0; k < 40; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        if (s->tts[0].state != NTX_TTS_VERIFY && ann >= 1) break;
    }
    if (s->tts[0].state != NTX_TTS_DL) {
        fail("t3c_state_dl");
        return;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fail("t3c_socketpair");
        return;
    }
    sp_nonblock(sv);
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000003));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) {
        fail("t3c_alloc");
        return;
    }
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);
    ntx_session_peer_on_rw(s, sv[0], (void *)(intptr_t)(pi + 1));
    if (s->tts[0].have_n != 1) {
        fail("t3c_have_n");
        return;
    }
    if (s->tts[0].store.pmap[1] != 0) {
        fail("t3c_pmap_corrupt");
        return;
    }
    ntx_peer_set_phave(&s->peers[pi], 1, 1);
    ntx_peer_set_phave(&s->peers[pi], 2, 1);
    ntx_peer_set_phave(&s->peers[pi], 3, 1);
    ntx_peer_set_phave(&s->peers[pi], 4, 1);
    ntx_session_data_update_peer_interest(s, pi);
    ntx_session_data_refill(s, 0);
    int req_1 = 0;
    for (;;) {
        uint8_t rx[4096];
        ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
        if (rn <= 0) break;
        for (ssize_t off = 0; off + 8 <= rn;) {
            uint32_t ln = rd32(rx + off);
            if (off + (ssize_t)ln + 4 > rn) break;
            if (ln == 13 && rx[off + 4] == MSG_REQUEST && rd32(rx + off + 5) == 1)
                req_1 = 1;
            off += (ssize_t)ln + 4;
        }
    }
    if (!req_1) {
        fail("t3c_req_corrupt");
        return;
    }
    ntx_session_data_on_piece(s, pi, 1, 0, pat, PS / 2);
    ntx_session_data_on_piece(s, pi, 1, PS / 2, pat + PS / 2, PS - PS / 2);
    if (!s->tts[0].have[1] || s->tts[0].have_n != 2) {
        fail("t3c_complete");
        return;
    }
    uint8_t rx[64];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    int saw_have = 0;
    if (rn >= 9 && rd32(rx) == 5 && rx[4] == MSG_HAVE && rd32(rx + 5) == 1)
        saw_have = 1;
    if (!saw_have) {
        fail("t3c_have_msg");
        return;
    }
    close(sv[0]);
    close(sv[1]);
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    free(pat);
    unlink("test/t3_store/partial.torrent");
    unlink("test/t3_store/partial");
    printf("PASS t3c_resume_partial\n");
}

static void t3d(void) {
    unlink("test/t3_store/precomp");
    unlink("test/t3_store/precomp.torrent");
    uint8_t *pat = mk_pat(3);
    write_file("test/t3_store/precomp", pat, 5);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("precomp", 5, PS, ih, pat, 1, tor, sizeof tor) != 0) {
        fail("t3d_build");
        return;
    }
    FILE *f = fopen("test/t3_store/precomp.torrent", "wb");
    if (!f) {
        fail("t3d_fopen");
        return;
    }
    if (fwrite(tor, 1, strlen(tor), f) != strlen(tor)) {
        fclose(f);
        fail("t3d_write");
        return;
    }
    fclose(f);
    if (ntx_session_add_torrent_file(s, "test/t3_store/precomp.torrent") != 0) {
        fail("t3d_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_VERIFY) {
        fail("t3d_state_verify");
        return;
    }
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3d_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    for (int k = 0; k < 40; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        if (s->tts[0].state != NTX_TTS_VERIFY) break;
    }
    if (s->tts[0].state != NTX_TTS_DONE) {
        fail("t3d_state_done");
        return;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fail("t3d_socketpair");
        return;
    }
    sp_nonblock(sv);
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000004));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) {
        fail("t3d_alloc");
        return;
    }
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);
    ntx_session_peer_on_rw(s, sv[0], (void *)(intptr_t)(pi + 1));
    if (!s->tts[0].pre_complete) {
        fail("t3d_pre_complete");
        return;
    }
    if (s->tts[0].have_n != 5) {
        fail("t3d_have_n");
        return;
    }
    if (ann != 0) {
        fail("t3d_zero_ann");
        return;
    }
    if (started_left != 0 || completed_left != 0) {
        fail("t3d_zero_ann_left");
        return;
    }
    peer_send_have_all(s, pi);
    uint8_t rx[64 + 16384];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    int saw_bf = 0;
    if (rn >= 9) {
        if (rd32(rx) == 5 + (size_t)1 && rx[4] == MSG_BITFIELD)
            saw_bf = 1;
        for (ssize_t off = 0; off + 8 <= rn;) {
            uint32_t ln = rd32(rx + off);
            if (off + (ssize_t)ln + 4 > rn) break;
            if (ln >= 1 && rx[off + 4] == MSG_BITFIELD)
                saw_bf = 1;
            off += (ssize_t)ln + 4;
        }
    }
    if (!saw_bf) {
        fail("t3d_bitfield");
        return;
    }
    uint64_t up_before = s->tts_up[0];
    peer_send_request(s, pi, 0, 0, 16384);
    if (s->tts_up[0] != up_before + 16384) {
        fail("t3d_upload");
        return;
    }
    memset(rx, 0, sizeof rx);
    rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    int saw_piece = 0;
    for (ssize_t off = 0; off + 8 <= rn;) {
        uint32_t ln = rd32(rx + off);
        if (off + (ssize_t)ln + 4 > rn) break;
        if (ln == 9 + 16384 && rx[off + 4] == MSG_PIECE && rd32(rx + off + 5) == 0 &&
            rd32(rx + off + 9) == 0 && rn >= off + 13 + 16384 && memcmp(rx + off + 13, pat, 16384) == 0)
            saw_piece = 1;
        off += (ssize_t)ln + 4;
    }
    if (!saw_piece) {
        fail("t3d_piece");
        return;
    }
    close(sv[0]);
    close(sv[1]);
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    free(pat);
    unlink("test/t3_store/precomp.torrent");
    unlink("test/t3_store/precomp");
    printf("PASS t3d_pre_complete\n");
}

static void t3e(void) {
    unlink("test/t3_store/pump");
    unlink("test/t3_store/pump.torrent");
    uint8_t *pat = mk_pat(4);
    write_file("test/t3_store/pump", pat, 100);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("pump", 100, PS, ih, pat, 1, tor, sizeof tor) != 0) {
        fail("t3e_build");
        return;
    }
    FILE *f = fopen("test/t3_store/pump.torrent", "wb");
    if (!f) {
        fail("t3e_fopen");
        return;
    }
    if (fwrite(tor, 1, strlen(tor), f) != strlen(tor)) {
        fclose(f);
        fail("t3e_write");
        return;
    }
    fclose(f);
    if (ntx_session_add_torrent_file(s, "test/t3_store/pump.torrent") != 0) {
        fail("t3e_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_VERIFY) {
        fail("t3e_state_verify");
        return;
    }
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3e_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    int ticks = 0;
    for (int k = 0; k < 64; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        ticks++;
        if (s->tts[0].state != NTX_TTS_VERIFY && ann >= 1) break;
    }
    if (s->tts[0].state != NTX_TTS_DONE) {
        fail("t3e_state_done");
        return;
    }
    if (!s->tts[0].pre_complete) {
        fail("t3e_pre_complete");
        return;
    }
    if (s->tts[0].have_n != 100) {
        fail("t3e_have_n");
        return;
    }
    if (ticks < 2) {
        fail("t3e_pump_multi_tick");
        return;
    }
    if (ann != 0) {
        fail("t3e_zero_ann");
        return;
    }
    uint64_t tick_after = s->tick_n;
    ntx_session_tick(s);
    ntx_netx_run_once(n, 0);
    trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
    if (s->tick_n != tick_after + 1) {
        fail("t3e_ticks_keep_running");
        return;
    }
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    free(pat);
    unlink("test/t3_store/pump.torrent");
    unlink("test/t3_store/pump");
    printf("PASS t3e_pump\n");
}

static void t3f(void) {
    unlink("test/t3_store/magnet");
    unlink("test/t3_store/mag.torrent");
    uint8_t *pat = mk_pat(5);
    write_file("test/t3_store/magnet", pat, 5);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t3_store";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20];
    char tor[8192];
    if (build_torrent("magnet", 5, PS, ih, pat, 1, tor, sizeof tor) != 0) {
        fail("t3f_build");
        return;
    }
    char ihx[41];
    for (int i = 0; i < 20; i++)
        sprintf(ihx + i * 2, "%02x", ih[i]);
    char mag[512];
    snprintf(mag, sizeof mag, "magnet:?xt=urn:btih:%s", ihx);
    if (ntx_session_add_magnet(s, mag) != 0) {
        fail("t3f_add");
        return;
    }
    if (s->tts[0].state != NTX_TTS_META) {
        fail("t3f_state_meta");
        return;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        fail("t3f_socketpair");
        return;
    }
    sp_nonblock(sv);
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000005));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) {
        fail("t3f_alloc");
        return;
    }
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peer_meta_id[pi] = 1;
    s->peer_meta_size[pi] = (uint32_t)strlen(tor);
    char info[32768];
    if (build_info("magnet", 5, PS, ih, pat, 1, info, sizeof info) <= 0) {
        fail("t3f_info");
        return;
    }
    size_t info_len = strlen(info);
    uint8_t payload[16512];
    size_t pn = 0;
    if (ntx_ut_metadata_data_build(payload, &pn, 0, (uint32_t)info_len, (const uint8_t *)info,
                                   info_len) != 0) {
        fail("t3f_data_build");
        return;
    }
    uint8_t msg[16640];
    size_t mn = ntx_ext_msg_build(msg, sizeof msg, 1, payload, pn);
    if (!mn) {
        fail("t3f_ext_build");
        return;
    }
    memcpy(s->peer_buf[pi], msg, mn);
    s->peer_buflen[pi] = mn;
    ntx_session_peer_process_inbuf(s, pi);
    if (s->tts[0].state != NTX_TTS_VERIFY) {
        fail("t3f_state_verify");
        return;
    }
    int tfd;
    uint16_t tport;
    if (trk_listen(&tfd, &tport) != 0) {
        fail("t3f_listen");
        return;
    }
    char url[64];
    trk_url(url, sizeof url, tport);
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    int cid = 0, ann = 0;
    uint64_t started_left = 0, completed_left = 0;
    for (int k = 0; k < 40; k++) {
        ntx_session_tick(s);
        ntx_netx_run_once(n, 0);
        trk_pump(tfd, &cid, &ann, &started_left, &completed_left);
        if (s->tts[0].state != NTX_TTS_VERIFY && ann >= 1) break;
    }
    if (s->tts[0].state != NTX_TTS_DONE) {
        fail("t3f_state_done");
        return;
    }
    if (!s->tts[0].pre_complete) {
        fail("t3f_pre_complete");
        return;
    }
    if (ann != 0) {
        fail("t3f_zero_ann");
        return;
    }
    close(sv[0]);
    close(sv[1]);
    close(tfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    free(pat);
    unlink("test/t3_store/magnet");
    printf("PASS t3f_magnet_resume\n");
}

int main(void) {
    ntx_rng_init();
    mkdir("test", 0755);
    mkdir("test/t3_store", 0755);
    unlink("test/t3_store/fresh");
    unlink("test/t3_store/fresh.torrent");
    unlink("test/t3_store/resume");
    unlink("test/t3_store/resume.torrent");
    unlink("test/t3_store/partial");
    unlink("test/t3_store/partial.torrent");
    unlink("test/t3_store/precomp");
    unlink("test/t3_store/precomp.torrent");
    unlink("test/t3_store/pump");
    unlink("test/t3_store/pump.torrent");
    unlink("test/t3_store/magnet");
    unlink("test/t3_store/mag.torrent");
    t3a();
    t3b();
    t3c();
    t3d();
    t3e();
    t3f();
    unlink("test/t3_store/fresh");
    unlink("test/t3_store/fresh.torrent");
    unlink("test/t3_store/resume");
    unlink("test/t3_store/resume.torrent");
    unlink("test/t3_store/partial");
    unlink("test/t3_store/partial.torrent");
    unlink("test/t3_store/precomp");
    unlink("test/t3_store/precomp.torrent");
    unlink("test/t3_store/pump");
    unlink("test/t3_store/pump.torrent");
    unlink("test/t3_store/magnet");
    unlink("test/t3_store/mag.torrent");
    if (g_fail) return 1;
    printf("ALL t_session_resume PASS\n");
    return 0;
}
