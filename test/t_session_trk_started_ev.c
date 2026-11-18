#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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
#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"

#include <netinet/in.h>

/* R39 (§5.5). `trk_started_ok` is the single fact behind two contracts: a share
 * reaches READY only once a tracker answered THIS slot's `started`, and trk_stop_one
 * owes a goodbye only to a `started` that really went out. trk_note_ok used to read
 * the per-SLOT trk_http_event instead of the event the answered request carried, so
 * a reply to request A was judged by request B's event.
 *
 * Which half of the tracker code is actually exposed:
 *
 *  - UDP (cases 1-5): request and answer live in DIFFERENT loop iterations, and the
 *    slot's event moves in between — the periodic tick sets NONE, ntx_session_data.c
 *    sets COMPLETED/STOPPED, the portmap branch of ntx_session_share.c puts STARTED
 *    back. Both directions are wrong: an answered `started` whose slot has moved on
 *    leaves the share in ANNOUNCING forever (and owes no goodbye), and a `none`
 *    reply landing while the slot happens to say STARTED buys READY — plus a goodbye
 *    it never earned — without its `started` ever being answered. A connect answer is
 *    a third case: it answers no announce at all, yet it set the flag (case 5: the
 *    share goes READY before its `started` has even been sent). These are RED before
 *    the fix.
 *
 *  - HTTP (cases 6-7): the reply is parsed inside the same call that built the
 *    request (trk_http_announce → trk_http_apply), and pump_http takes the event from
 *    the same slot field it passes down, so there the coupling is provably
 *    per-request already. Case 6 therefore PINS that contract (green before and after
 *    the fix, driven through the production fetch against a loopback tracker), and
 *    case 7 is its non-vacuity probe: the two inputs are forced apart, and it is red
 *    before the fix, so case 6 cannot be satisfied by the slot's own value.
 *
 * Production reachability, stated honestly: a share slot's tracker list is only ever
 * the pinned HTTPS pool (ntx_session_share_add fills trk_urls from share_trk_list),
 * so no UDP tracker can today reach trk_note_ok for a slot that has a share — the UDP
 * defects below are latent, reachable through the production API but not through
 * today's share configuration, in the same way R35 was latent in S26. The fix costs
 * one stored int per pending request and makes the §5.5 gate true by construction.
 */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int udp_sock(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa)) return -1;
    socklen_t sl = sizeof sa;
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    *port = ntohs(sa.sin_port);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

static ntx_netx *g_n;
static ntx_session *s;
static int trk;               /* the tracker's socket */
static struct sockaddr_in us; /* our trk_fd address; replies must come from the target */

/* The tracker socket is non-blocking and the announce leaves through the session's
 * own socket, so a bare recv can lose a race the production code does not control. */
static ssize_t recv_wait(int fd, void *buf, size_t n) {
    for (int waited = 0; waited < 2000; waited += 5) {
        ssize_t r = recv(fd, buf, n, MSG_DONTWAIT);
        if (r >= 0) return r;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
        usleep(5000);
    }
    return -1;
}

static void session_new(void) {
    static ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.max_peers = 8;
    g_n = ntx_netx_init(&cfg);
    s = ntx_session_init(g_n, &cfg);
    uint8_t ih[20] = {9};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    s->tts[0].state = NTX_TTS_META;
    uint16_t tp, our_port;
    trk = udp_sock(&tp);
    s->trk_fd = udp_sock(&our_port);
    if (trk < 0 || s->trk_fd < 0) { printf("FAIL sockets\n"); exit(1); }
    memset(&us, 0, sizeof us);
    us.sin_family = AF_INET;
    us.sin_addr.s_addr = htonl(0x7f000001);
    us.sin_port = htons(our_port);
    snprintf(s->trk_urls[0][0], sizeof s->trk_urls[0][0], "udp://127.0.0.1:%u", (unsigned)tp);
    s->trk_n[0] = 1;
}

static void session_free(void) {
    ntx_session_free(s);
    ntx_netx_free(g_n);
    close(trk);
}

static int32_t rd32(const uint8_t *p) { return (int32_t)ntx_wire_rd32(p); }

/* Skips the BEP 15 connect so that the ONLY trk_note_ok the case can see is the
 * announce answer's (case 5 covers the connect answer on its own): the announce then
 * goes out straight from pump_udp. */
static void arm_connected(void) {
    s->trk_conn_done[0][0] = 1;
    s->trk_conn_id[0][0] = 0x0123456789abcdefull;
    s->trk_conn_t0[0][0] = ntx_mono_ms();
}

/* reads the announce that left us; *ev_out = the event the packet carries */
static int announce_on_the_wire(int32_t *ev_out, int32_t *tid_out) {
    uint8_t req[160];
    if (recv_wait(trk, req, sizeof req) != 98) return -1;
    if (ev_out) *ev_out = rd32(req + 80);
    if (tid_out) *tid_out = rd32(req + 12);
    return 0;
}

static int answer_announce(int32_t tid) {
    uint8_t rsp[20] = {0};
    ntx_wire_wr32(rsp + 0, (uint32_t)NTX_TRACKER_ACTION_ANNOUNCE);
    ntx_wire_wr32(rsp + 4, (uint32_t)tid);
    ntx_wire_wr32(rsp + 8, 1800);
    ntx_wire_wr32(rsp + 12, 1);
    ntx_wire_wr32(rsp + 16, 1);
    return sendto(trk, rsp, 20, 0, (struct sockaddr *)&us, sizeof us) == 20 ? 0 : -1;
}

/* request carries req_ev; while its reply is outstanding the slot moves to slot_ev
 * (a plain production ntx_session_trk_announce); then the reply arrives. */
static int udp_case(int req_ev, int slot_ev, int expect_ok, const char *tag) {
    session_new();
    s->trk_started_ok[0] = 0;
    arm_connected();
    ntx_session_trk_announce(s, 0, req_ev);
    ntx_session_trk_pump_udp(s);
    int32_t ev = -99, tid = -1;
    if (announce_on_the_wire(&ev, &tid) != 0) return fail(tag);
    if (ev != req_ev) {
        printf("%s: announce on the wire carried event=%d, want %d\n", tag, (int)ev, req_ev);
        session_free();
        return 1;
    }
    ntx_session_trk_announce(s, 0, slot_ev); /* the slot moves; the request does not */
    if (s->trk_http_event[0] != slot_ev) return fail(tag);
    if (answer_announce(tid) != 0) return fail(tag);
    ntx_session_trk_on_udp(s, s->trk_fd, s);
    if (s->trk_fail[0][0] != 0) {
        printf("%s: the reply was not accepted (fail=%u)\n", tag, (unsigned)s->trk_fail[0][0]);
        session_free();
        return 1;
    }
    int got = s->trk_started_ok[0] != 0;
    if (got != expect_ok) {
        printf("%s: started_ok=%d want=%d — the request carried %s, the slot had moved to %d\n",
               tag, got, expect_ok,
               req_ev == NTX_TRACKER_EVENT_STARTED ? "`started`" : "no event",
               s->trk_http_event[0]);
        session_free();
        return 1;
    }
    printf("PASS udp %s\n", tag);
    session_free();
    return 0;
}

/* ---- the HTTP half: a real loopback tracker, the production fetch, no seams ---- */
static int g_http_lfd = -1;
static int g_http_wire_ev = -99;
static int g_http_served = 0;

static void *http_serve_thread(void *arg) {
    (void)arg;
    int cfd = accept(g_http_lfd, NULL, NULL);
    if (cfd < 0) return NULL;
    char req[4096];
    ssize_t n = 0;
    while (n < (ssize_t)sizeof req - 1) {
        ssize_t r = recv(cfd, req + n, sizeof req - 1 - (size_t)n, 0);
        if (r <= 0) break;
        n += r;
        req[n] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    if (n > 0) {
        const char *q = strstr(req, "event=");
        if (q) {
            q += 6;
            /* the URL spells the event, not its number (and no event= at all == none) */
            if (!strncmp(q, "started", 7)) g_http_wire_ev = NTX_TRACKER_EVENT_STARTED;
            else if (!strncmp(q, "stopped", 7)) g_http_wire_ev = NTX_TRACKER_EVENT_STOPPED;
            else if (!strncmp(q, "completed", 9)) g_http_wire_ev = NTX_TRACKER_EVENT_COMPLETED;
            else g_http_wire_ev = NTX_TRACKER_EVENT_NONE;
        } else {
            g_http_wire_ev = NTX_TRACKER_EVENT_NONE;
        }
        g_http_served = 1;
        static const char body[] = "d8:intervali1800e5:peers0:e";
        char resp[192];
        int rl = snprintf(resp, sizeof resp,
                          "HTTP/1.1 200 OK\r\nContent-Length: %u\r\nConnection: close\r\n\r\n%s",
                          (unsigned)(sizeof body - 1), body);
        if (rl > 0) {
            ssize_t off = 0;
            while (off < rl) {
                ssize_t w = send(cfd, resp + off, (size_t)(rl - off), 0);
                if (w <= 0) break;
                off += w;
            }
        }
    }
    close(cfd);
    return NULL;
}

/* slot says slot_ev, the request is built with req_ev (pump_http would take the
 * event from the same slot field; trk_http_announce is the call site ntx_share.c and
 * the tests use directly). */
static int http_case(int req_ev, int slot_ev, int expect_ok, int expect_wire, const char *tag) {
    session_new();
    s->trk_started_ok[0] = 0;
    g_http_wire_ev = -99;
    g_http_served = 0;
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    g_http_lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(g_http_lfd, (struct sockaddr *)&la, sizeof la) != 0 || listen(g_http_lfd, 4) != 0) {
        close(g_http_lfd);
        return fail("http_listen");
    }
    socklen_t ll = sizeof la;
    getsockname(g_http_lfd, (struct sockaddr *)&la, &ll);
    snprintf(s->trk_urls[0][0], 512, "http://127.0.0.1:%u/announce", (unsigned)ntohs(la.sin_port));
    s->trk_n[0] = 1;
    s->trk_http_event[0] = slot_ev;

    pthread_t th;
    if (pthread_create(&th, NULL, http_serve_thread, NULL) != 0) { close(g_http_lfd); return fail("thread"); }
    trk_http_announce(s, 0, 0, s->trk_urls[0][0], req_ev);
    pthread_join(th, NULL);
    close(g_http_lfd);

    if (!g_http_served) return fail("tracker_never_contacted");
    if (g_http_wire_ev != expect_wire) {
        printf("%s: request on the wire carried event=%d, want %d\n", tag, g_http_wire_ev, expect_wire);
        session_free();
        return 1;
    }
    if (s->trk_fail[0][0] != 0) {
        printf("%s: the reply was not accepted (fail=%u)\n", tag, (unsigned)s->trk_fail[0][0]);
        session_free();
        return 1;
    }
    int got = s->trk_started_ok[0] != 0;
    if (got != expect_ok) {
        printf("%s: started_ok=%d want=%d — the request carried %s, the slot says %d\n", tag, got, expect_ok,
               req_ev == NTX_TRACKER_EVENT_STARTED ? "`started`" : "no event", s->trk_http_event[0]);
        session_free();
        return 1;
    }
    printf("PASS http %s\n", tag);
    session_free();
    return 0;
}

/* 5: a CONNECT answer is not an announce answer; with the slot on `started` it must
 * not be what makes the share READY — the `started` has not even been sent yet. */
static int connect_answer_case(void) {
    session_new();
    s->trk_started_ok[0] = 0;
    ntx_session_trk_announce(s, 0, NTX_TRACKER_EVENT_STARTED);
    ntx_session_trk_pump_udp(s);
    uint8_t req[64];
    if (recv_wait(trk, req, sizeof req) != 16) return fail("c5_connect_req");
    uint8_t rsp[16] = {0};
    ntx_wire_wr32(rsp + 0, (uint32_t)NTX_TRACKER_ACTION_CONNECT);
    ntx_wire_wr32(rsp + 4, (uint32_t)rd32(req + 12));
    memset(rsp + 8, 0x42, 8);
    if (sendto(trk, rsp, 16, 0, (struct sockaddr *)&us, sizeof us) != 16) return fail("c5_connect_rsp");
    ntx_session_trk_on_udp(s, s->trk_fd, s);
    if (!s->trk_conn_done[0][0]) return fail("c5_connect_not_done");
    if (s->trk_started_ok[0] != 0) {
        printf("connect answer set started_ok — no announce had been answered yet\n");
        session_free();
        return 1;
    }
    printf("PASS udp connect_answer_does_not_mark_ready\n");
    session_free();
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    int rc = 0;

    /* 1/2: an answered `started` must count even after the slot moved on — otherwise
     * the share never reaches READY and never owes its goodbye. */
    rc |= udp_case(NTX_TRACKER_EVENT_STARTED, NTX_TRACKER_EVENT_COMPLETED, 1, "started_reply_after_slot_completed");
    rc |= udp_case(NTX_TRACKER_EVENT_STARTED, NTX_TRACKER_EVENT_STOPPED, 1, "started_reply_after_slot_stopped");
    /* 3/4: the other direction — a reply to a request that carried NO event must not
     * buy READY just because the slot happens to say `started`. Case 4 is the control
     * (nothing moved, so the flag must stay down for the right reason). */
    rc |= udp_case(NTX_TRACKER_EVENT_NONE, NTX_TRACKER_EVENT_STARTED, 0, "none_reply_while_slot_started");
    rc |= udp_case(NTX_TRACKER_EVENT_NONE, NTX_TRACKER_EVENT_NONE, 0, "none_reply_never_sets");
    /* control: the ordinary flow still works. */
    rc |= udp_case(NTX_TRACKER_EVENT_STARTED, NTX_TRACKER_EVENT_STARTED, 1, "plain_started_sets");

    /* 5: a CONNECT answer answers no announce. With the slot on `started` it must not
     * be what marks the share READY — its `started` has not even been sent yet. */
    rc |= connect_answer_case();

    /* 6: PIN (green before the fix): the HTTP reply is applied inside the call that
     * built the request, so the slot still says exactly what was asked — 7 proves the
     * assertion below is answered by the request, not by the slot. */
    rc |= http_case(NTX_TRACKER_EVENT_STARTED, NTX_TRACKER_EVENT_STARTED, 1, NTX_TRACKER_EVENT_STARTED,
                    "started_reply_keyed_to_request");
    /* 7: NON-VACUITY PROBE (red before the fix): the two inputs forced apart — the
     * slot says `started`, the request carried none. Only the request may count. */
    rc |= http_case(NTX_TRACKER_EVENT_NONE, NTX_TRACKER_EVENT_STARTED, 0, NTX_TRACKER_EVENT_NONE,
                    "none_reply_not_keyed_to_slot");

    if (rc == 0) printf("ALL PASS\n");
    return rc;
}
