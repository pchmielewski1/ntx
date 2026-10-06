#include "ntx_session_internal.h"
#include "../ui/ntx_diag.h"
#include "../proto/ntx_tracker.h"
#include "../proto/ntx_http.h"
#include "../proto/ntx_bencode.h"
#include "../net/ntx_sock.h"
#include "../crypto/ntx_rng.h"
#include "../net/ntx_netx.h"
#include "ntx_time.h"
#include "../proto/ntx_wire.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#define TRK_DNS_CACHE 32

static struct {
    char host[128];
    uint32_t ip;
    int8_t st; /* 0 empty, 1 ok, -1 neg (DoH/DNS failed) */
} dns_cache[TRK_DNS_CACHE];

static int trk_is_dead(const struct ntx_session *s, int tts_idx, int trk_idx) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return 1;
    if (trk_idx < 0 || trk_idx >= NTX_SESSION_MAX_TRK) return 1;
    return s->trk_fail[tts_idx][trk_idx] >= NTX_TRK_MAX_FAIL;
}

static void trk_note_ok(struct ntx_session *s, int tts_idx, int trk_idx) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return;
    if (trk_idx < 0 || trk_idx >= NTX_SESSION_MAX_TRK) return;
    s->trk_fail[tts_idx][trk_idx] = 0;
}

static void trk_note_fail(struct ntx_session *s, int tts_idx, int trk_idx, const char *why) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return;
    if (trk_idx < 0 || trk_idx >= s->trk_n[tts_idx] || trk_idx >= NTX_SESSION_MAX_TRK) return;
    if (s->trk_fail[tts_idx][trk_idx] >= NTX_TRK_MAX_FAIL) return;
    s->trk_fail[tts_idx][trk_idx]++;
    s->trk_conn_done[tts_idx][trk_idx] = 0;
    s->trk_http_pending[tts_idx][trk_idx] = 0;
    /* Dead trackers show as trk…dNN in the one-line CLI; no stderr unless --verbose. */
    if (s->cfg && s->cfg->verbose) {
        ntx_diag( "ntx: trk fail tts=%d trk=%d n=%u/%u (%s) %s\n", tts_idx, trk_idx,
                (unsigned)s->trk_fail[tts_idx][trk_idx], (unsigned)NTX_TRK_MAX_FAIL,
                why ? why : "?", s->trk_urls[tts_idx][trk_idx]);
        if (s->trk_fail[tts_idx][trk_idx] >= NTX_TRK_MAX_FAIL)
            ntx_diag( "ntx: trk dead (giving up): %s\n", s->trk_urls[tts_idx][trk_idx]);
    }
}

static uint32_t trk_resolve(const char *host) {
    for (int i = 0; i < TRK_DNS_CACHE; i++) {
        if (dns_cache[i].st == 0) continue;
        if (strcmp(dns_cache[i].host, host) != 0) continue;
        if (dns_cache[i].st < 0) return INADDR_NONE;
        return dns_cache[i].ip;
    }
    uint32_t ip = 0;
    int ok = (ntx_sock_resolve4(host, &ip) == 0 && ip != 0 && ip != INADDR_NONE);
    int slot = -1;
    for (int i = 0; i < TRK_DNS_CACHE; i++) {
        if (dns_cache[i].st == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) slot = (int)(ntx_rand_u32() % TRK_DNS_CACHE);
    snprintf(dns_cache[slot].host, sizeof dns_cache[slot].host, "%s", host);
    if (ok) {
        dns_cache[slot].ip = ip;
        dns_cache[slot].st = 1;
        return ip;
    }
    dns_cache[slot].ip = 0;
    dns_cache[slot].st = -1;
    return INADDR_NONE;
}

static int trk_parse_udp(const char *url, uint32_t *ip, uint16_t *port) {
    const char *p = url + 6;
    char host[128];
    int i = 0;
    while (*p && *p != ':' && i < 127) host[i++] = *p++;
    host[i] = 0;
    if (*p != ':') return 0;
    p++;
    int pr = atoi(p);
    if (pr <= 0 || pr > 65535) return 0;
    *port = (uint16_t) pr;
    *ip = trk_resolve(host);
    if (*ip == INADDR_NONE) return 0;
    return 1;
}

static uint32_t trk_interval_clamp(uint32_t iv) {
    if (iv == 0) iv = 1800;
    if (iv < 60) iv = 60;
    if (iv > 10800) iv = 10800;
    return iv;
}

static int trk_is_httpish(const char *url) {
    return url && (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0);
}

static void trk_sendto_ip(struct ntx_session *s, uint32_t ip, uint16_t port, const uint8_t *buf, size_t n) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = ip;
    sendto(s->trk_fd, buf, n, 0, (struct sockaddr *) &dst, sizeof dst);
}

/* The reply is matched by transaction id only, so the id must be unpredictable: a counter would let any
 * host that can send us a datagram forge tracker answers.  (The source address is checked too.) */
static int trk_find_pending(struct ntx_session *s, int32_t tid);
static int32_t trk_new_tid(struct ntx_session *s) {
    for (;;) {
        int32_t t = (int32_t)ntx_rand_u32();
        if (trk_find_pending(s, t) < 0) return t;
    }
}

static void trk_store_pending(struct ntx_session *s, int32_t tid, int tts_idx, int trk_idx, uint32_t ip,
                              uint16_t port) {
    for (int i = 0; i < NTX_TRK_PENDING; i++) {
        if (!s->trk_pending_used[i]) {
            s->trk_pending[i] = tid;
            s->trk_pending_tts[i] = tts_idx;
            s->trk_pending_trk[i] = trk_idx;
            s->trk_pending_ip[i] = ip;
            s->trk_pending_port[i] = port;
            s->trk_pending_t0[i] = ntx_mono_ms();
            s->trk_pending_used[i] = 1;
            return;
        }
    }
}

/* A reply only counts if it comes from the address the request went to. */
static int trk_find_pending_from(struct ntx_session *s, int32_t tid, uint32_t ip, uint16_t port) {
    for (int i = 0; i < NTX_TRK_PENDING; i++)
        if (s->trk_pending_used[i] && s->trk_pending[i] == tid && s->trk_pending_ip[i] == ip &&
            s->trk_pending_port[i] == port)
            return i;
    return -1;
}

static int trk_find_pending(struct ntx_session *s, int32_t tid) {
    for (int i = 0; i < NTX_TRK_PENDING; i++)
        if (s->trk_pending_used[i] && s->trk_pending[i] == tid) return i;
    return -1;
}

static uint64_t trk_left(const ntx_torrent *t) {
    if (!t->have_meta || t->size == 0) return UINT64_MAX; /* unknown size (magnet META) */
    if (t->verified_B >= t->size) return 0;
    return t->size - t->verified_B;
}

/* UDP trackers talk straight from our UDP socket: behind a SOCKS5 proxy or an NTX1 tunnel that would
 * leak the address the user is hiding, so those trackers are not used at all in that mode. */
static int trk_udp_blocked(const struct ntx_session *s) {
    return s->cfg && (s->cfg->proxy || s->cfg->tunnel);
}

static void trk_send_announce_one(struct ntx_session *s, int tts_idx, int trk_idx, int event) {
    if (trk_udp_blocked(s)) return;
    ntx_torrent *t = &s->tts[tts_idx];
    if (trk_idx < 0 || trk_idx >= s->trk_n[tts_idx]) return;
    if (trk_is_dead(s, tts_idx, trk_idx)) return;
    if (!s->trk_conn_done[tts_idx][trk_idx]) return;
    const char *url = s->trk_urls[tts_idx][trk_idx];
    if (strncmp(url, "udp://", 6) != 0) return;
    uint8_t req[98];
    uint32_t ip;
    uint16_t port;
    if (!trk_parse_udp(url, &ip, &port)) {
        trk_note_fail(s, tts_idx, trk_idx, "dns");
        return;
    }
    int32_t tid = trk_new_tid(s);
    ntx_tracker_udp_announce_build(req, s->trk_conn_id[tts_idx][trk_idx], tid,
                                   t->info_hash, s->peer_id, s->tts_down[tts_idx],
                                   trk_left(t), s->tts_up[tts_idx], event, s->trk_key,
                                   ntx_netx_port(s->netx));
    trk_store_pending(s, tid, tts_idx, trk_idx, ip, port);
    trk_sendto_ip(s, ip, port, req, 98);
}

static void trk_send_connect(struct ntx_session *s, int tts_idx, int trk_idx) {
    if (trk_udp_blocked(s)) return;
    if (trk_is_dead(s, tts_idx, trk_idx)) return;
    const char *url = s->trk_urls[tts_idx][trk_idx];
    if (strncmp(url, "udp://", 6) != 0) return;
    uint8_t req[16];
    uint32_t ip;
    uint16_t port;
    if (!trk_parse_udp(url, &ip, &port)) {
        trk_note_fail(s, tts_idx, trk_idx, "dns");
        return;
    }
    int32_t tid = trk_new_tid(s);
    ntx_tracker_udp_connect_build(req, tid);
    trk_store_pending(s, tid, tts_idx, trk_idx, ip, port);
    trk_sendto_ip(s, ip, port, req, 16);
}

static void w_udp(int fd, void *ctx) {
    ntx_session_trk_on_udp((struct ntx_session *) ctx, fd, ctx);
}

static void w_close(void *ctx) {
    ntx_session_trk_on_close((struct ntx_session *) ctx, ctx);
}

void ntx_session_trk_init(struct ntx_session *s) {
    s->trk_fd = ntx_sock_udp4();
    if (s->trk_fd < 0) return;
    ntx_sock_bind0(s->trk_fd);
    ntx_cbs cbs;
    cbs.r = w_udp;
    cbs.w = 0;
    cbs.cl = w_close;
    ntx_netx_add(s->netx, s->trk_fd, EPOLLIN, s, &cbs);
}

void ntx_session_trk_free(struct ntx_session *s) {
    if (s->trk_fd >= 0) {
        ntx_netx_del(s->netx, s->trk_fd);
        close(s->trk_fd);
        s->trk_fd = -1;
    }
}

static void trk_http_apply(struct ntx_session *s, int tts_idx, int trk_idx, const char *url,
                           const uint8_t *body, size_t bn);

static void trk_http_announce(struct ntx_session *s, int tts_idx, int trk_idx, const char *url, int event) {
    ntx_torrent *t = &s->tts[tts_idx];
    if (trk_is_dead(s, tts_idx, trk_idx)) return;
    static uint8_t tracker_id[8];
    char full[1600];
    size_t fn = ntx_tracker_http_url_build(full, sizeof full, url, t->info_hash, s->peer_id,
                                           ntx_netx_port(s->netx), s->tts_up[tts_idx],
                                           s->tts_down[tts_idx], trk_left(t), event,
                                           tracker_id, s->trk_key);
    if (!fn) {
        trk_note_fail(s, tts_idx, trk_idx, "url");
        if (s->cfg && s->cfg->verbose)
            ntx_diag( "ntx: trk http url overflow: %s\n", url);
        return;
    }
    uint8_t body[8192];
    size_t bn = 0;
    if (ntx_http_get(full, body, sizeof body, &bn) != 0) {
        trk_note_fail(s, tts_idx, trk_idx, "http");
        if (s->cfg && s->cfg->verbose)
            ntx_diag( "ntx: trk http connect fail: %s\n", url);
        return;
    }
    if (event == NTX_TRACKER_EVENT_STOPPED) return; /* goodbye: nothing in the reply is of use */
    trk_http_apply(s, tts_idx, trk_idx, url, body, bn);
}

/* Handle one HTTP tracker response body: schedule the next announce and feed the peers to the session. */
static void trk_http_apply(struct ntx_session *s, int tts_idx, int trk_idx, const char *url,
                           const uint8_t *body, size_t bn) {
    enum { MAX_PEERS = NTX_TRACKER_NUMWANT };
    uint8_t ips[MAX_PEERS * 4];
    uint16_t ports[MAX_PEERS];
    uint8_t ips6[MAX_PEERS][16];
    uint16_t ports6[MAX_PEERS];
    int32_t tid;
    uint32_t interval = 0, seeders = 0, leechers = 0;
    char err[128];
    /* The parser fills only as many slots as the response has peers; an entry with port 0 is "unused". */
    memset(ips, 0, sizeof ips);
    memset(ports, 0, sizeof ports);
    memset(ips6, 0, sizeof ips6);
    memset(ports6, 0, sizeof ports6);
    /* np = total (v4 + v6): it must not be used as the number of v4 slots. */
    int np = ntx_tracker_http_parse_ex(body, bn, &tid, &interval, &seeders, &leechers, ips, ports,
                                       MAX_PEERS, ips6, ports6, MAX_PEERS, err, sizeof err);
    if (np < 0) {
        trk_note_fail(s, tts_idx, trk_idx, "parse");
        if (s->cfg && s->cfg->verbose)
            ntx_diag( "ntx: trk http parse fail: %s (%s)\n", url, err);
        return;
    }
    trk_note_ok(s, tts_idx, trk_idx);
    interval = trk_interval_clamp(interval);
    s->trk_next[tts_idx] = ntx_mono_ms() + (uint64_t)interval * 1000;
    for (int k = 0; k < MAX_PEERS; k++) {
        uint32_t ip_net;
        memcpy(&ip_net, ips + (size_t)k * 4, 4);
        if (ip_net && ports[k]) {
            ntx_addr a;
            ntx_addr_set_v4(&a, ip_net);
            ntx_session_add_peer_from_tracker(s, tts_idx, &a, ports[k]);
        }
    }
    int n6 = 0;
    for (int k = 0; k < MAX_PEERS; k++) {
        if (!ports6[k]) continue;
        n6++;
        ntx_addr a;
        ntx_addr_set_v6(&a, ips6[k]);
        ntx_session_add_peer_from_tracker(s, tts_idx, &a, ports6[k]);
    }
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: trk http ok: %s peers=%d v6=%d\n", url, np, n6);
}

/* HTTP(S) trackers block the loop for as long as the server takes (seconds when it is dead), so while
 * UDP trackers are in use they go after them: the UDP replies normally deliver the first peers. */
#define TRK_HTTP_AFTER_UDP_MS 2500u
/* Resolving a tracker host costs a DoH round trip (~0.1 s) and blocks, so only this much work is done
 * per loop iteration; replies already sitting in the socket are then handled before the next batch. */
#define TRK_UDP_PUMP_BUDGET_MS 100u

void ntx_session_trk_announce(struct ntx_session *s, int tts_idx, int event) {
    ntx_torrent *t = &s->tts[tts_idx];
    if (t->state == NTX_TTS_DEAD || t->state == NTX_TTS_PAUSED) return;
    s->trk_http_event[tts_idx] = event;
    uint64_t now = ntx_mono_ms();
    int has_udp = 0;
    if (!trk_udp_blocked(s)) {
        for (int i = 0; i < s->trk_n[tts_idx]; i++)
            if (!trk_is_dead(s, tts_idx, i) && strncmp(s->trk_urls[tts_idx][i], "udp://", 6) == 0)
                has_udp = 1;
    }
    for (int i = 0; i < s->trk_n[tts_idx]; i++) {
        if (trk_is_dead(s, tts_idx, i)) continue;
        const char *url = s->trk_urls[tts_idx][i];
        if (trk_is_httpish(url)) {
            s->trk_http_pending[tts_idx][i] = 1;
            s->trk_http_due[tts_idx][i] = now + (uint64_t)(ntx_rand_u32() % 151) +
                                          (has_udp ? TRK_HTTP_AFTER_UDP_MS : 0);
        } else if (strncmp(url, "udp://", 6) == 0) {
            s->trk_udp_pending[tts_idx][i] = 1;
        }
    }
    if (s->trk_next[tts_idx] == 0)
        s->trk_next[tts_idx] = now + 15000;
}

void ntx_session_trk_pump_udp(struct ntx_session *s) {
    uint64_t now = ntx_mono_ms();
    uint64_t deadline = now + TRK_UDP_PUMP_BUDGET_MS;
    for (int tts_idx = 0; tts_idx < s->n_tts; tts_idx++) {
        ntx_torrent *t = &s->tts[tts_idx];
        for (int i = 0; i < s->trk_n[tts_idx]; i++) {
            if (!s->trk_udp_pending[tts_idx][i]) continue;
            s->trk_udp_pending[tts_idx][i] = 0;
            if (t->state == NTX_TTS_DEAD || t->state == NTX_TTS_PAUSED) continue;
            if (trk_is_dead(s, tts_idx, i)) continue;
            /* BEP15: connection id expires ~60s; refresh only live trackers. */
            if (s->trk_conn_done[tts_idx][i] && s->trk_conn_t0[tts_idx][i] &&
                now - s->trk_conn_t0[tts_idx][i] > 60000) {
                s->trk_conn_done[tts_idx][i] = 0;
            }
            if (!s->trk_conn_done[tts_idx][i])
                trk_send_connect(s, tts_idx, i);
            else
                trk_send_announce_one(s, tts_idx, i, s->trk_http_event[tts_idx]);
            now = ntx_mono_ms();
            if (now >= deadline) return;
        }
    }
}

void ntx_session_trk_pump_http(struct ntx_session *s, int max) {
    if (max <= 0) return;
    uint64_t now = ntx_mono_ms();
    for (int tts_idx = 0; tts_idx < s->n_tts && max > 0; tts_idx++) {
        ntx_torrent *t = &s->tts[tts_idx];
        if (t->state == NTX_TTS_DEAD || t->state == NTX_TTS_PAUSED) continue;
        for (int i = 0; i < s->trk_n[tts_idx] && max > 0; i++) {
            if (trk_is_dead(s, tts_idx, i)) {
                s->trk_http_pending[tts_idx][i] = 0;
                continue;
            }
            if (!s->trk_http_pending[tts_idx][i]) continue;
            if (s->trk_http_due[tts_idx][i] && now < s->trk_http_due[tts_idx][i]) continue;
            const char *url = s->trk_urls[tts_idx][i];
            if (!trk_is_httpish(url)) {
                s->trk_http_pending[tts_idx][i] = 0;
                continue;
            }
            s->trk_http_pending[tts_idx][i] = 0;
            s->trk_http_due[tts_idx][i] = 0;
            trk_http_announce(s, tts_idx, i, url, s->trk_http_event[tts_idx]);
            max--;
        }
    }
}

static void trk_retry_stale(struct ntx_session *s) {
    uint64_t now = ntx_mono_ms();
    for (int slot = 0; slot < NTX_TRK_PENDING; slot++) {
        if (!s->trk_pending_used[slot]) continue;
        if (now - s->trk_pending_t0[slot] < 8000) continue;
        int tts_idx = s->trk_pending_tts[slot];
        int trk_idx = s->trk_pending_trk[slot];
        s->trk_pending_used[slot] = 0;
        if (tts_idx < 0 || trk_idx < 0 || tts_idx >= s->n_tts) continue;
        if (trk_idx >= s->trk_n[tts_idx]) continue;
        const char *url = s->trk_urls[tts_idx][trk_idx];
        if (strncmp(url, "udp://", 6) != 0) continue;
        /* Timeout = one strike; do not silently retry forever. */
        trk_note_fail(s, tts_idx, trk_idx, "timeout");
        if (trk_is_dead(s, tts_idx, trk_idx)) continue;
        if (s->trk_conn_done[tts_idx][trk_idx])
            trk_send_announce_one(s, tts_idx, trk_idx, s->trk_http_event[tts_idx]);
        else
            trk_send_connect(s, tts_idx, trk_idx);
    }
}

/* Budget for all the goodbye announces together: a dead tracker must not make Ctrl+C hang. */
#define NTX_TRK_STOP_BUDGET_MS 3000u

static void trk_stop_one(struct ntx_session *s, int tts_idx, uint64_t deadline) {
    if (tts_idx < 0 || tts_idx >= s->n_tts) return;
    ntx_torrent *t = &s->tts[tts_idx];
    if (t->state != NTX_TTS_META && t->state != NTX_TTS_DL && t->state != NTX_TTS_DONE) return;
    s->trk_http_event[tts_idx] = NTX_TRACKER_EVENT_STOPPED;
    for (int i = 0; i < s->trk_n[tts_idx] && i < NTX_SESSION_MAX_TRK; i++) {
        s->trk_http_pending[tts_idx][i] = 0; /* a queued regular announce is pointless now */
        if (trk_is_dead(s, tts_idx, i) || s->trk_fail[tts_idx][i] != 0) continue; /* never answered */
        if (ntx_mono_ms() >= deadline) continue;
        const char *url = s->trk_urls[tts_idx][i];
        if (trk_is_httpish(url))
            trk_http_announce(s, tts_idx, i, url, NTX_TRACKER_EVENT_STOPPED);
        else if (strncmp(url, "udp://", 6) == 0 && s->trk_conn_done[tts_idx][i] && !trk_udp_blocked(s))
            trk_send_announce_one(s, tts_idx, i, NTX_TRACKER_EVENT_STOPPED); /* fire and forget */
    }
}

void ntx_session_trk_stop(struct ntx_session *s, int tts_idx) {
    trk_stop_one(s, tts_idx, ntx_mono_ms() + NTX_TRK_STOP_BUDGET_MS);
}

void ntx_session_trk_stop_all(struct ntx_session *s) {
    uint64_t deadline = ntx_mono_ms() + NTX_TRK_STOP_BUDGET_MS;
    for (int i = 0; i < s->n_tts; i++) trk_stop_one(s, i, deadline);
}

void ntx_session_trk_tick(struct ntx_session *s) {
    trk_retry_stale(s);
    ntx_session_trk_pump_udp(s);
    ntx_session_trk_pump_http(s, 1);
    uint64_t now = ntx_mono_ms();
    for (int i = 0; i < s->n_tts; i++) {
        if (s->tts_ratio_done[i]) continue;
        if (s->tts[i].state != NTX_TTS_META && s->tts[i].state != NTX_TTS_DL &&
            s->tts[i].state != NTX_TTS_DONE)
            continue;
        if (s->trk_next[i] && now >= s->trk_next[i])
            ntx_session_trk_announce(s, i, NTX_TRACKER_EVENT_NONE);
    }
}

void ntx_session_trk_boost_peers(struct ntx_session *s) {
    uint64_t now = ntx_mono_ms();
    for (int i = 0; i < s->n_tts; i++) {
        if (s->tts_ratio_done[i]) continue;
        if (s->tts[i].state != NTX_TTS_META && s->tts[i].state != NTX_TTS_DL &&
            s->tts[i].state != NTX_TTS_DONE)
            continue;
        int ok = 0, un = 0, hs = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_tts[pi] != i || s->peers[pi].fd == -1) continue;
            if (s->peer_phase[pi] == PH_OK) {
                ok++;
                if (ntx_peer_can_download(&s->peers[pi])) un++;
            } else
                hs++;
        }
        if (s->tts[i].state == NTX_TTS_DONE) {
            /* Seeding: need peer connections, not download unchokes. */
            if (ok >= NTX_MIN_OK_PEERS) continue;
            if (ok == 0)
                ntx_session_peer_cull_stale(s, 8, 20000);
            uint64_t boost_at = now + (ok == 0 ? NTX_TRK_BOOST_URGENT_MS : NTX_TRK_BOOST_LOW_UN_MS);
            if (s->trk_next[i] > now + NTX_TRK_BOOST_MAX_WAIT_MS || s->trk_next[i] > boost_at)
                s->trk_next[i] = boost_at;
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: trk boost seed tts=%d ok=%d hs=%d next=%llums\n", i, ok, hs,
                        (unsigned long long)(s->trk_next[i] > now ? s->trk_next[i] - now : 0));
            continue;
        }
        /*
         * Only re-announce when we lack peer *connections*. Low unchoke with many
         * OK peers is a swarm/protocol issue — hammering dead trackers only stalls DL.
         */
        if (ok >= NTX_MIN_OK_PEERS) {
            if (ok >= NTX_MIN_OK_PEERS && un < NTX_MIN_UNCHOKED && hs > 50)
                ntx_session_peer_cull_stale(s, 4, 20000);
            continue;
        }
        if (ok == 0)
            ntx_session_peer_cull_stale(s, 8, 20000);
        {
            uint64_t boost_at = now + (ok == 0 ? NTX_TRK_BOOST_URGENT_MS : NTX_TRK_BOOST_LOW_UN_MS);
            if (s->trk_next[i] > now + NTX_TRK_BOOST_MAX_WAIT_MS || s->trk_next[i] > boost_at)
                s->trk_next[i] = boost_at;
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: trk boost tts=%d ok=%d un=%d hs=%d next=%llums\n", i, ok, un, hs,
                        (unsigned long long)(s->trk_next[i] > now ? s->trk_next[i] - now : 0));
        }
    }
}

void ntx_session_trk_on_udp(struct ntx_session *s, int fd, void *ctx) {
    (void)ctx;
    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_in from;
        socklen_t flen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            return;
        }
        if (n < 4) return;
        if (flen < sizeof(struct sockaddr_in) || from.sin_family != AF_INET) continue;
        uint32_t from_ip = from.sin_addr.s_addr;
        uint16_t from_port = ntohs(from.sin_port);
        uint32_t action = ntx_wire_rd32(buf);
        if (action == NTX_TRACKER_ACTION_CONNECT) {
            int32_t tid;
            uint64_t cid;
            if (ntx_tracker_udp_connect_parse(buf, (size_t)n, &tid, &cid) != 0) continue;
            int slot = trk_find_pending_from(s, tid, from_ip, from_port);
            if (slot < 0) continue;
            int tts_idx = s->trk_pending_tts[slot];
            int trk_idx = s->trk_pending_trk[slot];
            s->trk_pending_used[slot] = 0;
            if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) continue;
            if (trk_idx < 0 || trk_idx >= NTX_SESSION_MAX_TRK) continue;
            if (trk_is_dead(s, tts_idx, trk_idx)) continue;
            trk_note_ok(s, tts_idx, trk_idx);
            s->trk_conn_done[tts_idx][trk_idx] = 1;
            s->trk_conn_id[tts_idx][trk_idx] = cid;
            s->trk_conn_t0[tts_idx][trk_idx] = ntx_mono_ms();
            trk_send_announce_one(s, tts_idx, trk_idx, s->trk_http_event[tts_idx]);
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: trk udp connect tts=%d trk=%d\n", tts_idx, trk_idx);
        } else if (action == NTX_TRACKER_ACTION_ANNOUNCE) {
            int32_t tid;
            uint32_t interval, leech, seed;
            uint8_t ips[NTX_TRACKER_NUMWANT * 4];
            uint16_t ports[NTX_TRACKER_NUMWANT];
            uint8_t ips6[NTX_TRACKER_NUMWANT][16];
            uint16_t ports6[NTX_TRACKER_NUMWANT];
            int n6 = 0;
            int np = ntx_tracker_udp_announce_parse_ex(buf, (size_t)n, &tid, &interval, &leech,
                                                       &seed, ips, ports, NTX_TRACKER_NUMWANT, NULL,
                                                       ips6, ports6, NTX_TRACKER_NUMWANT, &n6);
            if (np < 0) np = 0;
            int slot = trk_find_pending_from(s, tid, from_ip, from_port);
            if (slot < 0) continue;
            int tts_idx = s->trk_pending_tts[slot];
            int trk_idx = s->trk_pending_trk[slot];
            s->trk_pending_used[slot] = 0;
            if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) continue;
            if (trk_idx >= 0 && trk_idx < NTX_SESSION_MAX_TRK)
                trk_note_ok(s, tts_idx, trk_idx);
            interval = trk_interval_clamp(interval);
            s->trk_interval[tts_idx] = interval;
            s->trk_next[tts_idx] = ntx_mono_ms() + (uint64_t)interval * 1000;
            for (int j = 0; j < np; j++) {
                uint32_t ip_net;
                memcpy(&ip_net, ips + (size_t)j * 4, 4);
                if (ip_net && ports[j]) {
                    ntx_addr a;
                    ntx_addr_set_v4(&a, ip_net);
                    ntx_session_add_peer_from_tracker(s, tts_idx, &a, ports[j]);
                }
            }
            for (int j = 0; j < n6; j++) {
                if (!ports6[j]) continue;
                ntx_addr a;
                ntx_addr_set_v6(&a, ips6[j]);
                ntx_session_add_peer_from_tracker(s, tts_idx, &a, ports6[j]);
            }
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: trk udp announce tts=%d peers=%d v6=%d interval=%u\n",
                        tts_idx, np, n6, interval);
        } else if (action == NTX_TRACKER_ACTION_ERROR) {
            if (n < 8) continue;
            int32_t tid = (int32_t)ntx_wire_rd32(buf + 4);
            int slot = trk_find_pending_from(s, tid, from_ip, from_port);
            if (slot >= 0) {
                int tts_idx = s->trk_pending_tts[slot];
                int trk_idx = s->trk_pending_trk[slot];
                s->trk_pending_used[slot] = 0;
                trk_note_fail(s, tts_idx, trk_idx, "udp-err");
                if (s->cfg && s->cfg->verbose) {
                    size_t elen = (n > 8) ? (size_t)n - 8 : 0;
                    if (elen > 80) elen = 80;
                    ntx_diag( "ntx: trk udp error tts=%d len=%zu: %.*s\n", tts_idx, elen, (int)elen,
                            buf + 8);
                }
            }
        }
    }
}

void ntx_session_trk_on_close(struct ntx_session *s, void *ctx) {
    (void) ctx;
    if (s->trk_fd >= 0) {
        close(s->trk_fd);
        s->trk_fd = -1;
    }
}
