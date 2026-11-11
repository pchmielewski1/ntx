#include "ntx_session_internal.h"
#include "../net/ntx_netx.h"
#include "../net/ntx_sock.h"
#include "../proto/ntx_pcp.h"
#include "../crypto/ntx_rng.h"
#include "../ui/ntx_diag.h"
#include "ntx_time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>

/* PCP (RFC 6887) with a NAT-PMP (RFC 6886) fallback for shares (design §8), on
 * the existing ntx_netx loop, non-blocking, no threads. The codec in
 * src/proto/ntx_pcp.c is deliberately stateless, so every policy lives here: the
 * socket and its gateway-source check, the 12-byte nonce, the retransmission
 * schedule, the lifetime cap (RFC 6887 §8.3) and the epoch-rollback check
 * (§8.5). Everything static here is pm_-prefixed for the unity build. */

#define PM_LIFE_S 7200u  /* §8: ask for two hours, renew at half the grant */
#define PM_PROBE_MS 250u /* RFC 6887 §8.1.1: first retry, then doubled … */
#define PM_MAX_TRIES 9u  /* … at most nine sends per query, hard cap */
#define PM_RX_BUDGET 8   /* datagrams handled per read callback */

/* One outstanding query at a time, in this order. The NAT-PMP external-address
 * query exists only in the fallback: it is how CGNAT is found without PCP. */
enum { PM_PH_ADDR = 0, PM_PH_TCP, PM_PH_UDP, PM_NPH };
enum { PM_PCP = 0, PM_NATPMP = 1 };

struct ntx_portmap {
    ntx_netx *netx;
    const ntx_config *cfg;
    int fd;                   /* UDP socket connected to gateway:5351, -1 = closed */
    ntx_pm_state st;
    int want;                 /* mapping requested; the tick is what starts anything */
    int started;              /* the route was read and the socket opened */
    int gave_up;              /* permanently no for this sequence: stay quiet */
    int fam;                  /* PM_PCP, or PM_NATPMP after UNSUPP_VERSION */
    int addr_done;            /* NAT-PMP external address answered */
    int phase;                /* outstanding query, -1 = none */
    int tries;                /* sends made for the outstanding query */
    uint32_t gap;             /* interval before the next retransmission, ms */
    uint64_t next_try;        /* virtual ms of the next retransmission */
    uint32_t gw;              /* default-route gateway, network order */
    uint8_t client_ip[16];    /* our address on that route, IPv4-mapped */
    uint8_t req[60];
    size_t reqlen;
    uint8_t nonce[12];               /* of the outstanding query */
    uint8_t grant_nonce[PM_NPH][12]; /* the nonce each grant was made with (§11.1) */
    uint8_t proto;                   /* of the outstanding MAP query */
    uint16_t iport;                  /* internal port of the outstanding MAP query */
    int active[PM_NPH];
    int failed[PM_NPH];       /* this query exhausted its retries */
    uint16_t ext[PM_NPH];
    uint64_t renew_at[PM_NPH]; /* virtual ms */
    uint32_t epoch;
    int epoch_seen;            /* 0 until the first PCP answer: no baseline */
};

/* Process globals because the test hooks take no session. Production never sets
 * them, and only one session at a time ever owns a driver. */
static uint64_t pm_voff;
static const char *pm_route4_path;
static const char *pm_route6_path;
static uint16_t pm_gw_port_cfg;
static int pm_cgnat_warned;

void ntx_portmap_test_set_route_files(const char *v4, const char *v6) {
    pm_route4_path = (v4 && *v4) ? v4 : NULL;
    pm_route6_path = (v6 && *v6) ? v6 : NULL;
}

void ntx_portmap_test_set_gateway_port(uint16_t port) { pm_gw_port_cfg = port; }

void ntx_portmap_test_advance_ms(uint64_t ms) { pm_voff += ms; }

static uint16_t pm_gw_port(void) { return pm_gw_port_cfg ? pm_gw_port_cfg : NTX_PCP_PORT; }

static uint64_t pm_now(void) { return ntx_mono_ms() + pm_voff; }

/* ---- default route (design §8: /proc/net/route, /proc/net/ipv6_route) ---- */

static int pm_hex32(const char *tok, uint32_t *out) {
    char *end = NULL;
    if (!tok || !*tok) return 0;
    unsigned long v = strtoul(tok, &end, 16);
    if (!end || *end) return 0;
    *out = (uint32_t)v;
    return 1;
}

static int pm_nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* /proc/net/route: "Iface Destination Gateway Flags RefCnt Use Metric Mask …",
 * the addresses as host-byte-order hex. Lowest-metric 0.0.0.0/0 via a gateway. */
static int pm_route4(uint32_t *gw_net) {
    FILE *f = fopen(pm_route4_path ? pm_route4_path : "/proc/net/route", "r");
    if (!f) return 0;
    char line[512], iface[64], dst[32], gw[32], mask[32];
    int found = 0;
    unsigned best = 0;
    uint32_t best_gw = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned flags, refcnt, use, metric;
        if (sscanf(line, "%63s %31s %31s %u %u %u %u %31s", iface, dst, gw, &flags, &refcnt, &use, &metric,
                   mask) != 8)
            continue;
        uint32_t d, g, m;
        if (!pm_hex32(dst, &d) || !pm_hex32(gw, &g) || !pm_hex32(mask, &m)) continue;
        if (d != 0 || m != 0 || g == 0) continue;
        if (!found || metric < best) {
            found = 1;
            best = metric;
            best_gw = g;
        }
    }
    fclose(f);
    /* The printed hex is the raw u32 the kernel holds, i.e. already in network
     * order for sin_addr — strtoul's value goes in as it stands (no htonl). */
    if (found) *gw_net = best_gw;
    return found;
}

/* The ::/0 line of /proc/net/ipv6_route whose nexthop is IPv4-mapped — the only
 * v6-route form a UDP mapping to a v4 gateway can use. Both 32-hex fields are
 * printed in network order. */
static int pm_route6_line(const char *line, uint32_t *gw_net, unsigned *metric_out) {
    char dst[40], src[40], nh[40], iface[64];
    unsigned dpl, spl, hops, mtu, ref, metric, flags;
    if (sscanf(line, "%39s %x %39s %x %39s %u %u %u %u %u %63s", dst, &dpl, src, &spl, nh, &hops, &mtu, &ref,
               &metric, &flags, iface) != 11)
        return 0;
    if (dpl != 0 || strlen(dst) != 32 || strlen(nh) != 32) return 0;
    uint8_t d[16], n[16];
    for (int i = 0; i < 16; i++) {
        int hi = pm_nib(dst[2 * i]), lo = pm_nib(dst[2 * i + 1]);
        int h2 = pm_nib(nh[2 * i]), l2 = pm_nib(nh[2 * i + 1]);
        if (hi < 0 || lo < 0 || h2 < 0 || l2 < 0) return 0;
        d[i] = (uint8_t)((hi << 4) | lo);
        n[i] = (uint8_t)((h2 << 4) | l2);
    }
    for (int i = 0; i < 16; i++)
        if (d[i]) return 0;
    for (int i = 0; i < 10; i++)
        if (n[i]) return 0;
    if (n[10] != 0xff || n[11] != 0xff) return 0;
    if (n[12] == 0 && n[13] == 0) return 0; /* ::ffff:0.0.0.0 is not a gateway */
    memcpy(gw_net, n + 12, 4);
    *metric_out = metric;
    return 1;
}

static int pm_route6(uint32_t *gw_net) {
    FILE *f = fopen(pm_route6_path ? pm_route6_path : "/proc/net/ipv6_route", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    unsigned best = 0;
    uint32_t gw = 0;
    while (fgets(line, sizeof line, f)) {
        uint32_t g;
        unsigned metric;
        if (!pm_route6_line(line, &g, &metric)) continue;
        if (!found || metric < best) {
            found = 1;
            best = metric;
            gw = g;
        }
    }
    fclose(f);
    if (found) *gw_net = gw;
    return found;
}

static void pm_widen4(uint8_t out16[16], uint32_t ip_net) {
    memset(out16, 0, 16);
    out16[10] = 0xff;
    out16[11] = 0xff;
    memcpy(out16 + 12, &ip_net, 4);
}

/* 1 for an address that cannot sit behind a NAT box: a global next hop, or our own
 * source address on the default route. Either one means there is no private
 * address to map, so no mapping is made (§8). Loopback, link-local, RFC 1918,
 * CGNAT, ULA and the reserved ranges all count as the private side. */
static int pm_is_global(uint32_t ip_net) {
    uint8_t w[16];
    pm_widen4(w, ip_net);
    if (pcp_ip_is_cgnat_or_private(w)) return 0;
    const uint8_t a = w[12], b = w[13];
    if (a == 0 || a == 127) return 0;   /* this host / loopback */
    if (a == 169 && b == 254) return 0; /* link-local */
    if (a >= 224) return 0;             /* multicast and reserved */
    return 1;
}

/* ---- driver ---- */

static struct ntx_portmap *pm_alloc(struct ntx_session *s) {
    if (s->pm) return s->pm;
    struct ntx_portmap *pm = calloc(1, sizeof *pm);
    if (!pm) return NULL;
    pm->fd = -1;
    pm->phase = -1;
    pm->netx = s->netx;
    pm->cfg = s->cfg;
    s->pm = pm;
    return pm;
}

static void pm_close_sock(struct ntx_portmap *pm) {
    if (pm->fd < 0) return;
    ntx_netx_del(pm->netx, pm->fd);
    close(pm->fd);
    pm->fd = -1;
}

static void pm_clear_grants(struct ntx_portmap *pm) {
    for (int i = 0; i < PM_NPH; i++) {
        pm->active[i] = 0;
        pm->ext[i] = 0;
        pm->renew_at[i] = 0;
    }
}

static void pm_reset(struct ntx_portmap *pm, ntx_pm_state st) {
    pm_close_sock(pm);
    pm_clear_grants(pm);
    for (int i = 0; i < PM_NPH; i++) pm->failed[i] = 0;
    pm->phase = -1;
    pm->tries = 0;
    pm->started = 0;
    pm->gave_up = 0;
    pm->addr_done = 0;
    pm->epoch_seen = 0;
    pm->st = st;
}

/* §8: the diagnosis is stated once per process, never per retry. */
static void pm_warn_cgnat(void) {
    if (pm_cgnat_warned) return;
    pm_cgnat_warned = 1;
    ntx_diag("ntx: port mapping will not help: the ISP uses CGNAT\n");
}

/* RFC 6887 §8.3: a client SHOULD cap an absurd lifetime. The codec hands the grant
 * back verbatim precisely because the cap is a session policy, so it is ours. */
static uint32_t pm_cap_life(uint32_t granted) { return granted > PM_LIFE_S ? PM_LIFE_S : granted; }

static int pm_udp_wanted(const struct ntx_portmap *pm) { return pm->cfg && pm->cfg->utp; }

static uint8_t pm_op_of(int phase) { return (uint8_t)(phase == PM_PH_UDP ? 1 : 2); }

static void pm_build(struct ntx_portmap *pm, int phase, uint32_t lifetime, uint16_t sugg_port) {
    uint16_t lp = ntx_netx_port(pm->netx);
    pm->iport = lp;
    pm->phase = phase;
    if (phase == PM_PH_ADDR) {
        pm->reqlen = natpmp_build_addr(pm->req);
        return;
    }
    pm->proto = (uint8_t)(phase == PM_PH_TCP ? NTX_PCP_PROTO_TCP : NTX_PCP_PROTO_UDP);
    if (pm->fam == PM_PCP)
        pm->reqlen = pcp_build_map(pm->req, pm->client_ip, pm->nonce, pm->proto, lp, sugg_port, lifetime);
    else
        pm->reqlen = natpmp_build_map(pm->req, pm_op_of(phase), lp, sugg_port, lifetime);
}

static void pm_send(struct ntx_portmap *pm) {
    if (pm->fd < 0) return;
    /* A connected UDP socket reports only the peer's ICMP trouble; whatever the
     * answer, the retransmission schedule gets the next say. */
    (void)send(pm->fd, pm->req, pm->reqlen, 0);
    pm->tries++;
    pm->next_try = pm_now() + pm->gap;
    pm->gap *= 2;
}

/* Start a query from scratch: fresh nonce, fresh schedule, sent now. */
static void pm_start_query(struct ntx_portmap *pm, int phase, uint16_t sugg_port) {
    if (phase < 0 || pm->fd < 0) return;
    if (phase != PM_PH_ADDR) ntx_rand_bytes(pm->nonce, sizeof pm->nonce);
    pm->tries = 0;
    pm->gap = PM_PROBE_MS;
    pm_build(pm, phase, PM_LIFE_S, sugg_port);
    if (phase != PM_PH_ADDR) memcpy(pm->grant_nonce[phase], pm->nonce, sizeof pm->nonce);
    pm_send(pm);
}

/* RFC 6887 §11.1: a mapping is deleted with the same nonce and lifetime 0. One
 * datagram per live mapping, no waiting: stop() runs inside the 3 s close budget,
 * so deletes are fire-and-forget like the stopped announce. */
static void pm_send_deletes(struct ntx_portmap *pm) {
    if (pm->fd < 0) return;
    uint16_t lp = ntx_netx_port(pm->netx);
    uint8_t buf[60];
    for (int ph = PM_PH_TCP; ph < PM_NPH; ph++) {
        if (!pm->active[ph]) continue;
        size_t n;
        if (pm->fam == PM_PCP) {
            uint8_t proto = (uint8_t)(ph == PM_PH_TCP ? NTX_PCP_PROTO_TCP : NTX_PCP_PROTO_UDP);
            n = pcp_build_map(buf, pm->client_ip, pm->grant_nonce[ph], proto, lp, pm->ext[ph], 0);
        } else {
            n = natpmp_build_map(buf, pm_op_of(ph), lp, pm->ext[ph], 0);
        }
        if (send(pm->fd, buf, n, 0) < 0) break;
    }
}

static void pm_grant(struct ntx_portmap *pm, int phase, uint16_t ext_port, uint32_t life) {
    pm->active[phase] = 1;
    pm->failed[phase] = 0;
    pm->ext[phase] = ext_port;
    pm->renew_at[phase] = pm_now() + (uint64_t)(life / 2) * 1000u;
    pm->phase = -1;
    pm->tries = 0;
    if (pm->active[PM_PH_TCP]) pm->st = NTX_PM_ACTIVE; /* §8: announces carry the ext port */
}

/* The gateway says the mapping is gone (lifetime 0), or rebooted (epoch went
 * backwards, RFC 6887 §8.5): drop every grant and establish it again. */
static void pm_lost(struct ntx_portmap *pm) {
    pm_clear_grants(pm);
    for (int i = 0; i < PM_NPH; i++) pm->failed[i] = 0;
    pm->gave_up = 0;
    pm->phase = -1;
    pm->tries = 0;
    pm->st = NTX_PM_PENDING;
    pm_start_query(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
}

static void pm_cgnat(struct ntx_portmap *pm) {
    pm_clear_grants(pm);
    pm->phase = -1;
    pm->tries = 0;
    pm->gave_up = 1; /* §8: no workaround, no retries — the state is the answer */
    pm->st = NTX_PM_CGNAT;
    pm_warn_cgnat();
}

/* §8: only a datagram from the gateway itself, on the port we asked, is parsed.
 * The connect() already filters this in the kernel; the check stays because a
 * connected socket is not the security boundary, the source test is. */
static int pm_src_ok(const struct ntx_portmap *pm, const struct sockaddr_in *sa) {
    if (sa->sin_family != AF_INET) return 0;
    if (sa->sin_addr.s_addr != pm->gw) return 0;
    return ntohs(sa->sin_port) == pm_gw_port();
}

static void pm_rx(struct ntx_portmap *pm, const uint8_t *b, size_t n) {
    int ph = pm->phase;
    if (ph < 0) return; /* nothing outstanding: nothing to match an answer against */

    if (pm->fam == PM_PCP) {
        ntx_pcp_map_resp r;
        int rc = pcp_parse_map(b, n, pm->nonce, pm->proto, pm->iport, &r);
        if (rc == 1) { /* version mismatch: RFC 6886 is all this gateway speaks */
            pm->fam = PM_NATPMP;
            pm->addr_done = 0;
            pm_start_query(pm, PM_PH_ADDR, 0);
            return;
        }
        if (rc != 0) return; /* -1 garbage, -2 not an answer to our query */
        if (pm->epoch_seen && r.epoch < pm->epoch) {
            pm_lost(pm);
            return;
        }
        pm->epoch_seen = 1;
        pm->epoch = r.epoch;
        uint32_t life = pm_cap_life(r.lifetime);
        if (life == 0) {
            pm_lost(pm);
            return;
        }
        if (pcp_ip_is_cgnat_or_private(r.ext_ip16)) {
            pm_cgnat(pm);
            return;
        }
        pm_grant(pm, ph, r.ext_port, life);
        return;
    }

    if (ph == PM_PH_ADDR) {
        uint8_t ip4[4];
        if (natpmp_parse_addr(b, n, ip4) != 0) return;
        uint32_t net;
        memcpy(&net, ip4, 4);
        uint8_t wide[16];
        pm_widen4(wide, net);
        if (pcp_ip_is_cgnat_or_private(wide)) {
            pm_cgnat(pm);
            return;
        }
        pm->addr_done = 1;
        pm->phase = -1;
        pm->tries = 0;
        pm_start_query(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
        return;
    }

    uint16_t ext = 0;
    uint32_t life = 0;
    if (natpmp_parse_map(b, n, pm_op_of(ph), pm->iport, &ext, &life) != 0) return;
    life = pm_cap_life(life);
    if (life == 0) {
        pm_lost(pm);
        return;
    }
    pm_grant(pm, ph, ext, life);
}

static void pm_on_rw(int fd, void *ctx) {
    struct ntx_portmap *pm = (struct ntx_portmap *)ctx;
    for (int i = 0; i < PM_RX_BUDGET; i++) {
        uint8_t buf[1200];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) return;
        if (pm_src_ok(pm, &from)) pm_rx(pm, buf, (size_t)n);
    }
}

/* Read the route, judge whether mapping makes sense, open the gateway socket.
 * Returns 0 when the answer is permanently no (no route, or no NAT in the way). */
static int pm_open(struct ntx_portmap *pm) {
    pm->started = 1;
    uint32_t gw = 0;
    int have = pm_route4(&gw);
    if (!have) have = pm_route6(&gw);
    if (!have) {
        pm->st = NTX_PM_NONE;
        pm->gave_up = 1;
        return 0;
    }
    pm->gw = gw;
    if (pm_is_global(gw)) { /* next hop is no private gateway: nothing to traverse */
        pm->st = NTX_PM_OFF;
        pm->gave_up = 1;
        return 0;
    }
    int fd = ntx_sock_udp4();
    if (fd < 0 || ntx_sock_connect4(fd, gw, pm_gw_port()) != 0) {
        if (fd >= 0) close(fd);
        pm->st = NTX_PM_NONE;
        pm->gave_up = 1;
        return 0;
    }
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    memset(&me, 0, sizeof me);
    if (getsockname(fd, (struct sockaddr *)&me, &ml) == 0 && me.sin_family == AF_INET) {
        pm_widen4(pm->client_ip, me.sin_addr.s_addr);
        if (pm_is_global(me.sin_addr.s_addr)) { /* §8: a public address means no NAT */
            close(fd);
            pm->st = NTX_PM_OFF;
            pm->gave_up = 1;
            return 0;
        }
    }
    /* No close callback on purpose: an ICMP error for a datagram the gateway never
     * answered raises EPOLLERR on a connected UDP socket, and that is a soft error
     * the retransmission schedule already covers. */
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = pm_on_rw;
    pm->fd = fd;
    pm->fam = PM_PCP;
    pm->st = NTX_PM_PENDING;
    ntx_netx_add(pm->netx, fd, EPOLLIN, pm, &cbs);
    return 1;
}

static void pm_stop_now(struct ntx_portmap *pm) {
    if (pm->fd >= 0 && (pm->active[PM_PH_TCP] || pm->active[PM_PH_UDP])) pm_send_deletes(pm);
    pm_reset(pm, NTX_PM_OFF);
}

/* A query that ran out of retries: §8 "brak odpowiedzi bramy … oznacza status
 * „brak" i dalsze działanie bez mapowania". A failed TCP mapping takes UDP with it
 * (a gateway that will not map TCP will not map UDP either); a failed UDP mapping
 * must not disturb the live TCP one. */
static void pm_give_up_phase(struct ntx_portmap *pm, int ph) {
    pm->failed[ph] = 1;
    if (ph != PM_PH_UDP) pm->failed[PM_PH_UDP] = 1;
    if (ph == PM_PH_ADDR) {
        pm->failed[PM_PH_TCP] = 1;
        pm->failed[PM_PH_UDP] = 1;
    }
    if (!pm->active[PM_PH_TCP] && !pm->active[PM_PH_UDP]) {
        pm->st = NTX_PM_NONE;
        pm->gave_up = 1;
    }
}

/* ---- public API (ntx_session_portmap.h) ---- */

void ntx_session_portmap_want(struct ntx_session *s, int on) {
    const ntx_config *c = s->cfg;
    if (!c) return;
    /* §8: never under a proxy or a tunnel — inbound traffic would bypass it and the
     * mapping would reveal the address the user is hiding. */
    int enabled = !(c->proxy || c->tunnel) && (c->port_map == 1 || (on && c->port_map >= 0));
    if (!enabled) {
        if (s->pm) {
            pm_stop_now(s->pm);
            s->pm->want = 0;
        }
        return;
    }
    struct ntx_portmap *pm = pm_alloc(s);
    if (!pm) return;
    pm->netx = s->netx;
    pm->cfg = c;
    if (!pm->want) { /* fresh request, fresh sequence (retries and CGNAT verdict too) */
        pm->want = 1;
        pm_reset(pm, NTX_PM_OFF);
    }
}

void ntx_session_portmap_tick(struct ntx_session *s) {
    struct ntx_portmap *pm = s->pm;
    if (!pm || !pm->want) return;
    pm->netx = s->netx;
    pm->cfg = s->cfg;
    if (s->cfg && (s->cfg->proxy || s->cfg->tunnel)) {
        pm_reset(pm, NTX_PM_OFF);
        return;
    }
    if (!pm->started && !pm_open(pm)) return;
    if (pm->fd < 0) return;

    uint64_t now = pm_now();
    if (pm->phase >= 0) {
        if (now < pm->next_try) return;
        int ph = pm->phase;
        if ((uint32_t)pm->tries >= PM_MAX_TRIES) {
            pm->phase = -1;
            pm_give_up_phase(pm, ph);
            return;
        }
        pm_send(pm);
        return;
    }
    if (pm->gave_up) return;

    for (int i = 0; i < PM_NPH; i++)
        if (pm->active[i] && !pm->failed[i] && now >= pm->renew_at[i]) {
            pm_start_query(pm, i, pm->ext[i]); /* keep the granted port across renewals */
            return;
        }
    if (pm->fam == PM_NATPMP && !pm->addr_done && !pm->failed[PM_PH_ADDR]) {
        pm_start_query(pm, PM_PH_ADDR, 0);
        return;
    }
    if (!pm->active[PM_PH_TCP] && !pm->failed[PM_PH_TCP]) {
        pm_start_query(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
        return;
    }
    if (pm_udp_wanted(pm) && !pm->active[PM_PH_UDP] && !pm->failed[PM_PH_UDP])
        pm_start_query(pm, PM_PH_UDP, ntx_netx_port(pm->netx));
}

void ntx_session_portmap_stop(struct ntx_session *s) {
    struct ntx_portmap *pm = s->pm;
    if (!pm) return;
    pm_stop_now(pm);
    free(pm);
    s->pm = NULL;
}

ntx_pm_state ntx_session_portmap_state(const struct ntx_session *s) {
    return s->pm ? s->pm->st : NTX_PM_OFF;
}

uint16_t ntx_session_adv_port(const struct ntx_session *s) {
    const struct ntx_portmap *pm = s->pm;
    if (pm && pm->st == NTX_PM_ACTIVE && pm->active[PM_PH_TCP] && pm->ext[PM_PH_TCP])
        return pm->ext[PM_PH_TCP];
    return ntx_netx_port(s->netx);
}
