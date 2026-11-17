#include "ntx_session_internal.h"
#include "../net/ntx_netx.h"
#include "../net/ntx_sock.h"
#include "../proto/ntx_pcp.h"
#include "../crypto/ntx_rng.h"
#include "../ui/ntx_diag.h"
#include "ntx_time.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
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
 * schedule, the lifetime cap (RFC 6887 §8.3) and the restart test of §8.5.
 * Everything static here is pm_-prefixed for the unity build. */

#define PM_LIFE_S 7200u /* §8: ask for two hours, renew at half the grant */
/* Retransmission pacing, per family. RFC 6887 §8.1.1: IRT 3 s, doubled per
 * retransmission up to MRT 1024 s, each interval jittered by ±10%. RFC 6886 §3.1:
 * 250 ms, doubled, nine attempts, no jitter and no MRT — nine sends from 250 ms
 * end at 64 s, so the attempt cap is what stops NAT-PMP. (The one pair of
 * constants this file used before was the NAT-PMP schedule labelled RFC 6887 —
 * R11.) */
#define PM_PCP_IRT_MS 3000u     /* RFC 6887 §8.1.1 IRT */
#define PM_PCP_MRT_MS 1024000u  /* RFC 6887 §8.1.1 MRT */
#define PM_NATPMP_IRT_MS 250u   /* RFC 6886 §3.1 initial interval */
#define PM_MAX_TRIES 9u         /* nine sends per query, both families */
#define PM_RX_BUDGET 8          /* datagrams handled per read callback */
/* RFC 6887 §7.4 calls NO_RESOURCES and NETWORK_FAILURE short-lifetime errors and
 * §8 says the same request may succeed later; the reply names that wait in its own
 * Lifetime field. The wait is honoured, but never taken below this floor — a gateway
 * handing out lifetime 0 would otherwise buy a tight retry loop. */
#define PM_RETRY_MIN_S 60u
/* The §8.5 restart test compares the Epoch the gateway reports against what the
 * client's own clock says it must be, so a gateway whose Epoch just stands still is
 * judged a restart on every answer — and each judgement means one re-request. The
 * legitimate case needs one (the reply to the re-request carries a boot-time Epoch
 * that then becomes the baseline and passes), so this caps only the pathological one:
 * after that many detections in a row the sequence ends like any other refusal.
 * ponytail: the ceiling is per sequence, so a gateway that restarts once every few
 * minutes is met by one query per restart, forever — which is right. The upgrade path
 * if a flapping gateway ever proves noisy is a backoff on `restarts`, not more sends. */
#define PM_MAX_RESTARTS 3u
/* R12: the ask for a mapping the driver has just lost (its renewal met silence). One
 * cycle already costs the whole nine-send schedule of PM_MAX_TRIES (~13 min over PCP,
 * ~64 s over NAT-PMP), so one ask per this wait cannot hammer a gateway. The wait
 * doubles per ask that goes unanswered, 5 → 10 → 20 … minutes, capped at
 * PM_REACQ_MAX_MS: a share outlives an hour-long router reboot, so asking goes on for
 * the whole run and a gateway that comes back gets its mapping back, while a gateway
 * that is gone is met by one datagram an hour.
 * ponytail: the ceiling is 1 h, the doubling is per phase and not jittered. Upgrade
 * path if a fleet behind one gateway proves noisy: jitter it the way pm_jitter does
 * for PCP rather than shrinking the ceiling. */
#define PM_REACQ_MS 300000u       /* the first wait: 5 min */
#define PM_REACQ_MAX_MS 3600000u  /* doubling stops at 1 h => ~24 asks a day, worst case */

/* One outstanding query at a time, in this order. The NAT-PMP external-address
 * query exists only in the fallback: it is how CGNAT is found without PCP. */
enum { PM_PH_ADDR = 0, PM_PH_TCP, PM_PH_UDP, PM_NPH };
enum { PM_PCP = 0, PM_NATPMP = 1 };

/* The ::/0 gateway of /proc/net/ipv6_route: the NATIVE v6 nexthop (never widened to
 * v4-mapped — an IPv4-mapped address there is the bug R15 was) and the interface it
 * is reachable through, which S17b needs for sin6_scope_id on a link-local router.
 * Declared before the driver because pm_open keeps one. */
struct pm_gw6 {
    uint8_t addr[16]; /* network order, exactly as the kernel printed it */
    char iface[IF_NAMESIZE];
};

/* S17c · the v6 sequence, in full. Everything the v4 machine keeps at the top of
 * struct ntx_portmap — the outstanding query and its retransmission schedule, the
 * nonces, the grants and their renew/re-acquire clocks, the §8.5 Epoch baseline, the
 * one deferred retry — has its own copy here, and NOTHING is read across:
 * ntx_session_portmap.c's v4 arms touch pm->phase/pm->active/pm->epoch/... and the
 * v6 arms below touch only s6.*, so a v6 gateway that refuses, answers late or never
 * shows up cannot move one v4 timer, and a v4 refusal cannot end a v6 schedule.
 * The two halves are deliberately NOT one array-of-two machine: the v4 fields are
 * read by name from t_portmap.c and t_share_session.c (the pacing, R12/R13/R14
 * probes), and folding them into a per-family struct would have meant renaming every
 * one of those probes for no change in behaviour.
 * PM_PH_ADDR has a slot here and is never used: the external-address query belongs
 * to NAT-PMP, which RFC 6886 defines for IPv4 only, so the v6 half speaks PCP alone. */
struct pm_seq6 {
    int st;                   /* ntx_pm_state of the v6 half alone (see state6) */
    int gave_up;              /* no more asking for this sequence */
    int phase;                /* outstanding query (PM_PH_TCP/PM_PH_UDP), -1 = none */
    int tries;
    uint32_t gap;             /* un-jittered base of the next interval, ms */
    uint64_t next_try;
    uint8_t nonce[12];        /* of the outstanding query */
    uint8_t proto;            /* of the outstanding MAP query */
    uint16_t iport;           /* internal port of the outstanding MAP query */
    uint8_t client_ip[16];    /* our address on the v6 route: the PCP client address */
    uint8_t req[60];
    size_t reqlen;
    int active[PM_NPH];
    int failed[PM_NPH];
    uint16_t ext[PM_NPH];     /* == the listen port whenever active[] is set (the rule) */
    uint64_t renew_at[PM_NPH];
    uint64_t expire_at[PM_NPH];
    uint64_t reacq_at[PM_NPH];
    uint32_t reacq_gap[PM_NPH];
    uint8_t grant_nonce[PM_NPH][12];
    uint8_t grant_ip[PM_NPH][16];
    int retry_ph;             /* the one deferred retry of this half, -1 = none */
    uint64_t retry_at;
    int retried;
    uint32_t epoch;           /* §8.5 baseline of THIS family */
    int epoch_seen;
    uint64_t epoch_at;
    int restarts;
    int lost;                 /* §8.5 rollback: the tick owes this half one fresh query */
};

struct ntx_portmap {
    ntx_netx *netx;
    const ntx_config *cfg;
    int fd;                   /* UDP socket connected to gateway:5351, -1 = closed */
    /* ---- S17b · the IPv6 half's socket, and deliberately SEPARATE state.
     * Nothing here is read by the v4 sequence and no v4 field is written from the v6
     * path, so a v6 gateway that refuses, answers or never shows up cannot disturb the
     * v4 timers, phases, retries or grants (S17c put its MAP requests on this socket,
     * S17d aggregates the stats). Kept next to `fd` rather than in its own struct
     * because the two halves share the one netx loop and the one route read.
     *   fd6           AF_INET6 UDP socket connected to gw6.addr:5351, -1 when v6 is
     *                 not wanted, not reachable, or already given up.
     *   gw6_scope     the if_nametoindex(gw6.iface) handed to connect() for a
     *                 link-local gateway, 0 when the address needed none. It is also
     *                 what the source rule compares an incoming scope against — the
     *                 only witness of it, since getpeername answers sk_bound_dev_if
     *                 and not the connect-time scope (reads 0 either way).
     *   gw6_tried     connect() was attempted at all (a link-local gateway with no
     *                 resolvable interface must not be connected, and 0 tells that
     *                 refusal apart from an attempt the kernel refused).
     *   gw6_connected connect() took it, so the socket is registered and live.
     *   rx6_seen / rx6_ok  datagrams the v6 callback read, and the ones the source
     *                 rule let through. S17c parses the accepted ones, so the two
     *                 counters still say who was dropped and why nothing was: without
     *                 them the two rules (gateway address, gateway port) would have no
     *                 observable effect at all to test against.
     *   gw6_err      errno of the last thing the v6 half judged wrong: the kernel's
     *                 answer to connect(), or the SO_ERROR it reported later. The
     *                 reason a refusal happened, which nothing else on this socket
     *                 can report after the fd is gone. */
    int fd6;
    unsigned gw6_scope;
    int gw6_tried;
    int gw6_connected;
    int gw6_err;
    uint32_t rx6_seen;
    uint32_t rx6_ok;
    /* S17c · the v6 sequence itself: the whole per-family machine, read by no v4 arm
     * and writing no v4 field. A sequence that never reached a verdict leaves `st` at
     * OFF (no v6 route, or mapping refused outright); pm_open6 is what gives it a
     * verdict of its own. ntx_session_portmap_state6() reports it. */
    struct pm_seq6 s6;
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
    /* R15 / S17a: the ::/0 gateway of /proc/net/ipv6_route — the NATIVE v6 nexthop
     * (network order, never v4-mapped) and the interface it is reachable through,
     * which is what a link-local router needs for sin6_scope_id. The v6 socket that
     * consumes them is S17b; the parser runs and the test pins the fields. */
    struct pm_gw6 gw6;
    int gw6_seen;             /* the v6 route was read this sequence and named a gateway */
    uint8_t client_ip[16];    /* our address on that route, IPv4-mapped */
    uint8_t req[60];
    size_t reqlen;
    uint8_t nonce[12];               /* of the outstanding query */
    uint8_t grant_nonce[PM_NPH][12]; /* the nonce each grant was made with (§11.1) */
    uint8_t grant_ip[PM_NPH][16];    /* the external address each grant came with (§11.2) */
    uint8_t proto;                   /* of the outstanding MAP query */
    uint16_t iport;                  /* internal port of the outstanding MAP query */
    int active[PM_NPH];
    int failed[PM_NPH];       /* this query exhausted its retries */
    uint16_t ext[PM_NPH];
    uint64_t renew_at[PM_NPH]; /* virtual ms */
    uint64_t expire_at[PM_NPH]; /* virtual ms the gateway stops forwarding this grant (R12) */
    /* R12: a mapping this sequence held and lost is owed asks until it is held again.
     * `reacq_at` is the instant the next ask may go out (0 = none pending) and
     * `reacq_gap` the wait to use for the next loss (PM_REACQ_MS, doubled per ask,
     * capped); `reacq_gap == 0` also means "nothing was ever granted for this phase",
     * which is what separates a lost mapping from a first acquisition that the ordinary
     * arms of the tick already own. */
    uint64_t reacq_at[PM_NPH];
    uint32_t reacq_gap[PM_NPH];
    uint32_t epoch;
    int epoch_seen;            /* 0 until the first PCP answer: no baseline */
    uint64_t epoch_at;         /* virtual ms the baseline Epoch was received (§8.5) */
    int fallback_used;    /* the one PCP → NAT-PMP step of this sequence is spent (R9) */
    int retry_ph;         /* query the gateway told us to ask for again, -1 = none (R14) */
    uint64_t retry_at;    /* virtual ms that retry may go out (never sooner than PM_RETRY_MIN_S) */
    int retried;          /* the one deferred retry of this sequence is spent (R14) */
    int lost;             /* §8.5 rollback: the tick owes the sequence one fresh query (R10) */
    int restarts;         /* consecutive §8.5 restart detections; a grant resets them */
};

/* Process globals because the test hooks take no session. Production never sets
 * them, and only one session at a time ever owns a driver. */
static uint64_t pm_voff;
static const char *pm_route4_path;
static const char *pm_route6_path;
static uint16_t pm_gw_port_cfg;
/* S17b: the v6 gateway's port is its own hook. One hook for both families would
 * make "v4 gateway alive, v6 gateway gone" — the case that proves the halves are
 * independent — impossible to build. */
static uint16_t pm_gw6_port_cfg;
/* S17c: the client address a v6 sequence names, for the one case the sandbox cannot
 * produce on its own. getsockname() of a socket connected to [::1] answers ::1 and
 * there is no routable v6 address to bind a test socket to here (`ip -6 addr add` is
 * EPERM, every non-loopback bind is EADDRNOTAVAIL — both probed), so the family-skip
 * rule of §8 would have no test at all. NULL (production, and every other case) means
 * "ask the kernel", which is the path the wire-level cases pin byte for byte. */
static uint8_t pm_client6_cfg[16];
static int pm_client6_set;
static int pm_cgnat_warned;

void ntx_portmap_test_set_route_files(const char *v4, const char *v6) {
    pm_route4_path = (v4 && *v4) ? v4 : NULL;
    pm_route6_path = (v6 && *v6) ? v6 : NULL;
}

void ntx_portmap_test_set_gateway_port(uint16_t port) { pm_gw_port_cfg = port; }

void ntx_portmap_test_set_gateway6_port(uint16_t port) { pm_gw6_port_cfg = port; }

/* S17c: name the address the v6 sequence treats as our own on the route. NULL (the
 * production value) means "whatever getsockname() says", which is the rule the wire
 * cases depend on; a case that needs a routable client — or wants to show that a
 * non-routable one is refused — passes the 16 bytes instead, and pm6_is_global still
 * judges them. Without this the sandbox could not reach the v6 sequence at all: the
 * only address bindable here is ::1 (probed: EADDRNOTAVAIL for any global, EPERM for
 * `ip -6 addr add`), so getsockname always answers loopback and §8 always skips. */
void ntx_portmap_test_set_client6(const uint8_t *addr16) {
    if (addr16) {
        memcpy(pm_client6_cfg, addr16, 16);
        pm_client6_set = 1;
    } else {
        pm_client6_set = 0;
        memset(pm_client6_cfg, 0, sizeof pm_client6_cfg);
    }
}

void ntx_portmap_test_advance_ms(uint64_t ms) { pm_voff += ms; }

static uint16_t pm_gw_port(void) { return pm_gw_port_cfg ? pm_gw_port_cfg : NTX_PCP_PORT; }

/* RFC 6887 §8: both families ask on the same well-known port. */
static uint16_t pm_gw6_port(void) { return pm_gw6_port_cfg ? pm_gw6_port_cfg : NTX_PCP_PORT; }

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

/* /proc/net/ipv6_route, in the layout the kernel actually writes
 * (net/ipv6/route.c: ipv6_route_seq_show):
 *
 *   dst(32hex) dpl(2hex) src(32hex) spl(2hex) nexthop(32hex) metric(8hex)
 *   refcnt(8hex) use(8hex) flags(8hex) iface
 *
 * The three addresses are 16 raw bytes printed in network order and EVERY number
 * is hex — the prefix lengths included (a host route reads "80", not "128").
 * Reading metric/refcnt/use/flags as decimal, or the nexthop out of the src field,
 * therefore judges a different route than the one on the line (R15). */
#define PM_RTF_UP 0x00000001u
#define PM_RTF_GATEWAY 0x00000002u
#define PM_RTF_REJECT 0x00000200u
#define PM_METRIC_DEAD 0xffffffffu /* the unreachable ::/0 networkd keeps on lo */

/* Exactly n hex nibbles and nothing after them: a short, long or non-hex token is a
 * line we know nothing about, so it is ignored rather than guessed at. No strtoul,
 * so no overflow and no partial read to reason about. */
static int pm_hexbytes(const char *tok, size_t nbytes, uint8_t *out) {
    for (size_t i = 0; i < nbytes; i++) {
        int hi = pm_nib(tok[2 * i]), lo = pm_nib(tok[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return tok[2 * nbytes] == '\0';
}

static int pm_hexw(const char *tok, size_t n, uint32_t *out) {
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        int d = pm_nib(tok[i]);
        if (d < 0) return 0;
        v = (v << 4) | (uint32_t)d;
    }
    if (tok[n] != '\0') return 0;
    *out = v;
    return 1;
}

/* One line, judged on its own: 1 when it is a usable ::/0 via a gateway, with the
 * nexthop and interface returned and the metric handed out for the comparison. */
static int pm_route6_line(const char *line, struct pm_gw6 *gw, uint32_t *metric_out) {
    /* Every token is one wider than the field the kernel prints, so a field that is
     * too long is truncated into a token the exact-length check below rejects instead
     * of into a value that happens to parse. `src` and `use`/`refcnt` are read for
     * their positions only: drop one of them and the nexthop shifts into another
     * slot, which is exactly how the old parser ended up reading src as the gateway. */
    char dst[34], dpl[4], src[34], spl[4], nh[34], met[10], ref[10], use[10], flags[10], iface[64];
    if (sscanf(line, "%33s %3s %33s %3s %33s %9s %9s %9s %9s %63s", dst, dpl, src, spl, nh, met, ref, use,
               flags, iface) != 10)
        return 0;
    uint32_t dplen, metric, fl;
    if (!pm_hexw(dpl, 2, &dplen) || dplen != 0) return 0; /* only ::/0 is a default */
    if (!pm_hexw(met, 8, &metric) || !pm_hexw(flags, 8, &fl)) return 0;
    if (!(fl & PM_RTF_UP) || !(fl & PM_RTF_GATEWAY) || (fl & PM_RTF_REJECT)) return 0;
    if (metric == PM_METRIC_DEAD) return 0; /* no route, whatever the flags claim */
    uint32_t splen;
    if (!pm_hexw(spl, 2, &splen)) return 0;
    uint8_t d[16], n[16];
    if (!pm_hexbytes(dst, 16, d) || !pm_hexbytes(nh, 16, n)) return 0;
    for (int i = 0; i < 16; i++)
        if (d[i]) return 0; /* dst is not :: */
    int zero_nh = 1;
    for (int i = 0; i < 16; i++)
        if (n[i]) zero_nh = 0;
    if (zero_nh) return 0; /* directly connected: there is no gateway to ask */
    if (strlen(iface) >= IF_NAMESIZE) return 0; /* longer than the kernel can print */
    memcpy(gw->addr, n, 16);
    memcpy(gw->iface, iface, strlen(iface) + 1);
    *metric_out = metric;
    return 1;
}

/* The default-route gateway of the IPv6 table, or 0: no file (a kernel built
 * without IPv6), no usable ::/0, or nothing readable in it. */
static int pm_route6(struct pm_gw6 *out) {
    FILE *f = fopen(pm_route6_path ? pm_route6_path : "/proc/net/ipv6_route", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    struct pm_gw6 best;
    uint32_t best_metric = 0;
    while (fgets(line, sizeof line, f)) {
        struct pm_gw6 cand;
        uint32_t metric;
        if (!pm_route6_line(line, &cand, &metric)) continue;
        if (!found || metric < best_metric) {
            found = 1;
            best_metric = metric;
            best = cand;
        }
    }
    fclose(f);
    if (!found) return 0;
    *out = best;
    return 1;
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
    pm->fd6 = -1;
    pm->phase = -1;
    pm->retry_ph = -1;
    pm->s6.phase = -1; /* 0 would read as PM_PH_ADDR, the query this half never sends */
    pm->s6.retry_ph = -1;
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

/* The v6 socket's own teardown: the v4 fd, its registration and everything the v4
 * sequence holds are untouched, and nothing here clears a grant or a timer. */
static void pm_close_sock6(struct ntx_portmap *pm) {
    if (pm->fd6 < 0) return;
    ntx_netx_del(pm->netx, pm->fd6);
    close(pm->fd6);
    pm->fd6 = -1;
    pm->gw6_connected = 0;
}

/* Every trace of a mapping is gone, including the debt R12 records: a caller that
 * drops grants wholesale (reset, §8.5 rollback, CGNAT) is starting a different
 * sequence, and the re-acquisition budget of a mapping this sequence never held would
 * only make it ask for one again. `grant_nonce`/`grant_ip` stay as they are: nothing
 * reads them while `active` is 0 (R13), and the fresh ask draws a new nonce. */
static void pm_clear_grants(struct ntx_portmap *pm) {
    for (int i = 0; i < PM_NPH; i++) {
        pm->active[i] = 0;
        pm->ext[i] = 0;
        pm->renew_at[i] = 0;
        pm->expire_at[i] = 0;
        pm->reacq_at[i] = 0;
        pm->reacq_gap[i] = 0;
    }
}

static void pm_reset(struct ntx_portmap *pm, ntx_pm_state st) {
    pm_close_sock(pm);
    pm_close_sock6(pm);
    pm_clear_grants(pm);
    for (int i = 0; i < PM_NPH; i++) pm->failed[i] = 0;
    pm->phase = -1;
    pm->tries = 0;
    pm->started = 0;
    pm->gave_up = 0;
    pm->addr_done = 0;
    pm->epoch_seen = 0;
    pm->fallback_used = 0; /* the PCP → NAT-PMP step is per sequence, not per process (R9) */
    pm->retry_ph = -1;
    pm->retry_at = 0;
    pm->retried = 0;
    pm->lost = 0;
    pm->restarts = 0;
    /* The route is re-read with the next sequence, so a gateway that appeared or went
     * away between sequences cannot be answered from the previous answer. */
    memset(&pm->gw6, 0, sizeof pm->gw6);
    pm->gw6_seen = 0;
    /* The v6 half is reset with the sequence too: the scope belongs to the route that
     * is about to be re-read, and the try/connected pair is what tells "no v6 route"
     * from "a v6 route the kernel refused" for the sequence that is starting. */
    pm->gw6_scope = 0;
    pm->gw6_tried = 0;
    pm->gw6_err = 0;
    /* The rx counters belong to the socket this sequence is about to open, so they
     * start over with it — otherwise a second sequence would report the datagrams the
     * first one's socket read. */
    pm->rx6_seen = 0;
    pm->rx6_ok = 0;
    /* S17c: the v6 machine is the sequence's too — its outstanding query, nonces,
     * grants, Epoch baseline and deferred retry all die with the sequence, and OFF is
     * the honest starting point (pm_open6 is what gives the half a verdict). */
    memset(&pm->s6, 0, sizeof pm->s6);
    pm->s6.phase = -1;
    pm->s6.retry_ph = -1;
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

/* RFC 6887 §8.1.1: every retransmission interval is jittered by up to 10%, so a
 * fleet of clients behind one gateway does not retransmit in lockstep. Spread
 * uniformly over [ms − ms/10, ms + ms/10]. */
static uint32_t pm_jitter(uint32_t ms) {
    if (ms < 10u) return ms;
    uint32_t half = ms / 10u;
    return ms - half + ntx_rand_u32() % (2u * half + 1u);
}

static int pm_udp_wanted(const struct ntx_portmap *pm) { return pm->cfg && pm->cfg->utp; }

static uint8_t pm_op_of(int phase) { return (uint8_t)(phase == PM_PH_UDP ? 1 : 2); }

/* R19: what a FRESH ask (no grant in place, so `pm_start_query` draws a new nonce and
 * names no external address) suggests as its external port. The listen port for TCP,
 * and for UDP the port the TCP mapping holds whenever there is one. One announce
 * carries one port — `ntx_session_adv_port` reads the TCP grant alone, the UDP grant is
 * advertised nowhere — so a gateway that mapped TCP to X and UDP to Y leaves the peer
 * guessing which it reached; asking for X too is what keeps the two on the same port.
 * RFC 6887 §11.1 / RFC 6886 §3.3 both make it a PREFERENCE, and the internal port stays
 * the listen port either way (`pm_build`). A renewal never comes through here: it
 * already suggests the port its own grant came with.
 * v4 only: the v6 half's rule (S17c) is that a granted port must EQUAL the listen port,
 * so suggesting the TCP grant there could only ask for a port pm_grant6 then deletes. */
static uint16_t pm_sugg_port(const struct ntx_portmap *pm, int phase) {
    if (phase == PM_PH_UDP && pm->active[PM_PH_TCP] && pm->ext[PM_PH_TCP]) return pm->ext[PM_PH_TCP];
    return ntx_netx_port(pm->netx);
}

static void pm_build(struct ntx_portmap *pm, int phase, uint32_t lifetime, uint16_t sugg_port,
                     const uint8_t sugg_ip16[16]) {
    uint16_t lp = ntx_netx_port(pm->netx);
    pm->iport = lp;
    pm->phase = phase;
    if (phase == PM_PH_ADDR) {
        pm->reqlen = natpmp_build_addr(pm->req);
        return;
    }
    pm->proto = (uint8_t)(phase == PM_PH_TCP ? NTX_PCP_PROTO_TCP : NTX_PCP_PROTO_UDP);
    if (pm->fam == PM_PCP)
        pm->reqlen =
            pcp_build_map(pm->req, pm->client_ip, pm->nonce, pm->proto, lp, sugg_port, lifetime, sugg_ip16);
    else
        pm->reqlen = natpmp_build_map(pm->req, pm_op_of(phase), lp, sugg_port, lifetime);
}

/* The ICMP answer for a datagram sent on the connect()ed socket lives in SO_ERROR.
 * Reading it is the only thing that clears a level-triggered EPOLLERR, and the only
 * way this driver learns "nothing listens at the gateway port" (R9). */
static int pm_drain_err(struct ntx_portmap *pm) {
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(pm->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) return 0;
    return err;
}

static void pm_start_query(struct ntx_portmap *pm, int phase, uint16_t sugg_port);
static void pm_give_up_phase(struct ntx_portmap *pm, int ph, int reask);

/* The gateway's verdicts, named for --verbose only (R14): the number is what the
 * gateway sent and is always printed, the name is convenience. One line per refusal,
 * and a refusal ends the sequence, so this cannot repeat the way a retry loop does.
 * RFC 6887 §7.4 and RFC 6886 §3.5. */
static const char *const pm_pcp_result_name[] = {
    "SUCCESS", "UNSUPP_VERSION", "NOT_AUTHORIZED", "MALFORMED_REQUEST", "UNSUPP_OPCODE",
    "UNSUPP_OPTION", "MALFORMED_OPTION", "NETWORK_FAILURE", "NO_RESOURCES", "UNSUPP_PROTOCOL",
    "USER_EX_QUOTA", "CANNOT_PROVIDE_EXTERNAL", "ADDRESS_MISMATCH", "EXCESSIVE_REMOTE_PEERS"
};
static const char *const pm_natpmp_result_name[] = {
    "SUCCESS", "UNSUPP_VERSION", "NOT_AUTHORIZED", "NETWORK_FAILURE", "OUT_OF_RESOURCES",
    "UNSUPP_OPCODE"
};

static void pm_diag_result(int fam, uint32_t res) {
    static const char *const *t = NULL;
    size_t n = 0;
    if (fam == PM_PCP) {
        t = pm_pcp_result_name;
        n = sizeof pm_pcp_result_name / sizeof pm_pcp_result_name[0];
    } else {
        t = pm_natpmp_result_name;
        n = sizeof pm_natpmp_result_name / sizeof pm_natpmp_result_name[0];
    }
    ntx_diag("ntx: port map: %s result %u %s\n", fam == PM_PCP ? "PCP" : "NAT-PMP", res,
             res < n ? t[res] : "UNKNOWN");
}

/* The two codes per family that mean "not now, the same request may work later" —
 * RFC 6887 §7.4 NO_RESOURCES / NETWORK_FAILURE, RFC 6886 §3.5 out-of-resources /
 * network-failure. Every other verdict the gateway states is final for this run. */
static int pm_result_retryable(int fam, uint32_t res) {
    if (fam == PM_PCP) return res == NTX_PCP_RES_NETWORK_FAILURE || res == NTX_PCP_RES_NO_RESOURCES;
    return res == NTX_NATPMP_RES_NETWORK_FAILURE || res == NTX_NATPMP_RES_OUT_OF_RESOURCES;
}

/* The gateway answered the outstanding query with a verdict that is not a grant
 * (R14). The schedule stops in both cases — nine more datagrams at a gateway that
 * already refused say nothing new — and the difference is only in the future: the
 * retryable pair gets exactly one further attempt after the wait the reply itself
 * names (RFC 6887 §7.4, §8; RFC 6886 §3.5), never sooner than PM_RETRY_MIN_S, and a
 * lifetime of 0 means the gateway named no retry at all. Everything else is final:
 * the state says none and the tick stays quiet, exactly as for a gateway that never
 * answered, so the sequence is not reopened behind the gateway's back. */
static void pm_refused_result(struct ntx_portmap *pm, int ph, uint32_t res, uint32_t life_s) {
    pm->phase = -1;
    pm->tries = 0;
    pm_diag_result(pm->fam, res);
    pm_give_up_phase(pm, ph, 0);
    if (!pm_result_retryable(pm->fam, res) || life_s == 0 || pm->retried) return;
    uint64_t wait_s = life_s < PM_RETRY_MIN_S ? PM_RETRY_MIN_S : life_s;
    pm->retry_ph = ph;
    pm->retry_at = pm_now() + wait_s * 1000u;
    pm->gave_up = 0; /* the tick is what sends the one deferred attempt */
}

/* Nothing at the gateway port answered at all (R9). §8 keeps the order PCP first,
 * NAT-PMP second; the step is allowed once per sequence and never backwards, so a
 * gateway that answers neither cannot be ping-ponged between the two families. */
static void pm_refused(struct ntx_portmap *pm, int ph) {
    pm->phase = -1;
    pm->tries = 0;
    if (pm->fam == PM_PCP && !pm->fallback_used) {
        /* The same step a UNSUPP_VERSION answer takes (RFC 6886 §3.5): start over as
         * NAT-PMP, whose sequence opens with the external-address query. */
        pm->fallback_used = 1;
        pm->fam = PM_NATPMP;
        pm->addr_done = 0;
        pm_start_query(pm, PM_PH_ADDR, 0);
        return;
    }
    pm_give_up_phase(pm, ph, 1);
}

/* The one verdict for both ways the socket reports trouble (SO_ERROR via the close
 * callback, or the errno of send()). ECONNREFUSED is the ICMP port-unreachable of a
 * gateway without a PCP/NAT-PMP responder; anything else is a socket that cannot
 * send at all (EPIPE, ENOBUFS …), and nine retries of a datagram the kernel refused
 * is pure delay. ponytail: the hard-error path takes no NAT-PMP step — the fallback
 * rides the same fd, so a broken socket says nothing about a protocol. */
static void pm_sock_err(struct ntx_portmap *pm, int err) {
    /* An error says something only while a query is outstanding; with nothing
     * outstanding it is stale — drained, judged as nothing, the spin is gone. This
     * also makes the two report paths (recvfrom and the close callback, which epoll
     * hands out in the same event) safe against judging one error twice. */
    if (pm->phase < 0) return;
    int ph = pm->phase;
    pm->phase = -1;
    pm->tries = 0;
    if (err == ECONNREFUSED) {
        pm_refused(pm, ph);
        return;
    }
    pm_give_up_phase(pm, ph, 1);
}

/* The result of send() is never discarded (R9): trouble is judged here and the
 * retransmission schedule only gets the next say when the datagram went out. */
static void pm_send(struct ntx_portmap *pm) {
    if (pm->fd < 0 || pm->phase < 0) return;
    /* Drain before sending: the pending error belongs to the datagram that caused it
     * and must not be blamed on this one, and while it stays pending EPOLLERR keeps
     * firing, which is the spin. */
    (void)pm_drain_err(pm);
    if (send(pm->fd, pm->req, pm->reqlen, 0) < 0) {
        pm_sock_err(pm, errno ? errno : EIO);
        return;
    }
    pm->tries++;
    /* The wait just spent is the schedule's current interval, jittered for PCP
     * (§8.1.1); `gap` stays the un-jittered base and doubles for the next one,
     * never past MRT. NAT-PMP doubles freely — nine sends from 250 ms end at 64 s. */
    pm->next_try = pm_now() + (pm->fam == PM_PCP ? pm_jitter(pm->gap) : pm->gap);
    pm->gap = (pm->fam == PM_PCP && pm->gap >= PM_PCP_MRT_MS / 2u) ? PM_PCP_MRT_MS : pm->gap * 2u;
}

/* Start a query: fresh schedule, sent now. The nonce depends on whether this is the
 * first ask for the mapping or a renewal of one we hold. RFC 6887 §11.2: the gateway
 * keys a MAP request on the nonce, so a renewal that draws a new one is a request for
 * a SECOND mapping — the grant in place then just sits there until its lifetime runs
 * out — and the delete of §11.1 would go out with a nonce the gateway was never
 * asked about. So a live grant reuses its grant nonce and suggests the address and
 * port it came with; a fresh acquisition (nothing live: the opening of a sequence, or
 * the re-acquisition after pm_lost) draws a new nonce and states no preference.
 * `grant_nonce`/`grant_ip` are written only by pm_grant, never here (R13). */
static void pm_start_query(struct ntx_portmap *pm, int phase, uint16_t sugg_port) {
    if (phase < 0 || pm->fd < 0) return;
    const uint8_t *sugg_ip = NULL;
    pm->lost = 0; /* any fresh query is the sequence starting again (R10) */
    if (phase != PM_PH_ADDR) {
        if (pm->active[phase]) {
            memcpy(pm->nonce, pm->grant_nonce[phase], sizeof pm->nonce);
            sugg_ip = pm->grant_ip[phase];
        } else {
            ntx_rand_bytes(pm->nonce, sizeof pm->nonce);
        }
    }
    pm->tries = 0;
    pm->gap = pm->fam == PM_PCP ? PM_PCP_IRT_MS : PM_NATPMP_IRT_MS;
    pm_build(pm, phase, PM_LIFE_S, sugg_port, sugg_ip);
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
            n = pcp_build_map(buf, pm->client_ip, pm->grant_nonce[ph], proto, lp, pm->ext[ph], 0,
                              pm->grant_ip[ph]);
        } else {
            n = natpmp_build_map(buf, pm_op_of(ph), lp, pm->ext[ph], 0);
        }
        (void)pm_drain_err(pm); /* an ICMP for the last live query must not skip this delete (R9) */
        if (send(pm->fd, buf, n, 0) < 0) break;
    }
}

/* The only place a grant nonce is recorded (R13): the request identified by this
 * answer — its nonce is pm->nonce, which pcp_parse_map matched against the reply —
 * IS the mapping, so renewals and deletes go out with it (§11.1/§11.2), together with
 * the external address and port the gateway assigned. NAT-PMP has no nonce: its
 * request is identified by version/opcode/internal port, so only the port is kept. */
static void pm_grant(struct ntx_portmap *pm, int phase, uint16_t ext_port, uint32_t life,
                     const uint8_t ext_ip16[16]) {
    pm->active[phase] = 1;
    pm->failed[phase] = 0;
    /* R12: holding a mapping again means losing it is worth asking about again — the
     * backoff belongs to the mapping, so a fresh grant resets it and clears any ask
     * still queued for the one it replaces. */
    pm->reacq_gap[phase] = PM_REACQ_MS;
    pm->reacq_at[phase] = 0;
    memcpy(pm->grant_nonce[phase], pm->nonce, sizeof pm->nonce);
    if (ext_ip16) memcpy(pm->grant_ip[phase], ext_ip16, 16);
    else memset(pm->grant_ip[phase], 0, 16);
    pm->ext[phase] = ext_port;
    /* R19: the ask suggested the TCP grant's port (pm_sugg_port) and the gateway
     * forwarded some other one. The grant is KEPT — the UDP external port is never
     * advertised anywhere, so nothing the swarm does depends on it — but the two
     * mappings are now on different ports and a peer that was told the TCP one cannot
     * reach uTP: the operator has to be able to see that, which is all this line is
     * (the plan's "flagować rozbieżność"). Not a refusal, and nothing is sent from the
     * receive path (R10). */
    if (phase == PM_PH_UDP && pm->active[PM_PH_TCP] && pm->ext[PM_PH_TCP] &&
        ext_port != pm->ext[PM_PH_TCP])
        ntx_diag("ntx: port map: UDP port %u differs from the TCP port %u the swarm is told\n",
                 (unsigned)ext_port, (unsigned)pm->ext[PM_PH_TCP]);
    pm->renew_at[phase] = pm_now() + (uint64_t)(life / 2) * 1000u;
    /* R12: the instant the gateway itself stops forwarding this grant. A renewal that
     * is still in flight past it cannot be assumed held any more, and
     * `ntx_session_adv_port` must not tell the swarm to dial a port the gateway has
     * dropped. With the normal schedule a renewal is always over long before this
     * (PCP: the nine sends end ~783 s in, half of 7200 s is 3600 s), so it only bites
     * for a gateway that hands out a lifetime shorter than one send cycle. */
    pm->expire_at[phase] = pm_now() + (uint64_t)life * 1000u;
    pm->phase = -1;
    pm->tries = 0;
    if (pm->active[PM_PH_TCP]) pm->st = NTX_PM_ACTIVE; /* §8: announces carry the ext port */
}

/* The gateway restarted (its Epoch failed the RFC 6887 §8.5 test): drop every grant
 * and establish the mapping again. Nothing is sent from here — this runs inside the
 * receive callback, and a request out of the rx path is the request loop of R10.
 * `lost` is what the tick drives the fresh sequence from: leaving `phase` pending
 * would have the same effect, but "the grants are gone" is the fact to record, and the
 * tick's renewal loop only reaches `active`/`failed` mappings. */
static void pm_lost(struct ntx_portmap *pm) {
    pm_clear_grants(pm);
    for (int i = 0; i < PM_NPH; i++) pm->failed[i] = 0;
    pm->gave_up = 0;
    pm->retry_ph = -1; /* a fresh sequence supersedes any deferred retry (R14) */
    pm->retried = 0;
    pm->phase = -1;
    pm->tries = 0;
    pm->lost = 1;
    pm->st = NTX_PM_PENDING;
}

/* R18: the deletes go out FIRST. `pm_clear_grants` wipes `active`/`ext`, and a
 * lifetime-0 request is built from exactly those fields plus the grant nonce — cleared
 * first, there is nothing left to build one from and the gateway keeps forwarding into
 * a mapping this client has just publicly given up on, for the whole granted lifetime
 * (up to 7200 s). Fire-and-forget like pm_stop_now's deletes: this runs in the receive
 * path, and a delete's own failure is not retried (§7.4 — the same rule pm_grant6's
 * wrong-port delete follows). Only the v4 half: `pm_cgnat` is the v4 sequence's verdict,
 * the v6 half has no CGNAT to reach (U9) and a live v6 grant outlives this one and
 * keeps its renewals (U6). The R12 debt is still dropped deliberately — pm_clear_grants
 * owns that, and it is only right: the sequence is over, so a re-acquisition ask is
 * never owed. */
static void pm_cgnat(struct ntx_portmap *pm) {
    if (pm->fd >= 0 && (pm->active[PM_PH_TCP] || pm->active[PM_PH_UDP])) pm_send_deletes(pm);
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

/* The v6 sibling, with the scope added: a link-local gateway address is only
 * meaningful together with the interface it lives on, so "the same address" here
 * means the same 16 bytes AND the same scope the socket was connected through.
 * The scope on an incoming datagram is what the kernel reports for the ingress
 * device, which is why an unscoped fe80:: match is not accepted either.
 * ponytail: the ceiling of S17b — the comparison is against the scope connect()
 * was given, and a kernel that reports 0 for a loopback-delivered packet (what it
 * does for ::1, probed) only matches a gateway whose scope is 0 too. Upgrade path:
 * for S17c's real routers, compare against the route's ifindex as reported by
 * IPV6_PKTINFO if a gateway is ever found whose packets arrive with a scope set. */
static int pm_src6_ok(const struct ntx_portmap *pm, const struct sockaddr_in6 *sa) {
    if (sa->sin6_family != AF_INET6) return 0;
    if (memcmp(sa->sin6_addr.s6_addr, pm->gw6.addr, 16) != 0) return 0;
    if (sa->sin6_scope_id != pm->gw6_scope) return 0;
    return ntohs(sa->sin6_port) == pm_gw6_port();
}

/* RFC 6887 §8.5: the client keeps the Epoch of the last answer (seconds since the
 * gateway's boot, §8.7) and the instant it received it, then compares the two
 * differences — how far the gateway's counter moved against how far our own clock
 * moved. A restart is either side of that agreement failing:
 *   server_delta + 1 <  client_delta − client_delta/16   (the counter went backwards
 *                                                         or stands still)
 *   server_delta >      client_delta + client_delta/16 + 1   (it claims more uptime
 *                                                             than has elapsed here)
 * The plain `epoch < baseline` this driver used instead sees only a rollback, so a
 * gateway that came back with a bigger, absurd Epoch was taken as a healthy grant and
 * the stale port stayed advertised (R10). Whole seconds, as the RFC counts them. */
static int pcp_epoch_restarts(uint32_t base, uint64_t base_at, uint32_t epoch) {
    if (epoch < base) return 1;
    uint64_t cd = (pm_now() - base_at) / 1000u;
    if (cd > 0xffffffffu) cd = 0xffffffffu; /* asleep for 49 days: no usable expectation */
    uint64_t sd = (uint64_t)(epoch - base);
    return sd + 1u < cd - cd / 16u || sd > cd + cd / 16u + 1u;
}

static int pcp_epoch_restarted(const struct ntx_portmap *pm, uint32_t epoch) {
    if (!pm->epoch_seen) return 0;
    return pcp_epoch_restarts(pm->epoch, pm->epoch_at, epoch);
}

static void pm_no_mapping(struct ntx_portmap *pm, int ph, const char *why) {
    pm->phase = -1;
    pm->tries = 0;
    ntx_diag("ntx: port map: %s %s\n", pm->fam == PM_PCP ? "PCP" : "NAT-PMP", why);
    pm_give_up_phase(pm, ph, 0);
}

/* A SUCCESS MAP reply whose Lifetime is 0 grants nothing — §11.1 makes lifetime 0 the
 * delete and RFC 6886 §3.3 gives its mapping reply the same meaning — so both families
 * answer it the same way: as the refusal it is, on the R14 rule. It used to be
 * pm_lost, which re-requested from inside the receive path and was answered with
 * another lifetime 0, requests and refusals chasing each other at the pace of the RTT
 * (R10). As a refusal it needs no wait from the reply: lifetime 0 names none, so the
 * sequence is simply over. */
static void pm_zero_lifetime(struct ntx_portmap *pm, int ph) {
    pm_no_mapping(pm, ph, "granted lifetime 0");
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
        if (rc > 1) { /* the gateway stated a verdict: not a grant (R14) */
            pm_refused_result(pm, ph, (uint32_t)rc, r.lifetime);
            return;
        }
        if (rc != 0) return; /* -1 garbage, -2 not an answer to our query */
        if (pcp_epoch_restarted(pm, r.epoch)) {
            /* The baseline takes this reply's Epoch BEFORE the sequence is dropped, so
             * the reply that detected the restart cannot detect it again — the defect
             * of R10 was that every later reply re-entered pm_lost. `restarts` bounds
             * the one gateway this still cannot satisfy: a counter that never agrees
             * with our clock (a frozen Epoch), where each answer would otherwise arm
             * one more re-request. */
            pm->epoch = r.epoch;
            pm->epoch_at = pm_now();
            if ((uint32_t)++pm->restarts > PM_MAX_RESTARTS) {
                pm_no_mapping(pm, ph, "epoch never agrees with our clock");
                return;
            }
            pm_lost(pm);
            return;
        }
        pm->restarts = 0;
        pm->epoch_seen = 1;
        pm->epoch = r.epoch;
        pm->epoch_at = pm_now();
        uint32_t life = pm_cap_life(r.lifetime);
        if (life == 0) {
            pm_zero_lifetime(pm, ph);
            return;
        }
        if (pcp_ip_is_cgnat_or_private(r.ext_ip16)) {
            pm_cgnat(pm);
            return;
        }
        pm_grant(pm, ph, r.ext_port, life, r.ext_ip16);
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
    int rc = natpmp_parse_map(b, n, pm_op_of(ph), pm->iport, &ext, &life);
    if (rc > 1) { /* the gateway stated a verdict: not a grant (R14) */
        pm_refused_result(pm, ph, (uint32_t)rc, life);
        return;
    }
    if (rc != 0) return;
    life = pm_cap_life(life);
    if (life == 0) {
        pm_zero_lifetime(pm, ph);
        return;
    }
    pm_grant(pm, ph, ext, life, NULL);
}

/* ---- S17c · the PCP MAP sequence of the v6 half ---------------------------
 * The v4 machine above, copied only in its RULES and sharing every helper it can
 * (pm_jitter, pm_cap_life, pm_result_retryable, pm_diag_result, pcp_build_map,
 * pcp_parse_map, pcp_epoch_restarts, the PM_*_MS pacing constants). What it
 * deliberately does NOT share is one byte of state, and it has no NAT-PMP branch:
 * RFC 6886 is IPv4-only, so a v6 gateway that answers UNSUPP_VERSION has said no.
 *
 * The rule this half exists for (R15, design §8): over IPv6 PCP opens the firewall,
 * it does not translate. A tracker announce carries ONE port — the one
 * ntx_session_adv_port puts in the `port` field and in the BEP 10 `p` — and that
 * decision stays v4's. So a v6 grant is only usable when the gateway forwards the
 * listen port UNCHANGED; anything else is a mapping the swarm can never be told
 * about, which makes it a hole in the firewall for nothing. Such a grant is deleted
 * with the nonce it was made with (§11.1) and the family is settled for the run. */

/* 1 for the address a v6 PCP request may name as its client: routable from outside.
 * The loopback, unspecified, link-local (fe80::/10), unique-local (fc00::/7),
 * multicast and reserved ranges all say no — the same judgement pm_is_global makes
 * for the v4 side, where 127/8, 169.254/16 and the private/CGNAT ranges are refused.
 * A request with one of those in the client field asks a router to open a port to an
 * address that is not reachable from anywhere, so the family is skipped instead.
 * ::ffff:a.b.c.d is refused too: a v4-mapped client address in a v6 request is the
 * exact confusion R15 was about, and the socket is AF_INET6 with V6ONLY. */
static int pm6_is_global(const uint8_t a[16]) {
    static const uint8_t zeros10[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!memcmp(a, zeros10, 10)) return 0;           /* ::, ::1, ::ffff:a.b.c.d */
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return 0; /* fe80::/10 link-local */
    if (pcp_ip_is_cgnat_or_private(a)) return 0;     /* fc00::/7 ULA (+ v4 mapped) */
    if (a[0] >= 0xff) return 0;                      /* multicast and reserved */
    return 1;
}

/* The v6 half's own pacing: PCP for both families, so the IRT/MRT path of the v4
 * schedule always applies and no NAT-PMP branch is reachable here. The four
 * declarations below are what the mutual recursion of the schedule needs
 * (send ↔ sock_err, query ↔ build, give_up ↔ refused/no_mapping/grant) without
 * reordering the functions away from their v4 twins. */
static int pm_drain_err6(struct ntx_portmap *pm);
static void pm_sock_err6(struct ntx_portmap *pm, int err);
static void pm_start_query6(struct ntx_portmap *pm, int phase, uint16_t sugg_port);
static void pm_give_up_phase6(struct ntx_portmap *pm, int ph, int reask);

static void pm_build6(struct ntx_portmap *pm, int phase, uint32_t lifetime, uint16_t sugg_port,
                      const uint8_t sugg_ip16[16]) {
    struct pm_seq6 *s6 = &pm->s6;
    uint16_t lp = ntx_netx_port(pm->netx);
    s6->iport = lp;
    s6->phase = phase;
    s6->proto = (uint8_t)(phase == PM_PH_UDP ? NTX_PCP_PROTO_UDP : NTX_PCP_PROTO_TCP);
    s6->reqlen = pcp_build_map(s6->req, s6->client_ip, s6->nonce, s6->proto, lp, sugg_port, lifetime, sugg_ip16);
}

static void pm_send6(struct ntx_portmap *pm) {
    struct pm_seq6 *s6 = &pm->s6;
    if (pm->fd6 < 0 || s6->phase < 0) return;
    (void)pm_drain_err6(pm); /* the ICMP of the last datagram must not be blamed on this one (R9) */
    if (send(pm->fd6, s6->req, s6->reqlen, 0) < 0) {
        pm_sock_err6(pm, errno ? errno : EIO);
        return;
    }
    s6->tries++;
    s6->next_try = pm_now() + pm_jitter(s6->gap);
    s6->gap = s6->gap >= PM_PCP_MRT_MS / 2u ? PM_PCP_MRT_MS : s6->gap * 2u;
}

/* §8: the v6 half keeps the state the v4 half has no claim on. `st` at the top of the
 * struct stays the v4 sequence's — ntx_session_portmap_state() and therefore the
 * stats' `port_map` keep their v4 meaning until S17d aggregates the two. */
static void pm_set_st6(struct ntx_portmap *pm, ntx_pm_state st) { pm->s6.st = (int)st; }

/* The v6 verdict on a refusal the gateway stated (R14, §7.4): the schedule stops, and
 * the retryable pair gets exactly one further attempt after the wait the reply names,
 * never sooner than PM_RETRY_MIN_S. No NAT-PMP step — there is none to take. */
static void pm_refused_result6(struct ntx_portmap *pm, int ph, uint32_t res, uint32_t life_s) {
    struct pm_seq6 *s6 = &pm->s6;
    s6->phase = -1;
    s6->tries = 0;
    pm_diag_result(PM_PCP, res);
    pm_give_up_phase6(pm, ph, 0);
    if (!pm_result_retryable(PM_PCP, res) || life_s == 0 || s6->retried) return;
    uint64_t wait_s = life_s < PM_RETRY_MIN_S ? PM_RETRY_MIN_S : life_s;
    s6->retry_ph = ph;
    s6->retry_at = pm_now() + wait_s * 1000u;
    s6->gave_up = 0; /* the tick is what sends the one deferred attempt */
}

static void pm_no_mapping6(struct ntx_portmap *pm, int ph, const char *why) {
    struct pm_seq6 *s6 = &pm->s6;
    s6->phase = -1;
    s6->tries = 0;
    ntx_diag("ntx: port map6: PCP %s\n", why);
    pm_give_up_phase6(pm, ph, 0);
}

/* A SUCCESS whose Lifetime is 0 grants nothing (§11.1, RFC 6886 §3.3 alike): the
 * refusal, not a re-request — the request loop of R10 came from treating it as one. */
static void pm_zero_lifetime6(struct ntx_portmap *pm, int ph) { pm_no_mapping6(pm, ph, "granted lifetime 0"); }

/* The one place a v6 grant nonce is recorded (R13), and the gate the R15 rule sits
 * behind: the external port the gateway assigned MUST be the listen port, because
 * `ntx_session_adv_port` advertises one port for both families and it is a v4
 * decision. A gateway that hands out another port gets its mapping deleted with the
 * nonce it just granted and the family is settled — a v6 hole in a firewall for a
 * port no peer will ever be told to dial is worse than no mapping. */
static void pm_grant6(struct ntx_portmap *pm, int ph, uint16_t ext_port, uint32_t life,
                      const uint8_t ext_ip16[16]) {
    struct pm_seq6 *s6 = &pm->s6;
    uint16_t lp = ntx_netx_port(pm->netx);
    s6->phase = -1;
    s6->tries = 0;
    if (ext_port != lp) {
        uint8_t buf[60];
        size_t n = pcp_build_map(buf, s6->client_ip, s6->nonce, s6->proto, lp, ext_port, 0, ext_ip16);
        (void)pm_drain_err6(pm);
        if (pm->fd6 >= 0) (void)send(pm->fd6, buf, n, 0); /* §11.1, fire-and-forget */
        ntx_diag("ntx: port map6: gateway forwarded port %u, not the listen port %u — mapping removed\n",
                 (unsigned)ext_port, (unsigned)lp);
        pm_give_up_phase6(pm, ph, 0);
        return;
    }
    s6->active[ph] = 1;
    s6->failed[ph] = 0;
    s6->reacq_gap[ph] = PM_REACQ_MS; /* R12: losing this one is worth asking about again */
    s6->reacq_at[ph] = 0;
    memcpy(s6->grant_nonce[ph], s6->nonce, sizeof s6->nonce);
    if (ext_ip16) memcpy(s6->grant_ip[ph], ext_ip16, 16);
    else memset(s6->grant_ip[ph], 0, 16);
    s6->ext[ph] = ext_port;
    s6->renew_at[ph] = pm_now() + (uint64_t)(life / 2) * 1000u;
    s6->expire_at[ph] = pm_now() + (uint64_t)life * 1000u;
    if (s6->active[PM_PH_TCP]) pm_set_st6(pm, NTX_PM_ACTIVE);
}

/* The gateway restarted as far as THIS family is concerned (§8.5): its grants are
 * gone and the tick owes the half one fresh query. Nothing is sent from the receive
 * path (R10). The v4 baseline, its grants and its `lost` flag are untouched. */
static void pm_lost6(struct ntx_portmap *pm) {
    struct pm_seq6 *s6 = &pm->s6;
    for (int i = 0; i < PM_NPH; i++) {
        s6->active[i] = 0;
        s6->ext[i] = 0;
        s6->renew_at[i] = 0;
        s6->expire_at[i] = 0;
        s6->reacq_at[i] = 0;
        s6->reacq_gap[i] = 0;
        s6->failed[i] = 0;
    }
    s6->gave_up = 0;
    s6->retry_ph = -1;
    s6->retried = 0;
    s6->phase = -1;
    s6->tries = 0;
    s6->lost = 1;
    pm_set_st6(pm, NTX_PM_PENDING);
}

/* Marking a v6 phase failed also cancels its R12 debt, exactly as pm_fail_phase does. */
static void pm_fail_phase6(struct ntx_portmap *pm, int ph) {
    pm->s6.failed[ph] = 1;
    pm->s6.reacq_at[ph] = 0;
    pm->s6.reacq_gap[ph] = 0;
}

/* The v6 sibling of pm_give_up_phase, with the same two shapes (a phase that HELD a
 * mapping versus one that never got one) and the same rule that a lost TCP grant
 * takes the state off ACTIVE. The UDP grant is never advertised anywhere, so a
 * TCP verdict does not poison it and vice versa — except on a phase that never got a
 * grant at all, where a gateway that will not map TCP will not map UDP either. */
static void pm_give_up_phase6(struct ntx_portmap *pm, int ph, int reask) {
    struct pm_seq6 *s6 = &pm->s6;
    if (s6->active[ph] || s6->reacq_gap[ph] > 0) {
        s6->active[ph] = 0;
        s6->ext[ph] = 0;
        s6->renew_at[ph] = 0;
        s6->expire_at[ph] = 0;
        s6->failed[ph] = 1;
        if (reask && s6->reacq_gap[ph] > 0) {
            s6->reacq_at[ph] = pm_now() + s6->reacq_gap[ph];
            s6->reacq_gap[ph] = s6->reacq_gap[ph] * 2u > PM_REACQ_MAX_MS ? PM_REACQ_MAX_MS
                                                                         : s6->reacq_gap[ph] * 2u;
            s6->gave_up = 0;
            pm_set_st6(pm, s6->active[PM_PH_TCP] ? NTX_PM_ACTIVE : NTX_PM_PENDING);
        } else {
            pm_fail_phase6(pm, ph);
            if (!s6->active[PM_PH_TCP] && !s6->active[PM_PH_UDP]) {
                pm_set_st6(pm, NTX_PM_NONE);
                s6->gave_up = 1;
            } else if (!s6->active[PM_PH_TCP]) {
                pm_set_st6(pm, NTX_PM_PENDING);
            }
        }
        return;
    }
    pm_fail_phase6(pm, ph);
    if (ph != PM_PH_UDP) pm_fail_phase6(pm, PM_PH_UDP); /* as v4: UDP's verdict is UDP's */
    if (!s6->active[PM_PH_TCP] && !s6->active[PM_PH_UDP]) {
        pm_set_st6(pm, NTX_PM_NONE);
        s6->gave_up = 1;
    }
}

/* §11.1/§11.2, the v6 copy of pm_start_query: a renewal of a grant we hold repeats the
 * grant's nonce and suggests the address that came with it; a fresh acquisition draws
 * a new nonce and states no preference. `grant_nonce`/`grant_ip` are written only by
 * pm_grant6 (R13). */
static void pm_start_query6(struct ntx_portmap *pm, int phase, uint16_t sugg_port) {
    struct pm_seq6 *s6 = &pm->s6;
    if (phase < 0 || pm->fd6 < 0) return;
    const uint8_t *sugg_ip = NULL;
    s6->lost = 0;
    if (s6->active[phase]) {
        memcpy(s6->nonce, s6->grant_nonce[phase], sizeof s6->nonce);
        sugg_ip = s6->grant_ip[phase];
    } else {
        ntx_rand_bytes(s6->nonce, sizeof s6->nonce);
    }
    s6->tries = 0;
    s6->gap = PM_PCP_IRT_MS;
    pm_build6(pm, phase, PM_LIFE_S, sugg_port, sugg_ip);
    pm_send6(pm);
}

/* §11.1 at exit: one lifetime-0 datagram per live v6 mapping, with the nonce that
 * grant was made with. Fire-and-forget like the v4 deletes — stop() runs inside the
 * close budget. */
static void pm_send_deletes6(struct ntx_portmap *pm) {
    struct pm_seq6 *s6 = &pm->s6;
    if (pm->fd6 < 0) return;
    uint16_t lp = ntx_netx_port(pm->netx);
    uint8_t buf[60];
    for (int ph = PM_PH_TCP; ph < PM_NPH; ph++) {
        if (!s6->active[ph]) continue;
        uint8_t proto = (uint8_t)(ph == PM_PH_TCP ? NTX_PCP_PROTO_TCP : NTX_PCP_PROTO_UDP);
        size_t n = pcp_build_map(buf, s6->client_ip, s6->grant_nonce[ph], proto, lp, s6->ext[ph], 0,
                                 s6->grant_ip[ph]);
        (void)pm_drain_err6(pm);
        if (send(pm->fd6, buf, n, 0) < 0) break;
    }
}

/* The v6 answer to the outstanding query. There is exactly one codec here (PCP), so
 * a version mismatch is a refusal and not a fallback, and an all-private external
 * address has no CGNAT meaning over IPv6 — the firewall opening the gateway claims
 * to a non-routable address is the same useless thing the client-address rule refuses
 * at the request, so the mapping is refused the way any other unusable grant is
 * rather than tracked as the v4 sequence's one-off CGNAT diagnosis.
 * ponytail: the ceiling is that such a grant reads as "no mapping" and not as the
 * gateway misbehaving; the diag line names which. Upgrade path if a router is ever
 * found doing this: one process-wide warning beside pm_warn_cgnat, not a new state. */
static void pm_rx6(struct ntx_portmap *pm, const uint8_t *b, size_t n) {
    struct pm_seq6 *s6 = &pm->s6;
    int ph = s6->phase;
    if (ph < 0) return; /* nothing outstanding: nothing to match an answer against */
    ntx_pcp_map_resp r;
    int rc = pcp_parse_map(b, n, s6->nonce, s6->proto, s6->iport, &r);
    if (rc == 1) { /* NAT-PMP speaks only IPv4: this gateway has no v6 answer for us */
        pm_no_mapping6(pm, ph, "gateway does not speak PCP");
        return;
    }
    if (rc > 1) {
        pm_refused_result6(pm, ph, (uint32_t)rc, r.lifetime);
        return;
    }
    if (rc != 0) return; /* -1 garbage, -2 not an answer to our query */
    if (s6->epoch_seen && pcp_epoch_restarts(s6->epoch, s6->epoch_at, r.epoch)) {
        s6->epoch = r.epoch; /* the baseline moves first: this reply cannot detect it again (R10) */
        s6->epoch_at = pm_now();
        if ((uint32_t)++s6->restarts > PM_MAX_RESTARTS) {
            pm_no_mapping6(pm, ph, "epoch never agrees with our clock");
            return;
        }
        pm_lost6(pm);
        return;
    }
    s6->restarts = 0;
    s6->epoch_seen = 1;
    s6->epoch = r.epoch;
    s6->epoch_at = pm_now();
    uint32_t life = pm_cap_life(r.lifetime);
    if (life == 0) {
        pm_zero_lifetime6(pm, ph);
        return;
    }
    pm_grant6(pm, ph, r.ext_port, life, r.ext_ip16);
}

/* The whole v6 schedule, and the twin of the arms ntx_session_portmap_tick runs for
 * v4: rollback, outstanding retransmission, the one deferred retry, renewals, the
 * R12 re-acquisition, then the fresh acquisitions. Reached only while the v6 socket
 * is up, and it reads and writes pm->s6 and pm->fd6 — nothing else. */
static void pm_tick6(struct ntx_portmap *pm) {
    struct pm_seq6 *s6 = &pm->s6;
    if (pm->fd6 < 0) return;
    uint64_t now = pm_now();
    if (s6->lost) {
        s6->lost = 0;
        pm_start_query6(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
        return;
    }
    if (s6->phase >= 0) {
        if (now < s6->next_try) return;
        int ph = s6->phase;
        if ((uint32_t)s6->tries >= PM_MAX_TRIES) {
            s6->phase = -1;
            pm_give_up_phase6(pm, ph, 1);
            return;
        }
        pm_send6(pm);
        return;
    }
    if (s6->gave_up) return;
    if (s6->retry_ph >= 0) {
        int ph = s6->retry_ph;
        if (now >= s6->retry_at) {
            s6->retry_ph = -1;
            int first = !s6->retried;
            s6->retried = 1;
            s6->failed[ph] = 0;
            s6->failed[PM_PH_UDP] = 0;
            if (first && s6->st != NTX_PM_ACTIVE) pm_set_st6(pm, NTX_PM_PENDING);
            pm_start_query6(pm, ph, s6->ext[ph]);
            return;
        }
    }
    for (int i = 0; i < PM_NPH; i++)
        if (s6->active[i] && !s6->failed[i] && now >= s6->renew_at[i]) {
            pm_start_query6(pm, i, s6->ext[i]); /* keep the granted port across renewals */
            return;
        }
    for (int i = PM_PH_TCP; i < PM_NPH; i++)
        if (s6->reacq_at[i] && now >= s6->reacq_at[i]) {
            s6->reacq_at[i] = 0;
            pm_start_query6(pm, i, ntx_netx_port(pm->netx));
            return;
        }
    if (!s6->active[PM_PH_TCP] && !s6->failed[PM_PH_TCP]) {
        pm_start_query6(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
        return;
    }
    if (pm_udp_wanted(pm) && !s6->active[PM_PH_UDP] && !s6->failed[PM_PH_UDP])
        pm_start_query6(pm, PM_PH_UDP, ntx_netx_port(pm->netx));
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

/* ---- S17b · the receive and error side of the v6 socket --------------------
 * Separate callbacks on purpose: pm_on_rw / pm_on_err reach into pm->phase,
 * pm->tries, pm->fam and the grants, all of which are the v4 sequence's own, and
 * RFC 6886 has no IPv6 form at all — a v6 socket that reports a refusal has no
 * NAT-PMP to step to, so routing a v6 error through pm_sock_err would both hand
 * the v4 sequence a verdict it never asked for and invent a fallback. */

/* SO_ERROR of the v6 socket, read and thereby cleared — the v6 twin of
 * pm_drain_err, and for the same reason: an unread error holds EPOLLERR asserted
 * on a level-triggered loop that then never blocks again (R9). */
static int pm_drain_err6(struct ntx_portmap *pm) {
    int err = 0;
    socklen_t len = sizeof err;
    if (getsockopt(pm->fd6, SOL_SOCKET, SO_ERROR, &err, &len) != 0) return 0;
    return err;
}

/* The v6 socket's verdict on an error (R15/S17b, and the error rules of S08/S10).
 * ECONNREFUSED is the ICMP port-unreachable of a router with no PCP responder;
 * anything else is a socket that cannot send at all (EPIPE, ENOBUFS …). Both end the
 * v6 half of this sequence, and unlike v4 there is nothing left to do about it: there
 * is no NAT-PMP to step to (RFC 6886 is IPv4-only), the endpoint is the one connect()
 * chose from the route, and nine retransmissions to a port that answers with ICMP buy
 * nothing but the ICMP. So the sequence is settled here — NONE, quiet, with the
 * grants dropped: a socket that is gone cannot renew what it holds, and a state that
 * still said ACTIVE would claim a firewall opening the gateway is about to forget.
 * The v4 half is not mentioned by a single line of this, which is the separation S17b
 * pinned for the socket and S17c pins for the schedule. */
static void pm_end_seq6(struct ntx_portmap *pm, ntx_pm_state st) {
    struct pm_seq6 *s6 = &pm->s6;
    s6->phase = -1;
    s6->tries = 0;
    s6->lost = 0;
    s6->retry_ph = -1;
    s6->retry_at = 0;
    s6->gave_up = 1;
    for (int i = 0; i < PM_NPH; i++) {
        s6->active[i] = 0;
        s6->failed[i] = 0;
        s6->ext[i] = 0;
        s6->renew_at[i] = 0;
        s6->expire_at[i] = 0;
        s6->reacq_at[i] = 0;
        s6->reacq_gap[i] = 0;
    }
    pm_set_st6(pm, st);
}

static void pm_sock_err6(struct ntx_portmap *pm, int err) {
    if (pm->fd6 < 0) return;
    pm->gw6_err = err;
    pm_close_sock6(pm);
    pm_end_seq6(pm, NTX_PM_NONE);
}

static void pm_on_rw6(int fd, void *ctx) {
    struct ntx_portmap *pm = (struct ntx_portmap *)ctx;
    for (int i = 0; i < PM_RX_BUDGET; i++) {
        uint8_t buf[1200];
        struct sockaddr_in6 from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) return;
        pm->rx6_seen++;
        /* A datagram the source rule rejects is counted and dropped — and it must
         * never reach pm_rx6, whose own match rules (nonce, proto, internal port) are
         * weaker than "this came from the gateway" (§8 makes the source test the
         * boundary). It must equally never reach pm_rx, the v4 parser, which would
         * read it as an answer to the v4 sequence's outstanding query. */
        if (!pm_src6_ok(pm, &from)) continue;
        pm->rx6_ok++;
        pm_rx6(pm, buf, (size_t)n);
    }
}

static void pm_on_err6(void *ctx) {
    struct ntx_portmap *pm = (struct ntx_portmap *)ctx;
    if (pm->fd6 < 0) return;
    int err = pm_drain_err6(pm);
    if (err) pm_sock_err6(pm, err);
}

/* 1 for a link-local address (fe80::/10), which is meaningful only together with
 * the interface it was learned on and so cannot be connected without a scope. */
static int pm6_link_local(const uint8_t a[16]) { return a[0] == 0xfe && (a[1] & 0xc0) == 0x80; }

/* Open and connect the v6 half, then take the PCP client address off the socket.
 * Called from pm_open once per sequence — like the v4 socket, a v6 gateway this
 * kernel refused is not asked again until the next sequence. Nothing here reads or
 * writes a v4 field, and every way out leaves the v4 socket, its phase, its schedule
 * and its grants exactly as they were.
 *
 * The client address of the request is the LOCAL address the kernel picked for the
 * connect()ed socket (design §8 / RFC 6887 §7.1: the IP header's source is the
 * client address), read with getsockname — not an address guessed from the route.
 * It has to be a global one: a request naming a link-local or unique-local client
 * asks the router to open a port toward an address nothing outside can reach, so the
 * family is skipped with the state NONE rather than sent (§8).
 * Returns 1 when the sequence is running, 0 when v6 is off for it. */
static int pm_open6(struct ntx_portmap *pm) {
    /* Whoever calls this is starting a sequence, so anything the last one left is
     * dropped through the one path that unregisters AND closes — a bare `fd6 = -1`
     * here would orphan a registered fd on the loop. */
    pm_close_sock6(pm);
    pm->gw6_scope = 0;
    pm->gw6_err = 0;
    /* §5 / §8: never under a proxy or a tunnel, exactly as for v4 — the inbound
     * traffic a mapping opens would bypass it and the request would name the
     * address the user is hiding. pm_open is only reached from a tick that already
     * refuses both, so this is the guard on the socket itself, not a copy of the
     * caller's. */
    if (!pm->cfg || pm->cfg->proxy || pm->cfg->tunnel) return 0;
    if (!pm->gw6_seen) return 0; /* no usable ::/0 in /proc/net/ipv6_route */
    pm->gw6_tried = 1;
    pm_set_st6(pm, NTX_PM_PENDING); /* from here on the v6 half has a verdict to give */
    if (pm6_link_local(pm->gw6.addr)) {
        unsigned idx = if_nametoindex(pm->gw6.iface);
        /* A link-local address with no resolvable interface is not a gateway this
         * socket can reach: without a scope the kernel has no way to pick a device
         * (and says EINVAL for the attempt), so v6 is skipped for this sequence
         * rather than connected to an address that means nothing. */
        if (idx == 0) {
            pm_set_st6(pm, NTX_PM_NONE);
            return 0;
        }
        pm->gw6_scope = idx;
    }
    int fd = ntx_sock_udp6(); /* AF_INET6, non-blocking, IPV6_V6ONLY=1 */
    if (fd < 0) {
        pm_set_st6(pm, NTX_PM_NONE);
        return 0;
    }
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    memcpy(&sa.sin6_addr, pm->gw6.addr, 16);
    sa.sin6_port = htons(pm_gw6_port());
    sa.sin6_scope_id = pm->gw6_scope;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        pm->gw6_err = errno;
        close(fd);
        pm_set_st6(pm, NTX_PM_NONE);
        return 0;
    }
    /* The client address, straight from the kernel. getsockname failing or answering
     * something the request could not name is a family we know nothing about, so it
     * is skipped rather than mapped with a made-up address (the same reasoning as
     * pm_open's abort on the v4 side, R23).
     *
     * A routable client address is the precondition of the whole sequence: naming a
     * loopback, link-local or unique-local client asks the router to open a port
     * toward an address nothing outside can reach, so the family is SKIPPED — state
     * NONE, nothing ever sent (§8). The connected socket itself stays up: S17b pins
     * the source rule on it, and a socket that only reads is no exposure.
     * pm_client6_cfg is the test's stand-in for the address the kernel picks (see
     * ntx_portmap_test_set_client6); production never sets it and always reads the
     * socket, which is what makes the bytes in `client_ip` the getsockname answer. */
    struct sockaddr_in6 me;
    socklen_t ml = sizeof me;
    memset(&me, 0, sizeof me);
    int have_src = getsockname(fd, (struct sockaddr *)&me, &ml) == 0 && me.sin6_family == AF_INET6;
    if (have_src) memcpy(pm->s6.client_ip, me.sin6_addr.s6_addr, 16);
    if (pm_client6_set) {
        memcpy(pm->s6.client_ip, pm_client6_cfg, 16);
        have_src = 1;
    }
    int routable = have_src && pm6_is_global(pm->s6.client_ip);
    if (!have_src) memset(pm->s6.client_ip, 0, 16); /* nothing to name at all */
    pm->fd6 = fd;
    pm->gw6_connected = 1;
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = pm_on_rw6;
    cbs.cl = pm_on_err6;
    ntx_netx_add(pm->netx, fd, EPOLLIN, pm, &cbs);
    if (!routable) pm_end_seq6(pm, NTX_PM_NONE); /* §8: nothing routable to name */
    return 1;
}

/* EPOLLERR/EPOLLHUP (R9). The error must be read here, in the callback epoll gives
 * for it: an unread SO_ERROR stays pending, the level-triggered event never goes
 * away and the loop stops blocking. */
static void pm_on_err(void *ctx) {
    struct ntx_portmap *pm = (struct ntx_portmap *)ctx;
    if (pm->fd < 0) return;
    int err = pm_drain_err(pm);
    if (err) pm_sock_err(pm, err);
}

/* Read the route, judge whether mapping makes sense, open the gateway socket.
 * Returns 0 when the answer is permanently no (no route, or no NAT in the way). */
static int pm_open(struct ntx_portmap *pm) {
    pm->started = 1;
    uint32_t gw = 0;
    int have = pm_route4(&gw);
    /* R15 / S17a: the v6 default is read and kept on every sequence, whether or not
     * the v4 one answered. */
    struct pm_gw6 g6;
    if (pm_route6(&g6)) {
        pm->gw6 = g6;
        pm->gw6_seen = 1;
    }
    /* S17b: the v6 half is opened from the v6 route ALONE, before the v4 verdict — a
     * host whose v4 default is missing still gets its v6 socket, and a host whose v4
     * gateway refuses still keeps it. The call reads gw6_seen/gw6, writes only the
     * fd6/gw6_* fields, and cannot move the v4 state: `st`, `phase`, `tries`, `gap`,
     * `next_try` and the grants stay whatever the v4 path leaves them.
     * ponytail: the ceiling is that the connected v6 socket is not yet reported
     * anywhere (`st` is still the v4 sequence's alone, which is why a v6-only host
     * still reads NONE). Upgrade path: S17d adds port_map6/ext_port6 and aggregates
     * the two families into the reported `port_map`. */
    (void)pm_open6(pm);
    /* No v4 route means no v4 gateway to dial: the v6 nexthop cannot be widened into
     * one (that v4-mapped read is R15), and the socket here is AF_INET. */
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
    /* A connected UDP socket reports the gateway's ICMP port-unreachable as a
     * pending SO_ERROR, and epoll then holds EPOLLERR asserted until somebody reads
     * it. Without the close callback the loop would never block again (R9: 581 577
     * events in 0,3 s), so pm_on_err is what clears it — and what turns the error
     * into the "no PCP/NAT-PMP here" verdict. */
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = pm_on_rw;
    cbs.cl = pm_on_err;
    pm->fd = fd;
    pm->fam = PM_PCP;
    pm->st = NTX_PM_PENDING;
    ntx_netx_add(pm->netx, fd, EPOLLIN, pm, &cbs);
    return 1;
}

static void pm_stop_now(struct ntx_portmap *pm) {
    if (pm->fd >= 0 && (pm->active[PM_PH_TCP] || pm->active[PM_PH_UDP])) pm_send_deletes(pm);
    /* §11.1 for the v6 mappings too, from the same close budget: the deletes are
     * fire-and-forget, and a v6 half that never mapped anything sends nothing. */
    if (pm->fd6 >= 0 && (pm->s6.active[PM_PH_TCP] || pm->s6.active[PM_PH_UDP])) pm_send_deletes6(pm);
    pm_reset(pm, NTX_PM_OFF);
}

/* Marking a phase failed also cancels the R12 debt for it: the sequence has a verdict
 * for that phase, so nothing is owed on it any more. */
static void pm_fail_phase(struct ntx_portmap *pm, int ph) {
    pm->failed[ph] = 1;
    pm->reacq_at[ph] = 0;
    pm->reacq_gap[ph] = 0;
}

/* A query that ran out of retries — or stated a refusal — for a phase.
 * §8 "brak odpowiedzi bramy … oznacza status „brak" i dalsze działanie bez
 * mapowania". A failed TCP mapping takes UDP with it (a gateway that will not map TCP
 * will not map UDP either); a failed UDP mapping must not disturb the live TCP one.
 *
 * `reask` says which kind of failure this is: 1 when the gateway simply stopped
 * answering (the retransmission budget died, or the socket reports the responder is
 * gone), 0 when it stated a verdict. R14 keeps a stated verdict final for the
 * sequence, and only the silence owes a further ask.
 *
 * R12: when the phase HELD a mapping, that mapping is over either way — the gateway
 * let it expire at the end of its lifetime — so `active` is cleared here. Keeping it
 * set was the defect: `ntx_session_adv_port` went on handing the swarm a port nobody
 * forwards any more (announce, and the BEP 10 `p` of an ext handshake, told peers to
 * dial a dead port), and the renewal loop, which only walks `active && !failed`, never
 * asked for a mapping again, so the driver sat on a stale grant permanently. With the
 * grant gone `adv_port` falls back to the listen port at once, and on a silence the
 * ask goes out again from the re-acquisition arm of the tick, on a backoff of its own.
 * The verdict is not crossed over to the other protocol the way a first acquisition
 * poisons it: this gateway DID map this client once, the other mapping may well be
 * alive, and `failed` on it would cost it its renewals. */
static void pm_give_up_phase(struct ntx_portmap *pm, int ph, int reask) {
    if (ph != PM_PH_ADDR && (pm->active[ph] || pm->reacq_gap[ph] > 0)) {
        pm->active[ph] = 0;
        pm->ext[ph] = 0;
        pm->renew_at[ph] = 0;
        pm->expire_at[ph] = 0;
        pm->failed[ph] = 1;
        if (reask && pm->reacq_gap[ph] > 0) {
            pm->reacq_at[ph] = pm_now() + pm->reacq_gap[ph];
            pm->reacq_gap[ph] = pm->reacq_gap[ph] * 2u > PM_REACQ_MAX_MS ? PM_REACQ_MAX_MS
                                                                         : pm->reacq_gap[ph] * 2u;
            pm->gave_up = 0; /* the tick is what sends the ask */
            /* ACTIVE means "the TCP grant is in place" (`adv_port` reads exactly
             * that), so it is only right while that grant is; PENDING is the honest
             * state for a TCP mapping this driver still owes itself. */
            pm->st = pm->active[PM_PH_TCP] ? NTX_PM_ACTIVE : NTX_PM_PENDING;
        } else {
            /* No re-ask owed (a verdict was stated, or the budget is spent): the phase
             * is failed outright, which is also what drops the debt. */
            pm_fail_phase(pm, ph);
            if (!pm->active[PM_PH_TCP] && !pm->active[PM_PH_UDP]) {
                pm->st = NTX_PM_NONE;
                pm->gave_up = 1; /* nothing owed any more: §8 says "brak" */
            } else if (!pm->active[PM_PH_TCP]) {
                /* UDP is still mapped and TCP is settled for this sequence: ACTIVE
                 * would claim a TCP grant that is gone, and `gave_up` here would stop
                 * the renewals of the live UDP grant. `failed[TCP]` is what keeps the
                 * schedule quiet about TCP from here on. */
                pm->st = NTX_PM_PENDING;
            }
        }
        return;
    }
    pm_fail_phase(pm, ph);
    if (ph != PM_PH_UDP) pm_fail_phase(pm, PM_PH_UDP);
    if (ph == PM_PH_ADDR) {
        pm_fail_phase(pm, PM_PH_TCP);
        pm_fail_phase(pm, PM_PH_UDP);
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
    if (!pm->started) (void)pm_open(pm); /* sets `started`; 0 = the v4 half says no, v6 may still run */

    /* S17c · the v6 family first and independently: its own socket, its own
     * outstanding query, its own retransmission clock, renewals, deferred retry and
     * §8.5 rollback. It returns immediately when there is no v6 socket, and it cannot
     * hold the v4 schedule back — the v4 arms below run from this same tick whether or
     * not a v6 datagram went out, and vice versa. Reading `pm->fd` is what decides the
     * v4 half alone, so a host with no v4 default still gets its v6 sequence driven. */
    pm_tick6(pm);

    if (pm->fd < 0) return;

    /* The §8.5 rollback (R10): the receive path armed this, and the request goes out
     * here — one query per rollback, on a schedule of its own, instead of a datagram
     * from inside pm_on_rw. The fresh query starts the sequence again from TCP. */
    if (pm->lost) {
        pm->lost = 0;
        pm_start_query(pm, PM_PH_TCP, ntx_netx_port(pm->netx));
        return;
    }

    uint64_t now = pm_now();
    if (pm->phase >= 0) {
        if (now < pm->next_try) return;
        int ph = pm->phase;
        if ((uint32_t)pm->tries >= PM_MAX_TRIES) {
            pm->phase = -1;
            pm_give_up_phase(pm, ph, 1);
            return;
        }
        pm_send(pm);
        return;
    }
    if (pm->gave_up) return;

    /* The single deferred retry a retryable refusal promised (R14). It goes out at
     * most once per sequence and the schedule restarts behind it, so a gateway that
     * keeps saying NO_RESOURCES is met by one datagram per wait it names. */
    if (pm->retry_ph >= 0) {
        int ph = pm->retry_ph;
        /* Not yet due: fall through to the renewals below — a deferred retry for
         * one phase must not stall the renew window of a grant we already hold. */
        if (now >= pm->retry_at) {
            pm->retry_ph = -1;
            int first = !pm->retried;
            pm->retried = 1;
            pm->failed[ph] = 0;
            if (ph != PM_PH_UDP) pm->failed[PM_PH_UDP] = 0;
            if (first && pm->st != NTX_PM_ACTIVE) pm->st = NTX_PM_PENDING;
            pm_start_query(pm, ph, ph == PM_PH_ADDR ? 0 : pm->ext[ph]);
            return;
        }
    }

    for (int i = 0; i < PM_NPH; i++)
        if (pm->active[i] && !pm->failed[i] && now >= pm->renew_at[i]) {
            pm_start_query(pm, i, pm->ext[i]); /* keep the granted port across renewals */
            return;
        }

    /* R12: a mapping this driver held and lost (its renewal died) is asked for again,
     * on the doubling backoff of PM_REACQ_MS / PM_REACQ_MAX_MS. It sits behind the
     * renewals — a grant we do hold always comes first — and ahead of the fresh
     * acquisitions, which `failed` already excludes for this phase. The ask is a fresh
     * one: no live grant, so `pm_start_query` draws a new nonce and states no
     * preference (§11.1/§11.2, R13). */
    for (int i = PM_PH_TCP; i < PM_NPH; i++)
        if (pm->reacq_at[i] && now >= pm->reacq_at[i]) {
            pm->reacq_at[i] = 0;
            pm_start_query(pm, i, pm_sugg_port(pm, i));
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
        pm_start_query(pm, PM_PH_UDP, pm_sugg_port(pm, PM_PH_UDP));
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

/* S17c exposes the v6 family's own state and granted port, and nothing reads them
 * yet: ntx_session_portmap_state() — the value stats' `port_map` carries — keeps its
 * v4-only meaning until S17d aggregates the families and renders `port_map6` /
 * `ext_port6`. The distinction that matters for that aggregation is OFF vs the rest:
 * the v6 half was never brought up for this sequence (no route, no driver, mapping
 * off), whereas PENDING/ACTIVE/NONE are verdicts, including the §8 skip of a host
 * with no routable client address.
 * ponytail: the ceiling is that NONE does not distinguish "gateway refused" from "no
 * routable client address" from "schedule ran out"; the diag lines do. Upgrade path is
 * S17d's stats, which wants one number and not the reason. */
ntx_pm_state ntx_session_portmap_state6(const struct ntx_session *s) {
    return s->pm ? (ntx_pm_state)s->pm->s6.st : NTX_PM_OFF;
}

/* The port the v6 gateway forwards, or 0. It is by construction either 0 or the
 * listen port — pm_grant6 deletes a grant that offers anything else — so this can
 * never be a port the swarm should have been told about, which is the point of the
 * rule (`ntx_session_adv_port` stays a v4-only decision). */
uint16_t ntx_session_ext_port6(const struct ntx_session *s) {
    const struct ntx_portmap *pm = s->pm;
    if (!pm || !pm->s6.active[PM_PH_TCP]) return 0;
    return pm->s6.ext[PM_PH_TCP];
}

uint16_t ntx_session_adv_port(const struct ntx_session *s) {
    const struct ntx_portmap *pm = s->pm;
    /* The mapped port is advertised only while the driver actually holds the TCP
     * mapping: `active` is set by a grant and cleared the moment its renewal is given
     * up on (R12), and `expire_at` is the instant the gateway itself stops forwarding
     * it — a renewal that is merely in flight past `renew_at` keeps advertising (the
     * gateway still holds the mapping; dropping the port there would take a working
     * share off the air for nothing), one whose lifetime has run out does not. The UDP
     * mapping is deliberately not consulted: its external port is never advertised
     * anywhere, so a lost UDP grant must not cost the swarm the TCP one. */
    if (pm && pm->st == NTX_PM_ACTIVE && pm->active[PM_PH_TCP] && pm->ext[PM_PH_TCP] &&
        pm_now() < pm->expire_at[PM_PH_TCP])
        return pm->ext[PM_PH_TCP];
    return ntx_netx_port(s->netx);
}
