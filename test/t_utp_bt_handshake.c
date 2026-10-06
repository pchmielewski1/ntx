/* Acceptance: a uTP connection completes the BitTorrent
 * handshake over loopback between two ntx instances.
 *
 * The interop matrix proved the uTP SM + listener wire-healthy (raw
 * BEP29 peer drives SYN/STATE/DATA/FIN fine), but a real BT-over-uTP handshake
 * between two `--utp` instances never reached a handshaked peer: the accepted /
 * dialled virt fd was handed to the session but nothing ever pushed the arriving
 * payload to the session's read pump, so the 68-byte handshake bytes sat in the
 * glue rbuf unread (peers_hs stuck at 0, "hs dump stuck"). This test drives the
 * FULL path — netx shared-socket demux → uTP glue → session BT handshake pump —
 * and asserts a peer reaches PH_OK (pstr verified + infohash matched, i.e. the
 * reserved-bit-bearing handshake was exchanged both ways).
 *
 * Self-contained TU (mirrors t_session.c): every production .c it links is
 * #included, so the single-session globals sess_g_s/sp_g_s are file-scope and the
 * two-session scenario is driven by setting them to the session whose netx loop
 * is about to be pumped. Both instances load the SAME magnet (same info_hash) so
 * sp_match_tts accepts the handshake and promotes the peer to PH_OK. */
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/net/ntx_utp.c"
#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"
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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

/* Same infohash on both sides so sp_match_tts matches the handshake. */
static const char *MAGNET =
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=HS";

/* Count peers held over a uTP virt fd (fd <= -NTX_UTP_VIRT_BASE) in a phase.
 * want_ok: PH_OK reached (handshake fully exchanged + verified). Any phase with
 * a live virt fd counts for "a uTP peer exists". */
static int count_utp_peers(struct ntx_session *s, int want_ok) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        int fd = s->peers[pi].fd;
        if (fd > -NTX_UTP_VIRT_BASE) continue; /* not a uTP virt fd */
        if (want_ok && s->peer_phase[pi] != PH_OK) continue;
        c++;
    }
    return c;
}

/* First peer index holding a uTP virt fd (optionally already PH_OK), or -1. */
static int find_utp_peer(struct ntx_session *s, int want_ok) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        int fd = s->peers[pi].fd;
        if (fd > -NTX_UTP_VIRT_BASE) continue;
        if (want_ok && s->peer_phase[pi] != PH_OK) continue;
        return pi;
    }
    return -1;
}

/* Pump both netx loops once, attributing each loop's I/O callbacks to the
 * session that owns that netx (the single-session globals). */
static void pump_once(struct ntx_session *a, ntx_netx *na,
                      struct ntx_session *b, ntx_netx *nb) {
    sess_g_s = a; sp_g_s = a;
    ntx_netx_run_once(na, 1);
    sess_g_s = b; sp_g_s = b;
    ntx_netx_run_once(nb, 1);
}

/* Data-plane witness: inject one cleartext BT choke/unchoke message from
 * `from`'s PH_OK uTP peer and pump until the RECEIVER's mirrored per-peer
 * choke_us (set only by the MSG_CHOKE/MSG_UNCHOKE receive handlers in
 * sp_process_msgs) reaches `want`, with the receiver's peer still PH_OK.
 * A keystream desync makes the injected bytes decrypt to garbage, which the
 * receiver bad_msg_len-drops first — so peer survival + the observed state
 * transition together prove the message crossed the wire AND parsed VALID. */
static int inject_and_witness(struct ntx_session *from, ntx_netx *nfrom,
                              struct ntx_session *to, ntx_netx *nto,
                              int choked, int want) {
    int pif = find_utp_peer(from, 1);
    if (pif < 0) return 0;
    uint8_t m[5];
    size_t n = ntx_btmsg_build_choke(m, sizeof m, choked);
    if (n != 5) return 0;
    if (ntx_session_peer_send_raw(from, pif, m, n) != 0) return 0;
    for (int i = 0; i < 4000; i++) {
        pump_once(to, nto, from, nfrom);
        int pit = find_utp_peer(to, 1);
        if (pit < 0) return 0; /* receiver dropped the peer: desync/bad_msg_len */
        if (to->peers[pit].choke_us == want) return 1;
    }
    return 0;
}

int main(void) {
    ntx_rng_init();

    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "test/.scratch/14/store";
    cfg.port_lo = 6921;
    cfg.port_hi = 6949;
    cfg.max_peers = 50;
    cfg.allow_local_peers = 1; /* these tests talk to 127.0.0.1 */
    cfg.utp = 1; /* route peer dials + the accept listener over uTP */

    /* A = acceptor/seeder side (listens), B = dialer/leecher side. */
    ntx_netx *na = ntx_netx_init(&cfg);
    ntx_netx *nb = ntx_netx_init(&cfg);
    if (!na || !nb) { printf("FAIL netx-init\n"); return 1; }
    struct ntx_session *a = ntx_session_init(na, &cfg);
    struct ntx_session *b = ntx_session_init(nb, &cfg);
    if (!a || !b) { printf("FAIL session-init\n"); return 1; }

    if (ntx_session_add_magnet(a, MAGNET) != 0) { printf("FAIL magnet-a\n"); return 1; }
    if (ntx_session_add_magnet(b, MAGNET) != 0) { printf("FAIL magnet-b\n"); return 1; }

    uint16_t aport = ntx_netx_port(na);
    check(aport != 0, "acceptor-listen-port");
    /* The shared netx UDP socket is the single datagram owner on the listen
     * port: both the DHT and the uTP listener ride it. */
    check(ntx_netx_udp4_fd(na) >= 0, "shared-udp-owner-bound");

    /* B dials A over the loopback on A's shared-socket port; cfg.utp routes the
     * dial through the uTP glue, so the peer's fd is a virt fd. */
    ntx_addr tgt;
    ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_session_add_peer_from_tracker(b, 0, &tgt, aport);

    int dialer_has_utp = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (b->peers[pi].fd <= -NTX_UTP_VIRT_BASE) dialer_has_utp = 1;
    check(dialer_has_utp, "dial-yields-utp-virt-fd");

    /* Drive both loops until the dialer's peer reaches PH_OK (bounded). */
    int ok = 0;
    for (int i = 0; i < 20000 && !ok; i++) {
        pump_once(a, na, b, nb);
        if (count_utp_peers(b, 1) >= 1) ok = 1;
    }
    check(ok, "dialer-peer-handshaked-ph-ok");

    /* The acceptor must have taken the inbound uTP connection and driven its
     * half of the handshake to PH_OK too (both directions of the 68-byte HS). */
    int accept_ok = 0;
    for (int i = 0; i < 2000 && !accept_ok; i++) {
        pump_once(a, na, b, nb);
        if (count_utp_peers(a, 1) >= 1) accept_ok = 1;
    }
    check(accept_ok, "acceptor-peer-handshaked-ph-ok");

    /* Counters: the shared-socket demux must have seen uTP traffic on the
     * listen port (the SYN/DATA path), and the classifier must not have dropped
     * the handshake as unknown. */
    uint64_t dd = 0, du = 0, dr = 0;
    ntx_netx_demux_stats(na, &dd, &du, &dr);
    check(du >= 1, "demux-utp-counted");

    /* ---- Regression: real post-handshake traffic must leave a uTP
     * peer. Before the fix, out_flush/send_raw gated on `fd < 0` and returned -1 for a
     * live virt fd, so NO BT message could ever leave a uTP peer once it reached
     * PH_OK (the handshake only completed because the PE layer writes directly
     * through ntx_netx_write, masking it). Drive a choke from B's handshaked
     * peer and prove it hits the wire two ways: (a) send_raw now succeeds on a
     * virt fd (the exact regression: it used to return -1), and (b) the
     * acceptor's shared-socket demux sees a NEW uTP datagram beyond the
     * handshake-only baseline — bytes genuinely crossed the peer socket, so the
     * assertion is non-vacuous. (The peer may drop AFTER the message is delivered
     * — a separate, pre-existing uTP+PE keystream desync surfaced by this test and
     * noted separately; it does not affect the send-path proof, which is
     * captured the instant the datagram reaches the peer socket.) */
    int pib = find_utp_peer(b, 1);
    check(pib >= 0, "dialer-utp-peer-index-resolvable");
    uint64_t dd0 = 0, du0 = 0, dr0 = 0;
    ntx_netx_demux_stats(na, &dd0, &du0, &dr0);
    int sent_ok = -1;
    if (pib >= 0) {
        uint8_t choke[8];
        size_t cn = ntx_btmsg_build_choke(choke, sizeof choke, 1);
        if (cn > 0) sent_ok = ntx_session_peer_send_raw(b, pib, choke, cn);
    }
    check(sent_ok == 0, "post-hs-send-raw-succeeds-on-virt-fd");
    int crossed = 0;
    for (int i = 0; i < 400 && !crossed; i++) {
        pump_once(a, na, b, nb);
        uint64_t x, y, z;
        ntx_netx_demux_stats(na, &x, &y, &z);
        if (y > du0) crossed = 1;
    }
    check(crossed, "post-hs-message-crossed-utp-wire");

    /* ---- Regression: session_free must release virt peers through
     * ntx_netx_del, symmetric with session_remove/peer_free. Before the fix it only
     * close()d real fds and skipped the negative virt fd, leaving the glue slot
     * armed with cbs/ctx pointing into the freed session — the next demux tick
     * would call back into freed memory (UAF).
     *
     * This needs a *live, connected* virt peer at the moment of the free, so it
     * uses its own fresh pair (C acceptor / D dialer) and frees D the instant
     * both sides first reach PH_OK — before any post-handshake byte is exchanged.
     * (The a/b pair above has already torn its peers down via the pre-existing
     * post-HS PE desync, so it can't serve as a live-peer fixture.) At that
     * instant D's peer is a connected uTP conn with the session's rw/close cbs
     * bound, so the "armed" pre-check is non-vacuous: peer_connected must read 1
     * before the free and 0 after it. Pumping D's netx afterwards must not crash
     * (a stale armed slot would fire its callbacks into the freed session). */
    ntx_netx *nc = ntx_netx_init(&cfg);
    ntx_netx *nd = ntx_netx_init(&cfg);
    struct ntx_session *c = ntx_session_init(nc, &cfg);
    struct ntx_session *d = ntx_session_init(nd, &cfg);
    if (!c || !d) { printf("FAIL f2-session-init\n"); return 1; }
    ntx_session_add_magnet(c, MAGNET);
    ntx_session_add_magnet(d, MAGNET);
    uint16_t cport = ntx_netx_port(nc);
    ntx_addr tgt2;
    ntx_addr_set_v4(&tgt2, inet_addr("127.0.0.1"));
    ntx_session_add_peer_from_tracker(d, 0, &tgt2, cport);
    int d_ok = 0, c_ok = 0;
    for (int i = 0; i < 20000 && !(d_ok && c_ok); i++) {
        sess_g_s = d; sp_g_s = d;
        ntx_netx_run_once(nd, 1);
        sess_g_s = c; sp_g_s = c;
        ntx_netx_run_once(nc, 1);
        d_ok = count_utp_peers(d, 1) >= 1;
        c_ok = count_utp_peers(c, 1) >= 1;
    }
    check(d_ok && c_ok, "f2-pair-reached-ph-ok");
    int pid = find_utp_peer(d, 1);
    int dfd = (pid >= 0) ? d->peers[pid].fd : -1;
    check(dfd <= -NTX_UTP_VIRT_BASE, "f2-virt-fd-captured");
    check(dfd < 0 && ntx_netx_peer_connected(nd, dfd) == 1,
          "f2-slot-armed-before-free");
    ntx_session_free(d);
    int d_freed = 1;
    check(ntx_netx_peer_connected(nd, dfd) == 0,
          "f2-slot-released-by-session-free");
    /* Drive D's netx loop after its session is gone: a stale armed slot would
     * fire its r/w/close callbacks with ctx into the freed session here. */
    for (int i = 0; i < 50; i++) ntx_netx_run_once(nd, 1);
    check(1, "f2-demux-tick-after-free-no-crash");

    /* ---- uTP+PE RC4 keystream desync: once
     * a uTP peer reaches PH_OK, the first post-handshake message from the side
     * whose send window ever filled decrypts to garbage at the peer (bad_msg_len
     * drop -> FIN cascade). Root cause (verified by keystream-position
     * instrumentation): ntx_utp_virt_write leaked the SM's window/queue-full
     * zero-accept as a plain 0, while every session write path recognizes
     * would-block only as -1/EAGAIN — ntx_session_peer_out_flush read w==0 as
     * fatal and ntx_session_peer_send_raw then DISCARDED the message after
     * ntx_pe_encrypt had already advanced the send RC4. Wire bytes lost,
     * keystream advanced => the peer's recv keystream desyncs and the next
     * message misparses. Fix: virt_write mirrors virt_read's documented
     * non-blocking-socket contract (nothing accepted while alive => -1/EAGAIN),
     * so the message is buffered in peer_out and flushed in order; and
     * sp_peer_ok_poll's `fd < 0` bail (wrong for a live NEGATIVE uTP virt fd)
     * is widened to `fd == -1` (no peer) so the tick drains uTP backlogs.
     * Proof below: data-plane assertions in BOTH directions (known cleartext
     * choke len=1 id=0 parsed VALID at the receiver — peer survives, mirrored
     * choke_us transitions), then sustained bidirectional traffic survival. */
    ntx_netx *ne = ntx_netx_init(&cfg);
    ntx_netx *nf = ntx_netx_init(&cfg);
    struct ntx_session *e = ntx_session_init(ne, &cfg);
    struct ntx_session *f = ntx_session_init(nf, &cfg);
    if (!e || !f) { printf("FAIL f3-session-init\n"); return 1; }
    ntx_session_add_magnet(e, MAGNET);
    ntx_session_add_magnet(f, MAGNET);
    uint16_t eport = ntx_netx_port(ne);
    ntx_addr tgt3;
    ntx_addr_set_v4(&tgt3, inet_addr("127.0.0.1"));
    ntx_session_add_peer_from_tracker(f, 0, &tgt3, eport);
    int e_ok = 0, f_ok = 0;
    for (int i = 0; i < 20000 && !(e_ok && f_ok); i++) {
        sess_g_s = f; sp_g_s = f;
        ntx_netx_run_once(nf, 1);
        sess_g_s = e; sp_g_s = e;
        ntx_netx_run_once(ne, 1);
        e_ok = count_utp_peers(e, 1) >= 1;
        f_ok = count_utp_peers(f, 1) >= 1;
    }
    check(e_ok && f_ok, "f3-pair-reached-ph-ok");
    /* Wire-shape pre-proof of the injected message: choke is len=1 id=0. */
    {
        uint8_t probe[5];
        size_t pn = ntx_btmsg_build_choke(probe, sizeof probe, 1);
        check(pn == 5 && probe[0] == 0 && probe[1] == 0 && probe[2] == 0 &&
                  probe[3] == 1 && probe[4] == 0,
              "f3-injected-msg-is-choke-len1-id0");
    }
    /* E->F first: the direction the old bug left healthy (E's hello burst
     * was fully window-accepted), so a green here proves the harness is not
     * vacuous. F->E second: the direction the bug destroyed (F's hello lost
     * three 5-byte messages to the out_flush -1 path after the window filled).
     * Each leg = unchoke (witness choke_us->0) then choke (witness ->1). */
    /* e2f parse-witness restored unconditionally with the SM frontier split
     * (D21): the send-space send_acked and the derived receive frontier
     * (expected_seq-1) no longer share one field, so dialer-side window
     * recovery is deterministic and the choke_us witness stands. */
    check(inject_and_witness(e, ne, f, nf, 0, 0) &&
              inject_and_witness(e, ne, f, nf, 1, 1),
          "f3-data-plane-e2f-choke-parsed-valid");
    check(inject_and_witness(f, nf, e, ne, 0, 0) &&
              inject_and_witness(f, nf, e, ne, 1, 1),
          "f3-data-plane-f2e-choke-parsed-valid");
    /* Sustain post-handshake traffic both ways and require no drop: the
     * desync would corrupt a later message and bad_msg_len-drop a peer, so
     * survival across the full run is the end-to-end proof. */
    for (int i = 0; i < 1500; i++) {
        int pif = find_utp_peer(f, 1);
        if (pif >= 0 && (i % 8) == 0) {
            uint8_t ck[8];
            size_t cn = ntx_btmsg_build_choke(ck, sizeof ck, 1);
            if (cn > 0) ntx_session_peer_send_raw(f, pif, ck, cn);
        }
        pump_once(e, ne, f, nf);
    }
    check(count_utp_peers(e, 1) >= 1, "f3-acceptor-peer-survives-post-hs-traffic");
    check(count_utp_peers(f, 1) >= 1, "f3-dialer-peer-survives-post-hs-traffic");

    ntx_session_free(a);
    ntx_session_free(b);
    ntx_session_free(c);
    if (!d_freed) ntx_session_free(d);
    ntx_session_free(e);
    ntx_session_free(f);
    ntx_netx_free(na);
    ntx_netx_free(nb);
    ntx_netx_free(nc);
    ntx_netx_free(nd);
    ntx_netx_free(ne);
    ntx_netx_free(nf);

    return fails ? 1 : 0;
}
