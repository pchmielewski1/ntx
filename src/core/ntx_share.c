#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ntx_share.h"
#include "ntx_session_internal.h"
#include "ntx_share_meta.h"
#include "ntx_share_out.h"
#include "ntx_store.h"
#include "ntx_time.h"
#include "../crypto/ntx_rng.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_sha256.h"
#include "../proto/ntx_bencode.h"
#include "../proto/ntx_share_trackers.h"
#include "../proto/ntx_tracker.h"
#include "../ui/ntx_diag.h"

/* --share lifecycle (design §5.1..§5.6). */

/* One tick of hashing costs at most this much wall time: the loop budget of
 * §5.3, well inside the ~50 ms per-iteration ceiling of the plan. */
#define NTX_SHARE_HASH_BUDGET_MS 20
#define NTX_SHARE_READ_BUF (256u * 1024u)
#define NTX_SHARE_WARN_MS 60000u   /* §5.5: one warning after 60 s without READY */
#define NTX_SHARE_FSTAT_MS 1000u   /* §5.5: change detection once per second */
#define NTX_SHARE_REV_BASE_MS 300000u
#define NTX_SHARE_REV_MAX_MS 3600000u
/* Reading a .torrent for --share-from (§5.6). ntx's own builds stay far below
 * this (both hash lists are capped by the parser's 1 MiB string limit), so
 * anything larger is not a metainfo this module was asked to re-share. */
#define NTX_SHARE_FROM_MAX (4u * 1024u * 1024u)

struct ntx_share_slot {
    int fd; /* the only handle to the file: never re-opened by path (§5.1) */
    int ti;
    ntx_share_state st;
    ntx_share_err err;
    ntx_share_hasher *h;
    uint8_t *buf;
    uint64_t size, fed;
    uint32_t ps;
    char name[512];
    char magnet[NTX_SHARE_MAGNET_MAX];
    char torrent_path[NTX_SHARE_PATH_MAX];
    uint8_t ih2[32], sess_ih[20];
    /* §5.6: the validated .torrent, kept until the hash phase proves the bytes
     * match; then it becomes s->tts[ti] and this is emptied. NULL for --share.
     * sess_ih/ih2 stay ZERO while hashing (§5.3), so the two hashes the .torrent
     * claims — known from the moment it is read — live here instead. */
    ntx_torrent *src;
    uint8_t src_ih[20], src_ih2[32];
    int ev_full; /* one share event per slot, however it ends */
    int started_pending; /* §5.5: wait for the port mapping before `started` */
    uint64_t added_at, warn_at, fstat_at;
    int warned;
    struct stat saved; /* §5.5: dev/ino/size/mtime/ctime to re-check */
    /* §5.5: share trackers never stay dead; per-tracker backoff lives here so
     * trk_is_dead and ntx_session_trk.c stay untouched. */
    uint64_t rev_at[NTX_SESSION_MAX_TRK];
    uint8_t rev_lvl[NTX_SESSION_MAX_TRK];
    uint8_t was_dead[NTX_SESSION_MAX_TRK];
};

/* Share clock: real monotonic time plus a test offset, so backoff, the 60 s
 * warning and the 1 s fstat are testable without sleeping. The hash budget
 * deliberately uses the REAL clock — a virtual clock would let one tick hash
 * the whole file and break the §5.3 loop budget. */
static uint64_t share_voff;
static uint64_t share_now_ms(void) { return ntx_mono_ms() + share_voff; }
void ntx_share_test_advance_ms(uint64_t ms) { share_voff += ms; }

/* Queued share events, tagged with the owning slot so removing a torrent
 * drops its pending event (design §13 review focus 2) and a freed address can
 * never resurrect one. */
typedef struct {
    struct ntx_share_slot *owner;
    ntx_share_event ev;
} share_evt;
static share_evt share_evq[NTX_SESSION_MAX_TTS * 2];

static const char *const share_codes[] = {"ok", "bad_arg", "io",     "full",       "no_trackers",
                                          "too_big", "exists", "changed", "bad_arg"};
static const char *const share_msgs[] = {
    "ok",
    "invalid share argument",
    "cannot read the file",
    "too many shared files",
    "no HTTPS share trackers are pinned in this build",
    "file too large to share",
    "this file is already shared",
    "the file changed while sharing",
    "invalid file name"};

const char *ntx_share_err_code(ntx_share_err e) {
    if ((unsigned)e >= sizeof share_codes / sizeof share_codes[0]) return "bad_arg";
    return share_codes[e];
}

const char *ntx_share_err_msg(ntx_share_err e) {
    if ((unsigned)e >= sizeof share_msgs / sizeof share_msgs[0]) return share_msgs[NTX_SHARE_E_BAD_ARG];
    return share_msgs[e];
}

/* Full built-in share list, in list order (§5.4: announce + announce-list + magnet `tr`). */
static int share_trk_list(const char **out, int cap) {
    int n = ntx_share_tracker_count();
    if (n > cap) n = cap;
    for (int i = 0; i < n; i++) {
        const ntx_share_tracker *t = ntx_share_tracker_get(i);
        if (!t || !t->url) return i;
        out[i] = t->url;
    }
    return n;
}

static void share_evq_drop(struct ntx_session *s, struct ntx_share_slot *sl) {
    (void)s;
    for (size_t i = 0; i < sizeof share_evq / sizeof share_evq[0]; i++)
        if (share_evq[i].owner == sl) share_evq[i].owner = NULL;
}

static void share_evq_push(struct ntx_share_slot *sl) {
    if (!sl || sl->ev_full) return;
    for (size_t i = 0; i < sizeof share_evq / sizeof share_evq[0]; i++) {
        if (share_evq[i].owner) continue;
        ntx_share_event *ev = &share_evq[i].ev;
        memset(ev, 0, sizeof *ev);
        ev->i = sl->ti;
        ev->ok = sl->st == NTX_SHARE_READY;
        ev->err = ev->ok ? NTX_SHARE_OK : sl->err;
        memcpy(ev->ih, sl->sess_ih, 20); /* zeros while hashing, the real hash at READY */
        memcpy(ev->ih2, sl->ih2, 32);
        snprintf(ev->name, sizeof ev->name, "%s", sl->name);
        snprintf(ev->magnet, sizeof ev->magnet, "%s", sl->magnet);
        snprintf(ev->torrent_path, sizeof ev->torrent_path, "%s", sl->torrent_path);
        share_evq[i].owner = sl;
        sl->ev_full = 1; /* one event per share, however it ends */
        return;
    }
    sl->ev_full = 1;
}

/* The validated copy of a --share-from .torrent holds exactly what
 * ntx_torrent_validate_metainfo allocated, so it is released with the same
 * public contract the session slot teardown uses. The store of this copy is
 * never opened, so there is no fd to close. */
static void share_src_release(ntx_torrent *t) {
    if (!t) return;
    ntx_torrent_release(t);
}

static void share_src_free(ntx_torrent *t) {
    if (!t) return;
    share_src_release(t);
    free(t);
}

static void share_free_slot(struct ntx_session *s, int ti) {
    struct ntx_share_slot *sl = s->share[ti];
    if (!sl) return;
    share_evq_drop(s, sl);
    if (sl->fd >= 0) close(sl->fd);
    ntx_share_hasher_free(sl->h);
    free(sl->buf);
    share_src_free(sl->src);
    free(sl);
    s->share[ti] = NULL;
    s->tts_enc_strict[ti] = 0; /* session-level, set by share_add: ours to clear */
    s->trk_started_ok[ti] = 0;
    memset(s->trk_pin_fail[ti], 0, sizeof s->trk_pin_fail[ti]);
}

static void share_fail(struct ntx_session *s, struct ntx_share_slot *sl, ntx_share_err e) {
    if (!sl || sl->st == NTX_SHARE_FAILED) return;
    sl->st = NTX_SHARE_FAILED;
    sl->err = e;
    sl->started_pending = 0;
    share_evq_push(sl);
    /* The slot keeps its fd and (if any) store; serving is refused by
     * ntx_session_share_serving and the UI shows share=2 / code. */
    if (s && s->cfg && s->cfg->verbose)
        ntx_diag("ntx: share fail ti=%d %s (%s)\n", sl->ti, ntx_share_err_code(e), sl->name);
}

/* §5.5 all-trackers-pin-fail wording, stated once per share. */
static void share_warn_all_pinned(struct ntx_session *s, struct ntx_share_slot *sl) {
    if (sl->warned) return;
    int n = s->trk_n[sl->ti];
    if (n <= 0) return;
    int all = 1;
    for (int k = 0; k < n; k++)
        if (!s->trk_pin_fail[sl->ti][k]) all = 0;
    if (!all) return;
    sl->warned = 1;
    ntx_diag("ntx: share %s: keys in this ntx build are out of date or a MITM is in progress; "
             "update ntx\n", sl->name);
}

static void share_warn_slow(struct ntx_session *s, struct ntx_share_slot *sl, uint64_t now) {
    if (sl->warned || now < sl->warn_at) return;
    sl->warned = 1;
    int n = s->trk_n[sl->ti];
    int ok = 0, dead = 0, pinned = 0;
    for (int k = 0; k < n; k++) {
        if (s->trk_pin_fail[sl->ti][k]) pinned++;
        if (s->trk_fail[sl->ti][k] >= NTX_TRK_MAX_FAIL) dead++;
        if (s->trk_fail[sl->ti][k] == 0) ok++;
    }
    ntx_diag("ntx: share %s not ready after %llus: trackers ok=%d dead=%d pinned=%d of %d\n", sl->name,
             (unsigned long long)(NTX_SHARE_WARN_MS / 1000), ok, dead, pinned, n);
}

/* §5.5: dead share trackers are revived here (trk_is_dead is not edited). A
 * tracker rejected for a bad pin is never retried in this session. */
static void share_revive_trackers(struct ntx_session *s, struct ntx_share_slot *sl, uint64_t now) {
    int n = s->trk_n[sl->ti];
    if (n > NTX_SESSION_MAX_TRK) n = NTX_SESSION_MAX_TRK;
    for (int k = 0; k < n; k++) {
        int dead = s->trk_fail[sl->ti][k] >= NTX_TRK_MAX_FAIL;
        if (!dead) {
            if (sl->was_dead[k]) {
                sl->was_dead[k] = 0;
                sl->rev_lvl[k] = 0;
                sl->rev_at[k] = 0;
            }
            continue;
        }
        if (s->trk_pin_fail[sl->ti][k]) continue; /* fail-closed */
        if (!sl->was_dead[k]) {
            sl->was_dead[k] = 1;
            uint64_t bo = NTX_SHARE_REV_BASE_MS;
            for (int b = 0; b < sl->rev_lvl[k] && bo < NTX_SHARE_REV_MAX_MS; b++) bo *= 2;
            if (bo > NTX_SHARE_REV_MAX_MS) bo = NTX_SHARE_REV_MAX_MS;
            sl->rev_at[k] = now + bo;
            continue;
        }
        if (now < sl->rev_at[k]) continue;
        s->trk_fail[sl->ti][k] = (uint8_t)(NTX_TRK_MAX_FAIL - 1);
        s->trk_next[sl->ti] = 0;
        sl->was_dead[k] = 0;
        if (sl->rev_lvl[k] < 8) sl->rev_lvl[k]++;
    }
}

static int share_hash_tick(struct ntx_session *s, struct ntx_share_slot *sl);

/* §5.5 readiness tail: the fd snapshot the 1 s fstat compares against, then
 * ANNOUNCING with `started` held back for the mapping. */
static void share_announce(struct ntx_session *s, struct ntx_share_slot *sl) {
    s->tts[sl->ti].state = NTX_TTS_DONE;
    sl->st = NTX_SHARE_ANNOUNCING;
    sl->started_pending = 1; /* §5.5: only after the port mapping settled */
    sl->warn_at = share_now_ms() + NTX_SHARE_WARN_MS;
    sl->fstat_at = share_now_ms() + NTX_SHARE_FSTAT_MS;
}

/* §5.6.3: the piece hashes the file produced, against the two lists the
 * .torrent claims. A short read, a truncated or rewritten file lands here with
 * bytes that do not match — that is the `changed` of §5.6, never a share. */
static int share_verify_cmp(const struct ntx_share_slot *sl) {
    const ntx_torrent *src = sl->src;
    size_t ln = 0;
    const uint8_t *lay = ntx_share_hasher_layer(sl->h, &ln);
    const uint8_t *want = src->piece_layer;
    if (!lay != !want || ln != src->piece_layer_n) return -1;
    if (ln && memcmp(lay, want, ln) != 0) return -1;
    const uint8_t *sh = ntx_share_hasher_sha1(sl->h);
    return sh && src->phash && memcmp(sh, src->phash, (size_t)src->np * 20) == 0 ? 0 : -1;
}

/* §5.6: --share-from. The bytes were compared with the .torrent in the hash
 * phase, so the metainfo is not rebuilt — it IS the one read at share_add and
 * the link therefore cannot change. The .torrent is NOT rewritten (§5.6.5) and
 * the magnet is rebuilt from the CURRENT pinned list (§5.6.4); the tracker list
 * is not part of `info`, so that changes nothing about the hash. */
static int share_finish_from(struct ntx_session *s, struct ntx_share_slot *sl) {
    ntx_torrent *t = &s->tts[sl->ti];
    ntx_torrent *src = sl->src;

    if (share_verify_cmp(sl) != 0) return share_fail(s, sl, NTX_SHARE_E_CHANGED), -1;

    /* Review focus 5: one info-hash may live in exactly one slot, because
     * sp_match_tts returns the FIRST match and a second slot with the same hash
     * could never be reached by an incoming handshake. Checked before anything
     * is published, so the share that got there first is untouched. */
    for (int j = 0; j < NTX_SESSION_MAX_TTS; j++) {
        if (j == sl->ti || !s->share[j] || s->share[j]->st == NTX_SHARE_FAILED) continue;
        if (s->tts[j].np && memcmp(s->tts[j].info_hash, sl->src_ih, 20) == 0)
            return share_fail(s, sl, NTX_SHARE_E_EXISTS), -1;
    }

    const char *trks[NTX_SESSION_MAX_TRK];
    int ntrk = share_trk_list(trks, NTX_SESSION_MAX_TRK);
    if (ntrk < 1) return share_fail(s, sl, NTX_SHARE_E_NO_TRACKERS), -1;

    /* Publish the metainfo on the slot. The hash gate is the verification that
     * just ran, so the gate passes by construction; validate fills phash/ps/np/
     * size/name from the very bytes the file matched. `have`/`rarity`/`phash`
     * are fresh allocations, freed with the slot. */
    ntx_torrent_init_meta(t, sl->src_ih);
    memcpy(t->info_hash_v2, sl->src_ih2, 32);
    t->meta_version = 2;
    t->priv = 1;
    s->tts_enc_strict[sl->ti] = 1;
    /* NULL layers: hybrid, so the v1 SHA-1 list in `info` is the gate's own
     * check; the BEP 52 layers were just compared against the file itself. */
    int rc = ntx_torrent_validate_metainfo(t, src->info_raw, src->info_raw_n, NULL, 0);
    if (rc == 0 && src->piece_layer_n) {
        /* keep the layers: ntx_torrent_piece_complete_from and the BEP 52 hash
         * exchange (msgs 21..23) both answer from them */
        t->piece_layer = malloc(src->piece_layer_n);
        if (!t->piece_layer) rc = -1;
        else {
            memcpy(t->piece_layer, src->piece_layer, src->piece_layer_n);
            t->piece_layer_n = src->piece_layer_n;
        }
    }
    share_src_free(sl->src);
    sl->src = NULL;
    if (rc != 0) return share_fail(s, sl, NTX_SHARE_E_CHANGED), -1;
    if (t->np == 0 || t->size != sl->size || t->ps != sl->ps)
        return share_fail(s, sl, NTX_SHARE_E_CHANGED), -1;

    if (ntx_store_open_ro_fd(&t->store, sl->fd, sl->size, sl->ps) != 0)
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    for (uint32_t i = 0; i < t->np; i++) {
        t->have[i] = 1;
        t->store.pmap[i] = 2;
    }
    t->have_n = t->np;
    t->verified_B = t->size;
    t->pre_complete = 1;
    t->have_meta = 1; /* trk_left (left=0 of §5.5) and ntx_torrent_done read it */

    if (ntx_share_magnet(sl->magnet, sizeof sl->magnet, sl->src_ih, sl->src_ih2, sl->name, trks, ntrk) != 0)
        return share_fail(s, sl, NTX_SHARE_E_BAD_ARG), -1;
    memcpy(sl->sess_ih, sl->src_ih, 20);
    memcpy(sl->ih2, sl->src_ih2, 32);
    if (fstat(sl->fd, &sl->saved) != 0) return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    share_announce(s, sl);
    if (s->cfg && s->cfg->verbose)
        ntx_diag("ntx: share %s verified against %s\n", sl->name, sl->torrent_path);
    return 0;
}

/* §5.2 + §5.4: info dict (random salt) -> hash gate through the same validator
 * as a download -> read-only store over the held fd -> atomic .torrent. */
static int share_finish(struct ntx_session *s, struct ntx_share_slot *sl) {
    if (sl->src) return share_finish_from(s, sl);
    ntx_torrent *t = &s->tts[sl->ti];
    const char *trks[NTX_SESSION_MAX_TRK];
    int ntrk = share_trk_list(trks, NTX_SESSION_MAX_TRK);
    if (ntrk < 1) return share_fail(s, sl, NTX_SHARE_E_NO_TRACKERS), -1;

    char salt[33];
    uint8_t raw[16];
    ntx_rand_bytes(raw, sizeof raw);
    for (int i = 0; i < 16; i++) snprintf(salt + (size_t)i * 2, 3, "%02x", raw[i]);

    uint8_t *info = NULL, *tbuf = NULL;
    size_t info_n = 0, tbuf_n = 0;
    if (ntx_share_build_info(sl->h, sl->name, salt, &info, &info_n) != 0)
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    /* The hybrid wire/announce hash is SHA-1(info) (the v1 half), not the
     * trunc20(sha256) that ntx_torrent_metainfo_hash returns for meta version 2
     * — and ntx_share_write_torrent gates on exactly that SHA-1. */
    uint8_t ih[20], ih2[32];
    ntx_sha1(info, info_n, ih);
    ntx_sha256(info, info_n, ih2);
    if (ntx_share_build_torrent(info, info_n, sl->h, trks, ntrk, (int64_t)time(NULL), &tbuf, &tbuf_n) != 0) {
        free(info);
        free(tbuf);
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    }

    /* The validator wants the raw top-level "piece layers" dict, exactly as a
     * download gets it out of the parsed metainfo. */
    const uint8_t *layers = NULL;
    size_t layers_n = 0;
    ntx_be top;
    size_t consumed = 0;
    if (ntx_be_parse(tbuf, tbuf_n, &top, &consumed, 32, tbuf_n + 1) == 0) {
        const ntx_be *pl = ntx_be_dict_get(&top, "piece layers");
        if (pl && pl->t == NTX_BE_DICT && pl->end > pl->start) {
            layers = tbuf + pl->start;
            layers_n = pl->end - pl->start;
        }
        ntx_be_free(&top);
    }

    /* Fresh slot state with the REAL hashes: the hash gate needs both halves
     * of the hybrid before validate (same order test/t_share_meta.c uses). */
    ntx_torrent_init_meta(t, ih);
    memcpy(t->info_hash_v2, ih2, 32);
    t->meta_version = 2;
    t->priv = 1;
    s->tts_enc_strict[sl->ti] = 1;
    if (ntx_torrent_validate_metainfo(t, info, info_n, layers, layers_n) != 0) {
        free(info);
        free(tbuf);
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    }
    free(info);
    info = NULL;

    if (ntx_store_open_ro_fd(&t->store, sl->fd, sl->size, sl->ps) != 0) {
        free(tbuf);
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    }
    /* The author is the only source: every piece is present by construction, so
     * mark them all instead of reading 2 TiB back through verify_range. */
    for (uint32_t i = 0; i < t->np; i++) {
        t->have[i] = 1;
        t->store.pmap[i] = 2;
    }
    t->have_n = t->np;
    t->verified_B = t->size;
    t->pre_complete = 1;
    /* validate_metainfo leaves this to the store-open path a download uses; the
     * read-only store over the share fd never sets it, and trk_left (left=0 of
     * §5.5) plus ntx_torrent_done both read it. */
    t->have_meta = 1;
    /* have_meta is normally set by ntx_torrent_open_store, the write half a
     * share never calls; without it trk_left reports "unknown size" instead of
     * the left=0 the §5.5 readiness definition demands. */
    t->have_meta = 1;

    for (int j = 0; j < NTX_SESSION_MAX_TTS; j++) {
        if (j == sl->ti || !s->share[j] || s->share[j]->st == NTX_SHARE_FAILED) continue;
        if (s->tts[j].np && memcmp(s->tts[j].info_hash, ih, 20) == 0) {
            ntx_store_close(&t->store);
            free(tbuf);
            return share_fail(s, sl, NTX_SHARE_E_EXISTS), -1;
        }
    }

    const char *dir = (s->cfg && s->cfg->store_dir && s->cfg->store_dir[0]) ? s->cfg->store_dir : "downloads";
    if (ntx_share_torrent_path(sl->torrent_path, sizeof sl->torrent_path, dir, sl->name, ih) != 0) {
        ntx_store_close(&t->store);
        free(tbuf);
        return share_fail(s, sl, NTX_SHARE_E_BAD_ARG), -1;
    }
    ntx_share_err we = ntx_share_write_torrent(sl->torrent_path, tbuf, tbuf_n, ih);
    free(tbuf);
    if (we != NTX_SHARE_OK) {
        ntx_store_close(&t->store);
        share_fail(s, sl, we);
        return -1;
    }
    if (ntx_share_magnet(sl->magnet, sizeof sl->magnet, ih, ih2, sl->name, trks, ntrk) != 0) {
        ntx_store_close(&t->store);
        return share_fail(s, sl, NTX_SHARE_E_BAD_ARG), -1;
    }
    memcpy(sl->sess_ih, ih, 20);
    memcpy(sl->ih2, ih2, 32);
    if (fstat(sl->fd, &sl->saved) != 0) {
        ntx_store_close(&t->store);
        return share_fail(s, sl, NTX_SHARE_E_IO), -1;
    }
    share_announce(s, sl); /* §5.5: the same readiness tail as --share-from */
    return 0;
}

static int share_hash_tick(struct ntx_session *s, struct ntx_share_slot *sl) {
    uint64_t t0 = ntx_mono_ms();
    while (sl->fed < sl->size) {
        size_t want = (size_t)(sl->size - sl->fed);
        if (want > NTX_SHARE_READ_BUF) want = NTX_SHARE_READ_BUF;
        ssize_t r = pread(sl->fd, sl->buf, want, (off_t)sl->fed);
        if (r <= 0) return share_fail(s, sl, NTX_SHARE_E_IO), -1;
        /* -1 means the file grew, shrank or a fold failed: never retry it. */
        if (ntx_share_hasher_feed(sl->h, sl->buf, (size_t)r) != 0)
            return share_fail(s, sl, NTX_SHARE_E_CHANGED), -1;
        sl->fed += (uint64_t)r;
        if (ntx_mono_ms() - t0 >= NTX_SHARE_HASH_BUDGET_MS) break;
    }
    if (sl->fed >= sl->size && ntx_share_hasher_done(sl->h)) return share_finish(s, sl);
    return 0;
}

static void share_changed(struct ntx_session *s, struct ntx_share_slot *sl) {
    ntx_torrent *t = &s->tts[sl->ti];
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] != sl->ti || s->peer_phase[pi] != PH_OK || s->peers[pi].fd == -1) continue;
        if (!s->peers[pi].we_choke) {
            ntx_peer_set_we_choke(&s->peers[pi], 1);
            ntx_session_peer_send_choke(s, pi, 1);
        }
    }
    ntx_diag("ntx: share %s changed on disk, stopping\n", sl->name);
    if (t->state != NTX_TTS_DEAD) ntx_session_trk_stop(s, sl->ti); /* §5.5: stopped */
    share_fail(s, sl, NTX_SHARE_E_CHANGED);
}

static int share_stat_differs(const struct stat *a, const struct stat *b) {
    return a->st_dev != b->st_dev || a->st_ino != b->st_ino || a->st_size != b->st_size ||
           a->st_mtim.tv_sec != b->st_mtim.tv_sec || a->st_mtim.tv_nsec != b->st_mtim.tv_nsec ||
           a->st_ctim.tv_sec != b->st_ctim.tv_sec || a->st_ctim.tv_nsec != b->st_ctim.tv_nsec;
}

/* §5.6.1: read and accept the .torrent a --share-from must match. Everything
 * that can be decided before a single file byte is hashed is decided here, so a
 * mismatch is a synchronous BAD_ARG and never a share that dies later. The
 * metainfo is filled into *out (heap fields owned by the caller) together with
 * both halves of the hybrid hash, exactly as share_finish derives them. */
static ntx_share_err share_from_read(const char *path, uint64_t fsize, ntx_torrent *out, uint8_t ih[20],
                                     uint8_t ih2[32]) {
    ntx_share_err e = NTX_SHARE_E_BAD_ARG;
    FILE *f = fopen(path, "rb");
    if (!f) return e;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return e; }
    long sz = ftell(f);
    if (sz <= 0 || (uint64_t)sz > NTX_SHARE_FROM_MAX) { fclose(f); return e; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return e; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return e; }

    ntx_be top;
    size_t consumed = 0;
    if (ntx_be_parse(buf, rd, &top, &consumed, 32, (size_t)1 << 20) != 0) { free(buf); return e; }
    const ntx_be *info = ntx_be_dict_get(&top, "info");
    const ntx_be *layers = ntx_be_dict_get(&top, "piece layers");
    if (!info || info->t != NTX_BE_DICT || info->end <= info->start) {
        ntx_be_free(&top);
        free(buf);
        return e;
    }
    const uint8_t *ib = buf + info->start;
    size_t ibn = info->end - info->start;

    /* §5.6.1: private, one file, and the length is the file's length. */
    const ntx_be *pv = ntx_be_dict_get(info, "private");
    if (!pv || pv->t != NTX_BE_INT || pv->i == 0) {
        ntx_be_free(&top);
        free(buf);
        return e;
    }
    const ntx_be *psbe = ntx_be_dict_get(info, "piece length");
    const ntx_be *pieces = ntx_be_dict_get(info, "pieces");
    const ntx_be *lenbe = ntx_be_dict_get(info, "length");
    if (!psbe || psbe->t != NTX_BE_INT || !lenbe || lenbe->t != NTX_BE_INT || (uint64_t)lenbe->i != fsize ||
        !pieces || pieces->t != NTX_BE_STR || pieces->sn == 0 || pieces->sn % 20 != 0) {
        ntx_be_free(&top);
        free(buf);
        return e;
    }
    uint64_t ps64 = (uint64_t)psbe->i;
    if (ps64 < NTX_SHARE_PIECE_MIN || ps64 > NTX_SHARE_PIECE_MAX || (ps64 & (ps64 - 1)) != 0 ||
        (fsize + ps64 - 1) / ps64 != pieces->sn / 20) {
        ntx_be_free(&top);
        free(buf);
        return e;
    }
    /* The hybrid pair: SHA-1(info) is the wire/announce hash, SHA-256(info) the
     * v2 root, and the validator's gate wants both before it parses. */
    ntx_sha1(ib, ibn, ih);
    ntx_sha256(ib, ibn, ih2);
    ntx_torrent_init_meta(out, ih);
    memcpy(out->info_hash_v2, ih2, 32);
    out->meta_version = 2;
    int ok = ntx_torrent_validate_metainfo(out, ib, ibn,
                                           layers && layers->t == NTX_BE_DICT ? buf + layers->start : NULL,
                                           layers && layers->t == NTX_BE_DICT ? layers->end - layers->start : 0) == 0;
    ntx_be_free(&top);
    free(buf);
    /* Hybrid, one file, both hash lists: the hash phase compares the file against
     * the v1 SHA-1 list AND the BEP 52 layers, so a .torrent that carries only
     * one of them (or a second file) is not something ntx was asked to re-share.
     * A whole-file root needs no top-level "piece layers" (np == 1), exactly as
     * share_finish builds its own. */
    if (!ok || out->priv == 0 || out->hybrid != 1 || out->v2_nfiles != 1 || out->size != fsize ||
        out->np == 0 || !out->phash || out->ps != (uint32_t)ps64 || !ntx_share_name_ok(out->name) ||
        (out->np > 1 && !out->piece_layer)) {
        share_src_release(out);
        return e;
    }
    return NTX_SHARE_OK;
}

int ntx_session_share_add(ntx_session *s, const char *path, const char *from_torrent, ntx_share_err *err) {
    if (err) *err = NTX_SHARE_E_BAD_ARG;
    if (!s || !path || !path[0]) return -1;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = NTX_SHARE_E_IO;
        return -1;
    }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) || sb.st_size <= 0) {
        close(fd);
        if (err) *err = NTX_SHARE_E_IO;
        return -1;
    }
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    /* §5.6.1: with --share-from the name on disk may differ — the name inside
     * the .torrent is the one that stays, and it is validated there. */
    if (!from_torrent && !ntx_share_name_ok(bn)) {
        close(fd);
        if (err) *err = NTX_SHARE_E_BAD_NAME;
        return -1;
    }
    /* §5.6: everything decidable about the metainfo is decided before a byte of
     * the file is hashed, so a wrong .torrent is a synchronous BAD_ARG. */
    ntx_torrent *src = NULL;
    uint8_t src_ih[20] = {0}, src_ih2[32] = {0};
    uint32_t ps = 0;
    if (from_torrent) {
        src = calloc(1, sizeof *src);
        if (!src) {
            close(fd);
            if (err) *err = NTX_SHARE_E_IO;
            return -1;
        }
        ntx_share_err fe = share_from_read(from_torrent, (uint64_t)sb.st_size, src, src_ih, src_ih2);
        if (fe != NTX_SHARE_OK) {
            share_src_free(src);
            close(fd);
            if (err) *err = fe;
            return -1;
        }
        ps = src->ps; /* the piece length comes from the .torrent, never re-picked */
    } else if (smeta_piece_len((uint64_t)sb.st_size, &ps) != 0) { /* > 32 768 pieces */
        close(fd);
        if (err) *err = NTX_SHARE_E_TOO_BIG;
        return -1;
    }
    if (!ntx_share_available()) {
        close(fd);
        share_src_free(src);
        if (err) *err = NTX_SHARE_E_NO_TRACKERS;
        return -1;
    }
    int ti = ntx_session_free_slot(s);
    if (ti < 0) {
        close(fd);
        share_src_free(src);
        if (err) *err = NTX_SHARE_E_FULL;
        return -1;
    }
    ntx_share_hasher *h = ntx_share_hasher_new((uint64_t)sb.st_size, ps);
    uint8_t *rbuf = malloc(NTX_SHARE_READ_BUF);
    if (!h || !rbuf) {
        ntx_share_hasher_free(h);
        free(rbuf);
        close(fd);
        share_src_free(src);
        if (err) *err = NTX_SHARE_E_IO;
        return -1;
    }

    struct ntx_share_slot *sl = calloc(1, sizeof *sl);
    if (!sl) {
        ntx_share_hasher_free(h);
        free(rbuf);
        close(fd);
        share_src_free(src);
        if (err) *err = NTX_SHARE_E_IO;
        return -1;
    }
    sl->fd = fd;
    sl->ti = ti;
    sl->st = NTX_SHARE_HASHING;
    sl->h = h;
    sl->buf = rbuf;
    sl->size = (uint64_t)sb.st_size;
    sl->ps = ps;
    sl->added_at = share_now_ms();
    if (src) { /* §5.6: the name and the path stay the ones of the .torrent */
        sl->src = src;
        memcpy(sl->src_ih, src_ih, 20);
        memcpy(sl->src_ih2, src_ih2, 32);
        snprintf(sl->name, sizeof sl->name, "%s", src->name);
        snprintf(sl->torrent_path, sizeof sl->torrent_path, "%s", from_torrent);
    } else {
        snprintf(sl->name, sizeof sl->name, "%s", bn);
    }

    ntx_session_hash_reset(s, ti);
    uint8_t zeros[20] = {0};
    /* ponytail: init_meta on a reused slot matches what add_magnet does; the
     * DEAD-slot teardown in ntx_session_remove owns the previous field set. */
    ntx_torrent_init_meta(&s->tts[ti], zeros); /* §5.3: ih stays 40 zeros until hashed */
    s->tts[ti].state = NTX_TTS_VERIFY;
    s->tts[ti].priv = 1; /* BEP27: a share is private by definition (§4) */
    s->tts_enc_strict[ti] = 1;
    s->trk_n[ti] = 0;
    memset(s->trk_urls[ti], 0, sizeof s->trk_urls[ti]);
    for (int k = 0; k < ntx_share_tracker_count() && k < NTX_SESSION_MAX_TRK; k++) {
        const ntx_share_tracker *tk = ntx_share_tracker_get(k);
        if (!tk || !tk->url) break;
        snprintf(s->trk_urls[ti][k], sizeof s->trk_urls[ti][k], "%s", tk->url);
        s->trk_n[ti] = k + 1;
    }
    if (ti >= s->n_tts) s->n_tts = ti + 1;
    s->share[ti] = sl;
    ntx_session_portmap_want(s, 1); /* §8: map the port while any share is live */
    if (err) *err = NTX_SHARE_OK;
    return ti;
}

int ntx_session_share_poll_event(ntx_session *s, ntx_share_event *ev) {
    if (!s || !ev) return 0;
    for (size_t i = 0; i < sizeof share_evq / sizeof share_evq[0]; i++) {
        if (!share_evq[i].owner || share_evq[i].owner->ti < 0) continue;
        if (share_evq[i].owner->st == NTX_SHARE_HASHING) continue; /* nothing to report yet */
        int ti = share_evq[i].owner->ti;
        if (s->share[ti] != share_evq[i].owner) continue; /* stale slot, drop it */
        *ev = share_evq[i].ev;
        share_evq[i].owner = NULL;
        return 1;
    }
    return 0;
}

ntx_share_state ntx_session_share_state(const ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS || !s->share[ti]) return NTX_SHARE_NONE;
    return s->share[ti]->st;
}

uint32_t ntx_session_share_pct(const ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS) return 0;
    const struct ntx_share_slot *sl = s->share[ti];
    if (!sl || sl->st != NTX_SHARE_HASHING || sl->size == 0) return 0;
    return (uint32_t)((sl->fed * 100) / sl->size);
}

int ntx_session_share_serving(const ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS) return 1;
    const struct ntx_share_slot *sl = s->share[ti];
    if (!sl) return 1;
    return sl->st == NTX_SHARE_ANNOUNCING || sl->st == NTX_SHARE_READY;
}

/* §5.6: a pread that came back short or with EIO *while serving*. data_serve has
 * already refused the request; the share itself must not keep advertising itself
 * as serving, so it parks in FAILED/IO. No-op for plain torrents (sl == NULL),
 * which is what keeps the call free for the download path.
 * ponytail: no choke/stopped here, unlike share_changed — §5.6 asks only for the
 * refusal plus FAILED/IO, and ntx_session_share_serving gates every later
 * request. Upgrade path: route this through share_changed if a read error should
 * also send `stopped`. */
void ntx_session_share_io_failed(struct ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS) return;
    struct ntx_share_slot *sl = s->share[ti];
    if (!sl) return;
    share_fail(s, sl, NTX_SHARE_E_IO);
}

void ntx_session_share_tick(struct ntx_session *s) {
    if (!s) return;
    uint64_t now = share_now_ms();
    for (int ti = 0; ti < NTX_SESSION_MAX_TTS; ti++) {
        struct ntx_share_slot *sl = s->share[ti];
        if (!sl || s->tts[ti].state == NTX_TTS_DEAD) continue;
        if (sl->st == NTX_SHARE_HASHING) {
            share_hash_tick(s, sl);
            continue;
        }
        if (sl->st != NTX_SHARE_ANNOUNCING && sl->st != NTX_SHARE_READY) continue;

        /* §5.5: `started` waits for the mapping to settle (never PENDING), and
         * left=0 follows from verified_B == size set in share_finish. */
        if (sl->started_pending && ntx_session_portmap_state(s) != NTX_PM_PENDING) {
            sl->started_pending = 0;
            ntx_session_trk_announce(s, ti, NTX_TRACKER_EVENT_STARTED);
        }
        /* §5.5: ready = hashed + .torrent written + mapping settled + one pinned
         * tracker answered `started`; then exactly one ok event with the magnet. */
        if (sl->st == NTX_SHARE_ANNOUNCING && s->trk_started_ok[ti]) {
            sl->st = NTX_SHARE_READY;
            share_evq_push(sl);
            if (s->cfg && s->cfg->verbose)
                ntx_diag("ntx: shared — %s (torrent %s)\n", sl->name, sl->torrent_path);
        }
        share_revive_trackers(s, sl, now);
        share_warn_all_pinned(s, sl);
        if (sl->st == NTX_SHARE_ANNOUNCING) share_warn_slow(s, sl, now);

        if (now >= sl->fstat_at) { /* §5.5: fstat on the held fd, once a second */
            sl->fstat_at = now + NTX_SHARE_FSTAT_MS;
            struct stat cur;
            if (fstat(sl->fd, &cur) != 0 || share_stat_differs(&sl->saved, &cur)) {
                share_changed(s, sl);
                continue;
            }
        }
    }
}

void ntx_session_share_on_remove(struct ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS) return;
    struct ntx_share_slot *sl = s->share[ti];
    if (!sl) return;
    int was_hashing = sl->st == NTX_SHARE_HASHING;
    share_free_slot(s, ti); /* drops the queued event too (§13 focus 2) */
    if (was_hashing) {
        /* Nothing was announced and nothing may be: trk_stop only fires for
         * META/DL/DONE, and the slot is still VERIFY at this point. */
        s->tts[ti].state = NTX_TTS_VERIFY;
    }
    for (int k = 0; k < NTX_SESSION_MAX_TTS; k++)
        if (s->share[k]) return;
    ntx_session_portmap_want(s, 0); /* last share gone: release the mapping (§8) */
}

void ntx_session_share_free(struct ntx_session *s) {
    if (!s) return;
    for (int ti = 0; ti < NTX_SESSION_MAX_TTS; ti++)
        if (s->share[ti]) share_free_slot(s, ti);
}
