#include "ntx_pe.h"
#include "../net/ntx_netx.h"
#include "../crypto/ntx_ct.h"
#include "../crypto/ntx_rng.h"
#include "../core/ntx_time.h"
#include "ntx_wire.h"

#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
    PE_ST_SEND_DH = 1,
    PE_ST_RECV_DH,
    PE_ST_SEND_PE3,
    PE_ST_SEND_HS,
    PE_ST_RECV_VC,
    PE_ST_RECV_CRYPTO,
    PE_ST_RECV_PAD,
    PE_ST_RECV_SYNCHASH,
    PE_ST_RECV_SKEY,
    PE_ST_RECV_VC_R,
    PE_ST_RECV_CPROVIDE,
    PE_ST_RECV_PADLEN,
    PE_ST_RECV_PADIA,
    PE_ST_SEND_RHS,
    PE_ST_RECV_HS,
    PE_ST_DONE,
};

static ssize_t pe_send(ntx_pe *pe, const void *data, size_t n) {
    if (pe->netx)
        return ntx_netx_write(pe->netx, pe->fd, (const uint8_t *)data, n);
    return send(pe->fd, data, n, 0);
}

static ssize_t pe_recv(ntx_pe *pe, void *buf, size_t n) {
    if (pe->netx)
        return ntx_netx_read(pe->netx, pe->fd, (uint8_t *)buf, n);
    return recv(pe->fd, buf, n, 0);
}

static void pe_fail(ntx_pe *pe) {
    pe->failed = 1;
    ntx_dh_scrub(&pe->dh);
    ntx_wipe(pe->secret_buf, sizeof pe->secret_buf);
}

static void pe_mark_plain(ntx_pe *pe) {
    pe->plaintext = 1;
}

static int pe_search(const uint8_t *pat, size_t plen, const uint8_t *buf, size_t blen) {
    if (blen < plen) return -1;
    for (size_t i = 0; i <= blen - plen; i++)
        if (memcmp(buf + i, pat, plen) == 0) return (int)i;
    return -1;
}

static void pe_build_vc_field(uint8_t *ptr, uint32_t crypto_field, int pad_size, int include_ia) {
    memset(ptr, 0, 8);
    ptr += 8;
    ntx_wire_wr32(ptr, crypto_field);
    ptr += 4;
    ntx_wire_wr16(ptr, (uint16_t)pad_size);
    ptr += 2;
    ntx_rand_bytes(ptr, (size_t)pad_size);
    ptr += pad_size;
    if (include_ia)
        ntx_wire_wr16(ptr, NTX_PE_HANDSHAKE_LEN);
}

static int pe_send_out(ntx_pe *pe) {
    ssize_t w = pe_send(pe, pe->out + pe->sent, pe->outn - pe->sent);
    if (w > 0) pe->sent += (size_t)w;
    return pe->sent >= pe->outn;
}

static int pe_recv_eof(ntx_pe *pe, ssize_t r) {
    if (r == 0) {
        pe_fail(pe);
        return 1;
    }
    return 0;
}

static int pe_plaintext_peer(const uint8_t *buf, size_t n) {
    if (n >= 68 && buf[0] == 19 && memcmp(buf + 1, "BitTorrent protocol", 19) == 0)
        return 1;
    if (n >= 4 && buf[0] == 19 && n < 68 && memcmp(buf + 1, "BitTorrent", 10) == 0)
        return 1;
    return 0;
}

static int pe_recv_at_least(ntx_pe *pe, size_t min) {
    while (pe->inn < min) {
        ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
        if (pe_recv_eof(pe, r)) return -1;
        if (r > 0) {
            pe->inn += (size_t)r;
            if (pe_plaintext_peer(pe->in, pe->inn)) {
                pe_mark_plain(pe);
                return NTX_PE_PLAIN;
            }
        } else
            return 0;
    }
    for (;;) {
        ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
        if (r <= 0) break;
        pe->inn += (size_t)r;
        if (pe_plaintext_peer(pe->in, pe->inn)) {
            pe_mark_plain(pe);
            return NTX_PE_PLAIN;
        }
    }
    return 1;
}

static void pe_consume(ntx_pe *pe, size_t n) {
    if (n >= pe->inn) {
        pe->inn = 0;
        return;
    }
    memmove(pe->in, pe->in + n, pe->inn - n);
    pe->inn -= n;
}

/* Initiator RECV_VC: responder DH padding (0–512 B plaintext, possibly split
 * across TCP reads) precedes encrypted VC. Try every valid plain prefix. */
static int pe_find_vc_initiator(const ntx_pe *pe, size_t *plain_used, size_t *vc_off) {
    if (pe->inn < pe->plain_in + 8) return 0;
    ntx_rc4 base;
    pe_rc4_copy(&base, &pe->recv_rc4);
    uint8_t vc_pat[8];
    memset(vc_pat, 0, 8);
    ntx_rc4_xor(&base, vc_pat, 8);

    size_t min_plain = pe->plain_in;
    size_t max_plain = pe->inn - 8;
    if (max_plain > 1024) max_plain = 1024;

    int found = 0;
    size_t best_plain = 0, best_off = 0, best_total = (size_t)-1;

    for (size_t pl = min_plain; pl <= max_plain; pl++) {
        const uint8_t *enc = pe->in + pl;
        size_t enc_len = pe->inn - pl;
        int off = pe_search(vc_pat, 8, enc, enc_len);
        if (off < 0) continue;

        ntx_rc4 tmp;
        pe_rc4_copy(&tmp, &pe->recv_rc4);
        if (off > 0) {
            uint8_t junk[256];
            size_t left = (size_t)off;
            while (left > 0) {
                size_t chunk = left > sizeof junk ? sizeof junk : left;
                ntx_rc4_xor(&tmp, junk, chunk);
                left -= chunk;
            }
        }
        uint8_t vc[8];
        memcpy(vc, enc + off, 8);
        ntx_rc4_xor(&tmp, vc, 8);
        if (!pe_verify_vc(vc)) continue;

        size_t total = pl + (size_t)off;
        if (!found || total < best_total || (total == best_total && (size_t)off < best_off)) {
            found = 1;
            best_plain = pl;
            best_off = (size_t)off;
            best_total = total;
        }
    }
    if (!found) return 0;
    *plain_used = best_plain;
    *vc_off = best_off;
    return 1;
}

static void pe_advance_plain_hint(ntx_pe *pe, size_t plain_used) {
    if (plain_used <= pe->plain_in)
        pe->plain_in -= plain_used;
    else
        pe->plain_in = 0;
}

static int pe_step_initiator(ntx_pe *pe) {
    switch (pe->state) {
    case PE_ST_SEND_DH:
        if (pe_send_out(pe)) {
            pe->need = NTX_DH_KEY_LEN;
            pe->inn = 0;
            pe->state = PE_ST_RECV_DH;
        }
        return 0;
    case PE_ST_RECV_DH: {
        int rr = pe_recv_at_least(pe, NTX_DH_KEY_LEN);
        if (rr < 0) return -1;
        if (!rr) return 0;
        if (ntx_dh_compute_secret(&pe->dh, pe->in) < 0) {
            pe_fail(pe);
            return -1;
        }
        ntx_dh_export_shared(&pe->dh, pe->secret_buf);
        ntx_dh_scrub(&pe->dh); /* the copy in secret_buf is all we still need */
        pe_derive_rc4(pe);
        pe_compute_sync_hash(pe);
        pe_consume(pe, NTX_DH_KEY_LEN);
        pe->plain_in = pe->inn;
        pe->sync_discarded = 0;
        pe->state = PE_ST_SEND_PE3;
        return 0;
    }
    case PE_ST_SEND_PE3: {
        int pad = (int)(ntx_rand_u32() % 512);
        uint8_t plain[8 + 4 + 2 + 512 + 2];
        pe_build_vc_field(plain, 0x02, pad, 1);
        size_t plain_len = (size_t)(8 + 4 + 2 + pad + 2);
        memcpy(pe->out, pe->sync_hash, 20);
        pe_compute_skey_obf(pe, pe->out + 20);
        memcpy(pe->out + 40, plain, plain_len);
        ntx_pe_encrypt(pe, pe->out + 40, plain_len);
        pe->outn = 40 + plain_len;
        pe->sent = 0;
        pe->state = PE_ST_SEND_HS;
        return 0;
    }
    case PE_ST_SEND_HS:
        if (pe->sent < pe->outn) {
            if (!pe_send_out(pe)) return 0;
        }
        if (!pe->bt_hs_set) {
            pe_fail(pe);
            return -1;
        }
        memcpy(pe->out, pe->bt_hs, NTX_PE_HANDSHAKE_LEN);
        ntx_pe_encrypt(pe, pe->out, NTX_PE_HANDSHAKE_LEN);
        pe->outn = NTX_PE_HANDSHAKE_LEN;
        pe->sent = 0;
        if (!pe_send_out(pe)) return 0;
        pe->bt_hs_sent = 1;
        pe->sync_discarded = 0;
        pe->state_t0_ms = ntx_mono_ms();
        pe->state = PE_ST_RECV_VC;
        return 0;
    case PE_ST_RECV_VC: {
        ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
        if (r == 0) {
            pe_fail(pe);
            return -1;
        }
        if (r <= 0 && pe->inn < pe->plain_in + 8) return 0;
        if (r > 0) pe->inn += (size_t)r;
        if (pe_plaintext_peer(pe->in, pe->inn)) {
            pe_mark_plain(pe);
            return NTX_PE_PLAIN;
        }
        size_t plain_used = 0, vc_off = 0;
        if (!pe_find_vc_initiator(pe, &plain_used, &vc_off)) {
            /* The responder padding (0–1024 B) may arrive in several TCP segments. */
            size_t need = pe->plain_in + 1032;
            uint64_t now = ntx_mono_ms();
            if (pe->inn < need && pe->inn < sizeof pe->in - 64 &&
                pe->state_t0_ms && now - pe->state_t0_ms < 3000)
                return 0;
            if (pe->inn < need && pe->inn < sizeof pe->in - 64) return 0;
            if (pe->inn >= sizeof pe->in - 64) {
                if (pe_plaintext_peer(pe->in, pe->inn)) {
                    pe_mark_plain(pe);
                    return NTX_PE_PLAIN;
                }
                pe_fail(pe);
                return -1;
            }
            return 0;
        }
        pe_consume(pe, plain_used);
        pe_advance_plain_hint(pe, plain_used);
        if (vc_off > 0) {
            pe_rc4_discard(pe, vc_off);
            pe_consume(pe, vc_off);
        }
        ntx_pe_decrypt(pe, pe->in, 8);
        if (!pe_verify_vc(pe->in)) {
            pe_fail(pe);
            return -1;
        }
        pe_consume(pe, 8);
        pe->plain_in = 0;
        pe->sync_discarded = 0;
        pe->need = 6;
        pe->state = PE_ST_RECV_CRYPTO;
        return 0;
    }
    case PE_ST_RECV_CRYPTO:
        if (pe->inn < 6) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < 6) return 0;
        ntx_pe_decrypt(pe, pe->in, 6);
        if ((ntx_wire_rd32(pe->in) & 0x02) == 0) {
            pe_fail(pe);
            return -1;
        }
        pe->pad_len = (int)ntx_wire_rd16(pe->in + 4);
        if (pe->pad_len < 0 || pe->pad_len > 512) {
            pe_fail(pe);
            return -1;
        }
        pe_consume(pe, 6);
        pe->need = (size_t)pe->pad_len;
        pe->state = PE_ST_RECV_PAD;
        return 0;
    case PE_ST_RECV_PAD:
        if (pe->inn < pe->need) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < pe->need) return 0;
        ntx_pe_decrypt(pe, pe->in, pe->need);
        pe_consume(pe, pe->need);
        pe->need = NTX_PE_HANDSHAKE_LEN;
        pe->state = PE_ST_RECV_HS;
        return 0;
    case PE_ST_RECV_HS:
        if (pe->inn < pe->need) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < pe->need) return 0;
        ntx_pe_decrypt(pe, pe->in, NTX_PE_HANDSHAKE_LEN);
        memcpy(pe->bt_hs, pe->in, NTX_PE_HANDSHAKE_LEN);
        pe->bt_hs_got = 1;
        pe_consume(pe, NTX_PE_HANDSHAKE_LEN);
        pe->plain_in = 0;
        pe->done = 1;
        ntx_wipe(pe->secret_buf, sizeof pe->secret_buf); /* RC4 keys are derived; SKEY/HASH inputs are spent */
        pe->state = PE_ST_DONE;
#ifndef NDEBUG
        assert(pe->plain_in == 0);
#endif
        return 1;
    default:
        return pe->done ? 1 : 0;
    }
}

static int pe_step_responder(ntx_pe *pe) {
    switch (pe->state) {
    case PE_ST_RECV_DH: {
        int rr = pe_recv_at_least(pe, NTX_DH_KEY_LEN);
        if (rr < 0) return -1;
        if (!rr) return 0;
        if (ntx_dh_compute_secret(&pe->dh, pe->in) < 0) {
            pe_fail(pe);
            return -1;
        }
        ntx_dh_export_shared(&pe->dh, pe->secret_buf);
        ntx_dh_scrub(&pe->dh); /* the copy in secret_buf is all we still need */
        pe_compute_sync_hash(pe);
        pe_consume(pe, NTX_DH_KEY_LEN);
        /* keep coalesced initiator bytes (sync/obf/crypto) in pe->in for RECV_SYNCHASH */
        pe_build_dh_out(pe);
        pe->state = PE_ST_SEND_DH;
        return 0;
    }
    case PE_ST_SEND_DH:
        if (!pe_send_out(pe)) return 0;
        pe->sync_discarded = 0;
        pe->state = PE_ST_RECV_SYNCHASH;
        return 0;
    case PE_ST_RECV_SYNCHASH: {
        ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
        if (r <= 0 && pe->inn < 20) return 0;
        if (r > 0) {
            pe->inn += (size_t)r;
            if (pe_plaintext_peer(pe->in, pe->inn)) {
                pe_mark_plain(pe);
                return NTX_PE_PLAIN;
            }
        }
        if (pe->inn < 20) return 0;
        int off = pe_search(pe->sync_hash, 20, pe->in, pe->inn);
        if (off < 0) {
            if (pe->inn >= sizeof pe->in - 64) {
                if (pe_plaintext_peer(pe->in, pe->inn)) {
                    pe_mark_plain(pe);
                    return NTX_PE_PLAIN;
                }
                pe_fail(pe);
                return -1;
            }
            return 0;
        }
        pe_consume(pe, (size_t)off + 20);
        pe->need = 20;
        pe->state = PE_ST_RECV_SKEY;
        return 0;
    }
    case PE_ST_RECV_SKEY:
        if (pe->inn < 20) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < 20) return 0;
        if (!pe_verify_skey(pe, pe->in)) {
            pe_fail(pe);
            return -1;
        }
        pe_derive_rc4(pe);
        pe_consume(pe, 20);
        pe->need = 8;
        pe->state = PE_ST_RECV_VC_R;
        return 0;
    case PE_ST_RECV_VC_R:
        if (pe->inn < 8) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < 8) return 0;
        ntx_pe_decrypt(pe, pe->in, 8);
        for (int i = 0; i < 8; i++) {
            if (pe->in[i] != 0) {
                pe_fail(pe);
                return -1;
            }
        }
        pe_consume(pe, 8);
        pe->need = 4;
        pe->state = PE_ST_RECV_CPROVIDE;
        return 0;
    case PE_ST_RECV_CPROVIDE:
        if (pe->inn < 4) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < 4) return 0;
        ntx_pe_decrypt(pe, pe->in, 4);
        if ((ntx_wire_rd32(pe->in) & 0x02) == 0) {
            pe_fail(pe);
            return -1;
        }
        pe_consume(pe, 4);
        pe->need = 2;
        pe->state = PE_ST_RECV_PADLEN;
        return 0;
    case PE_ST_RECV_PADLEN:
        if (pe->inn < 2) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < 2) return 0;
        ntx_pe_decrypt(pe, pe->in, 2);
        pe->pad_len = (int)ntx_wire_rd16(pe->in);
        if (pe->pad_len < 0 || pe->pad_len > 512) {
            pe_fail(pe);
            return -1;
        }
        pe_consume(pe, 2);
        pe->need = (size_t)pe->pad_len + 2;
        pe->state = PE_ST_RECV_PADIA;
        return 0;
    case PE_ST_RECV_PADIA:
        if (pe->inn < pe->need) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < pe->need) return 0;
        ntx_pe_decrypt(pe, pe->in, pe->need);
        if ((int)ntx_wire_rd16(pe->in + pe->pad_len) != NTX_PE_HANDSHAKE_LEN) {
            pe_fail(pe);
            return -1;
        }
        pe_consume(pe, pe->need);
        {
            int pad = (int)(ntx_rand_u32() % 512);
            uint8_t plain[8 + 4 + 2 + 512];
            pe_build_vc_field(plain, 0x02, pad, 0);
            size_t plain_len = (size_t)(8 + 4 + 2 + pad);
            memcpy(pe->out, plain, plain_len);
            ntx_pe_encrypt(pe, pe->out, plain_len);
            pe->outn = plain_len;
            pe->sent = 0;
            if (!pe_send_out(pe)) return 0;
        }
        pe->need = NTX_PE_HANDSHAKE_LEN;
        pe->state = PE_ST_RECV_HS;
        return 0;
    case PE_ST_RECV_HS:
        if (pe->inn < pe->need) {
            ssize_t r = pe_recv(pe, pe->in + pe->inn, sizeof pe->in - pe->inn);
            if (r <= 0) return 0;
            pe->inn += (size_t)r;
        }
        if (pe->inn < pe->need) return 0;
        ntx_pe_decrypt(pe, pe->in, NTX_PE_HANDSHAKE_LEN);
        if (!pe->bt_hs_set) {
            pe_fail(pe);
            return -1;
        }
        memcpy(pe->out, pe->bt_hs, NTX_PE_HANDSHAKE_LEN);
        ntx_pe_encrypt(pe, pe->out, NTX_PE_HANDSHAKE_LEN);
        pe->outn = NTX_PE_HANDSHAKE_LEN;
        pe->sent = 0;
        memcpy(pe->bt_hs, pe->in, NTX_PE_HANDSHAKE_LEN);
        pe->bt_hs_got = 1;
        pe_consume(pe, NTX_PE_HANDSHAKE_LEN);
        pe->state = PE_ST_SEND_RHS;
        return 0;
    case PE_ST_SEND_RHS:
        if (!pe_send_out(pe)) return 0;
        pe->bt_hs_sent = 1;
        pe->plain_in = 0;
        pe->done = 1;
        ntx_wipe(pe->secret_buf, sizeof pe->secret_buf); /* RC4 keys are derived; SKEY/HASH inputs are spent */
        pe->state = PE_ST_DONE;
#ifndef NDEBUG
        assert(pe->plain_in == 0);
#endif
        return 1;
    default:
        return pe->done ? 1 : 0;
    }
}

int ntx_pe_init(ntx_pe *pe, int role, int fd) {
    memset(pe, 0, sizeof *pe);
    pe->role = role;
    pe->fd = fd;
    ntx_dh_init(&pe->dh);
    if (role == NTX_PE_INITIATOR) {
        pe->state = PE_ST_SEND_DH;
        pe_build_dh_out(pe);
    } else {
        pe->state = PE_ST_RECV_DH;
        pe->need = NTX_DH_KEY_LEN;
    }
    return 0;
}

void ntx_pe_set_netx(ntx_pe *pe, struct ntx_netx *netx) {
    pe->netx = netx;
}

void ntx_pe_set_infohash(ntx_pe *pe, const uint8_t hash[20]) {
    memcpy(pe->infohash, hash, 20);
    pe->infohash_cand_n = 0;
}

void ntx_pe_set_bt_handshake(ntx_pe *pe, const uint8_t hs[NTX_PE_HANDSHAKE_LEN]) {
    memcpy(pe->bt_hs, hs, NTX_PE_HANDSHAKE_LEN);
    pe->bt_hs_set = 1;
}

int ntx_pe_handshake_sent(const ntx_pe *pe) {
    return pe->bt_hs_sent;
}

int ntx_pe_step(ntx_pe *pe) {
    if (pe->done) return 1;
    if (pe->failed) return -1;
    if (pe->role == NTX_PE_INITIATOR)
        return pe_step_initiator(pe);
    return pe_step_responder(pe);
}

int ntx_pe_done(const ntx_pe *pe) {
    return pe->done;
}

void ntx_pe_encrypt(ntx_pe *pe, uint8_t *buf, size_t n) {
    ntx_rc4_xor(&pe->send_rc4, buf, n);
}

void ntx_pe_decrypt(ntx_pe *pe, uint8_t *buf, size_t n) {
    ntx_rc4_xor(&pe->recv_rc4, buf, n);
}

size_t ntx_pe_take_remainder(ntx_pe *pe, uint8_t *buf, size_t cap) {
    if (!pe->inn || !buf || !cap) return 0;
    size_t total = 0;
    if (pe->plain_in > 0) {
        size_t take = pe->plain_in;
        if (take > pe->inn) take = pe->inn;
        if (take > cap) take = cap;
        memcpy(buf, pe->in, take);
        pe_consume(pe, take);
        pe->plain_in -= take;
        total = take;
        buf += take;
        cap -= take;
        if (!cap || !pe->inn) return total;
    }
    ntx_pe_decrypt(pe, pe->in, pe->inn);
    size_t n = pe->inn;
    if (n > cap) n = cap;
    memcpy(buf, pe->in, n);
    pe->inn = 0;
    return total + n;
}

size_t ntx_pe_drain_to_peer(ntx_pe *pe, uint8_t *buf, size_t cap) {
    size_t n = 0;
    if (pe->bt_hs_got) {
        if (cap < NTX_PE_HANDSHAKE_LEN) return 0;
        memcpy(buf, pe->bt_hs, NTX_PE_HANDSHAKE_LEN);
        pe->bt_hs_got = 0;
        n = NTX_PE_HANDSHAKE_LEN;
    }
    return n + ntx_pe_take_remainder(pe, buf + n, cap - n);
}
