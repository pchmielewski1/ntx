#ifndef NTX_PE_H
#define NTX_PE_H

#include <stddef.h>
#include <stdint.h>
#include "../crypto/ntx_dh.h"
#include "../crypto/ntx_rc4.h"

struct ntx_netx;

enum { NTX_PE_INITIATOR = 0, NTX_PE_RESPONDER = 1 };

enum { NTX_PE_OK = 0, NTX_PE_DONE = 1, NTX_PE_FAIL = -1, NTX_PE_PLAIN = -2 };

#define NTX_PE_HANDSHAKE_LEN 68
#define NTX_PE_INFOHASH_CAND 16

typedef struct {
    int role;
    int state;
    int fd;
    struct ntx_netx *netx;
    uint8_t infohash[20];
    uint8_t infohash_cand[NTX_PE_INFOHASH_CAND][20];
    int infohash_cand_n;
    ntx_dh dh;
    ntx_rc4 send_rc4, recv_rc4;
    uint8_t sync_hash[20];
    uint8_t secret_buf[96];
    int done;
    int failed;
    uint8_t out[2048];
    size_t outn;
    size_t sent;
    uint8_t in[2048];
    size_t inn;
    size_t need;
    int sync_discarded;
    int pad_len;
    size_t plain_in;
    uint8_t bt_hs[NTX_PE_HANDSHAKE_LEN];
    int bt_hs_set;
    int bt_hs_got;
    int bt_hs_sent;
    int plaintext;
    uint64_t state_t0_ms;
} ntx_pe;

int ntx_pe_init(ntx_pe *pe, int role, int fd);
void ntx_pe_set_netx(ntx_pe *pe, struct ntx_netx *netx);
void ntx_pe_set_infohash(ntx_pe *pe, const uint8_t hash[20]);
void ntx_pe_set_bt_handshake(ntx_pe *pe, const uint8_t hs[NTX_PE_HANDSHAKE_LEN]);
int ntx_pe_handshake_sent(const ntx_pe *pe);
int ntx_pe_step(ntx_pe *pe);
int ntx_pe_done(const ntx_pe *pe);
void ntx_pe_encrypt(ntx_pe *pe, uint8_t *buf, size_t n);
void ntx_pe_decrypt(ntx_pe *pe, uint8_t *buf, size_t n);
size_t ntx_pe_take_remainder(ntx_pe *pe, uint8_t *buf, size_t cap);
size_t ntx_pe_drain_to_peer(ntx_pe *pe, uint8_t *buf, size_t cap);

/* Implemented in ntx_pe_vc.c: ntx_pe_vc_* (vc/crypto) */
void pe_rc4_copy(ntx_rc4 *dst, const ntx_rc4 *src);
void pe_xor20(uint8_t *dst, const uint8_t *a, const uint8_t *b);
void pe_derive_rc4(ntx_pe *pe);
void pe_build_dh_out(ntx_pe *pe);
void pe_rc4_discard(ntx_pe *pe, size_t n);
int pe_verify_vc(const uint8_t *p);
void pe_compute_skey_obf(const ntx_pe *pe, uint8_t out[20]);
int pe_verify_skey_hash(const ntx_pe *pe, const uint8_t *obf, const uint8_t hash[20]);
int pe_verify_skey(ntx_pe *pe, const uint8_t *obf);
void pe_compute_sync_hash(ntx_pe *pe);
#endif
