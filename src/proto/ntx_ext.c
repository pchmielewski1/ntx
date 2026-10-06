#include "ntx_ext.h"
#include "ntx_bencode.h"
#include "ntx_wire.h"

#include <stdlib.h>
#include <string.h>

size_t ntx_ext_msg_build(uint8_t *out, size_t cap, uint8_t ext_id, const uint8_t *payload, size_t plen) {
    /* BEP10: length = msg_id(1) + ext_id(1) + payload */
    size_t total = 4 + 2 + plen;
    if (!out || cap < total) return 0;
    ntx_wire_wr32(out, (uint32_t)(2 + plen));
    out[4] = (uint8_t)NTX_EXT_MSG_TYPE;
    out[5] = ext_id;
    if (plen) memcpy(out + 6, payload, plen);
    return total;
}

int ntx_ext_msg_parse(const uint8_t *buf, size_t n, uint8_t *ext_id, const uint8_t **payload, size_t *plen) {
    if (!buf || n < 6) return -1;
    if (buf[4] != (uint8_t)NTX_EXT_MSG_TYPE) return -1;
    uint32_t len = ntx_wire_rd32(buf);
    if (len < 2) return -1;
    if ((size_t)len + 4 > n) return -1;
    if (ext_id) *ext_id = buf[5];
    if (payload) *payload = buf + 6;
    if (plen) *plen = (size_t)(len - 2);
    return 0;
}

void ntx_ext_handshake_build(uint8_t *out, size_t *outn, const char *const *names, const uint8_t *ids, int n_ext,
                             int metadata_size, uint16_t port, const char *version) {
    if (!outn) return;
    *outn = 0;
    if (!out || !names || !ids || n_ext < 0) return;

    size_t cap = 128;
    for (int i = 0; i < n_ext; i++) cap += strlen(names[i]) + 16;
    if (version) cap += strlen(version) + 16;

    be_dict m;
    if (be_dict_init(&m, (size_t)n_ext) != 0) return;
    for (int i = 0; i < n_ext; i++) {
        ntx_be key = {0};
        key.t = NTX_BE_STR;
        key.sp = (uint8_t *)names[i];
        key.sn = strlen(names[i]);
        ntx_be val = {0};
        val.t = NTX_BE_INT;
        val.i = (int64_t)ids[i];
        if (be_dict_add(&m, key, val) != 0) {
            be_dict_free(&m);
            return;
        }
    }

    be_dict top;
    int top_n = 1 + (metadata_size > 0) + (port != 0) + (version != 0);
    if (be_dict_init(&top, top_n) != 0) {
        be_dict_free(&m);
        return;
    }
    ntx_be km = {0};
    km.t = NTX_BE_STR;
    km.sp = (uint8_t *)"m";
    km.sn = 1;
    ntx_be vm = {0};
    vm.t = NTX_BE_DICT;
    vm.nd = m.n;
    vm.k = m.kp;
    vm.v = m.vp;
    if (be_dict_add(&top, km, vm) != 0) {
        be_dict_free(&m);
        be_dict_free(&top);
        return;
    }
    if (metadata_size > 0) {
        ntx_be kms = {0};
        kms.t = NTX_BE_STR;
        kms.sp = (uint8_t *)"metadata_size";
        kms.sn = 13;
        ntx_be vms = {0};
        vms.t = NTX_BE_INT;
        vms.i = metadata_size;
        if (be_dict_add(&top, kms, vms) != 0) {
            be_dict_free(&m);
            be_dict_free(&top);
            return;
        }
    }
    if (port != 0) {
        ntx_be kp = {0};
        kp.t = NTX_BE_STR;
        kp.sp = (uint8_t *)"p";
        kp.sn = 1;
        ntx_be vp = {0};
        vp.t = NTX_BE_INT;
        vp.i = port;
        if (be_dict_add(&top, kp, vp) != 0) {
            be_dict_free(&m);
            be_dict_free(&top);
            return;
        }
    }
    if (version) {
        ntx_be kv = {0};
        kv.t = NTX_BE_STR;
        kv.sp = (uint8_t *)"v";
        kv.sn = 1;
        ntx_be vv = {0};
        vv.t = NTX_BE_STR;
        vv.sp = (uint8_t *)version;
        vv.sn = strlen(version);
        if (be_dict_add(&top, kv, vv) != 0) {
            be_dict_free(&m);
            be_dict_free(&top);
            return;
        }
    }

    ntx_be topdict = {0};
    topdict.t = NTX_BE_DICT;
    topdict.nd = top.n;
    topdict.k = top.kp;
    topdict.v = top.vp;
    size_t written = 0;
    if (ntx_be_encode(&topdict, out, cap, &written) == 0) *outn = written;
    else *outn = 0;

    be_dict_free(&m);
    be_dict_free(&top);
}

int ntx_ext_handshake_parse(const uint8_t *payload, size_t plen, uint8_t *ids, int max_ext, const char **names_out,
                             int *n_ext, int *metadata_size) {
    if (n_ext) *n_ext = 0;
    if (metadata_size) *metadata_size = 0;
    if (!payload || !ids || !names_out || max_ext < 0) return -1;

    ntx_be be;
    size_t consumed = 0;
    int rc = ntx_be_parse(payload, plen, &be, &consumed, 16, plen);
    if (rc != 0 || be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        return -1;
    }
    const ntx_be *m = ntx_be_dict_get(&be, "m");
    if (m && m->t == NTX_BE_DICT) {
        int n = 0;
        for (size_t i = 0; i < m->nd && n < max_ext; i++) {
            const ntx_be *k = m->k[i];
            const ntx_be *v = m->v[i];
            if (!k || !v || k->t != NTX_BE_STR || v->t != NTX_BE_INT) continue;
            char *nm = malloc(k->sn + 1);
            if (!nm) {
                ntx_be_free(&be);
                return -1;
            }
            memcpy(nm, k->sp, k->sn);
            nm[k->sn] = '\0';
            names_out[n] = nm;
            ids[n] = (uint8_t)v->i;
            n++;
        }
        *n_ext = n;
    }
    const ntx_be *ms = ntx_be_dict_get(&be, "metadata_size");
    /* peer-controlled; a negative or absurd value must not become a 4 GiB uint32 downstream */
    if (ms && ms->t == NTX_BE_INT && metadata_size && ms->i >= 1 && ms->i <= (int64_t)NTX_UT_METADATA_MAX)
        *metadata_size = (int)ms->i;
    /* optional BEP10 keys — parsed for forward compat; values ignored */
    (void)ntx_be_dict_get(&be, "p");
    (void)ntx_be_dict_get(&be, "v");
    (void)ntx_be_dict_get(&be, "yourip");
    (void)ntx_be_dict_get(&be, "ipv4");
    (void)ntx_be_dict_get(&be, "ipv6");
    (void)ntx_be_dict_get(&be, "reqq");
    ntx_be_free(&be);
    return 0;
}
