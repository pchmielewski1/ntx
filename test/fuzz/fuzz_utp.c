/* uTP (BEP29) header/SACK/extension-chain parsers (checklist poz. 6): the
   network-facing byte parsers of src/net/ntx_utp_hdr.c. */
#include "../../src/net/ntx_utp_hdr.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    ntx_utp_hdr h;
    if (ntx_utp_hdr_parse(data, len, &h) == 0) {
        uint8_t out[NTX_UTP_HDR_LEN];
        (void)ntx_utp_hdr_write(out, sizeof out, &h);
        if (h.extension != 0) {
            int first = 0;
            const uint8_t *pl = NULL;
            (void)ntx_utp_ext_skip(data + NTX_UTP_HDR_LEN, len - NTX_UTP_HDR_LEN, &first, &pl);
        }
    }
    uint16_t seqs[NTX_UTP_SACK_MAX / 4 + 8];
    int n_acked = 0;
    (void)ntx_utp_parse_sack(data, len, 7, seqs, &n_acked, (int)(sizeof seqs / sizeof seqs[0]));
    return 0;
}
