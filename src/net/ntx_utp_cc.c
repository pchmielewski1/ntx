#include "ntx_utp.h"

void ntx_utp_cc_init(ntx_utp_cc *cc) {
    for (int i = 0; i < NTX_UTP_CC_HISTORY; i++) cc->hist[i] = 0;
    cc->hist_n = 0;
    cc->hist_idx = 0;
}

int64_t ntx_utp_cc_update(ntx_utp_cc *cc, uint32_t ts_diff_us,
                          uint32_t outstanding, int64_t max_window) {
    if (ts_diff_us == 0) return max_window;
    if (cc->hist_n < NTX_UTP_CC_HISTORY) {
        cc->hist[cc->hist_idx] = ts_diff_us;
        cc->hist_idx = (cc->hist_idx + 1) % NTX_UTP_CC_HISTORY;
        cc->hist_n++;
    } else {
        cc->hist[cc->hist_idx] = ts_diff_us;
        cc->hist_idx = (cc->hist_idx + 1) % NTX_UTP_CC_HISTORY;
    }
    uint32_t base = cc->hist[0];
    for (int i = 1; i < cc->hist_n; i++)
        if (cc->hist[i] < base) base = cc->hist[i];
    if (base == 0) return max_window;
    uint32_t our_delay = ts_diff_us - base;
    int64_t off_target = (int64_t)NTX_UTP_TARGET_DELAY_US - (int64_t)our_delay;
    /* off_target is negative when the delay exceeds the target; "<< 16" on a negative
       value is undefined behaviour in C11, the multiplication is not (same result). */
    int64_t delay_factor = (off_target * 65536) / (int64_t)NTX_UTP_TARGET_DELAY_US;
    int64_t window_factor = 0;
    if (max_window != 0)
        window_factor = ((int64_t)outstanding << 16) / max_window;
    int64_t scaled_gain =
        ((int64_t)NTX_UTP_MAX_CWND_INC_PER_RTT * delay_factor * window_factor) >>
        32;
    int64_t new_window = max_window + scaled_gain;
    return new_window < 0 ? 0 : new_window;
}
