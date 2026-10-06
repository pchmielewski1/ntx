#include "ntx_ipc.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../core/ntx_session_internal.h" /* full struct ntx_session: tts[i].state/info_hash */

/* The dispatcher is the sole ntx_ipc.c-family consumer of the session
   primitives, so it lives in its own translation unit. The session-less test
   consumer (test/t_cli.c) #includes ntx_ipc.c for the JSON helpers but does
   not include this TU and never references ntx_ipc_dispatch, so it links with
   no session symbols at all. The session definitions bind STRONG here: the
   production binary always links the session (core/ is in SRCS) and the
   session-aware test TU (test/t_ipc_ctrl.c) #includes the session stack
   alongside this file. A missing session primitive is therefore a real link
   error, never a silent weak NULL. */

/* ---- dispatcher (§6.2, §8) ------------------------------------------- */
static const char *ipc_cmd_label(ntx_ipc_cmd c) {
    switch (c) {
    case NTX_CMD_PING: return "ping";
    case NTX_CMD_STATUS: return "status";
    case NTX_CMD_HELLO: return "hello";
    case NTX_CMD_ADD: return "add";
    case NTX_CMD_PAUSE: return "pause";
    case NTX_CMD_RESUME: return "resume";
    case NTX_CMD_REMOVE: return "remove";
    case NTX_CMD_QUIT: return "quit";
    default: return "";
    }
}
static const char *ipc_code_label(ntx_ipc_code c) {
    switch (c) {
    case NTX_IPC_E_BAD_JSON: return "bad_json";
    case NTX_IPC_E_UNKNOWN_CMD: return "unknown_cmd";
    case NTX_IPC_E_BAD_I: return "bad_i";
    case NTX_IPC_E_NO_SLOT: return "no_slot";
    case NTX_IPC_E_NOT_READY: return "not_ready";
    case NTX_IPC_E_BAD_ARG: return "bad_arg";
    case NTX_IPC_E_FULL: return "full";
    case NTX_IPC_E_IO: return "io";
    default: return "internal";
    }
}
/* append a printf segment; on any overflow the whole line collapses to
   internal -- §8: a half-written ack is worse than an honest error */
static int ipc_seg(char *out, size_t cap, size_t *pos, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(out + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (w < 0 || *pos + (size_t)w >= cap) { out[0] = 0; return -1; }
    *pos += (size_t)w;
    return 0;
}
static int ipc_tail_internal(char *out, size_t cap) {
    return snprintf(out, cap, "{\"type\":\"err\",\"cmd\":\"\",\"ok\":0,\"code\":\"internal\"}") > 0 ? 0 : -1;
}

int ntx_ipc_dispatch(struct ntx_session *s, const char *line, char *out, size_t cap) {
    ntx_ipc_req r;
    ntx_ipc_parse(line, &r);
    out[0] = 0;
    size_t pos = 0;
    const char *label = r.cmd_seen ? (r.cmd == NTX_CMD_NONE ? r.cmd_echo : ipc_cmd_label(r.cmd)) : "";
    char ec[NTX_IPC_CMD_ECHO * 6 + 1];
    if (ntx_json_escape(ec, sizeof ec, label) < 0) ec[0] = 0;

    /* validation gate (§6.4): validate before any mutation */
    if (r.pre != NTX_IPC_OK) {
        if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",")) return ipc_tail_internal(out, cap);
        if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq)) return ipc_tail_internal(out, cap);
        if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",", ec)) return ipc_tail_internal(out, cap);
        if (r.has_i && r.pre != NTX_IPC_E_BAD_I && r.i_raw >= 0 && r.i_raw < NTX_SESSION_MAX_TTS)
            if (ipc_seg(out, cap, &pos, "\"i\":%d,", r.i)) return ipc_tail_internal(out, cap);
        if (ipc_seg(out, cap, &pos, "\"ok\":0,\"code\":\"%s\"}", ipc_code_label(r.pre)))
            return ipc_tail_internal(out, cap);
        return 0;
    }
    if (r.cmd == NTX_CMD_HELLO) { /* §6.2: the reply is a repeat of hello */
        return ntx_ipc_hello_json(out, cap, NTX_IPC_BUILD_ID) < 0 ? ipc_tail_internal(out, cap) : 0;
    }
    if (r.cmd == NTX_CMD_STATUS) return NTX_IPC_F_EMIT_STATUS; /* §6.2 */
    if (r.cmd == NTX_CMD_QUIT) {
        ntx_session_quit(s); /* idempotent -- the glue finishes the shutdown */
        if (ipc_seg(out, cap, &pos, "{\"type\":\"ack\",")) return ipc_tail_internal(out, cap);
        if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq)) return ipc_tail_internal(out, cap);
        if (ipc_seg(out, cap, &pos, "\"cmd\":\"quit\",\"ok\":1}")) return ipc_tail_internal(out, cap);
        return NTX_IPC_F_QUIT;
    }

    /* HARDENING: the parser stores r.i = (int)v; a huge
       literal can wrap past the `>= NTX_SESSION_MAX_TTS' guard to a value in
       the range [0,MAX). The bounds decision uses the untruncated i_raw --
       any i outside [0,MAX) -> bad_i, with no i echo, before reaching the session
       primitives (§6.4 gate: no mutation on a malformed request). */
    if (r.cmd == NTX_CMD_PAUSE || r.cmd == NTX_CMD_RESUME || r.cmd == NTX_CMD_REMOVE) {
        if (r.i_raw < 0 || r.i_raw >= NTX_SESSION_MAX_TTS) {
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",")) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq)) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"ok\":0,\"code\":\"bad_i\"}", ec))
                return ipc_tail_internal(out, cap);
            return 0;
        }
    }

    /* common ack layout: type, seq?, cmd, [i], [ih], ok, [state] -- field order per §8 */
    if (ipc_seg(out, cap, &pos, "{\"type\":\"ack\",")) return ipc_tail_internal(out, cap);
    if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq)) return ipc_tail_internal(out, cap);
    if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",", ec)) return ipc_tail_internal(out, cap);

    switch (r.cmd) {
    case NTX_CMD_PING:
        if (ipc_seg(out, cap, &pos, "\"ok\":1}")) return ipc_tail_internal(out, cap);
        return 0;
    case NTX_CMD_ADD: {
        int slot = ntx_session_free_slot(s);
        if (slot < 0) { out[0] = 0; pos = 0;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"ok\":0,\"code\":\"full\"}", ec) < 0) return ipc_tail_internal(out, cap);
            return 0;
        }
        int rc;
        if (r.has_magnet) rc = ntx_session_add_magnet(s, r.magnet); /* -1 => bad xt= -> bad_arg */
        else if (strlen(r.path) > 511) rc = -2;                     /* §6.4 io */
        else rc = ntx_session_add_torrent_file(s, r.path);           /* -1 => io */
        if (rc == -1) { out[0] = 0; pos = 0;
            ntx_ipc_code c = r.has_magnet ? NTX_IPC_E_BAD_ARG : NTX_IPC_E_IO;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"ok\":0,\"code\":\"%s\"}", ec, ipc_code_label(c)) < 0)
                return ipc_tail_internal(out, cap);
            return 0;
        }
        if (rc == -2) { out[0] = 0; pos = 0;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"ok\":0,\"code\":\"io\"}", ec) < 0)
                return ipc_tail_internal(out, cap);
            return 0;
        }
        /* added: the slot is taken in free_slot order (same path as add_*),
           ih is known immediately (§6.2: a magnet has xt, a .torrent has info) */
        char ih[41];
        ntx_hex40(ih, s->tts[slot].info_hash);
        if (ipc_seg(out, cap, &pos, "\"i\":%d,\"ih\":\"%s\",\"ok\":1,\"state\":%d}",
                    slot, ih, (int)s->tts[slot].state) < 0) return ipc_tail_internal(out, cap);
        return 0;
    }
    case NTX_CMD_PAUSE: case NTX_CMD_RESUME: {
        int on = (r.cmd == NTX_CMD_PAUSE);
        int rc = ntx_session_set_paused(s, r.i, on);
        if (rc == NTX_PAUSE_E_DEAD || rc == NTX_PAUSE_E_RANGE) { out[0] = 0; pos = 0;
            ntx_ipc_code c = (rc == NTX_PAUSE_E_DEAD) ? NTX_IPC_E_NO_SLOT : NTX_IPC_E_BAD_I;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",", ec) < 0) return ipc_tail_internal(out, cap);
            if (c != NTX_IPC_E_BAD_I) if (ipc_seg(out, cap, &pos, "\"i\":%d,", r.i) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"ok\":0,\"code\":\"%s\"}", ipc_code_label(c)) < 0) return ipc_tail_internal(out, cap);
            return 0;
        }
        if (rc == NTX_PAUSE_E_STATE) { out[0] = 0; pos = 0;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"i\":%d,\"ok\":0,\"code\":\"not_ready\"}", ec, r.i) < 0)
                return ipc_tail_internal(out, cap);
            return 0;
        }
        /* §8 sample: pause/resume acks carry no ih (unlike add) -- the field order
           is pinned by the d_pause_sample gate (byte-exact). */
        if (ipc_seg(out, cap, &pos, "\"i\":%d,\"ok\":1,\"state\":%d}",
                    r.i, (int)s->tts[r.i].state) < 0) return ipc_tail_internal(out, cap);
        return 0;
    }
    case NTX_CMD_REMOVE: {
        if (s->tts[r.i].state == NTX_TTS_DEAD) { out[0] = 0; pos = 0;
            if (ipc_seg(out, cap, &pos, "{\"type\":\"err\",") < 0) return ipc_tail_internal(out, cap);
            if (r.has_seq && ipc_seg(out, cap, &pos, "\"seq\":%lld,", r.seq) < 0) return ipc_tail_internal(out, cap);
            if (ipc_seg(out, cap, &pos, "\"cmd\":\"%s\",\"i\":%d,\"ok\":0,\"code\":\"no_slot\"}", ec, r.i) < 0)
                return ipc_tail_internal(out, cap);
            return 0;
        }
        ntx_session_remove(s, r.i);
        if (ipc_seg(out, cap, &pos, "\"i\":%d,\"ok\":1,\"state\":%d}", r.i, (int)NTX_TTS_DEAD) < 0)
            return ipc_tail_internal(out, cap);
        return 0;
    }
    default:
        return ipc_tail_internal(out, cap);
    }
}
