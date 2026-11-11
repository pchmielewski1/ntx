#include "ntx_ipc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Parser + JSON helpers (§11.1). The dispatcher now lives in its own
   translation unit (src/ui/ntx_ipc_dispatch.c); this file no longer references
   the session primitives, so it links cleanly into session-less consumers such
   as test/t_cli.c. */

int ntx_json_escape(char *out, size_t cap, const char *s) {
    size_t pos = 0;
    if (!s) { if (cap == 0) return -1; out[0] = 0; return 0; }
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        int w;
        if (c == '"' || c == '\\')
            w = snprintf(out + pos, cap - pos, "\\%c", c);
        else if (c == '\n')
            w = snprintf(out + pos, cap - pos, "\\n");
        else if (c == '\r')
            w = snprintf(out + pos, cap - pos, "\\r");
        else if (c == '\t')
            w = snprintf(out + pos, cap - pos, "\\t");
        else if (c < 0x20)
            w = snprintf(out + pos, cap - pos, "\\u%04x", (unsigned)c);
        else {
            if (pos + 1 >= cap) goto refuse;
            out[pos++] = (char)c;
            continue;
        }
        if (w < 0 || pos + (size_t)w >= cap) goto refuse; /* clean refusal */
        pos += (size_t)w;
    }
    if (pos >= cap) goto refuse;
    out[pos] = 0;
    return (int)pos;
refuse:
    if (cap) out[0] = 0;
    return -1;
}

int ntx_hex40(char out[41], const uint8_t h[20]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 20; i++) {
        out[2 * i] = hx[h[i] >> 4];
        out[2 * i + 1] = hx[h[i] & 15u];
    }
    out[40] = 0;
    return 40;
}

/* §6.4/§11: "share" is advertised only while the built-in tracker list is
   usable. Weak reference for the same reason as the wrappers in ntx_main.c:
   test/t_cli.c links this TU with no share objects. */
__attribute__((weak)) int ntx_share_available(void);
/* Same reason: test/t_cli.c links this TU without the share objects, so a
   strong reference on the event emitter's only session-side helper would be an
   undefined symbol there. NULL ⇒ the emitter labels a failure "bad_arg". */
__attribute__((weak)) const char *ntx_share_err_code(ntx_share_err e);

int ntx_ipc_hello_json(char *out, size_t cap, const char *build_id) {
    char esc_build[64 * 6 + 1];
    if (ntx_json_escape(esc_build, sizeof esc_build, build_id ? build_id : "") < 0)
        esc_build[0] = 0;
    const char *sh = (ntx_share_available && ntx_share_available()) ? ",\"share\"" : "";
    int w = snprintf(out, cap,
                     "{\"type\":\"hello\",\"v\":1,\"protocol\":\"ntx-json\","
                     "\"max_tts\":%d,\"max_peers\":%d,\"build\":\"%s\","
                     "\"caps\":[\"ping\",\"status\",\"hello\",\"add\",\"pause\","
                     "\"resume\",\"remove\",\"quit\"%s]}",
                     NTX_SESSION_MAX_TTS, NTX_SESSION_MAX_PEERS, esc_build, sh);
    return (w < 0 || (size_t)w >= cap) ? -1 : w;
}

int ntx_ipc_share_event_json(char *out, size_t cap, const ntx_share_event *ev) {
    if (!ev) return -1;
    int w;
    if (!ev->ok) {
        const char *code = ntx_share_err_code ? ntx_share_err_code(ev->err) : "bad_arg";
        w = snprintf(out, cap, "{\"type\":\"share\",\"i\":%d,\"ok\":0,\"code\":\"%s\"}", ev->i, code);
        return (w < 0 || (size_t)w >= cap) ? -1 : w;
    }
    char ih[41], ih2[65], name[512 * 6 + 1], magnet[NTX_SHARE_MAGNET_MAX * 6 + 1],
         tor[NTX_SHARE_PATH_MAX * 6 + 1];
    ntx_hex40(ih, ev->ih);
    static const char hx[] = "0123456789abcdef";
    for (int k = 0; k < 32; k++) { ih2[2 * k] = hx[ev->ih2[k] >> 4]; ih2[2 * k + 1] = hx[ev->ih2[k] & 15u]; }
    ih2[64] = 0;
    if (ntx_json_escape(name, sizeof name, ev->name) < 0 ||
        ntx_json_escape(magnet, sizeof magnet, ev->magnet) < 0 ||
        ntx_json_escape(tor, sizeof tor, ev->torrent_path) < 0)
        return -1; /* §11.1: never a torn escape -> no line at all */
    w = snprintf(out, cap,
                 "{\"type\":\"share\",\"i\":%d,\"ok\":1,\"ih\":\"%s\",\"ih2\":\"%s\","
                 "\"name\":\"%s\",\"magnet\":\"%s\",\"torrent\":\"%s\"}",
                 ev->i, ih, ih2, name, magnet, tor);
    return (w < 0 || (size_t)w >= cap) ? -1 : w;
}

/* ── parser ─────────────────────────────────────────────────────────── */
static const char *ipc_ws(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* decode a JSON string starting at the opening quote; unescapes §11.1 set.
   0 = ok, -1 = malformed, -2 = value does not fit dst (→ bad_json). */
static int ipc_json_str(const char **pp, char *dst, size_t dst_sz) {
    const char *p = *pp;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    for (;;) {
        unsigned char c = (unsigned char)*p;
        if (c == 0 || c == '\n') return -1;
        if (c == '"') {
            if (o >= dst_sz) return -2;
            dst[o] = 0;
            *pp = p + 1;
            return 0;
        }
        if (c == '\\') {
            char e = *++p;
            char d;
            if (e == 0 || e == '\n') return -1;
            if (e == '"' || e == '\\' || e == '/') d = e;
            else if (e == 'n') d = '\n';
            else if (e == 'r') d = '\r';
            else if (e == 't') d = '\t';
            else if (e == 'b') d = '\b';
            else if (e == 'f') d = '\f';
            else if (e == 'u') {
                unsigned v = 0;
                for (int k = 1; k <= 4; k++) {
                    char h = p[k];
                    int dig = (h >= '0' && h <= '9') ? h - '0'
                              : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                              : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
                    if (dig < 0) return -1;
                    v = v * 16u + (unsigned)dig;
                }
                if (v > 0x7Fu) return -1; /* §3.4: non-ASCII travels raw */
                d = (char)v;
                p += 4;
            } else return -1;
            if (o + 1 >= dst_sz) return -2;
            dst[o++] = d;
            p++;
        } else {
            if (o + 1 >= dst_sz) return -2;
            dst[o++] = (char)c;
            p++;
        }
    }
}

/* consume a JSON string and report its decoded length without storing it.
   This lets the add/path validation distinguish "too long" (io) from a
   malformed value (bad_json) while keeping the public arg buffer at 512. */
static int ipc_json_str_len(const char **pp, size_t *len) {
    const char *p = *pp;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    for (;;) {
        unsigned char c = (unsigned char)*p;
        if (c == 0 || c == '\n') return -1;
        if (c == '"') {
            *len = o;
            *pp = p + 1;
            return 0;
        }
        if (c == '\\') {
            char e = *++p;
            if (e == 0 || e == '\n') return -1;
            if (e == '"' || e == '\\' || e == '/' || e == 'n' || e == 'r' ||
                e == 't' || e == 'b' || e == 'f') {
                o++;
                p++;
            } else if (e == 'u') {
                unsigned v = 0;
                for (int k = 1; k <= 4; k++) {
                    char h = p[k];
                    int dig = (h >= '0' && h <= '9') ? h - '0'
                              : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                              : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
                    if (dig < 0) return -1;
                    v = v * 16u + (unsigned)dig;
                }
                if (v > 0x7Fu) return -1;
                o++;
                p += 4;
            } else return -1;
            p++;
        } else {
            o++;
            p++;
        }
    }
}

static int ipc_num(const char **pp, long long *v) {
    const char *p = *pp;
    const char *s = p;
    if (*p == '-') p++;
    const char *ds = p;
    while (*p >= '0' && *p <= '9') p++;
    if (p == ds) return -1;               /* "1e5", "-", "1.5" → not a number */
    char buf[24];
    size_t n = (size_t)(p - s);
    if (n >= sizeof buf) return -1;       /* overflow guard: reject, no wrap */
    memcpy(buf, s, n);
    buf[n] = 0;
    char *end = 0;
    errno = 0;
    long long x = strtoll(buf, &end, 10);
    if (errno == ERANGE || !end || *end) return -1;
    *v = x;
    *pp = p;
    return 0;
}

static ntx_ipc_cmd ipc_map(const char *c) {
    if (!strcmp(c, "ping")) return NTX_CMD_PING;
    if (!strcmp(c, "status")) return NTX_CMD_STATUS;
    if (!strcmp(c, "hello")) return NTX_CMD_HELLO;
    if (!strcmp(c, "add")) return NTX_CMD_ADD;
    if (!strcmp(c, "pause")) return NTX_CMD_PAUSE;
    if (!strcmp(c, "resume")) return NTX_CMD_RESUME;
    if (!strcmp(c, "remove")) return NTX_CMD_REMOVE;
    if (!strcmp(c, "quit")) return NTX_CMD_QUIT;
    if (!strcmp(c, "share")) return NTX_CMD_SHARE;
    return NTX_CMD_NONE;
}

void ntx_ipc_parse(const char *line, ntx_ipc_req *r) {
    memset(r, 0, sizeof *r);
    r->cmd = NTX_CMD_NONE;
    r->pre = NTX_IPC_E_BAD_JSON;
    const char *p = ipc_ws(line);
    if (*p != '{') return;
    p = ipc_ws(p + 1);
    if (*p == '}') return;                /* {} → no cmd → bad_json (§6.4) */
    int path_overflow = 0, magnet_overflow = 0, torrent_overflow = 0;
    for (;;) {
        char key[16];
        int krc = ipc_json_str(&p, key, sizeof key);
        if (krc == -2) {
            /* §6.1: a key too long for the scratch buffer is by
               construction unrecognized (longest recognized key is "magnet" —
               6 B): skip the whole name:value pair, do not fail the document. */
            size_t skip;
            if (ipc_json_str_len(&p, &skip) != 0) return;   /* consume the key token */
            p = ipc_ws(p);
            if (*p != ':') return;
            p = ipc_ws(p + 1);
            if (*p == '"') { if (ipc_json_str_len(&p, &skip) != 0) return; }
            else if (*p == '-' || (*p >= '0' && *p <= '9')) {
                long long v;
                if (ipc_num(&p, &v) != 0) return;
            } else return;                                    /* literal/array: v1 rejects */
            goto member_tail;
        }
        if (krc != 0) return;
        p = ipc_ws(p);
        if (*p != ':') return;
        p = ipc_ws(p + 1);
        int is_cmd = !strcmp(key, "cmd"), is_seq = !strcmp(key, "seq");
        int is_i = !strcmp(key, "i");
        int is_mag = !strcmp(key, "magnet"), is_path = !strcmp(key, "path");
        int is_tor = !strcmp(key, "torrent");
        if (*p == '"') {
            if (is_seq || is_i) return;    /* numbers must not be strings */
            if (is_cmd) {
                int crc = ipc_json_str(&p, r->cmd_echo, sizeof r->cmd_echo);
                if (crc == -2) {
                    /* §6.4: a cmd too long to echo is still a cmd —
                       answer unknown_cmd with an empty echo, not bad_json (§6.1). */
                    size_t skip;
                    if (ipc_json_str_len(&p, &skip) != 0) return;
                    r->cmd_echo[0] = 0;             /* drop the partial token: echo stays clean */
                    r->cmd_seen = 1;                /* cmd_echo "" → ipc_map → NONE → unknown_cmd */
                } else if (crc != 0) {
                    return;
                } else {
                    r->cmd_seen = 1;
                }
            } else if (is_mag || is_path || is_tor) {
                /* measure first, then store: a value over the cap is "too long"
                   (io), never bad_json, and the public buffer stays at the cap */
                const char *start = p;
                size_t vlen = 0;
                if (ipc_json_str_len(&p, &vlen) != 0) return;
                char *dst = is_mag ? r->magnet : is_path ? r->path : r->torrent;
                size_t dcap = is_mag ? (size_t)NTX_IPC_MAGNET_MAX : (size_t)(NTX_IPC_ARGS_MAX - 1);
                if (is_mag) r->has_magnet = 1;
                else if (is_path) r->has_path = 1;
                else r->has_torrent = 1;
                int over = vlen > dcap;
                if (is_mag) magnet_overflow = over;
                else if (is_path) path_overflow = over;
                else torrent_overflow = over;
                if (!over) {
                    const char *q = start;
                    if (ipc_json_str(&q, dst, dcap + 1) != 0) return;
                }
            } else {
                /* §6.1: unknown-key value skipped by MEASURE only —
                   a ≥512 B string must not fail the document (sink[-2] → bad_json).
                   ipc_json_str_len mirrors the same escape grammar, so the
                   accept/reject verdict is unchanged for values that fit. */
                size_t skip;
                if (ipc_json_str_len(&p, &skip) != 0) return;
            }
        } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
            if (is_cmd || is_mag || is_path || is_tor) return; /* those must be strings */
            long long v;
            if (ipc_num(&p, &v) != 0) return;
            if (is_seq) { r->seq = v; r->has_seq = 1; }
            else if (is_i) { r->i = (int)v; r->i_raw = v; r->has_i = 1; }
        } else return;                     /* true/false/null/nesting: v1 rejects */
    member_tail:
        p = ipc_ws(p);
        if (*p == ',') { p = ipc_ws(p + 1); if (*p == '}') return; continue; }
        if (*p == '}') {
            p = ipc_ws(p + 1);
            if (*p) return;               /* trailing junk after } */
            break;
        }
        return;
    }
    /* ── validation §6.4: gate before anything can mutate state ── */
    if (!r->cmd_seen) return;                                  /* pre: bad_json */
    r->cmd = ipc_map(r->cmd_echo);
    if (r->cmd == NTX_CMD_NONE) { r->pre = NTX_IPC_E_UNKNOWN_CMD; return; }
    switch (r->cmd) {
    case NTX_CMD_PAUSE: case NTX_CMD_RESUME: case NTX_CMD_REMOVE:
        if (!r->has_i || r->i < 0 || r->i >= NTX_SESSION_MAX_TTS) {
            r->pre = NTX_IPC_E_BAD_I;
            break;
        }
        r->pre = NTX_IPC_OK;
        break;
    case NTX_CMD_ADD: {
        int both = r->has_magnet + r->has_path;
        if (both != 1) r->pre = NTX_IPC_E_BAD_ARG;               /* not either/both */
        else if (r->has_magnet && !magnet_overflow && !r->magnet[0]) r->pre = NTX_IPC_E_BAD_ARG;
        else if (r->has_path && !path_overflow && !r->path[0]) r->pre = NTX_IPC_E_BAD_ARG;
        else if (r->has_path && (path_overflow || strlen(r->path) > 511)) r->pre = NTX_IPC_E_IO; /* §6.4 */
        else if (r->has_magnet && magnet_overflow) r->pre = NTX_IPC_E_IO; /* §11: magnet > 2048 B */
        else r->pre = NTX_IPC_OK;
        break;
    }
    case NTX_CMD_SHARE: /* §11: path required, torrent optional (== --share-from) */
        if (!r->has_path || (!path_overflow && !r->path[0])) r->pre = NTX_IPC_E_BAD_ARG;
        else if (path_overflow || (r->has_torrent && torrent_overflow)) r->pre = NTX_IPC_E_IO;
        else r->pre = NTX_IPC_OK;
        break;
    default:
        r->pre = NTX_IPC_OK;
        break;
    }
}

/* ── line framer (§3.3, §3.7, §3.9): one line = one document ─────────── */
void ntx_ipc_reader_init(ntx_ipc_reader *r) {
    r->len = 0;
    r->overflow = 0;
}

void ntx_ipc_feed(ntx_ipc_reader *r, const char *buf, size_t n, const ntx_ipc_sink *sink) {
    for (size_t k = 0; k < n; k++) {
        char c = buf[k];
        if (c == '\n') {
            if (r->overflow) {
                r->overflow = 0;
                r->len = 0;
                if (sink->on_bad) sink->on_bad(sink->ud); /* §3.7: bad_json once */
            } else {
                if (r->len && r->line[r->len - 1] == '\r') r->line[--r->len] = 0;
                r->line[r->len] = 0;
                r->len = 0;
                if (r->line[0]) { /* blank lines: silence (§3.3 tolerate) */
                    if (sink->on_line(sink->ud, r->line) != 0) return; /* stop */
                }
            }
            continue;
        }
        if (r->overflow) continue; /* drain to the next \n */
        if (r->len >= NTX_IPC_LINE_MAX) { r->overflow = 1; continue; }
        r->line[r->len++] = c;
    }
}
