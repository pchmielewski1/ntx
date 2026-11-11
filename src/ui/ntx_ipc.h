#ifndef NTX_IPC_H
#define NTX_IPC_H

#include <stddef.h>
#include <stdint.h>

#include "../core/ntx_session.h" /* NTX_SESSION_MAX_TTS / _MAX_PEERS */
#include "../core/ntx_share.h"   /* ntx_share_event (the §11 share event line) */

/* JSON string escape (JSON Control API §11.1).
   Rules: '"' -> \" , '\\' -> \\ , '\n' -> \n , '\r' -> \r , '\t' -> \t ,
   other 0x00-0x1F -> \u00xx ; all other bytes (incl. >= 0x80) pass raw.
   Returns bytes written (excluding NUL) or -1 when the result would not
   fit in cap (never emits a torn escape). */
int ntx_json_escape(char *out, size_t cap, const char *s);

/* 40 lowercase hex digits of a 20-byte wire hash (§5.2). Always 40. */
int ntx_hex40(char out[41], const uint8_t h[20]);

/* ── Commands (§6) — pure parse + validation, no session calls (§6.4) ── */
#define NTX_IPC_LINE_MAX 4096 /* §3.7 frame limit */
#define NTX_IPC_ARGS_MAX 512  /* path/torrent value cap (§6.4, §11: ≤ 511 + NUL) */
#define NTX_IPC_MAGNET_MAX 2048 /* §11: magnet in add grew from 511 B (relaxation, back-compat) */
#define NTX_IPC_CMD_ECHO 64   /* unknown-cmd echo cap (§8 err.cmd) */

typedef enum {
    NTX_IPC_OK = 0,
    NTX_IPC_E_BAD_JSON, NTX_IPC_E_UNKNOWN_CMD, NTX_IPC_E_BAD_I,
    NTX_IPC_E_NO_SLOT, NTX_IPC_E_NOT_READY, NTX_IPC_E_BAD_ARG,
    NTX_IPC_E_FULL, NTX_IPC_E_IO, NTX_IPC_E_INTERNAL,
    NTX_IPC_E_NO_TRACKERS /* §11: new code, kept last so the v1 values are stable */
} ntx_ipc_code;

typedef enum {
    NTX_CMD_NONE = -1,
    NTX_CMD_PING = 0, NTX_CMD_STATUS, NTX_CMD_HELLO, NTX_CMD_ADD,
    NTX_CMD_PAUSE, NTX_CMD_RESUME, NTX_CMD_REMOVE, NTX_CMD_QUIT, NTX_CMD_SHARE
} ntx_ipc_cmd;

typedef struct ntx_ipc_req {
    ntx_ipc_cmd cmd;        /* NTX_CMD_NONE until a known name maps */
    int cmd_seen;           /* "cmd" key carried a string at all */
    ntx_ipc_code pre;       /* validation verdict, §6.4 (OK = executable) */
    long long seq; int has_seq;
    int i; int has_i;
    long long i_raw; /* untruncated "i" token; the dispatcher bounds-checks THIS
                        (parser truncates to int for the hot path; a huge literal
                        can wrap past the int guard — see the bounds check in ntx_ipc_dispatch.c). */
    char magnet[NTX_IPC_MAGNET_MAX + 1]; /* §11: add accepts a magnet of up to 2048 B */
    char path[NTX_IPC_ARGS_MAX];
    char torrent[NTX_IPC_ARGS_MAX]; /* share: the optional --share-from .torrent (§11) */
    int has_magnet, has_path, has_torrent; /* key presence, even for empty values (§6.4) */
    char cmd_echo[NTX_IPC_CMD_ECHO]; /* verbatim cmd token for ack/err */
} ntx_ipc_req;

/* Parse one framed line into a request and validate it (§6.1, §6.4).
   Pure: never touches the session. Unknown keys are skipped (§6.1).
   Duplicate keys: last one wins. Values: string | number; nesting rejected. */
void ntx_ipc_parse(const char *line, ntx_ipc_req *r);

/* Contract hello (§7). Returns length or -1 when cap too small.
   Key order is the document order of §7; build_id passes the escaper.
   §11: "share" joins caps only while ntx_share_available() (the §6.4 gate). */
int ntx_ipc_hello_json(char *out, size_t cap, const char *build_id);

/* Share result line (§11), one per share, own buffer >= 8 KiB:
   ok: {"type":"share","i":K,"ok":1,"ih":"<40 hex>","ih2":"<64 hex>","name":…,
        "magnet":…,"torrent":…}   fail: {"type":"share","i":K,"ok":0,"code":"…"}
   Returns length or -1 when the line would not fit cap. */
int ntx_ipc_share_event_json(char *out, size_t cap, const ntx_share_event *ev);

/* ── dispatcher (§6, §8): execute one parsed line, emit ack/err ─────────
   Returns bitfield: NTX_IPC_F_EMIT_STATUS → glue re-emits a stats snapshot
   now (status cmd); NTX_IPC_F_QUIT → session quit requested, glue exits 0.
   out receives the NUL-terminated reply line ("" when no reply, e.g. status).
   Ordering §3.6 is the glue's duty: dispatch before snapshot per tick. */
#define NTX_IPC_F_EMIT_STATUS 1
#define NTX_IPC_F_QUIT 2
struct ntx_session;
int ntx_ipc_dispatch(struct ntx_session *s, const char *line, char *out, size_t cap);

/* ── line framer (§3.3, §3.7, §3.9): one line = one document ────────────
   \r before \n stripped; a line longer than NTX_IPC_LINE_MAX overflows
   to on_bad once and is dropped to the next \n (never executed); the
   caller closes the channel itself on read()==0 (EOF ⇒ keep serving). */
typedef struct ntx_ipc_reader {
    char line[NTX_IPC_LINE_MAX + 1];
    size_t len;
    int overflow;
} ntx_ipc_reader;
typedef struct ntx_ipc_sink {
    void *ud;
    int (*on_line)(void *ud, const char *line); /* non-zero stops feeding */
    void (*on_bad)(void *ud);
} ntx_ipc_sink;
void ntx_ipc_reader_init(ntx_ipc_reader *r);
void ntx_ipc_feed(ntx_ipc_reader *r, const char *buf, size_t n, const ntx_ipc_sink *sink);

/* Build id carried in the hello contract line. ntx_main.c owns the single
   truth (NTX_BUILD_ID) and defines this first; the header guard lets the
   dispatcher + hello emitter compile standalone (can be overridden via -D). */
#ifndef NTX_IPC_BUILD_ID
#define NTX_IPC_BUILD_ID "seed-ratio-v1"
#endif

#endif /* NTX_IPC_H */
