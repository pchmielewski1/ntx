#!/usr/bin/env python3
"""Assert the NDJSON stream of ntx --stats-json (§12 gates).

Usage: python3 assert_ipc.py out.ndjson [options] — exits 1 on the first breach.
Contract (always):
  * line 1 is hello (caps verbatim), emitted exactly once;
  * every stats line is v1-conform: n == len(torrents), truncated never lies,
    ih values are 40-char lowercase hex, slot i in [0,16);
  * every reply (ack or err) carrying seq echoes the scripted cmd;
  * every err code belongs to the shipped catalog;
  * the LAST line of the main pass is the quit ack (§8: "the last line is the ack").

Options (V04, the real-pipe share leg — every one of them is off unless given,
so the original single-argument call is unaffected):
  --want SEQ=CMD      repeatable; replaces the built-in seq→cmd expectation map
  --share-ok N        exactly N share events with ok:1 (the §11 "exactly once")
  --ih / --ih2 / --name / --torrent   every ok share event carries this value
  --tracker SUBSTR    the event's magnet carries this percent-encoded tr=
  --ordering SEQ      the ack of SEQ precedes the ok share event, and a stats
                      line follows it (docs/json-api.md: ack → share → stats)
  --stats-min N       at least N stats lines in the stream
"""
import json, sys

def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)

# --- options -----------------------------------------------------------------
argv = sys.argv[1:]
FLAGS = {"--want": "want", "--share-ok": "share_ok", "--ih": "ih", "--ih2": "ih2",
         "--name": "name", "--torrent": "torrent", "--tracker": "tracker",
         "--ordering": "ordering", "--stats-min": "stats_min"}
OPTS = {v: None for v in FLAGS.values()}
want_list, pos = [], []
i = 0
while i < len(argv):
    a = argv[i]
    if a in FLAGS:
        if i + 1 >= len(argv):
            die(f"FAIL usage: {a} needs a value")
        if a == "--want":
            want_list.append(argv[i + 1])
        else:
            OPTS[FLAGS[a]] = argv[i + 1]
        i += 2
        continue
    pos.append(a)
    i += 1
if len(pos) != 1:
    die("usage: assert_ipc.py <out.ndjson> [--want SEQ=CMD ...] [--share-ok N] "
        "[--ih H] [--ih2 H] [--name N] [--torrent P] [--tracker S] [--ordering SEQ] "
        "[--stats-min N]")

BASE_CAPS = ["ping", "status", "hello", "add", "pause", "resume", "remove", "quit"]
# §11: "share" is advertised only while ntx_share_available() (>= NTX_SHARE_MIN_TRACKERS
# pinned https hosts), so the expected caps depend on the build under test.
SHARE_CAP = "share"
# Scripted share probes (interop_ipc.sh, seq 9 and 10): a missing file and a
# directory both fail the open/S_ISREG gate of share_add (§11) → io. no_trackers
# is accepted too so the gate stays honest on a build whose tracker list is
# unusable (§6.4), where share_add refuses before the filesystem check.
SHARE_ERR = ("io", "no_trackers")
CODES = ("bad_json", "unknown_cmd", "bad_i", "no_slot", "not_ready",
         "bad_arg", "full", "io", "internal", "no_trackers")

lines = []
with open(pos[0], "rb") as f:
    for raw in f:
        raw = raw.strip(b"\r\n")
        if not raw:
            continue
        try:
            lines.append(json.loads(raw))
        except Exception as e:
            die(f"FAIL unparseable line {len(lines)}: {raw[:120]!r}: {e}")

if not lines:
    die("FAIL empty stream")
if lines[0].get("type") != "hello" or lines[0].get("protocol") != "ntx-json" \
        or lines[0].get("v") != 1:
    die(f"FAIL hello must be line 0, got: {lines[0]}")
caps = lines[0]["caps"]
if caps not in (BASE_CAPS, BASE_CAPS + [SHARE_CAP]):
    die(f"FAIL caps drift: {caps}")
hellos = sum(1 for ln in lines if ln.get("type") == "hello")
if hellos != 1:
    die(f"FAIL hello must be emitted exactly once, saw {hellos}")

replies = {}
share_errs = {}
share_evs = []
stats_idx = []
for idx, ln in enumerate(lines):
    t = ln.get("type")
    if t == "stats":
        stats_idx.append(idx)
        if ln.get("v") != 1:
            die(f"FAIL stats v: {ln}")
        tts = ln.get("torrents")
        if not isinstance(tts, list):
            die(f"FAIL stats missing torrents list: {ln}")
        if ln.get("n") != len(tts):
            die(f"FAIL n != len(torrents): {ln.get('n')} vs {len(tts)}")
        if ("truncated" in ln) != (ln.get("truncated") == 1):
            die(f"FAIL truncated lies: {ln.get('truncated')}")
        for t_ in tts:
            ih = t_.get("ih", "")
            if len(ih) != 40 or any(c not in "0123456789abcdef" for c in ih):
                die(f"FAIL ih shape: {ih!r}")
            if not isinstance(t_.get("i"), int) or not 0 <= t_["i"] <= 15:
                die(f"FAIL slot i: {t_.get('i')}")
    elif t == "ack":
        if ln.get("ok") != 1:
            die(f"FAIL ack ok: {ln}")
        if "seq" in ln:
            replies[ln["seq"]] = ln["cmd"]
    elif t == "err":
        if ln.get("ok") != 0:
            die(f"FAIL err ok: {ln}")
        if ln.get("code") not in CODES:
            die(f"FAIL unknown code: {ln.get('code')}")
        if "seq" in ln:
            replies[ln["seq"]] = ln["cmd"]
            if ln["cmd"] == "share":
                share_errs[ln["seq"]] = ln.get("code")
    elif t == "share":
        share_evs.append((idx, ln))

# scripted expectations of interop_ipc.sh (same order, same seq numbers).
# seq=7 is the idempotency probe: the shipped dispatcher answers a remove of a
# DEAD slot with err/no_slot — the reply still echoes seq+cmd, so it is recorded
# from the err branch above (the brief's own wait_for pins '"code":"no_slot"').
if want_list:
    # The V04 leg scripts its own commands, so it declares its own expectations.
    want = {}
    for w in want_list:
        seq, _, cmd = w.partition("=")
        want[int(seq)] = cmd
else:
    want = {1: "ping", 2: "add", 3: "pause", 4: "pause", 5: "resume", 6: "remove",
            7: "remove", 8: "quit", 9: "share", 10: "share", 11: "add", 12: "share"}
for seq, cmd in want.items():
    if replies.get(seq) != cmd:
        die(f"FAIL ack seq={seq} want={cmd} got={replies.get(seq)}")
if not want_list:
    # §11 synchronous share errors: a nonexistent path and a directory are both io.
    for seq in (9, 10):
        if share_errs.get(seq) not in SHARE_ERR:
            die(f"FAIL share seq={seq} want code in {SHARE_ERR} got={share_errs.get(seq)}")
    # R30: "a\u0000b" is refused by the parser, never by the filesystem.
    if share_errs.get(12) != "bad_json":
        die(f"FAIL share seq=12 want code=bad_json got={share_errs.get(12)}")
if lines[-1].get("cmd") != "quit" or lines[-1].get("type") != "ack" \
        or lines[-1].get("ok") != 1:
    die(f"FAIL last line must be the quit ack: {lines[-1]}")

# ------------------------------------------------- V04: the real-pipe share ---
# The ready event is the only line of the protocol whose content is produced
# asynchronously, so the caller pins it here instead of with a grep. Each check
# is skipped only when the option is absent; when present it is exact.
ok_evs = [(i, ln) for i, ln in share_evs if ln.get("ok") == 1]
if OPTS["share_ok"] is not None:
    n = int(OPTS["share_ok"])
    if len(ok_evs) != n:
        die(f"FAIL ok share events: got {len(ok_evs)}, want exactly {n}: "
            f"{[l for _, l in share_evs]}")
for key in ("ih", "ih2", "name", "torrent"):
    want_v = OPTS[key]
    if want_v is None:
        continue
    if not ok_evs:
        die(f"FAIL no ok share event to check {key} against")
    for i, ln in ok_evs:
        if ln.get(key) != want_v:
            die(f"FAIL share event line {i} {key}: got {ln.get(key)!r} want {want_v!r}")
    # the slot id pairs the event with its ack (§11) and must be an int in range
    for i, ln in ok_evs:
        if not isinstance(ln.get("i"), int) or not 0 <= ln["i"] <= 15:
            die(f"FAIL share event line {i} slot i: {ln.get('i')!r}")
if OPTS["tracker"] is not None:
    if not ok_evs:
        die("FAIL no ok share event to check the magnet against")
    for i, ln in ok_evs:
        mag = ln.get("magnet") or ""
        if not mag.startswith("magnet:?xt=urn:btih:"):
            die(f"FAIL share event line {i} magnet: {mag[:60]!r}")
        if OPTS["tracker"] not in mag:
            die(f"FAIL share event line {i} magnet has no tr={OPTS['tracker']!r}: "
                f"{mag[:200]!r}")
if OPTS["ordering"] is not None:
    seq = int(OPTS["ordering"])
    ack_i = next((i for i, ln in enumerate(lines)
                  if ln.get("type") == "ack" and ln.get("seq") == seq), None)
    if ack_i is None:
        die(f"FAIL ordering: no ack for seq={seq}")
    if not ok_evs:
        die(f"FAIL ordering: no ok share event to order after ack seq={seq}")
    early = [i for i, _ in share_evs if i < ack_i]
    if early:
        die(f"FAIL ordering: share event(s) at {early} precede the ack of seq={seq} "
            f"at {ack_i} — §11 answers the command first")
    ev_i = ok_evs[0][0]
    if not ack_i < ev_i:
        die(f"FAIL ordering: ack(seq {seq}) at {ack_i} is not before the share "
            f"event at {ev_i}")
    after = [i for i in stats_idx if i > ev_i]
    if not after:
        die(f"FAIL ordering: no stats line after the share event at {ev_i} "
            f"(stats at {stats_idx})")
if OPTS["stats_min"] is not None:
    n = int(OPTS["stats_min"])
    if len(stats_idx) < n:
        die(f"FAIL stats lines: got {len(stats_idx)}, want >= {n}")
print(f"ipc stream OK: {len(lines)} lines, {len(replies)} acks, "
      f"{len(share_evs)} share events, {len(stats_idx)} stats")
