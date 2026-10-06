#!/usr/bin/env python3
"""Assert the NDJSON stream of ntx --stats-json (§12 gates).

Usage: python3 assert_ipc.py out.ndjson — exits 1 on the first breach.
Contract:
  * line 1 is hello (caps verbatim), emitted exactly once;
  * every stats line is v1-conform: n == len(torrents), truncated never lies,
    ih values are 40-char lowercase hex, slot i in [0,16);
  * every reply (ack or err) carrying seq echoes the scripted cmd;
  * every err code belongs to the shipped catalog;
  * the LAST line of the main pass is the quit ack (§8: "the last line is the ack").
"""
import json, sys

def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)

if len(sys.argv) != 2:
    die("usage: assert_ipc.py <out.ndjson>")

CAPS = ["ping", "status", "hello", "add", "pause", "resume", "remove", "quit"]
CODES = ("bad_json", "unknown_cmd", "bad_i", "no_slot", "not_ready",
         "bad_arg", "full", "io", "internal")

lines = []
with open(sys.argv[1], "rb") as f:
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
if caps != CAPS:
    die(f"FAIL caps drift: {caps}")
hellos = sum(1 for ln in lines if ln.get("type") == "hello")
if hellos != 1:
    die(f"FAIL hello must be emitted exactly once, saw {hellos}")

replies = {}
for ln in lines:
    t = ln.get("type")
    if t == "stats":
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

# scripted expectations of interop_ipc.sh (same order, same seq numbers).
# seq=7 is the idempotency probe: the shipped dispatcher answers a remove of a
# DEAD slot with err/no_slot — the reply still echoes seq+cmd, so it is recorded
# from the err branch above (the brief's own wait_for pins '"code":"no_slot"').
want = {1: "ping", 2: "add", 3: "pause", 4: "pause", 5: "resume",
        6: "remove", 7: "remove", 8: "quit"}
for seq, cmd in want.items():
    if replies.get(seq) != cmd:
        die(f"FAIL ack seq={seq} want={cmd} got={replies.get(seq)}")
if lines[-1].get("cmd") != "quit" or lines[-1].get("type") != "ack" \
        or lines[-1].get("ok") != 1:
    die(f"FAIL last line must be the quit ack: {lines[-1]}")
print(f"ipc stream OK: {len(lines)} lines, {len(replies)} acks")
