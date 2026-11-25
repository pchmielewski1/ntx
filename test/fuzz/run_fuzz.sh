#!/usr/bin/env bash
# Smoke fuzz (60s/target) for the 6 parser families.
# Toolchain: gcc lacks -ffuzz-target -> clang -fsanitize=fuzzer,address,undefined (auto-detected).
# All outputs go to test/.scratch/ (binaries, logs, crash artifacts). Never touches build/, ./ntx, .test.tmp.
set -euo pipefail

cd "$(dirname "$0")/../.."
WORK=test/.scratch
FUZZ=test/fuzz
CORPUS=$FUZZ/corpus
mkdir -p "$WORK"

# --- toolchain detection ----------------------------------------------------
PROBE=$WORK/t5_probe.c
printf '#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *d, size_t n){(void)d;(void)n;}\n' > "$PROBE"
CC=""
FUZZ_FLAGS=""
if cc -ffuzz-target -fsanitize=address,undefined -c "$PROBE" -o "$WORK/t5_probe.o" 2>/dev/null; then
  CC=cc
  FUZZ_FLAGS="-ffuzz-target -fsanitize=address,undefined"
elif command -v clang >/dev/null 2>&1 && clang -fsanitize=fuzzer,address,undefined -c "$PROBE" -o "$WORK/t5_probe.o" 2>/dev/null; then
  CC=clang
  FUZZ_FLAGS="-fsanitize=fuzzer,address,undefined"
else
  echo "TOOLCHAIN: no libFuzzer support (gcc -ffuzz-target missing, no clang). Harnesses delivered; smoke runs skipped."
  exit 0
fi
echo "TOOLCHAIN: $CC ($FUZZ_FLAGS)"

# --- seed corpus (valid inputs from fixtures / test files) ------------------
mkdir -p "$CORPUS"/bencode "$CORPUS"/tracker "$CORPUS"/dht "$CORPUS"/http "$CORPUS"/utp "$CORPUS"/x509
cp test/vectors/bencode/spam.encoded   "$CORPUS/bencode/seed_spam"
cp test/vectors/bencode/nested.encoded "$CORPUS/bencode/seed_nested"
cp test/vectors/bencode/torrent.encoded "$CORPUS/bencode/seed_torrent"
cp test/vectors/doh/a_example.bin "$CORPUS/tracker/seed_doh_a"
python3 - "$CORPUS" <<'PYEOF'
import os, struct, sys

def be(x):
    if isinstance(x, int):
        return b"i" + str(x).encode() + b"e"
    if isinstance(x, bytes):
        return str(len(x)).encode() + b":" + x
    if isinstance(x, list):
        return b"l" + b"".join(be(i) for i in x) + b"e"
    items = sorted(x.items(), key=lambda kv: (len(kv[0]), kv[0]))
    return b"d" + b"".join(be(k.encode()) + be(v) for k, v in items) + b"e"

d = sys.argv[1]
def w(name, data):
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

# tracker: valid UDP connect response (16 B) + announce response (20 B header + 3 peers)
w("tracker/seed_udp_connect", struct.pack(">IiQ", 0, 0xCAFE, 0x1234567890ABCDEF))
w("tracker/seed_udp_announce",
  struct.pack(">iiiii", 1, 0x1234, 1800, 5, 3) +
  struct.pack(">4sH", b"\x01\x02\x03\x04", 6881) +
  struct.pack(">4sH", b"\x05\x06\x07\x08", 6882) +
  struct.pack(">4sH", b"\x09\x0a\x0b\x0c", 6883))
w("tracker/seed_http_dict",
  be({"peers": b"\x01\x02\x03\x04\x1a\x41", "seeders": 1, "interval": 1800, "leechers": 2}))

# dht: BEP5 announce_peer query + find_node response (2 x 26 B nodes) + raw compact nodes blob
node = bytes(range(1, 21)) + struct.pack(">4sH", b"\x01\x02\x03\x04", 6881)
w("dht/seed_announce_peer",
  be({"a": {"id": bytes(20), "info_hash": bytes(range(20)), "port": 6881},
      "q": b"announce_peer", "t": b"\x12\x34", "y": b"q"}))
w("dht/seed_find_node_resp",
  be({"r": {"g": bytes(20), "nodes": node + node}, "t": b"\x12\x34", "y": b"r"}))
w("dht/seed_nodes_compact", node + node)

# http: valid URL + bencoded tracker dict
w("http/seed_url", b"http://tracker.example.com:8080/announce?info_hash=%AA%BB")
w("http/seed_dict",
  be({"peers": b"\x01\x02\x03\x04\x1a\x41", "seeders": 1, "interval": 1800, "leechers": 2}))

# utp: plain DATA, STATE with a 4-byte SACK extension, SYN
def utp_hdr(t, ext=0):
    return struct.pack(">BBHIHHHH", (t << 4) | 1, ext, 7, 1234, 5, 3000, 42, 41)
w("utp/seed_data", utp_hdr(0) + b"handshake-bytes")
w("utp/seed_state_sack", utp_hdr(2, 1) + struct.pack(">BB", 1, 4) + b"\xff\xff\x00\x00" + struct.pack(">BB", 0, 0))
w("utp/seed_syn", utp_hdr(4))
w("utp/seed_sack_only", bytes(range(64)))

# x509: one valid PKCS#1 v1.5 and one PSS tuple from the checked-in vectors,
# plus a valid ECDSA sig DER and P-256 SPKI (same bytes as t_p256_ecdsa.c)
import glob
for mode, vf in ((0, "test/vectors/rsa_pkcs1/vectors.txt"), (1, "test/vectors/rsa_pss/vectors.txt")):
    for line in open(vf):
        f = line.split()
        if len(f) == 6 and f[4] == "1":
            w("x509/seed_%s" % ("pkcs1" if mode == 0 else "pss"),
              bytes([mode]) + bytes.fromhex(f[0]) + bytes.fromhex(f[3]) + bytes.fromhex(f[2]))
            break
der = bytes.fromhex("3046022100914d52011344b43cf280b169a35f31ac8b47a5f9b3e2bae70989797496"
                    "9e33ba022100ec499be92f70d359c6671c06575979dee9b8ade36b23c648f26aab2f"
                    "3c1dd35b")
spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004f50b530908b6fe"
                     "b23ced7a7cb90a3c0bcad11c34517fce18e1b0b7f6a114302731323a0b38319b91"
                     "f90f758ab4fd1d6b255be008465e651926629dc7a333ce53")
w("x509/seed_sig_der", bytes([2]) + der)
w("x509/seed_spki", bytes([3]) + spki)
PYEOF

# --- build + smoke fuzz ------------------------------------------------------
declare -A HARNESS=(
  [bencode]=fuzz_bencode.c
  [tracker]=fuzz_tracker.c
  [dht]=fuzz_dht.c
  [http]=fuzz_http.c
  [utp]=fuzz_utp.c
  [x509]=fuzz_x509.c
)

for name in bencode tracker dht http utp x509; do
  bin="$WORK/fuzz_$name"
  echo "== [$name] build"
  "$CC" -O1 -g -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L $FUZZ_FLAGS \
    -o "$bin" "$FUZZ/${HARNESS[$name]}" -lm
  echo "== [$name] fuzz 60s"
  rm -f "$WORK"/fuzz_${name}_crash-* "$WORK"/fuzz_${name}_assertion-* 2>/dev/null || true
  set +e
  timeout 60 "$bin" -corpus="$CORPUS/$name" -max_len=4096 -timeout=5 \
    -artifact_prefix="$WORK/fuzz_${name}_" 2> "$WORK/fuzz_${name}.log"
  rc=$?
  set -e
  crash_n=0
  for c in "$WORK"/fuzz_${name}_crash-* "$WORK"/fuzz_${name}_assertion-*; do
    if [ -e "$c" ]; then crash_n=$((crash_n + 1)); fi
  done
  if [ "$crash_n" -gt 0 ]; then
    echo "CRASH [$name] (rc=$rc):"
    for c in "$WORK"/fuzz_${name}_crash-* "$WORK"/fuzz_${name}_assertion-*; do
      [ -e "$c" ] || continue
      echo "  $c"
      od -A d -t x1z "$c" | head -8
    done
  else
    execs=$(grep -oE 'exec/s: [0-9]+' "$WORK/fuzz_${name}.log" | tail -1 | awk '{print $2}' || true)
    total=$(grep -oE '^#[0-9]+' "$WORK/fuzz_${name}.log" | tail -1 | tr -d '#' || true)
    echo "OK [$name]: no crash, ${execs:-?} exec/s (${total:-0} total runs, rc=$rc)"
  fi
done
echo "== done"
