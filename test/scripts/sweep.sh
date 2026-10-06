#!/bin/bash
# Parallel compile + run of every test/t_*.c, optionally under extra compiler flags.
#
#   test/scripts/sweep.sh OUTDIR [extra cflags...]
#
# e.g. the sanitizer sweep used for the security audit:
#   test/scripts/sweep.sh /tmp/asan -O1 -g -fno-omit-frame-pointer \
#       -fsanitize=address,undefined -fno-sanitize-recover=undefined \
#       -Wno-format-truncation -Wno-restrict
#
# Results land in OUTDIR/summary (OK / FAIL rc= / CCFAIL per suite, then DONE) and per-suite logs.
# Suites that open sockets or fixed directories can collide when run in parallel: re-run any
# failure on its own (or `make test`) before treating it as real.
set -u
OUT=$1; shift
EXTRA="$*"
mkdir -p "$OUT"
cd "$(dirname "$0")/../.."
run_one() {
  f=$1; OUT=$2; shift 2
  n=$(basename "$f" .c)
  if ! gcc -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L "$@" -o "$OUT/$n.bin" "$f" -lm >"$OUT/$n.cc.log" 2>&1; then
    echo "CCFAIL $n" >> "$OUT/summary"; return
  fi
  ASAN_OPTIONS=detect_leaks=0 timeout 600 "$OUT/$n.bin" >"$OUT/$n.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then echo "OK $n" >> "$OUT/summary"; else echo "FAIL $n rc=$rc" >> "$OUT/summary"; fi
}
export -f run_one
: > "$OUT/summary"
ls test/t_*.c | xargs -P "${JOBS:-8}" -I{} bash -c "run_one {} $OUT $EXTRA"
echo DONE >> "$OUT/summary"
