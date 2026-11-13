#!/usr/bin/env bash
#
# Cross-compile every test/t_*.c with the riscv64 toolchain and run it under
# qemu-riscv64 user-mode emulation.
#
# Usage (from anywhere): scripts/riscv/run-suite.sh
#
# Each test is built with the same flags as `make test` (dynamic glibc) to
# test/.riscv64.<base>.tmp (gitignored), run from the repo root through
# scripts/riscv/qemu-user-run.sh, and removed. Failures accumulate; the list is
# printed at the end and the script exits nonzero if any test failed, or
# prints ALL PASS and exits 0 when the whole suite is green.
#
# NTX_TEST_TIMEOUT_SCALE is exported to the tests (test/tscale.h) and defaults
# to 4 here, NOT to the native 1: this script only ever runs the suite under
# qemu-riscv64 TCG (native is `make test`, a different target), so native parity
# is the wrong floor for it. TCG measured ~1.5x native on the tick-budget case
# (66..68 ms vs 34..45 ms against the 100 ms reference in t_share_session.c);
# 4 leaves headroom of the same kind the ASAN branch takes. Only ts_ms() users
# are affected — no test sleeps behind it, so the 300 s hang guard is untouched.
# Set NTX_TEST_TIMEOUT_SCALE=1 explicitly to get native parity.
#
# NTX_TEST_TIMEOUT (default 300 s) bounds each test, so a hang fails instead of
# blocking; exit 124 (TERM) or 137 (KILL after -k 10) is a timeout failure.
# NTX_TEST_GLOB overrides the test file glob (debugging aid).
set -uo pipefail

cd "$(dirname "$0")/../.."

if [ ! -d test ] || [ ! -f scripts/riscv/qemu-user-run.sh ]; then
    echo "[run-suite] ERROR: must run from the nanotorrent repo root" >&2
    exit 2
fi

RISCV_CC="${RISCV_CC:-riscv64-linux-gnu-gcc}"
CFLAGS="${CFLAGS:--O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections}"
LDFLAGS="${LDFLAGS:--Wl,--gc-sections}"
LDLIBS="${LDLIBS:--lm}"
export NTX_TEST_TIMEOUT_SCALE="${NTX_TEST_TIMEOUT_SCALE:-4}"
NTX_TEST_TIMEOUT="${NTX_TEST_TIMEOUT:-300}"
TEST_GLOB="${NTX_TEST_GLOB:-test/t_*.c}"

if ! command -v timeout >/dev/null 2>&1; then
    echo "[run-suite] ERROR: coreutils 'timeout' not found on PATH (hang guard requires it)" >&2
    exit 127
fi
if ! command -v "$RISCV_CC" >/dev/null 2>&1; then
    echo "[run-suite] ERROR: RISCV_CC not found: $RISCV_CC (install gcc-riscv64-linux-gnu)" >&2
    exit 127
fi

failures=()
total=0

shopt -s nullglob
test_files=($TEST_GLOB)
shopt -u nullglob

if [ "${#test_files[@]}" -eq 0 ]; then
    echo "[run-suite] ERROR: test glob '$TEST_GLOB' matched zero test files — refusing to report ALL PASS" >&2
    exit 1
fi

for f in "${test_files[@]}"; do
    base="$(basename "$f" .c)"
    bin="test/.riscv64.${base}.tmp"
    total=$((total + 1))
    printf '==> %s ' "$base"

    # shellcheck disable=SC2086 # CFLAGS/LDFLAGS/LDLIBS are word-split by design
    if ! "$RISCV_CC" $CFLAGS -o "$bin" "$f" $LDFLAGS $LDLIBS; then
        echo "COMPILE FAIL"
        failures+=("$base (compile)")
        rm -f "$bin"
        continue
    fi

    timeout -k 10 "$NTX_TEST_TIMEOUT" bash scripts/riscv/qemu-user-run.sh "$bin"
    rc=$?
    rm -f "$bin"
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "TIMEOUT (exceeded ${NTX_TEST_TIMEOUT}s)"
        failures+=("$base (timeout ${NTX_TEST_TIMEOUT}s rc=$rc)")
    elif [ "$rc" -ne 0 ]; then
        echo "RUN FAIL (rc=$rc)"
        failures+=("$base (run rc=$rc)")
    else
        echo "ok"
    fi
done

echo
echo "suite: $total tests, $(( total - ${#failures[@]} )) passed, ${#failures[@]} failed"
if [ "${#failures[@]}" -gt 0 ]; then
    echo "FAILURES:"
    for x in "${failures[@]}"; do
        echo "  FAIL $x"
    done
    exit 1
fi
echo "ALL PASS"
exit 0
