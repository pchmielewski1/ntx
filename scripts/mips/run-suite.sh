#!/usr/bin/env bash
#
# Cross-compile every test/t_*.c with the MIPS toolchain and run it under
# qemu-mipsel user-mode emulation (x86_64 host).
#
# Usage (from anywhere): scripts/mips/run-suite.sh
#
# Each test binary is built statically to test/.mipsel.<base>.tmp (gitignored)
# with the same flags as `make test`, plus -static (required: dynamic musl
# binaries do not run under qemu-mipsel without a sysroot -L). Binaries are
# removed after each run. Failures accumulate; the list is printed at the end
# and the script exits nonzero if any test failed, or prints ALL PASS and
# exits 0 when the whole suite is green.
#
# NTX_TEST_TIMEOUT_SCALE is propagated into the qemu environment so guests
# can scale their internal timing windows (Task 5).
set -uo pipefail

cd "$(dirname "$0")/../.."

if [ ! -d test ] || [ ! -f scripts/mips/qemu-user-run.sh ]; then
    echo "[run-suite] ERROR: must run from the nanotorrent repo root" >&2
    exit 2
fi

MIPS_CC="${MIPS_CC:-$HOME/toolchains/mipsel-linux-musl/bin/mipsel-linux-musl-gcc}"
CFLAGS="${CFLAGS:--O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections}"
LDFLAGS="${LDFLAGS:--Wl,--gc-sections}"
LDLIBS="${LDLIBS:--lm}"
export NTX_TEST_TIMEOUT_SCALE="${NTX_TEST_TIMEOUT_SCALE:-1}"

if [ ! -x "$MIPS_CC" ]; then
    echo "[run-suite] ERROR: MIPS_CC not executable: $MIPS_CC" >&2
    exit 127
fi

failures=()
total=0

for f in test/t_*.c; do
    base="$(basename "$f" .c)"
    bin="test/.mipsel.${base}.tmp"
    total=$((total + 1))
    printf '==> %s ' "$base"

    # shellcheck disable=SC2086 # CFLAGS/LDFLAGS/LDLIBS are word-split by design
    if ! "$MIPS_CC" $CFLAGS -static -o "$bin" "$f" $LDFLAGS $LDLIBS; then
        echo "COMPILE FAIL"
        failures+=("$base (compile)")
        rm -f "$bin"
        continue
    fi

    bash scripts/mips/qemu-user-run.sh "$bin"
    rc=$?
    rm -f "$bin"
    if [ "$rc" -ne 0 ]; then
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
