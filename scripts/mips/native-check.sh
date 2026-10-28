#!/usr/bin/env bash
#
# Out-of-tree native (x86_64 host) regression harness for the mipsel port.
#
# Usage (from anywhere): scripts/mips/native-check.sh
#
# Proves the mipsel portability changes (32-bit x25519 fallback in
# src/crypto/ntx_x25519_fe.c, pointer-size-guarded GCM checks in
# src/crypto/ntx_aes.c) did not disturb the native 64-bit build:
#
#   1. Compiles ALL src/*.c as ONE program -> test/.agent-work/native-check/ntx-native
#      with the same flags `make ntx` uses, minus the harden PIE/RELRO sets
#      (those are irrelevant to codegen regressions and require PIE toolchain
#      defaults). Must build clean under -Werror.
#   2. Per-file `-fsyntax-only` pass over every src/*.c (fast sanity).
#   3. Compiles EVERY test/t_*.c into test/.agent-work/native-check/ and runs
#      each from the repo root with the same flags `make test` uses. Any
#      compile or run failure is reported and the script exits nonzero; on a
#      fully green suite it prints ALL PASS and exits 0.
#
# Hard guarantees (mipsel port ground rules):
#   - NEVER writes to the repo root: no `ntx`, no `.test.tmp`, no root `make`.
#   - Every binary/object it produces lives ONLY under test/.agent-work/native-check/.
#   - The shipped aarch64 `ntx` binary is never touched (integrity is proven
#     out-of-band via md5sum/stat around this script's invocation).
#
# CC_NATIVE overrides the detected host compiler (default: gcc, else cc).
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ ! -d src ] || [ ! -d test ]; then
    echo "[native-check] ERROR: must run from the nanotorrent repo root" >&2
    exit 2
fi

if command -v gcc >/dev/null 2>&1; then
    CC_NATIVE="${CC_NATIVE:-gcc}"
elif command -v cc >/dev/null 2>&1; then
    CC_NATIVE="${CC_NATIVE:-cc}"
else
    echo "[native-check] ERROR: no host C compiler (gcc or cc) found on PATH" >&2
    exit 127
fi

OUT="test/.agent-work/native-check"
mkdir -p "$OUT"

# Same as Makefile CFLAGS (make ntx / make test) without HARDEN_CFLAGS.
CFLAGS_NATIVE="${CFLAGS_NATIVE:--O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections}"
# make test links with LDFLAGS/LDLIBS; make ntx additionally hardens (omitted here by design).
LDFLAGS_NATIVE="${LDFLAGS_NATIVE:--Wl,--gc-sections}"
LDLIBS_NATIVE="${LDLIBS_NATIVE:--lm}"

echo "[native-check] host compiler: $CC_NATIVE ($("$CC_NATIVE" --version | head -n 1))"
echo "[native-check] artifacts dir: $OUT (repo root is never written to)"

# ---------------------------------------------------------------------------
# 1. Whole program: all src/*.c as one native binary (no harden PIE/RELRO).
# ---------------------------------------------------------------------------
mapfile -t SRCS < <(find src -name '*.c' | sort)
if [ "${#SRCS[@]}" -eq 0 ]; then
    echo "[native-check] ERROR: no src/*.c found" >&2
    exit 2
fi

echo "[native-check] == step 1: whole-program build (${#SRCS[@]} src/*.c -> $OUT/ntx-native)"
# shellcheck disable=SC2086 # CFLAGS/LDFLAGS/LDLIBS are word-split by design
"$CC_NATIVE" $CFLAGS_NATIVE -o "$OUT/ntx-native" "${SRCS[@]}" $LDFLAGS_NATIVE $LDLIBS_NATIVE
echo "[native-check] whole-program build OK (clean under -Werror)"
"$OUT/ntx-native" --version

# ---------------------------------------------------------------------------
# 2. Per-file syntax-only sanity over every src/*.c.
# ---------------------------------------------------------------------------
echo "[native-check] == step 2: per-file -fsyntax-only over ${#SRCS[@]} src/*.c"
for f in "${SRCS[@]}"; do
    # shellcheck disable=SC2086
    "$CC_NATIVE" $CFLAGS_NATIVE -fsyntax-only "$f"
done
echo "[native-check] per-file syntax pass OK (${#SRCS[@]}/${#SRCS[@]})"

# ---------------------------------------------------------------------------
# 3. Full native test suite: compile+run every test/t_*.c out-of-tree.
#    Same flags as `make test`; binaries live in $OUT, cwd stays repo root
#    (mirrors `make test` running ./.test.tmp from the root).
# ---------------------------------------------------------------------------
echo "[native-check] == step 3: native test suite (test/t_*.c)"
failures=()
total=0
for f in test/t_*.c; do
    base="$(basename "$f" .c)"
    bin="$OUT/$base"
    total=$((total + 1))
    printf '==> %s ' "$base"

    # shellcheck disable=SC2086
    if ! "$CC_NATIVE" $CFLAGS_NATIVE -o "$bin" "$f" $LDFLAGS_NATIVE $LDLIBS_NATIVE; then
        echo "COMPILE FAIL"
        failures+=("$base (compile)")
        rm -f "$bin"
        continue
    fi

    rc=0
    "$bin" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "RUN FAIL (rc=$rc)"
        failures+=("$base (run rc=$rc)")
    else
        echo "ok"
    fi
done

echo
echo "native suite: $total tests, $(( total - ${#failures[@]} )) passed, ${#failures[@]} failed"
if [ "${#failures[@]}" -gt 0 ]; then
    echo "FAILURES:"
    for x in "${failures[@]}"; do
        echo "  FAIL $x"
    done
    exit 1
fi
echo "ALL PASS"
exit 0
