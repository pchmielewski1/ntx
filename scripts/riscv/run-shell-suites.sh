#!/usr/bin/env bash
#
# Run the shell-level gates (test-cli, test-net, test-ipc, test-tls13) against
# the riscv64 binary under qemu-riscv64 user-mode emulation.
#
# Usage (from anywhere, after `make riscv`): scripts/riscv/run-shell-suites.sh
#
# The gates hard-code ./ntx relative to their own repo root, so this script
# builds a scratch root test/.scratch/riscv64-shell/ holding copies of the gate
# scripts and an executable ./ntx wrapper that runs the riscv64 binary through
# scripts/riscv/qemu-user-run.sh. The native ./ntx is never read, built or
# written. The scratch root is removed when every gate passes and kept for
# inspection otherwise.
#
# NTX_RISCV_BIN overrides the binary under test (default: ntx-riscv64).
# test-tls13 exiting 77 (no openssl / cannot listen) is a skip, as in
# `make test-tls13`.
set -uo pipefail

cd "$(dirname "$0")/../.."
REPO=$PWD
RISCV_CC="${RISCV_CC:-riscv64-linux-gnu-gcc}"
BIN="${NTX_RISCV_BIN:-ntx-riscv64}"
case "$BIN" in
    /*) ;;
    *) BIN="$REPO/$BIN" ;;
esac

if [ ! -f "$BIN" ]; then
    echo "[riscv-shell] ERROR: $BIN not found (run make riscv first)" >&2
    exit 2
fi
# ELF e_machine (2 bytes at offset 18, little-endian) must be 0x00f3 = EM_RISCV.
if [ "$(od -An -tx1 -j18 -N2 "$BIN" | tr -d ' \n')" != "f300" ]; then
    echo "[riscv-shell] ERROR: $BIN is not a RISC-V ELF binary" >&2
    exit 2
fi

W="$REPO/test/.scratch/riscv64-shell"
rm -rf "$W"
mkdir -p "$W/test/interop/ipc"
cp test/cli_errors.sh test/net_loopback.sh test/tls13_interop.sh "$W/test/"
cp test/interop/ipc/interop_ipc.sh test/interop/ipc/assert_ipc.py "$W/test/interop/ipc/"

wrap() { # wrap <wrapper-path> <riscv64-binary>
    printf '#!/bin/sh\nexec bash "%s/scripts/riscv/qemu-user-run.sh" "%s" "$@"\n' "$REPO" "$2" > "$1" || exit 2
    chmod +x "$1" || exit 2
}
wrap "$W/ntx" "$BIN"

# Same sources and flags test/tls13_interop.sh uses for its native probe.
TLS_SRC=$(sed -n 's/^  SRC="\(.*\)"$/\1/p' test/tls13_interop.sh)
if [ -z "$TLS_SRC" ]; then
    echo "[riscv-shell] ERROR: cannot read the SRC= list from test/tls13_interop.sh" >&2
    exit 2
fi
# shellcheck disable=SC2086 # TLS_SRC is a word list by design
if ! "$RISCV_CC" -O2 -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -DNTX_TLS13_LIVE=1 \
        -o "$W/tls_probe-riscv64" test/tls_probe.c $TLS_SRC -lm; then
    echo "[riscv-shell] ERROR: tls_probe cross-compile failed" >&2
    exit 1
fi
# A non-RISC-V probe would let test/tls13_interop.sh silently fall back to a
# native gcc build; fail hard instead of gating a release on unemulated TLS.
if [ "$(od -An -tx1 -j18 -N2 "$W/tls_probe-riscv64" | tr -d ' \n')" != "f300" ]; then
    echo "[riscv-shell] ERROR: $W/tls_probe-riscv64 is not a RISC-V ELF binary" >&2
    exit 2
fi
wrap "$W/tls_probe" "$W/tls_probe-riscv64"

failures=()
gate() { # gate <name> <command...>
    local name=$1 rc
    shift
    echo "==> $name"
    "$@"
    rc=$?
    if [ "$rc" -eq 0 ] || { [ "$name" = test-tls13 ] && [ "$rc" -eq 77 ]; }; then
        echo "ok $name (rc=$rc)"
    else
        echo "FAIL $name (rc=$rc)"
        failures+=("$name")
    fi
}

gate test-cli   sh   "$W/test/cli_errors.sh"
gate test-net   sh   "$W/test/net_loopback.sh"
gate test-ipc   bash "$W/test/interop/ipc/interop_ipc.sh"
gate test-tls13 bash "$W/test/tls13_interop.sh" "$W/tls_probe"

echo
if [ "${#failures[@]}" -gt 0 ]; then
    echo "riscv64 shell gates FAILED: ${failures[*]} (scratch kept: $W)"
    exit 1
fi
rm -rf "$W"
echo "ALL PASS (riscv64 shell gates)"
