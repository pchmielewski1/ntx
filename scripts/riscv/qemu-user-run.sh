#!/usr/bin/env bash
#
# Run a dynamically linked riscv64 glibc binary under qemu-riscv64 user-mode
# emulation (x86_64 or aarch64 host).
#
# Usage: scripts/riscv/qemu-user-run.sh <binary> [args...]
#
# <binary> is absolute or relative to the current directory. The guest exit
# code becomes this script's exit code. Environment:
#   QEMU_RISCV64   qemu binary (default: qemu-riscv64, else qemu-riscv64-static, on PATH)
#   RISCV_SYSROOT  glibc sysroot holding the riscv64 dynamic loader
#                  (default: /usr/riscv64-linux-gnu from libc6-riscv64-cross)
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <binary> [args...]" >&2
    exit 2
fi

bin=$1
shift
case "$bin" in
    /*) ;;
    *) bin="$PWD/$bin" ;;
esac
if [ ! -f "$bin" ]; then
    echo "[qemu-riscv64] ERROR: binary not found: $bin" >&2
    exit 127
fi

sysroot="${RISCV_SYSROOT:-/usr/riscv64-linux-gnu}"
if [ ! -e "$sysroot/lib/ld-linux-riscv64-lp64d.so.1" ]; then
    echo "[qemu-riscv64] ERROR: sysroot missing: $sysroot/lib/ld-linux-riscv64-lp64d.so.1 (install libc6-dev-riscv64-cross or set RISCV_SYSROOT)" >&2
    exit 127
fi

qemu="${QEMU_RISCV64:-}"
if [ -z "$qemu" ]; then
    for name in qemu-riscv64 qemu-riscv64-static; do
        if command -v "$name" >/dev/null 2>&1; then
            qemu=$name
            break
        fi
    done
fi
if [ -z "$qemu" ]; then
    echo "[qemu-riscv64] ERROR: no qemu-riscv64 on PATH (install qemu-user or set QEMU_RISCV64)" >&2
    exit 127
fi

export QEMU_LD_PREFIX="$sysroot"
exec "$qemu" -0 ntx "$bin" "$@"
