#!/usr/bin/env bash
#
# Run a static mipsel binary under qemu-mipsel user-mode emulation (x86_64 host).
#
# Usage: scripts/mips/qemu-user-run.sh <repo-relative-binary> [args...]
#
# The binary path is repo-relative (run from the repo root); the script prefixes
# "$PWD/". The guest exit code is propagated as this script's exit code.
#
# QEMU auto-detection order:
#   1. ~/toolchains/qemu/usr/bin/qemu-mipsel-static  (sudo-less deb extract)
#   2. ~/toolchains/qemu/usr/bin/qemu-mipsel         (QEMU >= 9 deb layout)
#   3. qemu-mipsel-static / qemu-mipsel on PATH      (system install, if any)
#   4. docker image ntx-qemu:mipsel (FROM ubuntu:24.04 + qemu-user-static)
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <repo-relative-binary> [args...]" >&2
    exit 2
fi

BIN="$PWD/$1"
if [ ! -f "$BIN" ]; then
    echo "[qemu-run] ERROR: binary not found: $BIN (path must be repo-relative)" >&2
    exit 127
fi

for candidate in \
    "$HOME/toolchains/qemu/usr/bin/qemu-mipsel-static" \
    "$HOME/toolchains/qemu/usr/bin/qemu-mipsel"; do
    if [ -x "$candidate" ]; then
        exec "$candidate" -0 ntx "$BIN" "${@:2}"
    fi
done

for name in qemu-mipsel-static qemu-mipsel; do
    if command -v "$name" >/dev/null 2>&1; then
        exec "$name" -0 ntx "$BIN" "${@:2}"
    fi
done

if command -v docker >/dev/null 2>&1; then
    exec docker run --rm -v "$PWD:/repo" ntx-qemu:mipsel \
        qemu-mipsel-static -0 ntx "/repo/$1" "${@:2}"
fi

echo "[qemu-run] ERROR: no qemu-mipsel available (host binary under ~/toolchains/qemu, system qemu-mipsel, or docker image ntx-qemu:mipsel)" >&2
exit 127
