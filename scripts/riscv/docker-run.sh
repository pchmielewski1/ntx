#!/usr/bin/env bash
#
# Run a command in an Ubuntu 22.04 container that has the riscv64 cross
# toolchain and qemu-user (the same packages as the GitHub Actions riscv64
# jobs), as the calling user, with the repository mounted at /repo.
#
# Usage: scripts/riscv/docker-run.sh <command> [args...]
#   e.g. scripts/riscv/docker-run.sh make riscv test-riscv
#
# The image ntx-riscv64-env:22.04 is built from scripts/riscv/Dockerfile on
# first use; `docker rmi ntx-riscv64-env:22.04` forces a rebuild. The platform
# is pinned to the host's so a cached foreign-arch ubuntu image is never used,
# and the container runs as the calling uid so no root-owned files land in
# the repository.
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "[docker-run] ERROR: docker not found on PATH" >&2
    exit 127
fi

case "$(uname -m)" in
    x86_64) platform=linux/amd64 ;;
    aarch64|arm64) platform=linux/arm64 ;;
    *) echo "[docker-run] ERROR: unsupported host architecture $(uname -m)" >&2; exit 2 ;;
esac

image=ntx-riscv64-env:22.04
if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build --platform "$platform" -t "$image" scripts/riscv
fi

exec docker run --rm --platform "$platform" --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -e NTX_VERSION -e NTX_TEST_TIMEOUT_SCALE -e NTX_TEST_TIMEOUT -e NTX_TEST_GLOB \
    -v "$PWD:/repo" -w /repo "$image" "$@"
