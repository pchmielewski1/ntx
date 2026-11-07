# Local riscv64 build/test environment: the same Ubuntu release and packages as
# the riscv64 jobs in .github/workflows/{ci,release}.yml. Used by docker-run.sh.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      gcc-riscv64-linux-gnu libc6-dev-riscv64-cross binutils-riscv64-linux-gnu \
      qemu-user make python3 openssl file ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
