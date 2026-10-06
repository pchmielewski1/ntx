# D5 interop CI image: reference BitTorrent client (transmission-daemon) + tooling.
#
# The host repo sits on a fuse.sshfs mount that the docker daemon cannot
# bind-mount, so the source is copied into the image at build time (docker build
# reads the context client-side, which works with sshfs). ntx is still compiled
# IN THE CONTAINER from this source — no prebuilt binary is ever shipped.
FROM debian:bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc make libc6-dev aria2 transmission-daemon python3 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Makefile /repo/Makefile
COPY src /repo/src
COPY test/interop /repo/test/interop

WORKDIR /repo
