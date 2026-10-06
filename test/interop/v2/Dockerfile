# BEP52 v2/hybrid interop image (ntx).
#
# Reference clients we try to drive head-less inside CI:
#   * transmission-daemon + transmission-cli (transmission-remote) — the same
#     reference client the v1 interop matrix (test/interop/Dockerfile) uses.
#     It is a v1-only engine: it refuses every BEP52 fixture we feed it
#     ("invalid or corrupt torrent file"), which the matrix records as a
#     FAIL-with-reason instead of pretending the cell ran.
#   * qbittorrent-nox — a libtorrent-based engine that DOES speak BEP52, but
#     it is a GUI binary: even under Xvfb it never opens a listening socket
#     head-less. The matrix probes it and records the observed reason.
FROM debian:bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        transmission-daemon transmission-cli \
        qbittorrent-nox xvfb xauth dbus python3 coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY qbt-seed.sh /usr/local/bin/qbt-seed.sh
RUN chmod +x /usr/local/bin/qbt-seed.sh
COPY torrents /interop/torrents

WORKDIR /interop
