#!/usr/bin/env bash
# Build a Debian package from an already built ntx binary.
#
#   packaging/build-deb.sh VERSION DEB_ARCH BINARY OUTDIR
#
# e.g. packaging/build-deb.sh 0.1.0 amd64 ./ntx dist
#
# The package depends only on libc6; the minimum version is taken from the glibc of the machine that built the
# binary (build on the oldest distribution you want to support).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 VERSION DEB_ARCH BINARY OUTDIR" >&2
  exit 2
fi
version=$1
arch=$2
binary=$3
outdir=$4

cd "$(dirname "$0")/.."
[ -x "$binary" ] || { echo "error: $binary is not an executable file" >&2; exit 1; }

glibc=$(getconf GNU_LIBC_VERSION | grep -Eo '[0-9]+\.[0-9]+$')
[ -n "$glibc" ] || { echo "error: cannot detect the glibc version" >&2; exit 1; }

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/ntx"
install -m 0755 "$binary" "$root/usr/bin/ntx"
strip --strip-unneeded "$root/usr/bin/ntx"
install -m 0644 README.md "$root/usr/share/doc/ntx/README.md"
install -m 0644 LICENSE "$root/usr/share/doc/ntx/copyright"
gzip -9n -c CHANGELOG.md > "$root/usr/share/doc/ntx/changelog.gz"
chmod 0644 "$root/usr/share/doc/ntx/changelog.gz"

size_kb=$(du -sk "$root/usr" | cut -f1)
cat > "$root/DEBIAN/control" <<EOF
Package: ntx
Version: $version
Section: net
Priority: optional
Architecture: $arch
Depends: libc6 (>= $glibc)
Installed-Size: $size_kb
Maintainer: Piotr Chmielewski <chmielewski811@gmail.com>
Homepage: https://github.com/pchmielewski1/ntx
Description: small BitTorrent client with no dependencies
 ntx downloads magnet links and .torrent files (BitTorrent v1, v2 and hybrid),
 verifies every piece, resumes after a restart and seeds afterwards. It supports
 DHT, PEX, uTP, MSE/PE encryption, HTTP/HTTPS/UDP trackers, SOCKS5, and uses its
 own TLS 1.3 client and DNS-over-HTTPS resolver instead of OpenSSL.
EOF

mkdir -p "$outdir"
out="$outdir/ntx_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$root" "$out" > /dev/null
echo "$out"
