#!/usr/bin/env bash
# Build a binary RPM from an already built ntx binary (Fedora / RHEL / openSUSE).
#
#   packaging/build-rpm.sh VERSION RPM_ARCH BINARY OUTDIR
#
# e.g. packaging/build-rpm.sh 0.1.2 x86_64 ./ntx dist
#
# RPM_ARCH is the RPM architecture name: x86_64 or aarch64. It must match the
# host `rpm --eval '%{_arch}'` (or pass --target); on Ubuntu runners that is
# typically x86_64 / aarch64.
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: $0 VERSION RPM_ARCH BINARY OUTDIR" >&2
  exit 2
fi
version=$1
arch=$2
binary=$3
outdir=$4

cd "$(dirname "$0")/.."
[ -x "$binary" ] || { echo "error: $binary is not an executable file" >&2; exit 1; }
command -v rpmbuild >/dev/null || { echo "error: rpmbuild not found (install rpm)" >&2; exit 1; }

host_arch=$(rpm --eval '%{_arch}')
if [ "$host_arch" != "$arch" ]; then
  echo "error: RPM_ARCH=$arch but host rpm arch is $host_arch" >&2
  exit 1
fi

# RPM sorts "0.1.0-rc1" after "0.1.0"; use ~ for pre-releases like the .deb helper.
rpm_version=${version/-/\~}

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,payload/usr/bin,payload/usr/share/doc/ntx}

# Payload lives outside rpmbuild's %{buildroot} (which is under BUILDROOT/<name>/).
install -m 0755 "$binary" "$root/payload/usr/bin/ntx"
strip --strip-unneeded "$root/payload/usr/bin/ntx" 2>/dev/null || true
install -m 0644 README.md LICENSE CHANGELOG.md "$root/payload/usr/share/doc/ntx/"

cat > "$root/SPECS/ntx.spec" <<EOF
Name:           ntx
Version:        $rpm_version
Release:        1%{?dist}
Summary:        Small BitTorrent client with no dependencies
License:        MIT
URL:            https://github.com/pchmielewski1/ntx
BuildArch:      $arch
AutoReqProv:    no
Requires:       glibc

%description
ntx downloads magnet links and .torrent files (BitTorrent v1, v2 and hybrid),
verifies every piece, resumes after a restart and seeds afterwards. It supports
DHT, PEX, uTP, MSE/PE encryption, HTTP/HTTPS/UDP trackers, SOCKS5, and uses its
own TLS 1.3 client and DNS-over-HTTPS resolver instead of OpenSSL.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a $root/payload/. %{buildroot}/

%files
/usr/bin/ntx
%doc /usr/share/doc/ntx/README.md
%doc /usr/share/doc/ntx/CHANGELOG.md
%license /usr/share/doc/ntx/LICENSE
EOF

rpmbuild \
  --define "_topdir $root" \
  --define "_build_id_links none" \
  --define "debug_package %{nil}" \
  -bb "$root/SPECS/ntx.spec"

mkdir -p "$outdir"
rpm=$(find "$root/RPMS" -name 'ntx-*.rpm' -type f | head -n 1)
[ -n "$rpm" ] || { echo "error: rpmbuild produced no package" >&2; exit 1; }
# Stable release asset name (drop disttag like .fc40 for GitHub Releases).
out="$outdir/ntx-${version}-1.${arch}.rpm"
cp -a "$rpm" "$out"
echo "$out"
