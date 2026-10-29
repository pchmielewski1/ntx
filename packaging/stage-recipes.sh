#!/usr/bin/env bash
# Stamp packaging recipes for VERSION into OUTDIR and write a packaging tarball.
#
#   packaging/stage-recipes.sh VERSION OUTDIR
#
# Produces:
#   OUTDIR/ntx-VERSION-packaging.tar.gz   (gentoo/arch/alpine/nix/rpm recipes)
#   and the same tree unpacked under OUTDIR/packaging-staged/ (for inspection).
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 VERSION OUTDIR" >&2
  exit 2
fi
version=$1
outdir=$2
repo=$(cd "$(dirname "$0")/.." && pwd)
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

subst() {
  # Replace @VERSION@ in stdin.
  sed "s/@VERSION@/${version}/g"
}

mkdir -p \
  "$staging/gentoo/net-p2p/ntx" \
  "$staging/arch" \
  "$staging/alpine" \
  "$staging/nix" \
  "$staging/rpm"

subst < "$repo/packaging/gentoo/net-p2p/ntx/ntx.ebuild.in" \
  > "$staging/gentoo/net-p2p/ntx/ntx-${version}.ebuild"
cp "$repo/packaging/gentoo/net-p2p/ntx/metadata.xml" \
  "$staging/gentoo/net-p2p/ntx/metadata.xml"

subst < "$repo/packaging/arch/PKGBUILD.in" > "$staging/arch/PKGBUILD"
subst < "$repo/packaging/alpine/APKBUILD.in" > "$staging/alpine/APKBUILD"
subst < "$repo/packaging/rpm/ntx.spec.in" > "$staging/rpm/ntx.spec"
subst < "$repo/packaging/nix/default.nix.in" > "$staging/nix/default.nix"
subst < "$repo/packaging/nix/flake.nix.in" > "$staging/nix/flake.nix"
cp "$repo/packaging/README.md" "$staging/README.md"

mkdir -p "$outdir"
tar -C "$staging" -czf "$outdir/ntx-${version}-packaging.tar.gz" .
echo "$outdir/ntx-${version}-packaging.tar.gz"
