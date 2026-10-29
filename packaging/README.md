# Packaging

Recipes and helpers so each GitHub Release can cover Debian/Ubuntu, Fedora/RHEL/openSUSE,
Arch, Alpine, Gentoo, NixOS, plain Linux binaries, and OpenWrt mipsel.

Templates use `@VERSION@`; `stage-recipes.sh` stamps them for a release. Binary builders take
an already-built `./ntx`.

| Path | Role |
|------|------|
| `build-deb.sh` | Binary `.deb` (amd64 / arm64) — used by Actions |
| `build-rpm.sh` | Binary `.rpm` (x86_64 / aarch64) — used by Actions |
| `stage-recipes.sh` | Stamp Gentoo / Arch / Alpine / Nix / RPM source recipes → `ntx-VERSION-packaging.tar.gz` |
| `gentoo/net-p2p/ntx/` | Gentoo ebuild template + `metadata.xml` |
| `arch/PKGBUILD.in` | Arch Linux `PKGBUILD` |
| `alpine/APKBUILD.in` | Alpine `APKBUILD` |
| `rpm/ntx.spec.in` | Source RPM spec (rebuild from the GitHub tag) |
| `nix/` | `default.nix` + `flake.nix` |

Architectures shipped as **prebuilt** assets: `x86_64` / `amd64`, `aarch64` / `arm64`, and
`mipsel` (static musl, attached manually). Gentoo / Arch / Alpine / Nix build from the release
**tag** on the machine’s native arch (Linux + `epoll` only).
