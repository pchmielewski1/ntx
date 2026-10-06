# Releasing

Releases are made by GitHub Actions
([`.github/workflows/release.yml`](../.github/workflows/release.yml)). The version number comes from git, not from
a file: the workflow passes it to the build (`make ntx NTX_VERSION=1.2.3`), so `ntx --version`, the `.deb` and the
release all agree. The `NTX_VERSION` default in `src/core/ntx_config.h` is only what a local build prints.

## How a version is chosen

| Event | Version |
|-------|---------|
| Push to `main` | The highest stable tag `vX.Y.Z` with the patch number plus one (`v0.1.0` first, then `v0.1.1`, ...). Pre-release tags are ignored when counting. |
| Push of a tag `vX.Y.Z` | Exactly that version. Use this to start a new minor or major line: tagging `v0.2.0` makes the next push release `v0.2.1`. |
| Push of a tag `vX.Y.Z-suffix` (for example `v0.1.0-rc1`) | Exactly that version, published as a pre-release. |
| Manual run from the Actions tab | The next patch version is built and tested, and the files are kept as workflow artifacts. Nothing is published. |

Put `[skip release]` in the head commit message of a push to `main` to skip the release (the workflow then does
nothing). Only one release runs at a time. If several pushes arrive while one is running, GitHub keeps only the
newest of the waiting runs, so not every push is guaranteed its own version.

The release notes are the section of `CHANGELOG.md` whose heading starts with the version (`## 0.1.0 - ...`; a
pre-release suffix is ignored when looking it up), followed by an install hint and the list of commits since the
previous release. Versions without a changelog section get only the commit list.

## What the workflow does

On Ubuntu 22.04 runners, one for x86-64 and one for arm64, it builds, runs `make size`, `make test`,
`make test-cli`, `make test-net`, `make test-ipc` and `make test-tls13`, and only then packages. Nothing is
published unless both architectures pass.

Each release contains:

| File | Contents |
|------|----------|
| `ntx-<version>-linux-x86_64`, `ntx-<version>-linux-aarch64` | The stripped binary |
| `ntx_<version>_amd64.deb`, `ntx_<version>_arm64.deb` | The binary in `/usr/bin`, plus README, licence and changelog under `/usr/share/doc/ntx` |
| `SHA256SUMS` | Checksums of all of the above |

The `.deb` is built by [`packaging/build-deb.sh`](../packaging/build-deb.sh). It depends only on `libc6`, with the
minimum version taken from the glibc of the build machine. For a pre-release the package version uses `~`
(`0.1.0~rc1`) so that it sorts before `0.1.0`. The binaries are dynamically linked against glibc; there is no
static (musl) release build.

## Building a package by hand

```sh
make ntx NTX_VERSION=0.2.0
packaging/build-deb.sh 0.2.0 amd64 ./ntx dist   # or arm64, matching the machine that built ./ntx
```
