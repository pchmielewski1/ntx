# Releasing

A release is produced by pushing a version tag. The workflow
[`.github/workflows/release.yml`](../.github/workflows/release.yml) does the rest.

## Steps

1. Set the version in `src/core/ntx_config.h` (`NTX_VERSION`), for example `"0.2.0"`.
2. In `CHANGELOG.md`, make sure there is a section whose heading starts with that version
   (`## 0.2.0 - 2026-11-01`). Its text becomes the release notes; the workflow fails if the section is missing.
3. Commit, then tag and push:

   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```

   The tag must be `v` plus exactly `NTX_VERSION`, otherwise the workflow stops. A version with a hyphen
   (`v0.2.0-rc1`) is published as a pre-release.

## Trying it without publishing

The workflow can also be started by hand from the Actions tab (`workflow_dispatch`). That run builds, tests
and packages on both architectures and keeps the files as workflow artifacts, but it never creates a release:
only a pushed tag does.

## What the workflow does

On Ubuntu 22.04 runners, one for x86-64 and one for arm64, it runs `make ntx`, `make size`, `make test`,
`make test-cli`, `make test-net`, `make test-ipc` and `make test-tls13`, and only then packages. Nothing is
published unless both architectures pass.

The release contains:

| File | Contents |
|------|----------|
| `ntx-<version>-linux-x86_64`, `ntx-<version>-linux-aarch64` | The stripped binary |
| `ntx_<version>_amd64.deb`, `ntx_<version>_arm64.deb` | The binary in `/usr/bin`, plus README, licence and changelog under `/usr/share/doc/ntx` |
| `SHA256SUMS` | Checksums of all of the above |

The `.deb` is built by [`packaging/build-deb.sh`](../packaging/build-deb.sh). It depends only on `libc6`, with the
minimum version taken from the glibc of the build machine. The binaries are dynamically linked against glibc;
there is no static (musl) release build.

## Building a package by hand

```sh
make ntx
packaging/build-deb.sh 0.2.0 amd64 ./ntx dist   # or arm64, matching the machine that built ./ntx
```
