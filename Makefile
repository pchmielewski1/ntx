CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections
LDFLAGS ?= -Wl,--gc-sections
# Exploit-mitigation flags for the shipped binary: kept out of CFLAGS/LDFLAGS so overriding those (CC=musl-gcc
# static builds, packagers) does not silently drop them.  PIE + full RELRO + non-exec stack + stack protector
# + bounds-checked libc string functions.
HARDEN_CFLAGS ?= -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fPIE
HARDEN_LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack
LDLIBS := -lm
SRCS := $(shell find src -name '*.c')
# Release builds set the version from the git tag: make ntx NTX_VERSION=1.2.3 (default: see src/core/ntx_config.h).
VERSION_DEFINE := $(if $(NTX_VERSION),-DNTX_VERSION='"$(NTX_VERSION)"')
MIPS_CC ?= $(HOME)/toolchains/mipsel-linux-musl/bin/mipsel-linux-musl-gcc
RISCV_CC ?= riscv64-linux-gnu-gcc

.PHONY: all test test-net test-mipsel native-check test-cli test-interop test-ipc interop_ipc size static clean probe test-live test-tls13 riscv size-riscv test-riscv test-riscv-shell pins-check pins-update test-share

# Share-tracker key gate (design §6.2). The only targets allowed to reach the
# network: `make` and `make test` never call them. pins-update is the sole writer
# of the generated block in src/proto/ntx_share_trackers.c and of pins.txt.
PINS := python3 scripts/pins/pins.py
pins-check: ; @$(PINS) check
pins-update: ; @$(PINS) update
# Test build: -DNTX_SHARE_TRACKERS_INC replaces the table (Task 1 hook) and the
# .inc prints the banner below, so a stray test binary cannot pass for a release.
SHARETEST_INC := $(CURDIR)/scripts/pins/sharetest_trackers.inc
ntx-sharetest: $(SRCS) $(SHARETEST_INC) ; $(CC) $(CFLAGS) $(HARDEN_CFLAGS) $(VERSION_DEFINE) -DNTX_SHARE_TRACKERS_INC='"$(SHARETEST_INC)"' -o $@ $(SRCS) $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)

ntx: $(SRCS) ; $(CC) $(CFLAGS) $(HARDEN_CFLAGS) $(VERSION_DEFINE) -o $@ $(SRCS) $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)
# Mirrors the `static` target precedent for -static musl: HARDEN_CFLAGS compile mitigations
# (-fstack-protector-strong, _FORTIFY_SOURCE=2, -fPIE) are KEPT; only the PIE *link* flag (-pie)
# is dropped (impossible for a static binary); relro/now/noexecstack link flags are kept.
mips: $(SRCS) ; $(MIPS_CC) $(CFLAGS) $(HARDEN_CFLAGS) -static $(VERSION_DEFINE) -o ntx-mipsel $(SRCS) $(LDFLAGS) -Wl,-z,relro,-z,now,-z,noexecstack $(LDLIBS)
# riscv64 (glibc, dynamic) keeps every hardening flag of `ntx` and writes its own file, so the native ./ntx is
# never rebuilt. Always rebuilds (like `mips`); the riscv check targets below must not depend on it.
riscv: $(SRCS) ; $(RISCV_CC) $(CFLAGS) $(HARDEN_CFLAGS) $(VERSION_DEFINE) -o ntx-riscv64 $(SRCS) $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)
all: ntx
probe: test/trk_http_probe.c src/proto/ntx_http.c src/proto/ntx_tracker.c src/proto/ntx_bencode.c src/net/ntx_sock.c src/net/ntx_addr.c src/net/ntx_proxy.c src/proto/ntx_doh.c src/proto/ntx_h2.c src/net/ntx_tls.c src/net/ntx_tls_rec.c src/ui/ntx_diag.c src/crypto/ntx_sha1.c src/crypto/ntx_sha256.c src/crypto/ntx_hmac.c src/crypto/ntx_aes.c src/crypto/ntx_rng.c src/crypto/ntx_x25519_fe.c src/crypto/ntx_x25519.c src/crypto/ntx_bignum.c src/crypto/ntx_rsa_pkcs1.c src/crypto/ntx_p256.c src/proto/ntx_http_url.c src/proto/ntx_https.c src/proto/ntx_https_pin.c src/crypto/ntx_hkdf.c src/net/ntx_tls13.c
	$(CC) $(CFLAGS) -I. -o trk_http_probe test/trk_http_probe.c src/proto/ntx_http.c src/proto/ntx_tracker.c src/proto/ntx_bencode.c src/net/ntx_sock.c src/net/ntx_addr.c src/net/ntx_proxy.c src/proto/ntx_doh.c src/proto/ntx_h2.c src/net/ntx_tls.c src/net/ntx_tls_rec.c src/ui/ntx_diag.c src/crypto/ntx_sha1.c src/crypto/ntx_sha256.c src/crypto/ntx_hmac.c src/crypto/ntx_aes.c src/crypto/ntx_rng.c src/crypto/ntx_x25519_fe.c src/crypto/ntx_x25519.c src/crypto/ntx_bignum.c src/crypto/ntx_rsa_pkcs1.c src/crypto/ntx_p256.c src/proto/ntx_http_url.c src/proto/ntx_https.c src/proto/ntx_https_pin.c src/crypto/ntx_hkdf.c src/net/ntx_tls13.c $(LDFLAGS) $(LDLIBS)
# TEST_BIN lets parallel streams run the suite without colliding on one binary.
TEST_BIN ?= .test.tmp
test: $(wildcard test/t_*.c)
	@for f in $^; do $(CC) $(CFLAGS) -o $(TEST_BIN) $$f $(LDFLAGS) $(LDLIBS) && ./$(TEST_BIN) || exit 1; done; echo ALL PASS
test-live: test/t_tls_golden.c $(wildcard test/fixtures/tls/*.bin)
	@$(CC) $(CFLAGS) -o .test-live.tmp test/t_tls_golden.c $(LDLIBS) && ./.test-live.tmp; rc=$$?; rm -f .test-live.tmp; exit $$rc
test-mipsel: ; @CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" LDLIBS="$(LDLIBS)" MIPS_CC="$(MIPS_CC)" bash scripts/mips/run-suite.sh
test-riscv: ; @CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" LDLIBS="$(LDLIBS)" RISCV_CC="$(RISCV_CC)" bash scripts/riscv/run-suite.sh
test-riscv-shell: ; @RISCV_CC="$(RISCV_CC)" bash scripts/riscv/run-shell-suites.sh
native-check: ; @bash scripts/mips/native-check.sh
test-net: ntx ; ./test/net_loopback.sh
test-tls13: ; @rm -f .tls_probe.tmp; ./test/tls13_interop.sh ./.tls_probe.tmp; rc=$$?; rm -f .tls_probe.tmp; [ $$rc -eq 77 ] && exit 0; exit $$rc
test-cli: ntx ; ./test/cli_errors.sh && ./test/pins_tool.sh
interop_ipc: ntx ; ./test/interop/ipc/interop_ipc.sh
test-ipc: interop_ipc
# Private-share end-to-end (Task I1): the script renders trackers.inc from the
# ephemeral HTTPS tracker's port + SPKI and compiles its own pinned .sharetest_e2e.tmp,
# so this target stays thin; ntx-sharetest keeps the share-test build in the gate.
test-share: ntx-sharetest ; ./test/interop/share/share_e2e.sh
test-interop: ; \
  mkdir -p test/.scratch && \
  CTX=$$(mktemp -d test/.scratch/interop-ctx.XXXXXX) && \
  cp -a Makefile $$CTX/ && cp -a src $$CTX/ && \
  mkdir -p $$CTX/test && cp -a test/interop $$CTX/test/ && \
  cp test/interop/Dockerfile $$CTX/Dockerfile && \
  docker build -t ntx-interop $$CTX && \
  docker run --rm -v ntx-interop-work:/work ntx-interop bash /repo/test/interop/interop.sh ; \
  rc=$$?; rm -rf $$CTX; exit $$rc
size: ntx ; size ntx; ls -l ntx; sz=$$(stat -c%s ntx); [ $$sz -lt 1048576 ] || { echo "SIZE FAIL $$sz >= 1048576 (1MiB gate)"; exit 1; }
size-riscv: ; @test -f ntx-riscv64 || { echo "ntx-riscv64 missing (run make riscv)"; exit 1; }; ls -l ntx-riscv64; sz=$$(stat -c%s ntx-riscv64); [ $$sz -lt 1048576 ] || { echo "SIZE FAIL $$sz >= 1048576 (1MiB gate)"; exit 1; }
static: ; CC=musl-gcc $(MAKE) ntx LDFLAGS="-static" LDLIBS="-static" HARDEN_LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack"
clean: ; rm -f ntx ntx-mipsel ntx-riscv64 ntx-sharetest trk_http_probe .test.tmp .test-live.tmp .tls_probe.tmp src/*/*.o
