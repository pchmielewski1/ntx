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

.PHONY: all test test-net test-cli test-interop test-ipc interop_ipc size static clean probe test-live test-tls13

ntx: $(SRCS) ; $(CC) $(CFLAGS) $(HARDEN_CFLAGS) $(VERSION_DEFINE) -o $@ $(SRCS) $(LDFLAGS) $(HARDEN_LDFLAGS) $(LDLIBS)
all: ntx
probe: test/trk_http_probe.c src/proto/ntx_http.c src/proto/ntx_tracker.c src/proto/ntx_bencode.c src/net/ntx_sock.c src/net/ntx_addr.c src/net/ntx_proxy.c src/proto/ntx_doh.c src/proto/ntx_h2.c src/net/ntx_tls.c src/net/ntx_tls_rec.c src/ui/ntx_diag.c src/crypto/ntx_sha1.c src/crypto/ntx_sha256.c src/crypto/ntx_hmac.c src/crypto/ntx_aes.c src/crypto/ntx_rng.c src/crypto/ntx_x25519_fe.c src/crypto/ntx_x25519.c src/crypto/ntx_bignum.c src/crypto/ntx_rsa_pkcs1.c src/crypto/ntx_p256.c src/proto/ntx_http_url.c src/proto/ntx_https.c src/proto/ntx_https_pin.c src/crypto/ntx_hkdf.c src/net/ntx_tls13.c
	$(CC) $(CFLAGS) -I. -o trk_http_probe test/trk_http_probe.c src/proto/ntx_http.c src/proto/ntx_tracker.c src/proto/ntx_bencode.c src/net/ntx_sock.c src/net/ntx_addr.c src/net/ntx_proxy.c src/proto/ntx_doh.c src/proto/ntx_h2.c src/net/ntx_tls.c src/net/ntx_tls_rec.c src/ui/ntx_diag.c src/crypto/ntx_sha1.c src/crypto/ntx_sha256.c src/crypto/ntx_hmac.c src/crypto/ntx_aes.c src/crypto/ntx_rng.c src/crypto/ntx_x25519_fe.c src/crypto/ntx_x25519.c src/crypto/ntx_bignum.c src/crypto/ntx_rsa_pkcs1.c src/crypto/ntx_p256.c src/proto/ntx_http_url.c src/proto/ntx_https.c src/proto/ntx_https_pin.c src/crypto/ntx_hkdf.c src/net/ntx_tls13.c $(LDFLAGS) $(LDLIBS)
test: $(wildcard test/t_*.c)
	@for f in $^; do $(CC) $(CFLAGS) -o .test.tmp $$f $(LDFLAGS) $(LDLIBS) && ./.test.tmp || exit 1; done; echo ALL PASS
test-live: test/t_tls_golden.c $(wildcard test/fixtures/tls/*.bin)
	@$(CC) $(CFLAGS) -o .test-live.tmp test/t_tls_golden.c $(LDLIBS) && ./.test-live.tmp; rc=$$?; rm -f .test-live.tmp; exit $$rc
test-net: ntx ; ./test/net_loopback.sh
test-tls13: ; @rm -f .tls_probe.tmp; ./test/tls13_interop.sh ./.tls_probe.tmp; rc=$$?; rm -f .tls_probe.tmp; [ $$rc -eq 77 ] && exit 0; exit $$rc
test-cli: ntx ; ./test/cli_errors.sh
interop_ipc: ntx ; ./test/interop/ipc/interop_ipc.sh
test-ipc: interop_ipc
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
static: ; CC=musl-gcc $(MAKE) ntx LDFLAGS="-static" LDLIBS="-static" HARDEN_LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack"
clean: ; rm -f ntx trk_http_probe .test.tmp .test-live.tmp .tls_probe.tmp src/*/*.o
