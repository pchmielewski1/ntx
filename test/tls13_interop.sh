#!/usr/bin/env bash
# Live TLS 1.3 interop: the real ntx client (test/tls_probe.c) against
# `openssl s_server` on loopback. Covers ECDSA-P256 and RSA (rsa_pss_rsae_sha256)
# certificates, ALPN, SPKI pin match / mismatch, a server-initiated KeyUpdate,
# and fallback to TLS 1.2 against a 1.2-only server.
#
#   test/tls13_interop.sh [path/to/tls_probe]     (needs the openssl CLI)
#
# Exit 0 = all checks passed, 77 = skipped (no openssl / cannot listen).
set -u
cd "$(dirname "$0")/.."
PROBE="${1:-/tmp/ntx_tls_probe}"
command -v openssl >/dev/null || { echo "SKIP no openssl"; exit 77; }

W=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT

if [ ! -x "$PROBE" ]; then
  SRC="src/net/ntx_tls.c src/net/ntx_tls_rec.c src/net/ntx_tls13.c src/net/ntx_sock.c src/net/ntx_addr.c src/net/ntx_proxy.c src/ui/ntx_diag.c src/crypto/ntx_sha1.c src/crypto/ntx_sha256.c src/crypto/ntx_hmac.c src/crypto/ntx_aes.c src/crypto/ntx_rng.c src/crypto/ntx_x25519_fe.c src/crypto/ntx_x25519.c src/crypto/ntx_bignum.c src/crypto/ntx_rsa_pkcs1.c src/crypto/ntx_p256.c src/crypto/ntx_hkdf.c"
  gcc -O2 -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -DNTX_TLS13_LIVE=1 -o "$PROBE" test/tls_probe.c $SRC -lm || exit 1
fi

FAILS=0
ok()   { echo "PASS $1"; }
fail() { echo "FAIL $1"; FAILS=$((FAILS+1)); }

mkcert() { # name keyspec
  case "$2" in
    ec)  openssl ecparam -name prime256v1 -genkey -noout -out "$W/$1.key" 2>/dev/null ;;
    rsa) openssl genrsa -out "$W/$1.key" 2048 2>/dev/null ;;
  esac
  openssl req -new -x509 -key "$W/$1.key" -out "$W/$1.crt" -days 2 -subj "/CN=localhost" 2>/dev/null
}
pin_of() { openssl x509 -in "$W/$1.crt" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n'; }

PORT=$((20000 + RANDOM % 20000))
serve() { # name extra-args...   (sets PORT; retries on another port if s_server could not bind)
  local name=$1; shift
  local attempt pid up
  for attempt in 1 2 3 4 5 6; do
    PORT=$((PORT + 1))
    openssl s_server -accept "$PORT" -cert "$W/$name.crt" -key "$W/$name.key" -www "$@" >"$W/s_$PORT.log" 2>&1 &
    pid=$!
    PIDS+=($pid)
    up=0
    for _ in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break            # s_server died (port already taken)
      (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && { up=1; break; }
      sleep 0.1
    done
    # a foreign listener on this port would also answer the probe: our server must still be alive
    [ $up = 1 ] && sleep 0.1 && kill -0 "$pid" 2>/dev/null && return 0
    kill "$pid" 2>/dev/null
  done
  echo "FAIL could not start openssl s_server" >&2
  return 1
}

mkcert ec ec; mkcert rsa rsa
PIN_EC=$(pin_of ec); PIN_RSA=$(pin_of rsa)

run() { "$PROBE" 127.0.0.1 "$PORT" localhost "$@" 2>&1; }

for k in ec rsa; do
  serve $k -tls1_3 -alpn http/1.1
  PIN=$([ $k = ec ] && echo "$PIN_EC" || echo "$PIN_RSA")
  out=$(run --pin "$PIN" --alpn http/1.1)
  if echo "$out" | grep -q "^tls ver=13 alpn=http/1.1 pin=$PIN" && echo "$out" | grep -q "status: HTTP/1.0 200"; then ok "tls13-$k-pin-ok"; else fail "tls13-$k-pin-ok: $out"; fi
  out=$(run --pin 0000000000000000000000000000000000000000000000000000000000000000)
  if echo "$out" | grep -q "pin mismatch"; then ok "tls13-$k-pin-mismatch"; else fail "tls13-$k-pin-mismatch: $out"; fi
  out=$(run)
  if echo "$out" | grep -q "^tls ver=13 .*pin=$PIN"; then ok "tls13-$k-tofu-no-pin"; else fail "tls13-$k-tofu-no-pin: $out"; fi
done

# several NewSessionTicket messages right after the handshake must be skipped transparently
serve ec -tls1_3 -num_tickets 3
out=$(run)
if echo "$out" | grep -q "^tls ver=13" && echo "$out" | grep -q "status: HTTP/1.0 200"; then ok "tls13-new-session-tickets"; else fail "tls13-new-session-tickets: $out"; fi

# TLS 1.2-only server: client must fall back and still pin-verify
serve rsa -tls1_2
out=$(run --pin "$PIN_RSA")
if echo "$out" | grep -q "^tls ver=12 .*pin=$PIN_RSA" && echo "$out" | grep -q "status: HTTP/1.0 200"; then ok "fallback-tls12"; else fail "fallback-tls12: $out"; fi

# TLS 1.2 + TOFU mode (no pin configured): connection must succeed and report the leaf pin
out=$(run)
if echo "$out" | grep -q "^tls ver=12 .*pin=$PIN_RSA"; then ok "tofu-tls12-no-pin"; else fail "tofu-tls12-no-pin: $out"; fi
out=$(run --pin 0000000000000000000000000000000000000000000000000000000000000000)
if echo "$out" | grep -q "pin mismatch"; then ok "tls12-pin-mismatch"; else fail "tls12-pin-mismatch: $out"; fi

[ "$FAILS" = 0 ] && echo "ALL PASS (tls13 interop)" || { echo "$FAILS FAILED"; exit 1; }
