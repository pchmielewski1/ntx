#!/bin/sh
# CLI error-handling gate for `make test-cli`.
# Verifies that invalid command lines fail fast with a message and a non-zero exit
# status instead of being silently ignored (typo'd options, malformed --proxy that
# would otherwise fall back to a DIRECT connection, unreadable .torrent, ...).
# Needs no network: every negative case must exit before any session work starts.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
test -x ./ntx || { echo "test-cli: ./ntx not built (run make)" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
H=0123456789abcdef0123456789abcdef01234567
MAG="magnet:?xt=urn:btih:$H"
printf 'not a torrent' > "$TMP/junk.torrent"
: > "$TMP/empty.torrent"
printf 'just text\n' > "$TMP/notmagnet.txt"
fails=0

# expect <name> <want-rc> <stderr-regex|-> -- args...
expect() {
  name=$1; want=$2; re=$3; shift 4
  timeout -k 1 3 ./ntx --store-dir="$TMP/store" "$@" >"$TMP/out" 2>"$TMP/err" </dev/null
  rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL $name: exit $rc, want $want" >&2
    sed 's/^/    | /' "$TMP/err" | head -5 >&2
    fails=$((fails + 1))
    return
  fi
  if [ "$re" != "-" ] && ! grep -Eq -- "$re" "$TMP/err"; then
    echo "FAIL $name: stderr lacks /$re/" >&2
    sed 's/^/    | /' "$TMP/err" | head -5 >&2
    fails=$((fails + 1))
    return
  fi
  echo "PASS $name"
}

expect no-args           2 'usage:'                 -- 
expect unknown-option    2 "unknown option '--bogus'" -- --bogus "$MAG"
expect typo-option       2 "unknown option '--dth'"   -- --dth "$MAG"
expect missing-torrent   2 'not a magnet link'      -- "$TMP/nope.txt"
expect text-not-magnet   2 'not a magnet link'      -- "$TMP/notmagnet.txt"
expect extra-argument    2 'unexpected argument'    -- "$MAG" "$TMP/notmagnet.txt"
expect port-not-number   2 'invalid value for --port-lo' -- --port-lo=abc "$MAG"
expect port-too-big      2 'invalid value for --port-hi' -- --port-hi=99999 "$MAG"
expect port-negative     2 'invalid value for --port-lo' -- --port-lo=-1 "$MAG"
expect peers-not-number  2 'invalid value for --max-peers' -- --max-peers=lots "$MAG"
expect limit-negative    2 'invalid value for --down-limit' -- --down-limit=-5 "$MAG"
expect limit-suffix      2 'invalid value for --up-limit'   -- --up-limit=10k "$MAG"
expect proxy-bad-scheme  2 'invalid --proxy'        -- --proxy=http:127.0.0.1:8080 "$MAG"
expect proxy-bad-port    2 'invalid --proxy'        -- --proxy=socks5:127.0.0.1:0 "$MAG"
expect proxy-no-port     2 'invalid --proxy'        -- --proxy=socks5:127.0.0.1 "$MAG"
expect tunnel-no-port    2 'invalid --tunnel'       -- --tunnel=example.org "$MAG"
expect dht-with-proxy    2 'cannot be combined'     -- --dht --proxy=socks5:127.0.0.1:9 "$MAG"
expect dht-with-tunnel   2 'cannot be combined'     -- --dht --tunnel=127.0.0.1:9 "$MAG"
expect bad-magnet        1 'invalid magnet link'    -- 'magnet:?xt=urn:btih:zzzz'
expect torrent-missing   1 'cannot load .torrent'   -- "$TMP/missing.torrent"
expect torrent-junk      1 'cannot load .torrent'   -- "$TMP/junk.torrent"
expect torrent-empty     1 'cannot load .torrent'   -- "$TMP/empty.torrent"

# ── --share / --share-from / --port-map (design §9) ──────────────────────────
# The five rejected command lines are a contract: the wording is fixed, so these
# cases compare the whole stderr line as a FIXED STRING, not a regex.
# expect_exact <name> <want-rc> <exact-stderr-line> -- args...
expect_exact() {
  name=$1; want=$2; want_line=$3; shift 4
  timeout -k 1 3 ./ntx --store-dir="$TMP/store" "$@" >"$TMP/out" 2>"$TMP/err" </dev/null
  rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL $name: exit $rc, want $want" >&2
    sed 's/^/    | /' "$TMP/err" | head -5 >&2
    fails=$((fails + 1))
    return
  fi
  if ! grep -Fxq -- "$want_line" "$TMP/err"; then
    echo "FAIL $name: stderr lacks the exact line:" >&2
    printf '%s\n' "$want_line" | sed 's/^/    want| /' >&2
    sed 's/^/    got | /' "$TMP/err" | head -5 >&2
    fails=$((fails + 1))
    return
  fi
  echo "PASS $name"
}

printf 'shareable\n' > "$TMP/plain.bin"
printf 'x' > "$TMP/$(printf 'a\001b')"

expect_exact share-with-magnet 2 'ntx: --share cannot be combined with a magnet or .torrent argument' \
  -- --share="$TMP/plain.bin" "$MAG"
expect_exact share-with-torrent 2 'ntx: --share cannot be combined with a magnet or .torrent argument' \
  -- --share="$TMP/plain.bin" "$TMP/junk.torrent"
expect_exact share-twice        2 'ntx: --share given twice' \
  -- --share="$TMP/plain.bin" --share="$TMP/plain.bin"
expect_exact share-from-no-share 2 'ntx: --share-from requires --share' \
  -- --share-from="$TMP/junk.torrent"
expect_exact portmap-both       2 'ntx: --port-map and --no-port-map are mutually exclusive' \
  -- --port-map --no-port-map "$MAG"
expect_exact portmap-with-proxy 2 'ntx: --port-map cannot be used with --proxy or --tunnel (inbound traffic would bypass it and the mapping would reveal your address)' \
  -- --port-map --proxy=socks5:127.0.0.1:9 "$MAG"
expect_exact portmap-with-tunnel 2 'ntx: --port-map cannot be used with --proxy or --tunnel (inbound traffic would bypass it and the mapping would reveal your address)' \
  -- --port-map --tunnel=127.0.0.1:9 "$MAG"

# Startup failures (design §9): a share that cannot be added exits 1 with a
# message. Every case is a synchronous check inside ntx_session_share_add, so
# nothing is hashed and no packet leaves the host. The wording of the reason
# belongs to the share module; the path and the "cannot share" prefix do not.
expect share-dir        1 'cannot share'  -- --share="$TMP"
expect share-empty      1 'cannot share'  -- --share="$TMP/empty.torrent"
expect share-missing    1 'cannot share'  -- --share="$TMP/nonexistent"
expect share-ctrl-name  1 'cannot share'  -- --share="$TMP/$(printf 'a\001b')"
expect share-from-junk  1 'cannot share'  -- --share="$TMP/plain.bin" --share-from="$TMP/junk.torrent"

# Valid spellings must still be accepted: the client keeps running until `timeout`
# kills it (124). Proxy points at a closed local port, so nothing leaves the host.
expect valid-options-run 124 - -- --port-lo=0 --port-hi=0 --max-peers=0 --down-limit=0 \
  --up-limit=4096 --proxy=socks5:127.0.0.1:9 --tunnel=127.0.0.1:9 --smooth "$MAG"

# ── --help suppression when the share gate is closed (design §6.4) ───────────
# ntx_share_available() is driven by the built-in tracker table, which holds 7
# hosts on this build (pinned by test/t_share_contract.c), so the hidden path
# needs a build whose table falls below NTX_SHARE_MIN_TRACKERS. The table is
# replaceable through -DNTX_SHARE_TRACKERS_INC (the Task 1 hook) — the built-in
# table is never edited here. Skipped when the tree or a compiler is missing,
# as in scripts/riscv/run-shell-suites.sh, which runs this gate from a scratch
# root that holds only the scripts and an ./ntx wrapper.
NS="$TMP/ntx_noshare"
NS_HDR="$TMP/share_trackers_one_host.h"
if command -v cc >/dev/null 2>&1 && [ -f src/ntx_main.c ] && [ -f src/proto/ntx_share_trackers.c ]; then
  printf '%s\n' \
    'static const strk_raw strk_raw_tab[] = {' \
    '    {"https://one.example:443/announce", "one.example",' \
    '     {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, 0, 0}},' \
    '};' > "$NS_HDR"
  # shellcheck disable=SC2046 # find expands the source list by design
  if cc -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L \
       -D"NTX_SHARE_TRACKERS_INC=\"$NS_HDR\"" -o "$NS" $(find src -name '*.c') -lm \
       >"$TMP/build_err" 2>&1; then
    # The shipped build must OFFER the three options ...
    if timeout -k 1 5 ./ntx --help >"$TMP/out" 2>/dev/null </dev/null \
       && grep -q -- '--share=PATH' "$TMP/out" && grep -q -- '--share-from=' "$TMP/out" \
       && grep -q -- '--port-map' "$TMP/out"; then
      echo "PASS help-offers-share-options"
    else
      echo "FAIL help-offers-share-options" >&2
      sed 's/^/    | /' "$TMP/out" | head -8 >&2
      fails=$((fails + 1))
    fi
    # ... the gated build must not show them at all, and must still show the rest.
    if timeout -k 1 5 "$NS" --help >"$TMP/out" 2>/dev/null </dev/null \
       && grep -q '^usage:' "$TMP/out" && grep -q -- '--store-dir=' "$TMP/out" \
       && ! grep -q -- '--share' "$TMP/out" && ! grep -q -- '--port-map' "$TMP/out"; then
      echo "PASS help-hides-share-options"
    else
      echo "FAIL help-hides-share-options" >&2
      sed 's/^/    | /' "$TMP/out" | head -8 >&2
      fails=$((fails + 1))
    fi
    # ... and using --share there is a startup failure (exit 1), with the
    # no_trackers text from ntx_share_err_msg on stderr.
    timeout -k 1 3 "$NS" --store-dir="$TMP/store" --share="$TMP/plain.bin" \
      >"$TMP/out" 2>"$TMP/err" </dev/null
    rc=$?
    if [ "$rc" -eq 1 ] && grep -Fq 'no HTTPS share trackers are pinned in this build' "$TMP/err"; then
      echo "PASS share-gated-no-trackers"
    else
      echo "FAIL share-gated-no-trackers: exit $rc, want 1 + the no_trackers message" >&2
      sed 's/^/    | /' "$TMP/err" | head -5 >&2
      fails=$((fails + 1))
    fi
  else
    echo "SKIP share-gate build (compiler failed; see below)" >&2
    sed 's/^/    | /' "$TMP/build_err" | head -10 >&2
  fi
else
  echo "SKIP share-gate build (no cc or no sources here)" >&2
fi

# --help is a success path and goes to stdout
if timeout -k 1 5 ./ntx --help >"$TMP/out" 2>"$TMP/err" </dev/null && grep -q '^usage:' "$TMP/out"; then
  echo "PASS help-stdout-rc0"
else
  echo "FAIL help-stdout-rc0" >&2
  fails=$((fails + 1))
fi

# --version prints "ntx X.Y.Z" on stdout and exits 0 without starting a session
if timeout -k 1 5 ./ntx --version >"$TMP/out" 2>"$TMP/err" </dev/null && grep -Eq '^ntx [0-9]+\.[0-9]+\.[0-9]+' "$TMP/out"; then
  echo "PASS version-stdout-rc0"
else
  echo "FAIL version-stdout-rc0" >&2
  fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then
  echo "test-cli: $fails failure(s)" >&2
  exit 1
fi
echo "test-cli: ALL PASS"
