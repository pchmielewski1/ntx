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

# Valid spellings must still be accepted: the client keeps running until `timeout`
# kills it (124). Proxy points at a closed local port, so nothing leaves the host.
expect valid-options-run 124 - -- --port-lo=0 --port-hi=0 --max-peers=0 --down-limit=0 \
  --up-limit=4096 --proxy=socks5:127.0.0.1:9 --tunnel=127.0.0.1:9 --smooth "$MAG"

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
