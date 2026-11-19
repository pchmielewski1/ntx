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
# R34: a repeated --share-from was cicho accepted (last one wins) while every
# other option is strict — the second occurrence is a command-line error, same
# shape and same exit as `--share given twice`. Order-independent: the duplicate
# is caught in the parser, before the "--share-from requires --share" check.
expect_exact share-from-twice 2 'ntx: --share-from given twice' \
  -- --share="$TMP/plain.bin" --share-from="$TMP/junk.torrent" --share-from="$TMP/empty.torrent"
expect_exact share-from-twice-before-share 2 'ntx: --share-from given twice' \
  -- --share-from="$TMP/junk.torrent" --share-from="$TMP/empty.torrent" --share="$TMP/plain.bin"
# Guards: strictness must stop at the duplicate. One --share-from is still
# accepted (the verdict below comes from the share module, not the parser), and
# two --share slots stay the separate error they have always been.
expect share-from-once-ok  1 'cannot share' -- --share="$TMP/plain.bin" --share-from="$TMP/junk.torrent"
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
# S26/R36: the basename is a share name, so the ONE gate (ntx_share_name_ok)
# refuses every ASCII control character — tab and DEL included, not just \x01 —
# and a name that is not valid UTF-8. The files really exist: an ENOENT would
# also say "cannot share" (with "cannot read the file"), so creating them is
# what makes these cases test the NAME and not the open.
printf 'x' > "$TMP/$(printf 'a\tb')"
printf 'x' > "$TMP/$(printf 'a\177b')"
printf 'x' > "$TMP/$(printf 'a\nb')"
printf 'x' > "$TMP/$(printf 'a\303\050b')"
expect share-tab-name    1 'cannot share' -- --share="$TMP/$(printf 'a\tb')"
expect share-del-name    1 'cannot share' -- --share="$TMP/$(printf 'a\177b')"
expect share-nl-name     1 'cannot share' -- --share="$TMP/$(printf 'a\nb')"
# The ill-formed name is built inside the child shell, not passed through `timeout`:
# uutils-coreutils' timeout (ubuntu-latest) refuses an argv that is not valid UTF-8
# (exit 125) before ntx runs, while GNU's passes it on. ntx still gets the same bytes.
timeout -k 1 3 sh -c 'exec ./ntx --store-dir="$1/store" --share="$1/$(printf "a\303\050b")"' \
    sh "$TMP" >"$TMP/out" 2>"$TMP/err" </dev/null
rc=$?
if [ "$rc" -ne 1 ]; then
  echo "FAIL share-badutf8-name: exit $rc, want 1" >&2
  sed 's/^/    | /' "$TMP/err" | head -5 >&2
  fails=$((fails + 1))
elif ! grep -Eq -- 'cannot share' "$TMP/err"; then
  echo "FAIL share-badutf8-name: stderr lacks /cannot share/" >&2
  sed 's/^/    | /' "$TMP/err" | head -5 >&2
  fails=$((fails + 1))
else
  echo "PASS share-badutf8-name"
fi
# and the reason on stderr is the name module's text, not a read error
if timeout -k 1 3 ./ntx --store-dir="$TMP/store" --share="$TMP/$(printf 'a\tb')" \
     >"$TMP/out" 2>"$TMP/err" </dev/null; then :; fi
if ! grep -Fq 'invalid file name' "$TMP/err"; then
  echo "FAIL share-tab-name-reason: stderr lacks 'invalid file name'" >&2
  sed 's/^/    | /' "$TMP/err" | head -3 >&2
  fails=$((fails + 1))
else
  echo "PASS share-tab-name-reason"
fi
# Positive control: the same gate must NOT refuse a legal multi-byte name — an
# over-long name is cut on a character boundary, never rejected (the S15 rule).
# A share that passes the name gate goes on to hash, so the verdict here is only
# that the run never said "invalid file name".
printf 'x' > "$TMP/$(printf 'za\305\274\303\263\305\202.txt')"
timeout -k 1 3 ./ntx --store-dir="$TMP/store" --no-port-map --port-lo=0 --port-hi=0 \
  --proxy=socks5:127.0.0.1:9 --share="$TMP/$(printf 'za\305\274\303\263\305\202.txt')" \
  >"$TMP/out" 2>"$TMP/err" </dev/null
if grep -Fq 'invalid file name' "$TMP/err"; then
  echo "FAIL share-utf8-name: a legal multi-byte name was refused" >&2
  sed 's/^/    | /' "$TMP/err" | head -3 >&2
  fails=$((fails + 1))
else
  echo "PASS share-utf8-name"
fi
expect share-from-junk  1 'cannot share'  -- --share="$TMP/plain.bin" --share-from="$TMP/junk.torrent"

# ── the store directory of a share (design §5.4, docs/cli.md "Created on demand") ──
# R2: `--share` promises the store dir is created on demand. Before the fix nothing
# ever created it, so open() of the .torrent answered ENOENT after the WHOLE file
# had been hashed, and the reason on stderr was "cannot read the file".
#
# Still no network here: the .torrent is written straight after hashing, so its
# arrival proves the run got past the destination, and the negative case exits before
# any hashing at all. --proxy points at a closed port and --no-port-map keeps the
# gateway out, so no case needs a tracker to answer (and none needs 120 s of hashing
# either: the polls below only ever wait for hashing to reach its end).
dd if=/dev/urandom of="$TMP/big.bin" bs=1048576 count=8 >/dev/null 2>&1

# poll_for <secs> <dir> — wait for one *.torrent to appear under <dir>
poll_for() {
  _s=$1 _d=$2 _i=0
  while [ "$_i" -lt "$_s" ]; do
    if [ -d "$_d" ] && [ -n "$(find "$_d" -maxdepth 1 -type f -name '*.torrent' 2>/dev/null)" ]; then
      return 0
    fi
    sleep 1
    _i=$((_i + 1))
  done
  return 1
}

# CLI: a store dir that does not exist yet is created and holds the .torrent, and
# the share is never reported as a read failure. SIGTERM then ends it with exit 0.
start_share() { # <store-dir> [flags...] — ./ntx --share in the background
  sd=$1
  shift
  ./ntx --share="$TMP/big.bin" --store-dir="$sd" \
    --no-port-map --port-lo=0 --port-hi=0 --proxy=socks5:127.0.0.1:9 "$@" \
    >"$TMP/out" 2>"$TMP/err" </dev/null &
  SHARE_PID=$!
}
stop_share() { # -> SHARE_RC of the started ntx, after a polite SIGTERM
  kill -TERM "$SHARE_PID" 2>/dev/null
  _i=0
  while kill -0 "$SHARE_PID" 2>/dev/null && [ "$_i" -lt 20 ]; do sleep 0.25; _i=$((_i + 1)); done
  kill -KILL "$SHARE_PID" 2>/dev/null
  # wait must run in THIS shell: a $(...) subshell cannot reap the parent's child
  wait "$SHARE_PID" 2>/dev/null
  SHARE_RC=$?
}

start_share "$TMP/on-demand"
rc=1
if poll_for 40 "$TMP/on-demand"; then rc=0; fi
mode=$(find "$TMP/on-demand" -maxdepth 1 -type f -name '*.torrent' -exec stat -c '%a' {} \; 2>/dev/null)
count=$(find "$TMP/on-demand" -maxdepth 1 -type f -name '*.torrent' 2>/dev/null | wc -l)
stop_share; src_rc=$SHARE_RC
if [ "$rc" -eq 0 ] && [ "$count" -eq 1 ] && [ "$mode" = "600" ] && [ "$src_rc" -eq 0 ] \
   && ! grep -Fq 'cannot read the file' "$TMP/err" \
   && ! grep -Fq 'share failed' "$TMP/err"; then
  echo "PASS share-store-created-on-demand"
else
  echo "FAIL share-store-created-on-demand: torrent=$count mode='$mode' rc=$src_rc, want one 0600 .torrent in the new dir and exit 0" >&2
  sed 's/^/    | /' "$TMP/err" | head -5 >&2
  fails=$((fails + 1))
fi

# JSON: the same with --stats-json — the destination is created, and no share event
# reports ok=0. (The ready event needs a tracker to answer, which is share_e2e's
# job; here the contract is "the store dir is never the reason the share dies".)
start_share "$TMP/on-demand-json" --stats-json
rc=1
if poll_for 40 "$TMP/on-demand-json"; then rc=0; fi
count=$(find "$TMP/on-demand-json" -maxdepth 1 -type f -name '*.torrent' 2>/dev/null | wc -l)
stop_share; src_rc=$SHARE_RC
if [ "$rc" -eq 0 ] && [ "$count" -eq 1 ] && [ "$src_rc" -eq 0 ] \
   && ! grep -Eq '"type":"share","i":[0-9]+,"ok":0' "$TMP/out"; then
  echo "PASS share-store-created-on-demand-json"
else
  echo "FAIL share-store-created-on-demand-json: torrent=$count rc=$src_rc, want one .torrent in the new dir, no failed share event, exit 0" >&2
  tail -3 "$TMP/out" | cut -c1-200 | sed 's/^/    | /' >&2
  sed 's/^/    | /' "$TMP/err" | head -5 >&2
  fails=$((fails + 1))
fi

# A store dir that exists but is not writable is a clear, EARLY io error: the
# reason names writing the .torrent, never reading the file, and it lands before
# any hashing. Under --stats-json that is provable — the JSON loop is only entered
# after ntx_session_share_add returned, so a synchronous verdict means not one
# hello/stats line and no hashing at all.
mkdir -p "$TMP/ro-store" && chmod 0500 "$TMP/ro-store"
t0=$(date +%s)
timeout -k 1 20 ./ntx --stats-json --share="$TMP/big.bin" --store-dir="$TMP/ro-store" \
  --no-port-map --port-lo=0 --port-hi=0 --proxy=socks5:127.0.0.1:9 \
  >"$TMP/out" 2>"$TMP/err" </dev/null
rc=$?
el=$(( $(date +%s) - t0 ))
chmod 0700 "$TMP/ro-store"
if [ "$rc" -eq 1 ] && [ "$el" -le 5 ] \
   && grep -Fq 'cannot write the .torrent into' "$TMP/err" \
   && grep -Fq "$TMP/ro-store" "$TMP/err" \
   && ! grep -Fq 'cannot read the file' "$TMP/err" \
   && ! grep -q '"type":"stats"' "$TMP/out"; then
  echo "PASS share-store-unwritable-early"
else
  echo "FAIL share-store-unwritable-early: exit $rc after ${el}s, want 1 fast + 'cannot write the .torrent into' naming the dir, no stats line" >&2
  sed 's/^/    | /' "$TMP/err" | head -5 >&2
  tail -2 "$TMP/out" | cut -c1-200 | sed 's/^/    out| /' >&2
  fails=$((fails + 1))
fi

# ── the share size ceiling (§5.6, docs/cli.md "Validation and exit codes") ────
# `too_big` is the one synchronous reason the plan's §6 still had no CLI case for:
# t_share_session.c and t_share_contract.c cover the enum and the wire code, so
# nothing proved the CLI ever refused an over-large file with the documented text.
# The ceiling is NTX_SHARE_MAX_PIECES (32768) pieces at NTX_SHARE_PIECE_MAX
# (64 MiB), decided by smeta_piece_len() from the stat alone — so one piece over
# 32768 * 64 MiB is enough and the file is never read. It is SPARSE (dd `seek=`,
# no blocks allocated), so the case costs a stat, not two terabytes.
dd if=/dev/zero of="$TMP/huge.bin" bs=67108864 count=0 seek=32769 >/dev/null 2>&1
if [ "$(stat -c%s "$TMP/huge.bin" 2>/dev/null)" = "2199090364416" ]; then
  expect_exact share-too-big 1 "ntx: cannot share $TMP/huge.bin: file too large to share" \
    -- --share="$TMP/huge.bin"
  # Synchronous like every other reason: the piece ceiling is a stat, so a 2 TiB
  # file must be refused before any hashing, and nothing may reach the store dir.
  t0=$(date +%s)
  timeout -k 1 20 ./ntx --store-dir="$TMP/toobig-store" --share="$TMP/huge.bin" \
    --no-port-map --port-lo=0 --port-hi=0 --proxy=socks5:127.0.0.1:9 \
    >"$TMP/out" 2>"$TMP/err" </dev/null
  rc=$?
  el=$(( $(date +%s) - t0 ))
  n=$(find "$TMP/toobig-store" -maxdepth 1 -type f -name '*.torrent' 2>/dev/null | wc -l)
  if [ "$rc" -eq 1 ] && [ "$el" -le 5 ] && [ "$n" -eq 0 ] \
     && grep -Fq 'file too large to share' "$TMP/err" \
     && ! grep -Fq 'cannot read the file' "$TMP/err"; then
    echo "PASS share-too-big-early"
  else
    echo "FAIL share-too-big-early: exit $rc after ${el}s, torrent=$n, want 1 fast, no .torrent, 'file too large to share'" >&2
    sed 's/^/    | /' "$TMP/err" | head -5 >&2
    fails=$((fails + 1))
  fi
else
  echo "SKIP share-too-big (no sparse files on this filesystem)" >&2
fi

# ── an empty --share= value ───────────────────────────────────────────────────
# `--share=` with nothing after the equals sign is not "no share": g_share_path
# becomes the empty string, the option is set, so it is the share module's
# bad_arg (`invalid share argument`) and not the parser's — and it must not be
# mistaken for a read error, which is what a missing path would say.
expect_exact share-empty-value 1 'ntx: cannot share : invalid share argument' \
  -- --share=

# ── a --share-from that describes a DIFFERENT file (§5.6, docs/cli.md) ────────
# docs/cli.md: "under --share-from the hashes are compared instead of published,
# and a mismatch is the `changed` failure, never a share under a wrong link".
# Only a rejected .torrent (junk, missing) was covered here; a VALID one for the
# wrong bytes is the case that matters — it is the one where publishing would
# hand out a link that does not describe the file being seeded. The pair comes
# from the committed metainfo fixture (test/scripts/share_gen.py): meta.torrent
# is valid, its data.bin is the file it really describes, and a fresh 16 KiB of
# noise has the same length but different hashes. Skipped where the vectors are
# not next to this script, as in the riscv scratch root of
# scripts/riscv/run-shell-suites.sh.
VEC="$ROOT/test/vectors/share/one_piece_16k"
if [ -f "$VEC/meta.torrent" ] && [ -f "$VEC/data.bin" ]; then
  dd if=/dev/urandom of="$TMP/other-16k.bin" bs=16384 count=1 >/dev/null 2>&1
  if [ "$(stat -c%s "$TMP/other-16k.bin" 2>/dev/null)" = "16384" ]; then
    # exit 1 is CLI mode's verdict for a share that died after being added; the
    # reason is `changed`, the store dir gets no .torrent and stdout no magnet.
    timeout -k 1 20 ./ntx --store-dir="$TMP/mismatch-store" \
      --no-port-map --port-lo=0 --port-hi=0 --proxy=socks5:127.0.0.1:9 \
      --share="$TMP/other-16k.bin" --share-from="$VEC/meta.torrent" \
      >"$TMP/out" 2>"$TMP/err" </dev/null
    rc=$?
    n=$(find "$TMP/mismatch-store" -maxdepth 1 -type f -name '*.torrent' 2>/dev/null | wc -l)
    if [ "$rc" -eq 1 ] && [ "$n" -eq 0 ] && ! grep -q '^magnet:' "$TMP/out" \
       && grep -Fxq 'ntx: share failed: the file changed while sharing' "$TMP/err"; then
      echo "PASS share-from-hash-mismatch"
    else
      echo "FAIL share-from-hash-mismatch: exit $rc, torrent=$n, want 1 + 0 + the exact 'share failed: the file changed while sharing' line and no magnet on stdout" >&2
      printf '%s\n' '    want| ntx: share failed: the file changed while sharing' >&2
      sed 's/^/    got | /' "$TMP/err" | head -5 >&2
      tail -3 "$TMP/out" | cut -c1-160 | sed 's/^/    out | /' >&2
      fails=$((fails + 1))
    fi
    # Non-vacuity: the SAME .torrent with the file it really describes must not be
    # refused — an assertion that fires for every --share-from would pass here too.
    # The share then announces, so `timeout` ends it (124); what is pinned is that
    # it never said `share failed`.
    timeout -k 1 3 ./ntx --store-dir="$TMP/match-store" \
      --no-port-map --port-lo=0 --port-hi=0 --proxy=socks5:127.0.0.1:9 \
      --share="$VEC/data.bin" --share-from="$VEC/meta.torrent" \
      >"$TMP/out" 2>"$TMP/err" </dev/null
    rc=$?
    if [ "$rc" -eq 124 ] && ! grep -Fq 'share failed' "$TMP/err" \
       && ! grep -Fq 'cannot share' "$TMP/err"; then
      echo "PASS share-from-matching-torrent-ok"
    else
      echo "FAIL share-from-matching-torrent-ok: exit $rc, want 124 (still running) with no share failure for the file the .torrent describes" >&2
      sed 's/^/    | /' "$TMP/err" | head -5 >&2
      fails=$((fails + 1))
    fi
  else
    echo "SKIP share-from-hash-mismatch (cannot write the 16 KiB payload)" >&2
  fi
else
  echo "SKIP share-from-hash-mismatch (no test/vectors/share here)" >&2
fi

# ── stdout carries the magnet and nothing else (docs/cli.md step 5) ───────────
# `ntx --share=FILE > link.txt` is documented to produce a file ntx itself
# accepts, so stdout holds exactly one line — the magnet — and every diagnostic
# (banner, status line, `shared —` note) stays on stderr. No tracker answers in
# this file, so a share here never reaches ready and the half that is provable
# without one is the SHAPE of stdout, which must hold in both states: empty
# while the share is not ready, or exactly one magnet line — never a second line
# and never anything that is not the link. Under --stats-json the same rule is
# stricter still (nothing raw may touch stdout, §9/C3), so `--stats-json
# --share=…` must emit NDJSON only and never a bare `magnet:` line. The positive
# half — the ready magnet really is stdout's single line, and the JSON share
# event really carries the link — is share_e2e.sh, where a tracker answers.
start_share "$TMP/mag-cli"
rc=1
if poll_for 40 "$TMP/mag-cli"; then rc=0; fi
stop_share
out_lines=$(wc -l < "$TMP/out" | tr -d ' \t')
mag_lines=$(grep -c '^magnet:?xt=urn:btih:' "$TMP/out" 2>/dev/null || true)
mag_lines=${mag_lines:-0}
if [ "$rc" -eq 0 ] && [ "$out_lines" -le "$mag_lines" ] && [ "$mag_lines" -le 1 ] \
   && [ -s "$TMP/err" ] && grep -Fq 'ntx: build ' "$TMP/err"; then
  echo "PASS share-magnet-is-stdout-only"
else
  echo "FAIL share-magnet-is-stdout-only: hashed=$rc, stdout=$out_lines line(s) of which $mag_lines magnet line(s), want <=1 line and it must be the magnet, with the banner on stderr" >&2
  head -3 "$TMP/out" | cut -c1-160 | sed 's/^/    out| /' >&2
  head -3 "$TMP/err" | cut -c1-160 | sed 's/^/    err| /' >&2
  fails=$((fails + 1))
fi

start_share "$TMP/mag-json" --stats-json
rc=1
if poll_for 40 "$TMP/mag-json"; then rc=0; fi
stop_share
if [ "$rc" -eq 0 ] && grep -q '"type":"stats"' "$TMP/out" && ! grep -q '^magnet:' "$TMP/out"; then
  echo "PASS no-raw-magnet-on-json-stdout"
else
  echo "FAIL no-raw-magnet-on-json-stdout: hashed=$rc, want stats lines on stdout and no raw magnet line" >&2
  grep -n '^magnet:' "$TMP/out" | head -3 | cut -c1-160 | sed 's/^/    out| /' >&2
  tail -2 "$TMP/out" | cut -c1-160 | sed 's/^/    out| /' >&2
  fails=$((fails + 1))
fi

# Valid spellings must still be accepted: the client keeps running until `timeout`
# kills it (124). Proxy points at a closed local port, so nothing leaves the host.
expect valid-options-run 124 - -- --port-lo=0 --port-hi=0 --max-peers=0 --down-limit=0 \
  --up-limit=4096 --proxy=socks5:127.0.0.1:9 --tunnel=127.0.0.1:9 --smooth "$MAG"

# ── --help suppression when the share gate is closed (design §6.4) ───────────
# ntx_share_available() is driven by the built-in tracker table, which holds
# well above NTX_SHARE_MIN_TRACKERS hosts on this build (the count is derived
# from the generated block by test/t_share_contract.c), so the hidden path
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
