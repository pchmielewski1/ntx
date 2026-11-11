# `scripts/pins` — share-tracker key gate (design §6.2)

`pins.py` answers one question before a release: are the SPKI pins compiled into
`src/proto/ntx_share_trackers.c` still the keys the hosts serve, and are the hosts
still acceptable share trackers? `make` and `make test` never run it — only
`make pins-check` (the release gate) and `make pins-update` (the maintainer) do,
and both reach the network.

## Commands

```
make pins-check            # release gate; exit 1 = do not publish
make pins-update           # absorb verified new keys, print the diff, commit it
./ntx-sharetest            # build with scripts/pins/sharetest_trackers.inc (test table)
```

`pins.py check|update [--offline-fixture DIR] [--tries N] [--trackers F] [--pins-txt F]`

Report rows are `<host> <OK|NEW-KEY|WEBPKI-FAIL|FULL-SCRAPE|UNREACHABLE> <detail>`.
Exit `0` = OK or warnings only; exit `1` = a blocking row of the §6.2 table:

| Row for a host            | `check` | `update` |
|---------------------------|---------|----------|
| key matches a pin         | `0`     | `0`      |
| verified key not listed   | `1`     | `0` (absorbs it) |
| WebPKI verification fails | `1`     | `1`      |
| host serves a full scrape | `1`     | `1`      |
| unreachable / timeout     | `0` (warning) | `0` (warning) |
| fewer than 2 qualified    | `1`     | `1`      |

Qualified = `OK`, plus `NEW-KEY` for `update` (that key is about to be pinned).
Two or more qualified hosts is `NTX_SHARE_MIN_TRACKERS` in
`src/proto/ntx_share_trackers.h`. Each host gets up to 3 `openssl` attempts
(`--tries`).

## What `update` writes

Verified new keys go into the free pin slot of the row, keeping the old key for
the transition; at 4 pins (`NTX_HTTPS_PIN_MAX`) the oldest is dropped. It rewrites
only the block between `/* BEGIN GENERATED */` and `/* END GENERATED */` in
`src/proto/ntx_share_trackers.c`, regenerates the share rows of `pins.txt`, prints
a unified diff and changes nothing else. A host whose verification failed never
gets a key. A host with a bad chain or a full scrape must be removed by hand —
`update` refuses to write a block that would fall below the minimum.

`src/proto/ntx_share_trackers.c` is never hand-edited: that block is this tool's
output, reviewed as a diff and committed by the maintainer. No CI job commits to
the supply chain (§6.2).

## Offline fixtures

`test/vectors/pins/<case>/fixture.txt` holds recorded `openssl` results so
`make test` can exercise every row of the table without a network or a real key.
Lines:

```
HOST <url> <host> <64-hex pin>…                 # one table row
PROBE <host> verify <rc>                        # openssl "Verify return code"
PROBE <host> cert <base64 leaf DER>             # the leaf openssl presented
PROBE <host> scrape <body>                      # /scrape answer body
PROBE <host> unreachable <detail>               # host did not answer
```

`test/pins_tool.sh` (from `make test-cli`) runs all six cases and asserts the exit
codes above. Regenerate certificates with `openssl req -x509 -newkey rsa:2048
-nodes` and compute every pin with the tool — never hand-type hex.
