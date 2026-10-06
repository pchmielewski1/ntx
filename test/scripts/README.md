# test/scripts

Reference generators and helpers for the test suite. The generators produce known-answer vectors and golden fixtures with code that is independent of the C sources (Python's `hashlib`, `hmac`, `pow()`, or the OpenSSL-backed `cryptography` package), so a bug cannot hide by being present on both sides.

## Rule: never type expected bytes by hand

Every expected hash, pin, key, MAC, signature, size delta and every long hex block is produced by a script from this directory, stored under `test/vectors/` or `test/fixtures/`, and only then read by a test. Do not paste long hex constants into `.c` files; make the test read the vector file instead. (A few older tests quote short published standard vectors inline, for example the RFC 7748 values in `t_x25519.c`.)

Run all scripts from the repository root.

## Requirements

- `python3` and `bash`.
- The Python package `cryptography` is needed by `aes_vectors.py`, `p256_vectors.py`, `rsa_pkcs1_vectors.py`, `rsa_pss_vectors.py` and `tls13_ref.py`. All other scripts use only the Python standard library.

## Vector and fixture generators

| Script | Produces | Used by |
|--------|----------|---------|
| `aes_vectors.py` | `test/vectors/aes/vectors.txt`: AES-128-GCM and CTR vectors (made with `cryptography`) | `t_aes_kat.c` |
| `bignum_vectors.py` | `test/vectors/bignum/vectors.txt`: `modexp`, `mulmod`, `mod` and `reject` lines (Python big integers; fixed seed) | `t_bignum.c` |
| `dh_kat.py` | `test/vectors/dh/kat.txt`: 768-bit DH exponentiation vectors (Python `pow()`; fixed seed); also checks the MSE/PE modulus | `t_dh_kat.c` |
| `mac_vectors.py` | `test/vectors/mac/vectors.txt`: HMAC-SHA1, HMAC-SHA256, HKDF-Expand and TLS 1.2 PRF vectors (stdlib; fixed seed) | `t_mac_kat.c` |
| `p256_vectors.py` | `test/vectors/p256/vectors.txt`: ECDSA P-256 and SPKI vectors | `t_p256_kat.c` |
| `rsa_pkcs1_vectors.py` | `test/vectors/rsa_pkcs1/vectors.txt`: RSASSA-PKCS1-v1_5/SHA-256 vectors, including degenerate-key forgeries | `t_rsa_pkcs1_kat.c` |
| `rsa_pss_vectors.py` | `test/vectors/rsa_pss/vectors.txt`: RSASSA-PSS (SHA-256, MGF1-SHA256, salt 32) vectors | `t_rsa_pss.c` |
| `tls13_ref.py` | An independent TLS 1.3 (RFC 8446) implementation. Writes `test/vectors/tls13/kat.txt` and the server streams and expectations in `test/fixtures/tls/` | `t_tls13.c`, `t_tls_golden.c` |
| `bep52_gen.py` | BEP52 fixtures in `test/vectors/bep52/{single_16k,multi_v2,hybrid_ok,hybrid_bad_order}/` (`meta.torrent`, file data, `manifest.txt`) | `t_bep52_*.c`, `t_merkle.c`, `t_magnet.c`, `t_hash_exchange.c` |
| `bep52_hash_msgs.py` | BEP52 hash-exchange wire vectors `test/vectors/bep52/hash_*.bin` and `hashes_omitted_proof_layers.bin`, each with a `.meta.json` | `t_hash_msg.c` |
| `gen_fixtures_announce_dht_pe.py` | Frozen wire fixtures in `test/fixtures/{announce,dht,pe}/` (see [`test/fixtures/README.md`](../fixtures/README.md)) | `t_golden_announce.c`, `t_golden_dht.c`, `t_golden_pe.c` |
| `socks_udp_frames.py` | `test/vectors/socks/udp_associate_frames.bin` and `.meta.json`: SOCKS5 UDP ASSOCIATE framing (RFC 1928 section 7) | `t_socks_udp.c` |
| `utp_header.py` | `test/vectors/utp/header/{vectors,sack,ext}.txt` and `test/vectors/utp/{cc_constants,cc}.txt` | `t_utp_hdr.c`, `t_utp_cc.c` |
| `utp_demux_vectors.py` | `test/vectors/utp/demux_classify.bin` and `.meta.json`: first-byte classifier cases (DHT / uTP / drop) | `t_utp_demux.c` |
| `ipc_vectors.py` | `test/vectors/ipc/*.jsonl`: control-channel commands and JSON-escaping cases | `t_ipc_ctrl.c`, `t_cli.c` |

`p256_vectors.py`, `rsa_pkcs1_vectors.py`, `rsa_pss_vectors.py` and the randomised signatures in `tls13_ref.py` create fresh keys or random messages on every run, so regenerating them changes the committed files (the new files are valid; the old ones are one sample). The other generators are deterministic.

Not every vector file has a generator here: `test/vectors/sha1`, `rc4`, `x25519`, `bencode`, `https`, `tls_spki`, `rsa_pkcs1_sha256` and `doh` hold hand-collected standard test vectors or files made with the `openssl` CLI. See the notes in [Vector directories](#vector-directories).

## Helper scripts

| Script | Purpose |
|--------|---------|
| `hex_norm.py [--expect N] [FILE]` | Normalises hex (strips whitespace and commas, lower-cases) from `FILE` or stdin and prints it; exits 1 if `--expect N` is given and the length is not `N` bytes. |
| `hex_cmp.py A B` | Compares two hex strings or files after normalisation; prints `HEX MATCH` (exit 0) or `HEX MISMATCH (A vs B)` (exit 1). |
| `pin_from_der.py FILE.der` | Prints SHA-256 of the DER SubjectPublicKeyInfo of an X.509 certificate (or of a bare SPKI file) as 64 lowercase hex characters. This is the SPKI pin format used by `--https-pin-file`. |
| `hkdf_ref.py` | HKDF (RFC 5869, HMAC-SHA256) reference. `--case 1 --extract` and `--case 1 --expand` print the RFC 5869 test case 1 PRK and OKM and assert them; `--hkdf5869 --ikm HEX --salt HEX --info HEX --len N` runs an arbitrary extract-and-expand. TLS 1.3 key schedule values come from `tls13_ref.py`. |
| `sweep.sh OUTDIR [cflags...]` | Parallel compile-and-run of every `test/t_*.c` (for example under `-fsanitize=address,undefined`). See [docs/testing.md](../../docs/testing.md#sanitizer-sweep). |
| `size_delta.sh [limit_kb]` | Prints the size difference between `./ntx` and the byte count stored in `test/.ntx-size-baseline`, and exits 1 if `limit_kb` is given and the growth exceeds it. The baseline file is not tracked in git: create it yourself first, for example `stat -c%s ntx > test/.ntx-size-baseline`. The release size gate itself is `make size`. |

Examples:

```sh
python3 test/scripts/pin_from_der.py test/vectors/tls_spki/test_leaf.der      # 64 hex characters
python3 test/scripts/hex_norm.py --expect 32 test/vectors/tls_spki/test_leaf.pin.hex
python3 test/scripts/hex_cmp.py test/vectors/tls_spki/test_leaf.pin.hex <(python3 test/scripts/pin_from_der.py test/vectors/tls_spki/test_leaf.der)
python3 test/scripts/hkdf_ref.py --case 1 --extract    # compare with test/vectors/hkdf/extract1.expected
python3 test/scripts/hkdf_ref.py --case 1 --expand     # compare with test/vectors/hkdf/expand1.expected
```

## Vector directories

| Directory | Content and origin |
|-----------|--------------------|
| `test/vectors/aes`, `bignum`, `dh`, `mac`, `p256`, `rsa_pkcs1`, `rsa_pss` | Generated by the scripts above. |
| `test/vectors/tls13` | `kat.txt` from `tls13_ref.py`; leaf certificates, keys and pins for the TLS 1.3 tests (see its `README.txt`). |
| `test/vectors/bep52` | Generated by `bep52_gen.py` and `bep52_hash_msgs.py` (see its `README.txt`). |
| `test/vectors/socks`, `utp`, `ipc` | Generated by `socks_udp_frames.py`, `utp_header.py` / `utp_demux_vectors.py`, `ipc_vectors.py`. |
| `test/vectors/hkdf` | `*.expected` files with the HKDF outputs checked by `t_hkdf.c`; the first two (`extract1`, `expand1`) are the values `hkdf_ref.py --case 1` prints. |
| `test/vectors/tls_spki` | `test_leaf.der` (self-signed `ntx-test.local` certificate) and `google_rsa_leaf.der` (a public RSA leaf certificate for `*.google.com`), each with the `.pin.hex` made by `pin_from_der.py`. |
| `test/vectors/https` | Reference data for the pin-file and URL formats (`sample_pins.txt`, `urls.txt`); see its `README.txt`. No test reads these two files at present. |
| `test/vectors/rsa_pkcs1_sha256` | One RSA-2048 signature made with the `openssl` CLI (see its `README.txt`). |
| `test/vectors/doh` | A hand-built DNS response (see its `README.txt`). |
| `test/vectors/sha1`, `rc4`, `bencode` | Hand-collected standard vectors and bencode edge cases, read by `t_sha1.c`, `t_rc4.c`, `t_bencode.c`. |
| `test/vectors/x25519` | `rfc7748.txt`, the RFC 7748 vectors. `t_x25519.c` quotes the same values inline, so no test reads this file. |

## Hex pitfalls

- A pin is 64 hex characters (32 bytes). Validate with `hex_norm.py --expect 32`.
- Compare bytes (`memcmp`, or `hex_cmp.py`), not hex strings read by eye.
- A leading `0x00` in a DER INTEGER is padding, not "trailing zeros" in the printed hex. Do not trim it from RSA moduli.
- A pin is a `uint8_t[32]`, not a C string: an embedded `0x00` is legal.
