HTTPS pin-file and URL test data
================================

These two files are reference examples. No test in test/ reads them at the moment:
test/t_https_pin.c builds its pin files itself from test/vectors/tls_spki/, and the
URL cases that test/t_http_url.c checks are written inline in that file. Keep the
files in step with the behaviour described here.

Pin file format (sample_pins.txt; the same format as --https-pin-file, see docs/cli.md)
----------------------------------------------------------------------------------------
  - One pin per line: <host> <64 hex characters>, separated by a single space.
  - <host> is an exact host name or a wildcard "*.suffix".
  - A pin is the SHA-256 of the certificate's DER SubjectPublicKeyInfo (32 bytes, shown
    as 64 hex characters; the samples use lower case).
  - Blank lines are ignored; lines that start with '#' are comments.

  The two sample pins belong to the certificates in test/vectors/tls_spki/:
    test.example    -> test_leaf.pin.hex
    google.example  -> google_rsa_leaf.pin.hex

Pin validation and generation (never type pins by hand)
-------------------------------------------------------
  python3 test/scripts/pin_from_der.py <leaf.der>       # prints the 64-hex pin
  sed -n 1p test/vectors/https/sample_pins.txt | awk '{print $2}' | python3 test/scripts/hex_norm.py --expect 32
      (hex_norm.py checks one value per run, so validate one line at a time)

URL cases (urls.txt)
--------------------
  Each URL is followed by a "# host=... port=... path=..." comment with the expected
  result of ntx_http_url_parse():
  - default ports: http -> 80, https -> 443
  - explicit port: http://h:8080/announce
  - IPv6 literal in brackets: https://[::1]:8443/announce
  - missing path -> "/"
  - query string kept as part of the request path
  - sub-domain host with a non-standard port
