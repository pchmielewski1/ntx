RSASSA-PKCS1-v1_5 / SHA-256 verification fixture: one RSA-2048 key (e = 65537) and
one signature, made with the openssl command line:

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
  openssl dgst -sha256 -sign <key> msg.bin

The private key is not stored; every file here is public data.

  n.hex       modulus, 256 bytes big-endian (512 hex characters)
  e.hex       public exponent, 3 bytes big-endian (010001)
  msg.bin     the signed message (34 bytes)
  digest.hex  SHA-256 of msg.bin (32 bytes)
  sig.hex     signature, 256 bytes big-endian (512 hex characters)

test/t_rsa_pkcs1.c checks that:
  - SHA-256(msg.bin) equals digest.hex;
  - ntx_rsa_pkcs1_verify_sha256(n, 256, e, 3, sig, 256, digest) returns 1;
  - the same signature with the first digest byte flipped returns 0.

Many more cases (1024 to 4096-bit keys, tampered inputs, degenerate keys) are in
test/vectors/rsa_pkcs1/vectors.txt, made by test/scripts/rsa_pkcs1_vectors.py.
