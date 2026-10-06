a_example.bin: a DNS response for example.com, type A, answer 93.184.216.34, TTL 3600.

Hand-built RFC 1035 wire format (the answer name is the compression pointer 0xC00C).
It is the same message that test/t_doh.c embeds as FIX_RESP, which checks it against
the file. It is also a seed for the tracker fuzz corpus (test/fuzz/run_fuzz.sh).

This tests DNS message parsing only; there is no TLS or HTTP transport involved.
