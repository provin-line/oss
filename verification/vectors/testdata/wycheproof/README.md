# Wycheproof test vectors

Source: https://github.com/C2SP/wycheproof
Commit: d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9
License: Apache License 2.0 (`LICENSE`, fetched verbatim from the repository at that commit; the repository has no NOTICE file at that commit)

Files, from `testvectors_v1/` at that commit, unmodified:

- `ed25519_test.json`: Ed25519 signature verification.
- `ecdsa_secp256r1_sha256_p1363_test.json`: ECDSA P-256 with SHA-256, signatures as `r || s` (IEEE P1363), the form ES256 uses.
- `rsa_signature_2048_sha256_test.json`, `rsa_signature_3072_sha256_test.json`, `rsa_signature_4096_sha256_test.json`: RSASSA-PKCS1-v1_5 with SHA-256.

The files are data only; tests read them and never run anything from them.
