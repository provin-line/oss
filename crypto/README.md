# crypto — Cryptographic Primitives

Minimal interfaces for key generation, signing, and verification, plus the Ed25519
implementation and the ES256 and RS256 verifiers.

## Interfaces

- `KeyGenerator` — `Generate() (*KeyPair, error)`, `Algorithm() string`
- `Signer` — `Sign(did, keyID string, data []byte) ([]byte, error)`
- `Verifier` — `Verify(publicKey, data, signature []byte) (bool, error)`

## Conventions

- **`Signer` is deliberately DID-aware**, not a raw primitive: production signers call
  the registry's SignerService (KMS model — private keys never leave the registry).
  A raw-key signer exists only for tests and CLI-local owner keys.
- `ed25519/` is the signing suite. `es256/` (ECDSA P-256 with SHA-256) and `rs256/`
  (RSASSA-PKCS1-v1_5 with SHA-256) verify only; each package names its key and
  signature bytes: ES256 takes the SEC1 uncompressed point and `r || s`, RS256 the
  DER of a PKCS #1 RSAPublicKey of 2048 to 4096 bits.
- ECDSA signature bytes are not unique (`(r, n-s)` verifies as `(r, s)` does), so
  nothing counts or deduplicates signatures by their bytes.
- Implementations reject malformed key/signature sizes before delegating to the
  underlying library.
