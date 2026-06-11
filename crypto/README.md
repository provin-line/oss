# packages/crypto — Cryptographic Primitives

Minimal interfaces for key generation, signing, and verification, plus the Ed25519
implementation.

## Interfaces

- `KeyGenerator` — `Generate() (*KeyPair, error)`, `Algorithm() string`
- `Signer` — `Sign(did, keyID string, data []byte) ([]byte, error)`
- `Verifier` — `Verify(publicKey, data, signature []byte) (bool, error)`

## Conventions

- **`Signer` is deliberately DID-aware**, not a raw primitive: production signers call
  the registry's SignerService (KMS model — private keys never leave the registry).
  A raw-key signer exists only for tests and CLI-local owner keys.
- `ed25519/` is the only implementation in the PoC. P-256/P-384 are post-PoC; the
  interfaces already carry the algorithm dimension so adding them is non-breaking.
- Implementations reject malformed key/signature sizes before delegating to the
  underlying library.
