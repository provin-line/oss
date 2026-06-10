# provenance — Shared VC Signing / Verification Mechanics

Component-facing interfaces over the VC machinery in `packages/vc`:

- `Provider` — `Sign(ctx, payload, inputHash, outputHash) (*Credential, error)`;
  owns the per-process chain state (`previousCredential` linking) and, for Origin
  Sources deployed in the audit-reachable conformance class (config-driven), the
  origin commitment (`vc.OriginCommitment` — see
  [../originsource/README.md](../originsource/README.md)).
- `Verifier` — `Verify(ctx, *Credential) (*VerifyResult, error)`; returns the
  confidence verdict (weakest-link over axes).

## vcdid/ — DID/VC-backed implementation

- Signing delegates to the registry's SignerService over ConnectRPC (KMS model);
  data is pre-hashed locally and only the `sha256:` digest crosses the wire.
- Chain state (`lastVC`) is mutex-guarded — providers may be shared across goroutines.
- Verification resolves issuer DIDs via `packages/resolver` and pre-hashes with
  SHA-256 to match the remote-signer convention.

These packages carry **no component semantics** — every component type that signs or
verifies uses them.
