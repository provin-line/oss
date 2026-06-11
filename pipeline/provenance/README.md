# provenance — Shared VC Signing / Verification Mechanics

Process-facing interfaces over the VC machinery in `vc`:

- `Provider` — `Sign(ctx, payload, inputHash, outputHash) (*Credential, error)`;
  owns the per-process chain state (`previousCredential` linking) and, for any
  boundary deployed in the audit-reachable conformance class (config-driven), the
  source commitment (`vc.SourceCommitment` — see
  [../source/README.md](../source/README.md); chain-preserving
  boundaries commit to their full consumed set, predecessor included).
- `Verifier` — `Verify(ctx, *Credential) (*VerifyResult, error)`; returns the
  confidence verdict (weakest-link over axes).

## vcdid/ — DID/VC-backed implementation

- Signing delegates to the registry's SignerService over ConnectRPC (KMS model);
  data is pre-hashed locally and only the `sha256:` digest crosses the wire.
- Chain state (`lastVC`) is mutex-guarded — providers may be shared across goroutines.
- Verification resolves issuer DIDs via `resolver` and pre-hashes with
  SHA-256 to match the remote-signer convention.

These packages carry **no process semantics** — every process type that signs or
verifies uses them.
