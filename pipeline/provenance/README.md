# provenance — Shared VC Signing / Verification Mechanics

Process-facing interfaces over the VC machinery in `vc`:

- `ChainedSigner` — `SignChainPreserving(ctx, payload, inputHash, outputHash, predecessor)`;
  issues the chain-preserving credential for a Chained Process
  (`previousCredential` = the predecessor's content hash). The predecessor is
  the event's verified input credential, handed per call by the runtime. For
  audit-reachable deployments (config-driven) the signer attaches the source
  commitment (`vc.SourceCommitment` — see [../source/README.md](../source/README.md))
  over the consumed conformant set — for a stateless 1:1 process exactly
  {predecessor} (all-consumed semantics).
- `SourceSigner` — `SignFirstDrop(ctx, payload, inputHash, outputHash)`; issues a
  FirstDrop (fresh chain origin) for a Source Process. The consumed-set path
  an audit-reachable aggregation needs gates with the aggregate runtime.
- `Verifier` — `Verify(ctx, *Credential) (*VerifyResult, error)`; returns the
  confidence verdict (weakest-link over axes).
- `ChainVerifier` — `VerifyChain(ctx, head) (*VerifyResult, error)`; full-chain
  verification for `VerificationFull` processes (sinks, observation tooling).
  Chain retrieval by content address is the implementation's concern.

Signing capabilities are split by chain behaviour, mirroring `vc.Builder`'s
explicit method split: a process is constructed with exactly the capability
matching its declared `contract.ChainBehavior`, so the type system enforces
that a Chained Process cannot issue a FirstDrop. Signers carry no chain
state — the chain link names the event's input credential, never the
process's previously issued one.

## vcdid/ — DID/VC-backed implementation

- Signing delegates to the registry's SignerService over ConnectRPC (KMS model);
  data is pre-hashed locally and only the `sha256:` digest crosses the wire.
- Stateless with respect to the chain: the predecessor arrives per call. One
  provider value implements both signer capabilities and may be shared across
  goroutines without locking.
- Verification resolves issuer DIDs via `resolver` and pre-hashes with
  SHA-256 to match the remote-signer convention.

These packages carry **no process semantics** — every process type that signs or
verifies uses them.
