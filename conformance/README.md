# conformance/ — provin profile conformance artifacts

Machine-checkable facts of the **provin wire profile**, pinned as data and
executed against this implementation by `go test ./conformance/`.

**Nothing in this directory is normative prose, and none of it restates a
norm.** The sources of truth are:

| Norm | Source of truth |
|---|---|
| dPLaaX protocol rules (claim grammar, grounding, open-world default, …) | `dplaax.spec_draft` rule catalog (`rules/` + `schemas/` + `vectors/`) |
| provin claim registry and per-claim semantics (closed / conformant-closed / open) | [vc/credential.go](../vc/credential.go) (`TransformationClaim` registry, doc comments) + [vc/README.md](../vc/README.md) |
| provin profile context document (byte-canonical) | [vc/contexts/provin-v1.jsonld](../vc/contexts/provin-v1.jsonld) |

## What the vectors pin

- `vectors/claim-*.json` — for each registry claim: the wire token is
  grammar-valid, the implementation emits it with exactly the profile's
  `@context` list, the grounding check accepts it, and its expansion is the
  pinned vocabulary IRI (claim identity = (grounding URL, label)).
- `vectors/context-001.json` — the byte ledger of the profile context
  document: its sha256, the prefix grounding it carries, and `@protected`.
  Changing the document bytes is a deliberate act; update the ledger in the
  same change or the harness fails.

Vector shape follows the `dplaax.spec_draft` vector conventions. The
`instantiates` field references the protocol rule ids a vector exercises —
informational, not a claim of membership in the protocol's vector set.

Per-claim *semantics* are declarations by the signer (accountability, not
machine-verified properties), so they are deliberately **absent** from the
vectors: duplicating them here would create a second source of truth.

## dplaax protocol vectors (vendored)

`vectors/dplaax/` vendors the protocol's own conformance vector catalog
(`dplaax.spec_draft` `vectors/`, 91 vectors as of 2026-07-02) byte-exact,
pinned by `MANIFEST.sha256`. The manifest test fails on any in-place edit —
adopting a spec change is a deliberate act: run
`scripts/sync-spec-vectors.sh` and commit the vendored diff.

**Tranche 1 — executed in CI** (`dplaax_test.go`), 65 vectors asserted across
the pure-function families (commitment-012 is loaded but skipped — see
tranche 2):

| family | driver |
|---|---|
| `canon-001..008` | `canon.NewStrictDecoder` + `jcs.Canonicalize` |
| `cred-001..029` | strict decode + `vc.PipelinePassCredential.ValidateWireForm` — the same single implementation the verifier's data-integrity axis delegates to |
| `commitment-001..011` | wire form / `VerifyChain` (all-consumed) / `NewSourceCommitment` + `ComputeSourceRoot` (construction) / `VerifySourceCommitment` (verification) |
| `chain-006..008` | `vc.Verifier.VerifyChain` — data-flow continuity on the DataIntegrity axis (fixtures carry synthetic proofs; the resolver-dependent axes are out of scope here) |
| `confidence-001..006` | `vc.EvaluateConfidence` (synthesis) / real `Verify` with an entries-driven lifecycle registry, effectiveDates time-shifted so the proof.created order relations are preserved |
| `delegation-001..005` | `delegation.Build` re-signing + `delegation.Verify` — structural defects (purpose, scope, foreign subject) are checked before the signature, so they survive the re-signing |
| `signer-001..003` | `vc.VerifyProof` mandatory-member / no-op gates; `vc.RegisterCryptosuite` registration gate |

**Tranche 2 — not yet executed** (behavior-fixture drivers to build):
`chain-001..005` (trigger classification — issuance behavior),
`process-001..006`, `audit-001..004` (attribution walker),
`registry-001..002` and `resolver-001..008` (store/sequence drivers), and
`commitment-012` (restart persistence — blocked on the durable-store epic).
