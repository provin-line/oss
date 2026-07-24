# conformance/ — provin profile conformance artifacts

Machine-checkable facts of the **provin wire profile**, pinned as data and
executed against this implementation by `go test ./conformance/`.

**Nothing in this directory is normative prose, and none of it restates a
norm.** The sources of truth are:

| Norm | Source of truth |
|---|---|
| dPLaaX protocol rules (claim grammar, grounding, open-world default, …) | `dplaax.spec` rule catalog (`rules/` + `schemas/` + `vectors/`) |
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

Vector shape follows the `dplaax.spec` vector conventions. The
`instantiates` field references the protocol rule ids a vector exercises —
informational, not a claim of membership in the protocol's vector set.

Per-claim *semantics* are declarations by the signer (accountability, not
machine-verified properties), so they are deliberately **absent** from the
vectors: duplicating them here would create a second source of truth.

## dplaax protocol vectors (vendored)

`vectors/dplaax/` vendors the protocol's own conformance vector catalog
(`dplaax.spec` `vectors/`, whole corpus) byte-exact, pinned by
`MANIFEST.sha256`. The manifest test fails on any in-place edit — adopting a
spec change is a deliberate act: run `scripts/sync-spec-vectors.sh` and commit
the vendored diff.

### One entry point, a coverage guard

`TestDplaaxAllVectors` (`allvectors_test.go`) is the single CI-facing test. It
first proves the coverage ledger is complete against `MANIFEST.sha256` — every
vector has exactly one of a runner (`dplaaxRunners`) or a ledgered skip
(`dplaaxSkips`), and no ledger entry names a vector outside the manifest — then
runs each vector as a subtest. A vector synced in without a driver or a skip
reason turns the harness red: **silent partial coverage cannot survive.** The
completeness check (`checkCoverage`, pinned by `TestCheckCoverage`) reads only
the static maps and the manifest, so `-run 'TestDplaaxAllVectors/canon'` runs a
subset without spuriously failing the guard.

Run it: `make conformance`, or `go test ./conformance/ -run TestDplaaxAllVectors`.

### Coverage: 95 driven, 5 ledgered skips (100 total)

**Tranche 1** — pure-function families (runners in `dplaax_test.go`):

| family | driver |
|---|---|
| `canon-001..008` | `canon.NewStrictDecoder` + `jcs.Canonicalize` |
| `cred-001..032` | strict decode + `vc.PipelinePassCredential.ValidateWireForm` — the same single implementation the verifier's data-integrity axis delegates to |
| `commitment-001..011, 013` | wire form / `VerifyChain` (all-consumed) / `NewSourceCommitment` + `ComputeSourceRoot` (construction) / `VerifySourceCommitment` (verification) |
| `chain-006..008` | `vc.Verifier.VerifyChain` — data-flow continuity on the DataIntegrity axis (fixtures carry synthetic proofs; the resolver-dependent axes are out of scope here) |
| `confidence-001..006` | `vc.EvaluateConfidence` (synthesis) / real `Verify` with an entries-driven lifecycle registry, effectiveDates time-shifted so the proof.created order relations are preserved |
| `delegation-001..005` | `delegation.Build` re-signing + `delegation.Verify` — structural defects (purpose, scope, foreign subject) are checked before the signature, so they survive the re-signing |
| `signer-001..003` | `vc.VerifyProof` mandatory-member / no-op gates; `vc.RegisterCryptosuite` registration gate |

**Tranche 2** — behavior-fixture families driven against real seams
(`tranche2_test.go`):

| family | driver |
|---|---|
| `commitment-012` | `vcresolver/filestore` durable store: Put → new instance over same dir (restart) → Get resolves |
| `resolver-001..003, 008` | `vc.PipelinePassCredential.Hash` content-address (address form, immutability, base64url body) |
| `resolver-004..005, 009` | authority-scoped state→confidence mapping (resolver.states, P0-11): Unavailable and authoritative NotFound via `vc.Verifier` over a fake DID resolver (indeterminate / failed); non-authoritative NotFound via the real `auditor.ConsumeVerifier` (`ErrSourceNotFound` → indeterminate) |
| `registry-001..002` | `schemaregistry/store/yamlstore` append-only (O_EXCL) + deprecate-retains-body |
| `chain-001..005` | trigger↔`PreviousCredential` wire-shape invariant (no runtime classifier exists — see below) |
| `audit-001..004` | real `vc.Verifier.AttributeOwner` (exported P0-11) walking a resolver built from the vector's controller-binding fixture — per-segment attribution + origin default, cross-checked against the structural `did/dplaax.Parse().OwnerDID()` prefix |
| `process-004` | real `sink.Processor`: order-recording `Verifier`+`Writer` assert the sink verifies the received credential strictly before its external write (driven for both production and observation-only kinds — verify precedes write regardless of verdict policy) |
| `process-005..006` | receipt wire-form + `PreviousCredential` presence + the receipt identity shape (`transformationClaim == provin:sink-receipt`, `inputHash == outputHash`); Custom-origin must not carry `previousCredential` |

**Ledgered skips (5)** — visible via the guard, each with its own ground (not
a blanket family reason):

- `resolver-006` — structurally enforced (P0-11): `vcresolver.Store` exposes no
  eviction/delete surface, so the forbidden Resolved→NotFound transition is
  unconstructible — the API's absence is the enforcement, stronger than a
  behavioral test. The vector is retained as the shape pin should an eviction
  surface ever appear.
- `resolver-007` — reserved (P0-11): `resolver.batch.shape` binds any batch
  lookup surface an implementation or profile adds, without obligating one to
  exist; `dplaax.vc.v1` defines none. The vector pins the shape such a surface
  must satisfy.
- `process-001..003` — blocked: no process-type/behavior classifier seam (the
  four-type catalog is a static deployment attribute, not a callable classifier;
  recorded in the scope's gap-backlog).

Where a tranche-2 driver reconstructs a rule the implementation embodies
structurally rather than in a callable function (chain trigger classification —
the wire projection is the settled conformance obligation per
chain.trigger.retention's notes), the driver comment records it: the harness
pins the vectors against the real primitives it can reach.
