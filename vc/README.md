# vc — Verifiable Credentials (W3C Data Integrity)

The credential model, proof creation/verification, cryptosuite registry, and
confidence evaluation (the three axes) for `PipelinePassCredential` — the VC issued at every pipeline process boundary.

## Core design: body-as-source-of-truth

The credential struct exposes **no data fields**. The canonical body map is the single
source of truth for both signing and hashing; reads go through accessors returning
defensive copies. Construction has exactly three paths: signed build, unsigned build
(tests/relay), and JSON unmarshal (verifier path). Unknown signed-scope fields survive
round-trips so future vocabulary additions participate in hashes without code changes.

(Rationale: the predecessor codebase shipped a dual-source bug where struct-field
mutation silently diverged from the signed body.)

## Proof algorithm

```
hashData = SHA-256(canon(proofConfig)) ‖ SHA-256(canon(document))
proofValue = base58btc("z" multibase) Ed25519 signature over hashData
```

Cryptosuites: `eddsa-jcs-2022` (Phase 1, MUST), `eddsa-rdfc-2022` (Phase 2, MAY).
New suites register in the dispatch table and must pass an **init-time IRI expansion
probe** — the binary panics at startup rather than serve broken canonicalization.

## Chain topology — linear invariant

- `previousCredential` is **singular**: the chain is strictly linear, never a DAG.
  Empty/absent marks a chain origin (FirstDrop): external ingestion or aggregation.
- Aggregation starts a fresh chain — normatively because the run is not triggered
  by a single conformant event (trigger rule); the rationale is that the result has
  no identity relationship with any single input (Paper 01 §4.8). The **base credential schema
  carries no upstream-reference fields** — input manifests are a data-payload /
  business-logic concern. The one sanctioned extension is the **source commitment**
  (`derived_from` / `source_root` / `source_root_canonical`): an optional audit
  attribute any credential carries under the **audit-reachable conformance class**
  (orthogonal to `previousCredential`; chain-preserving credentials commit to their
  full consumed set, predecessor included),
  riding the open signed body as profile vocabulary declared via the dplaax
  JSON-LD context (the wire names are pinned by the dPLaaX Origin Source
  specification — shared across profiles, so they are not renamed per profile).
  It is a content
  commitment over the consumed source set, not a parent link — chain topology stays
  strictly linear, and Paper 01 §4.8's exclusion (no upstream links in the chain, no
  upstream fields in the base schema) is preserved.
- The subject carries hashes, never the payload itself (Paper 01 §4.3): integrity is
  proven without embedding data in the credential.

## Trust evaluation

- Three-state domain per axis and overall: `failed ⊏ indeterminate ⊏ verified`,
  composed by greatest lower bound (weakest link). `failed` = inconsistency
  established; `indeterminate` = could not complete with current inputs (may resolve
  later). The distinction keeps verification deterministic across verifiers given the
  same snapshots.
- Axes: **Data integrity** (input/output binding + schema content-hash),
  **Signer authenticity** (signature + cryptosuite lifecycle at `proof.created`),
  **Chain consistency** (controller chain to the terminal Owner DID + ordering).
- Chain classification (orthogonal to confidence): `ChainOrigin` /
  `ChainSingleOwnerDerived` / `ChainMultiOwnerDerived` — who signed and how many
  trust boundaries were crossed, not how the data was produced.
- Lifecycle phases: Unknown → Active → Deprecated → Sunset, keyed on `proof.created`.
  **Zero values fail closed.** The published append-only form of the lifecycle policy
  (registry artifact vs service) is still being settled at the spec layer.
- No-op identifier ban (`""`, `"none"`, `"null"`, `"identity"`) at registration and
  verification time (JOSE `alg:none` class defense).
- Source-commitment checking (`VerifySourceCommitment`) is deliberately **outside the
  three normative axes** and the per-event path: it is an on-demand audit operation.
  Source credentials are gathered asynchronously (VC resolver, counterparties'
  stores); the verdict is `indeterminate` until the claimed set is fully resolved, so
  the hot path stays O(1) per boundary. The commitment proves claim integrity
  (tamper-evidence after issuance), never claim completeness — omission detection is
  an audit-layer reconciliation against ingress VC stores.

## contexts/

JSON-LD context documents embedded at compile time (`go:embed`): W3C credentials v2,
dplaax VC v1, security data-integrity v2. Never fetched at runtime — verifier output
must be stable regardless of what upstream URLs serve.
