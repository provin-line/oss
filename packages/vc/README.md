# packages/vc — Verifiable Credentials (W3C Data Integrity)

The credential model, proof creation/verification, cryptosuite registry, and trust
policy for `PipelinePassCredential` — the VC issued at every pipeline process boundary.

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

## Chain & origin fields

- `previousCredential` — hash link to the predecessor VC (empty = FirstDrop).
- `derived_from` / `source_root` / `source_root_canonical` — Origin Source provenance
  (Merkle commitment over source VC wire bytes). Wired into builder AND verifier from
  the start (the predecessor left these spec-only — that gap is the first thing this
  PoC closes).

## Trust policy

- Verification confidence = weakest-link over axes (Signature / DID resolution / Schema).
- Allowlists: two-tier (per-pipeline overrides registry advisory), `nil` = inherit vs
  empty = deny-all distinction is load-bearing.
- Lifecycle phases: Unknown → Active → Deprecated (announcement-date grace) → Sunset.
  **Zero values fail closed.**
- No-op identifier ban (`""`, `"none"`, `"null"`, `"identity"`) at both allowlist
  construction and verification time (JOSE `alg:none` class defense).

## contexts/

JSON-LD context documents embedded at compile time (`go:embed`): W3C credentials v2,
dplaax VC v1, security data-integrity v2. Never fetched at runtime — verifier output
must be stable regardless of what upstream URLs serve.
