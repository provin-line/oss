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

## Future receptacle

Cross-repo consumption of the protocol's own conformance vectors
(`dplaax.spec_draft` `vectors/`, 78 vectors) lands here when the harness
grows the families beyond the profile facts.
