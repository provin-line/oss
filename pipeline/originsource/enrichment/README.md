# enrichment — Origin Source Variant, N = 1

One Pipeline-conformant input joined with external lookups (DB / API), emitting a new
FirstDrop.

## Conventions

- `derived_from` contains exactly **one** upstream Pipeline source DID. External
  lookup targets are never included — they are not Pipeline-conformant signing
  entities.
- `source_root` commits to the single source VC's canonical wire bytes.
- The ingress side carries FilterConvert-equivalent verification obligations
  (verify + store the upstream VC before deriving from it).
- Boundary translation adapters (external ecosystem VC → dplaax FirstDrop) are a
  special form of this variant: the external VC is re-signed at the boundary and
  excluded from origin commitments.

## Status

Interface + conventions only in this PoC phase. No reference implementation yet.
