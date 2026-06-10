# originsource — FirstDrop-Issuing Component

The Origin Source component type. Its **only definitional property** is emitting a new
FirstDrop VC (empty `previousCredential` — cuts the chain). Internal mechanics —
input cardinality, Pool/cache state, external lookups, aggregation logic — are
protocol-invisible and free for the implementation to choose.

## Origin commitments

A FirstDrop that derives from Pipeline-conformant sources commits to them:

- `derived_from` — the set of upstream Pipeline source DIDs (deduplicated; set
  equality with actual source issuers is verified at L2 audit)
- `source_root` — RFC 6962 Merkle root over the canonicalized wire bytes of the
  source VCs (`packages/merkle`)
- `source_root_canonical` — names the canonicalizer used for the leaves

External (non-Pipeline-conformant) inputs — files, API pulls, DB lookups, boundary
ecosystem VCs (SCITT / GAIA-X / …) — are **never** included in `derived_from` or
`source_root` leaves. Cryptographic linkage to external ecosystems is a separate
adapter-layer concern, expressed via separate metadata.

## Variants (reference-implementation naming, by input cardinality N)

| Variant | N | Internal mechanics | Status in this repo |
|---|---|---|---|
| `externalsource/` | 0 | Ingestion from outside the network (HTTP push / file / poll) | `apipush/` reference implementation |
| `enrichment/` | 1 | One Pipeline-conformant input joined with external lookups | Interface + conventions only |
| `aggregate/` | ≥ 1 | Pool + windowing / aggregation over Pipeline-conformant inputs | Interface + conventions only |

Variants are conventions, not Type Contract distinctions — at the protocol level there
is exactly one Origin Source type.
