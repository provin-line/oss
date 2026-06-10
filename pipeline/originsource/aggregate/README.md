# aggregate — Origin Source Variant, N ≥ 1

Pool + windowing / aggregation logic over one or more Pipeline-conformant inputs
(possibly with different schemas), emitting a new FirstDrop with a new schema.

## Conventions

- This is where **stateful** pipeline workloads live (pool, window, join) —
  FilterConvert's statelessness is definitional, so aggregation can never migrate
  there.
- `derived_from` lists the deduplicated set of all upstream Pipeline source DIDs in
  the window; `source_root` commits to the full set of source VC wire bytes
  (order-independent — leaves are content-hash sorted).
- Ingress verification + ingress-VC storage obligations apply per consumed input.
- Pool/cache state is internal mechanics: protocol-invisible, implementation's choice
  (in-memory, embedded KV, …) — but it must not leak into the contract surface.

## Status

Interface + conventions only in this PoC phase. No reference implementation yet.
