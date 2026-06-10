# aggregate — Origin Source Mechanics: Pool + Window

Pool + windowing / aggregation logic over one or more Pipeline-conformant inputs
(possibly with different schemas), emitting a new FirstDrop with a new schema.

## Conventions

- This is where **stateful** pipeline workloads live (pool, window, join) —
  FilterConvert's statelessness is definitional, so aggregation can never migrate
  there.
- The run is triggered by a timer / window expiry — never by a single predecessor
  event — so the output is a FirstDrop with `transformationType: "aggregate"`
  (trigger rule). A run that happens to fold exactly one pending input is still a
  FirstDrop (batch-of-1 rule).
- Recording which inputs were used is optional and lives in the output payload as
  the aggregator's business logic; it is integrity-protected for free because
  outputHash = sha256(output) is bound by the issuer's signature. It is never a
  credential field (Paper 01 §4.8).
- Ingress verification + ingress-VC storage obligations apply per consumed input.
- Pool/cache state is internal mechanics: protocol-invisible, implementation's choice
  (in-memory, embedded KV, …) — but it must not leak into the contract surface.

## Status

Interface + conventions only in this PoC phase. No reference implementation yet.
