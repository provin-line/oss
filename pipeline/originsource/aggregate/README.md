# aggregate — Origin Source Mechanics: Pool + Window

Pool + windowing / aggregation logic over one or more Pipeline-conformant inputs
(possibly with different schemas), emitting a new FirstDrop with a new schema.

## Conventions

- This is where **stateful** pipeline workloads live (pool, window, join) —
  FilterConvert's statelessness is definitional, so aggregation can never migrate
  there.
- The run is triggered by a timer / window expiry — never by a single predecessor
  event — so the output is a FirstDrop with `transformationClaim: "provin:aggregate"`
  (trigger rule). A run that happens to fold exactly one pending input is still a
  FirstDrop (batch-of-1 rule).
- Recording which inputs were used is optional and lives in the output payload as
  the aggregator's business logic; it is integrity-protected for free because
  outputHash = sha256(output) is bound by the issuer's signature. It is never a
  credential field (Paper 01 §4.8).
- Ingress verification + ingress-VC storage obligations apply per consumed input.
- Pool/cache state is internal mechanics: protocol-invisible, implementation's choice
  (in-memory, embedded KV, …) — but it must not leak into the contract surface.

## Accountability under audit

Cutting the chain does not create an accountability gap — it concentrates
accountability on the cutter, and post-hoc audits can still attribute upstream
responsibility:

1. **Liability default**: the FirstDrop is signed by the aggregator's Process DID
   and controller-chains to its Owner DID. An aggregator that records no source
   manifest owns the output's responsibility entirely; recording sources is how
   responsibility is shared, and a recorded manifest is tamper-evident
   (outputHash + signature).
2. **Fabrication is detectable**: manifest entries resolve to source VCs signed by
   their issuers; a fabricated source fails resolution or signature checks.
3. **Omission is detectable by reconciliation against adversarial records** the
   aggregator can neither edit nor delete: its own L2-signed RegisterSubscription
   records held by *publishers'* ChainManagers (non-repudiable), the publishers'
   append-only emission streams (sequence-numbered, signed), and the aggregator's
   ingress-VC store obligation. "Subscribed to B, received B's events, manifest
   says only A" is an auditable inconsistency pinned on the aggregator.

Preconditions: VC-resolver and emission records must be retained for the audit
horizon (a deployment obligation — the in-memory PoC stores do not satisfy it), and
accountability for non-federation inputs terminates at the ingesting owner.

## Status

Interface + conventions only in this PoC phase. No reference implementation yet.
