# aggregate — Source Process Mechanics: Pool + Window

Pool + windowing / aggregation logic over one or more Pipeline-conformant inputs
(possibly with different schemas), emitting a new FirstDrop with a new schema.

## Conventions

- This is where **stateful** pipeline workloads live (pool, window, join) —
  Chained Process's statelessness is definitional, so aggregation can never migrate
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
   and controller-chains to its Owner DID, and responsibility for everything
   preceding the cut defaults to that Owner — unconditionally (spec rule
   audit.attribution.origin-default). Recording sources never moves this
   default: a commitment proves what the cutter claims to have consumed, never
   that the claim is complete, so it cannot shed liability (an under-declared
   source set would otherwise launder it). What a recorded manifest
   (tamper-evident via outputHash + signature) buys is the means to continue an
   investigation upstream, where source issuers' own credentials make their
   transformations attributable in their own right.
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

The **signer capability** (slice-17k) and the **pool/window runtime** (slice-17l) have landed.
`aggregate.Process` is a `contract.Process` that pools verified ingress (per-input adjacent verify →
payload↔credential binding → `StoreIngressVC`, all fail-closed), and on each window tick folds the
pool via a pluggable `Fold` seam (`ManifestFold` is the reference), strict-JSON-gates the output,
and emits a `provin:aggregate` FirstDrop through `SignAggregateFirstDrop` + the shared
`transport.Emitter`. Dedup is by content address; empty windows are skipped. **Wiring has landed
too**: a config `aggregate` role + `buildAggregateProcess` in `pipeline/runtime`'s data plane
(`cmd/pipeline`), plus a NATS end-to-end test; `Config` takes injected `transport.Subscriber`s
so the runtime itself stays broker-free.
