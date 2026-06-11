# tlog — Per-Organization Transparency Log

Append-only, tamper-evident, independently verifiable record sequences — the
persistence substrate of the audit model. No network-global log exists
(per-peer trust root): each organization hosts its own logs under its own DID.

## Why this is load-bearing

The post-hoc audit model attributes responsibility by reconciling records that
parties cannot edit or deny: emission streams, ingress receipts, subscription
registrations, VC bodies. All of that presumes the records still exist and
haven't been quietly rewritten. This package is that guarantee's contract.

## Contract design: production-grade contract, staged implementations

The contract includes everything a CT-style log needs — signed checkpoints
(non-repudiable log heads), and the optional `Prover` capability for
inclusion/consistency proofs. Implementations stage up **without contract
changes**:

| Stage | Implementation | Tamper evidence | Proofs |
|---|---|---|---|
| PoC | durable hash-chained file log | chain hash (replay to verify) | none (`Prover` not implemented) |
| Production | Merkle tree log (CT-style) | signed tree heads | inclusion + consistency via `Prover` |

Callers discover proof support by type assertion; auditors fall back to chain
replay when absent.

## Consumers

- Publisher emission logs (envelope hash + sequence number) — the "what was
  delivered" record in audit reconciliation
- Ingress receipt logs (verified ingress credentials)
- Persistent VC-store registration logs
- The cryptosuite lifecycle registry (`vc.LifecycleRegistry`) — the
  append-only `(id, phase, effective_date)` artifact each wire profile
  publishes

## Conventions

- Records are never mutated or deleted; retention for the audit horizon is a
  deployment obligation.
- Checkpoint signing uses the organization's keys via `crypto`
  (injected); the log never holds key material.
