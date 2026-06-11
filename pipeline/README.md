# pipeline/ — Pipeline Process Peer Catalog

A pipeline is a **graph composition of Pipeline Processes**. The protocol defines
four peer process types — none is privileged; there is no "core" type and no
"outer" type:

| Type | Pipeline-conformant input | Output | VC chain behaviour | Definitional property |
|---|---|---|---|---|
| **Chained Process** | 1 | 1 (or 0 when filtered) | Preserves chain (`previousCredential`) | Stateless 1:1 transformation |
| **Source Process** | N ≥ 0 (free) | 1 | **Cuts the chain — emits a new FirstDrop** | FirstDrop issuance is the *only* definitional property |
| **Sink Process** | 1 (or N) | 0 (outside world) | Chain terminates in-network | — |
| **Custom Process** | any | any | any | Conforms to the Pipeline Contract on ≥ 1 I/O side |

Stateful workloads (aggregate / join / window) belong in Source Process — never in
Chained Process, whose statelessness is definitional.

## Chain behaviour criterion — the trigger rule (provin wire profile, normative)

A boundary's output is **chain-preserving** iff its execution was triggered by the
arrival of exactly one Pipeline-conformant predecessor event (`previousCredential` =
that event's credential). Any other trigger — timer, window expiry, user/external
push, poll, arrival of a non-conformant external credential — yields a **FirstDrop**.

- Decidability over cleverness: a non-event-triggered run that happens to consume a
  single pending input is still a FirstDrop (the batch-of-1 rule).
- Fan-out is permitted: linearity constrains each credential to one predecessor,
  not one successor — chains may branch forward.
- Any credential MAY carry a source commitment (the audit-reachable conformance
  class — see [source/README.md](source/README.md)): an audit
  attribute over the full consumed conformant source set, not a parent link.
  Orthogonal to `previousCredential` — a chain-preserving credential's committed
  set includes the triggering predecessor (all-consumed semantics). Trigger
  semantics and linearity are unaffected.

| Term | Operation | Trigger | Chain |
|---|---|---|---|
| **Enrichment** | side-fetch external data joined onto the triggering event | predecessor event | preserved (`provin:enrich`) |
| **Boundary translation** | re-sign an external-ecosystem credential (SCITT, …) as a dplaax credential | non-conformant credential arrival | FirstDrop |
| **Aggregation** | fold N pooled inputs into one output | timer / window | FirstDrop (`aggregate`) |

## Layout

```
contract/        Pipeline Contract — the public contract; external adapter repos
                 implement this. Custom Processes are expressed here (no dir).
chained/         Chained Process runtime (filter + converter steps, VC signing)
source/          Source Process mechanics (ingest/ + aggregate/)
sink/            Sink Process (console reference implementation)
provenance/      shared mechanics: VC signing/verification providers
observer/        shared mechanics: process-event observers (log, VC store)
transport/       shared mechanics: pub-sub abstraction (NATS impl; Hub swap point)
```

Process-type directories are the **protocol position**; shared-mechanics packages
(`provenance/`, `observer/`, `transport/`) carry no process semantics. Whether a
given binary is a Source Process or a chain-preserving forwarder is decided by its
signing path (FirstDrop vs carried `previousCredential`), not by its directory.

## Reference implementations vs extension adapters

This repository ships reference implementations only (`apipush`, `console`).
Vendor/ecosystem adapters (EDC, Kafka, SNS, …) live in **separate repositories**
implementing `contract/` — keeping that contract stable is this layer's primary
API obligation.
