# pipeline/ — Pipeline Component Peer Catalog

A pipeline is a **graph composition of Pipeline Components**. The protocol defines
four peer component types — none is privileged; there is no "core" type and no
"outer" type:

| Type | Pipeline-conformant input | Output | VC chain behaviour | Definitional property |
|---|---|---|---|---|
| **FilterConvert** | 1 | 1 (or 0 when filtered) | Preserves chain (`previousCredential`) | Stateless 1:1 transformation |
| **Origin Source** | N ≥ 0 (free) | 1 | **Cuts the chain — emits a new FirstDrop** | FirstDrop issuance is the *only* definitional property |
| **External Sink** | 1 (or N) | 0 (outside world) | Chain terminates in-network | — |
| **Custom** | any | any | any | Conforms to the Pipeline Contract on ≥ 1 I/O side |

Stateful workloads (aggregate / join / window) belong in Origin Source — never in
FilterConvert, whose statelessness is definitional.

## Layout

```
contract/        Pipeline Contract — the public contract; external adapter repos
                 implement this. Custom components are expressed here (no dir).
filterconvert/   FilterConvert runtime (filter + converter steps, VC signing)
originsource/    Origin Source variants (externalsource / enrichment / aggregate)
externalsink/    External Sink (console reference implementation)
provenance/      shared mechanics: VC signing/verification providers
observer/        shared mechanics: process-event observers (log, VC store)
transport/       shared mechanics: pub-sub abstraction (NATS impl; Hub swap point)
```

Component-type directories are the **protocol position**; shared-mechanics packages
(`provenance/`, `observer/`, `transport/`) carry no component semantics. Whether a
given binary is an Origin Source or a chain-preserving forwarder is decided by its
signing path (FirstDrop vs carried `previousCredential`), not by its directory.

## Reference implementations vs extension adapters

This repository ships reference implementations only (`apipush`, `console`).
Vendor/ecosystem adapters (EDC, Kafka, SNS, …) live in **separate repositories**
implementing `contract/` — keeping that contract stable is this layer's primary
API obligation.
