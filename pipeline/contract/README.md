# pipeline/contract — The Pipeline Contract

The public contract every Pipeline Component conforms to on at least one I/O side.
**This is the package external adapter repositories import** — its stability
obligations are the strictest in the repository.

## What the contract covers

1. **I/O shape** — how a component consumes from and/or produces to the pipeline
   transport (message envelope, subject conventions).
2. **VC chain behaviour** — exactly one per output side:
   - *chain-preserving*: output VC carries `previousCredential` = hash of the input VC
     (FilterConvert)
   - *FirstDrop issuance*: output VC has no `previousCredential` — a fresh chain
     origin (Origin Source: external ingestion or aggregation; upstream references
     are a data-payload concern, never credential fields)
   - *termination*: consumes and verifies, produces nothing in-network (External Sink)
3. **Verification obligations on ingress** — which verification strategy a component
   must run before trusting input (none / adjacent / full), and the obligation to
   store verified ingress VCs for audit reachability.

## Conventions

- Interfaces here are transport-agnostic and VC-implementation-agnostic: they depend
  on `packages/vc` types and `pipeline/transport` abstractions only — never on NATS,
  never on `gen/`.
- A component that cannot satisfy a contract obligation must fail at startup, not
  degrade silently at runtime.
- Versioning: breaking changes to this package require a major protocol discussion
  first — external repositories build against it.
