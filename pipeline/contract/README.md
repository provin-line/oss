# pipeline/contract — The Pipeline Contract

The public contract every Pipeline Component conforms to on at least one I/O side.
**This is the package external adapter repositories import** — its stability
obligations are the strictest in the repository.

## What the contract covers

1. **I/O shape** — how a component consumes from and/or produces to the pipeline
   transport: the `Envelope` (credential + optional inline payload + sequence
   number) and subject conventions. **Normative semantics are hash-based**;
   whether the payload rides inline or by reference is a per-subscription
   transport choice — verification never depends on the delivery form.
2. **VC chain behaviour** — exactly one per output side:
   - *chain-preserving*: output VC carries `previousCredential` = hash of the input VC
     (FilterConvert; audit-reachable deployments additionally attach a source
     commitment over the full consumed set, the triggering predecessor included)
   - *FirstDrop issuance*: output VC has no `previousCredential` — a fresh chain
     origin (Origin Source: external ingestion or aggregation; input manifests are a
     data-payload concern; audit-reachable deployments additionally attach a source
     commitment — an audit attribute, not a parent link)
   - *termination*: consumes and verifies, produces nothing in-network (External Sink)
3. **Verification obligations on ingress** — which verification strategy a component
   must run before trusting input (none / adjacent / full), and the obligation to
   store verified ingress VCs for audit reachability.

## Method set (finalized)

- **`Component` is the only mandatory contract**: `Run` plus the declaration
  methods `ChainBehavior()` and `VerificationStrategy()`. One `Component` value
  represents exactly one pipeline output side (or a terminating consumer);
  multi-output Custom components compose one `Component` per side.
- **`Processor` is optional** — the contract for event-triggered processing,
  driven by a transport runtime loop (one input event, one `Result`). Mechanics
  that own their trigger (timer / window aggregation) implement `Component`
  directly. First-stage push ingestion is event-triggered (the push is the event).
- **Declarations are instance-level**: `ChainBehavior()` is intrinsic to the
  component type; `VerificationStrategy()` is fixed at construction (the same code
  may run as a chain head with `none` and mid-chain with `adjacent`) and scopes
  over Pipeline-conformant ingress sides only — a floor obligation applied
  uniformly; non-conformant input is unverifiable by definition.
- **`Result` invariants** (producing component, `StatusPassed`):
  `sha256(Payload) == outputHash`, and `Payload` is never empty (profile norm —
  empty and absent bytes are wire-identical in proto3; forbidding empty makes a
  missing payload on an inline subscription a decidable violation).
- **`Confidence` is a pointer on every `Result`**: nil = no verification ran —
  absence is a contract-layer concept, never a confidence-lattice state. For
  terminating components (sinks) it carries the whole verdict.

## Conventions

- Interfaces here are transport-agnostic and VC-implementation-agnostic: they depend
  on `vc` types and `pipeline/transport` abstractions only — never on NATS,
  never on `gen/`.
- A component that cannot satisfy a contract obligation must fail at startup, not
  degrade silently at runtime. Startup enforcement of the verification declaration
  splits in two: `strategy ≠ none ⇒ IngressVCStore configured` is self-contained;
  the legitimacy of a `none` declaration is checked against deploy wiring metadata.
- Versioning: breaking changes to this package require a major protocol discussion
  first — external repositories build against it.
