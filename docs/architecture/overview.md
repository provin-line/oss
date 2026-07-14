# Architecture overview

provin is the reference implementation (**wire profile `provin`**) of the
**dPLaaX protocol**: a decentralized data-pipeline engine in which every data
transformation is signed as a W3C Verifiable Credential, forming a linear
provenance chain any participant can verify independently. This page is the
source of truth for the system's **planes and trust layers** — how the parts
relate and where trust comes from. For naming, repository layout, the
dependency-direction rule, and the library-package catalog, see the
[root README](../../README.md); for what runs where, see
[deployment.md](deployment.md).

## Two planes, one node

The `standalone` binary composes two planes over one configuration:

- **Control plane** — the registry and coordination services (DID registry,
  schema registry, signer, VC resolver, audit, tlog, chain manager), served
  as ConnectRPC handlers on one HTTP listener. State is DB-free: YAML
  records and append-only file logs under the data dir
  ([deployment.md — durable state](deployment.md#durable-state)).
- **Data plane** — zero or more **pipeline loops** (the process peer types
  in [processes.md](processes.md)) running over a shared NATS connection.
  Loops consume, transform, sign, and emit events; the control plane serves
  the evidence they produce (credentials, log checkpoints, audit verdicts).

A node with zero loops is a pure registry; a node with loops and no
registry role still needs a resolvable registry for verification. The
composition is config-driven — see the quickstart for a working topology.

## Trust layers

The auth stack separates three concerns; each layer answers a different
question and none substitutes for another
([network/README.md — two-layer authentication](../../network/README.md#two-layer-authentication)
is the enforcement catalog; [protocol/auth.md](../protocol/auth.md) is the
protocol view):

| Layer | Question | Mechanism |
| --- | --- | --- |
| **L1 — API access** | May this caller invoke this RPC? | bearer token + external policy decision point (PDP), enforced per-RPC by interceptors |
| **L2 — peer wire proof** | Did this named peer really send this request? | per-RPC Ed25519 signature over a canonical view, nonce replay defense, DID-resolved keys |
| **L3 — provenance** | Is this data's history authentic? | the credential chain itself: Data Integrity proofs, content-addressed links, transparency logs, audit verdicts |

The load-bearing property is **where L3's trust does NOT come from**: a
relying party verifying a provenance chain trusts signatures, content
hashes, and chain structure — not the transport that delivered them, and
not the L1/L2 session that happened to carry the bytes. That independence
claim is deliberately narrow: it covers **cryptographic provenance
verification** (credential signatures, content hashes, chain structure). It
does not extend to peer authorization, relationship evidence, payload
availability, or audit completeness — those depend on L2 and on the
operational evidence obligations in
[audit-obligations.md](../concepts/audit-obligations.md).

## Verification model

Real-time paths verify **adjacent** credentials only (the immediately
preceding link, fail-closed per process policy — see
[processes.md](processes.md)). Full-chain verification is deliberately
asynchronous: an audit runner assembles each consumed head's chain from the
local store and records a per-head verdict, served over the AuditService.
This keeps the relay path fast and makes audit coverage an inspectable,
durable record instead of an inline side effect.

## Where to go next

| Topic | Document |
| --- | --- |
| Process peer catalog (Chained / Source / Sink / Custom) | [processes.md](processes.md) |
| Deployment shapes, config traps, health, metrics | [deployment.md](deployment.md) |
| Service API surfaces and endpoint derivation | [../protocol/services.md](../protocol/services.md) |
| Auth layers L1/L2 in protocol terms | [../protocol/auth.md](../protocol/auth.md) |
| `did:dplaax` method specification | [../did/method.md](../did/method.md) |
| Evidence retention duties | [../concepts/audit-obligations.md](../concepts/audit-obligations.md) |
| Term vocabulary | [../GLOSSARY.md](../GLOSSARY.md) |
