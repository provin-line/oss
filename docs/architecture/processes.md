# Process peer catalog

A pipeline is a graph composition of **Pipeline Processes** — four peer
types, none privileged. The normative definitions (the peer-type table and
the chain-behaviour **trigger rule**) live in
[pipeline/README.md](../../pipeline/README.md); this page is the
architecture view: what each type is *for*, what it signs, what it
verifies, and what it emits. Deployment wiring (which loops a node runs)
is configuration — see [deployment.md](deployment.md).

## Shared mechanics

Every process type composes the same building blocks
(`pipeline/contract` is the public contract; external adapters implement
it):

- **Envelope** — one event on the wire: the signed credential, the payload
  bytes (or none, in the stripped by-reference form), and the producer's
  sequence number.
- **Chain behaviour** — `FirstDrop` (a fresh chain origin) or
  `ChainPreserving` (`previousCredential` = the triggering predecessor's
  content hash). Decided by the **trigger rule**, not by what a process
  calls itself.
- **Verification strategy** — consuming processes verify the *adjacent*
  (immediately preceding) credential before acting; full-chain
  verification is the async audit runner's job
  ([overview.md — verification model](overview.md#verification-model)).
- **Payload delivery** — inline (payload in the envelope) or by-reference
  (payload dereferenced from the producer's serving boundary by the
  credential's declared `outputHash`). Either way the **binding gate** —
  sha256(payload) must equal the declared `outputHash` — is the sole
  integrity check tying bytes to credential.
- **Emission log** — every producer appends one record per emitted
  sequence number to an append-only log; sequence gaps are *evidence to
  investigate* (POSSIBLE LOSS), not automatic tamper verdicts.
- **Process observers** — fire-and-forget post-event notification
  (`contract.ProcessObserver`); observation can never affect a pipeline
  outcome.

## Chained Process

Stateless 1:1 transformation — statelessness is definitional; stateful
work belongs in a Source Process. Per event: verify the adjacent
credential **fail-closed** (only a Verified verdict proceeds — rejection
leniency belongs to sinks, never producing processes), store the ingress
credential (the audit trail precedes transformation), acquire and bind
the payload, transform (filter / converter steps), then sign
chain-preserving: the issued credential carries
`previousCredential` = the consumed credential's content hash. Filtered
events terminate quietly (no output, observable via observers).

## Source Process

Emitting a **FirstDrop** is the only definitional property: a Source cuts
the chain and starts a new one. Anything not triggered by the arrival of
exactly one Pipeline-conformant predecessor is a Source emission — timer,
window expiry, external push, poll (the trigger rule; see
pipeline/README.md for the batch-of-1 rule and the enrichment /
boundary-translation / aggregation classification).

Two reference mechanics ship in-repo:

- **Ingest** — zero Pipeline-conformant inputs; one *external* input per
  event in the push implementation (`POST /ingest/{loop}/push`,
  PDP-guarded, with a public readiness probe at
  `GET /ingest/{loop}/health`). The raw external record is signed as a
  FirstDrop attributed to the loop's process DID.
- **Aggregate** — N pooled inputs folded by a window/timer trigger. Each
  pooled input is adjacent-verified **before pooling** (fail-closed drop:
  nothing unverified, unbound, or unstored reaches the pool). The output
  is a FirstDrop carrying a **source commitment** over the full consumed
  conformant set — an audit attribute, not a parent link; the chain stays
  strictly linear. Where the audit substrate is configured, the aggregate
  self-audits at the emit locus: each emitted head is registered
  (store → receipt → audit queue) before broadcast.

## Sink Process

The in-network chain terminus: consumes, verifies, and hands the payload
to the outside world (console and file reference implementations ship
in-repo). The **sink kind** is the verdict policy, and leniency is a
property of one kind — not of sinks in general:

| Kind | Verdict policy | Obligations |
| --- | --- | --- |
| `observation-only` | writes regardless of verdict — inspection tooling MAY observe failed/indeterminate events | records the verdict with the output (the record must never read as verified when it wasn't) |
| `production` | fail-closed: only Verified is written | receipt issuance MAY be configured |
| `archival` | fail-closed: only Verified is written | receipt issuance MUST be configured, and every reject lands in a durable, hash-chained reject log |

Receipts are the sink-side audit anchor: a receipt-issuing sink registers
each receipt local-first (store → tlog → audit queue) before any optional
remote publish.

## Custom Process

Any input/output shape, expressed by implementing `pipeline/contract` on
at least one I/O side — there is no dedicated runtime directory, because
the contract *is* the extension surface. Vendor and ecosystem adapters
(EDC, Kafka, SNS, …) live in separate repositories; keeping the contract
stable is the pipeline layer's primary API obligation. Whether a custom
binary is a Source or a chain-preserving forwarder is decided by its
signing path (FirstDrop vs carried `previousCredential`), never by its
name.
