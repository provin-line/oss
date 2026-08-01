# sink — Sink Process: Chain Termination

The Sink Process type: consumes pipeline output, verifies it, and writes
to the outside world. The VC chain terminates inside the network — a sink produces
no in-network output.

## Conventions

- Sinks verify the credential they consume (adjacent strategy — the immediately
  preceding credential) by default. A purpose-first Agent sink instead runs a
  synchronous full selected-chain appraisal and names its exact EvidenceView;
  the async audit runner remains a separate retrospective path. Sinks
  surface the verification verdict alongside the payload in whatever they emit
  externally.
- A sink never re-publishes to pipeline subjects; doing so would make it a
  Chained Process or Source Process in disguise. A receipt (below) is NOT an
  in-band re-publish: it goes to the local VC store + a dedicated tlog + the
  audit queue, never onto a chain subject.

## Sink kinds (deploy-layer attribute, `contract.SinkKind`)

| Kind | invalid emit | reject | issuer allow-list | receipt |
| --- | --- | --- | --- | --- |
| observation-only | MAY | not required | optional (unrestricted) | not required |
| production | PROHIBITED | MUST | MUST enforce (non-empty) | MAY |
| archival | PROHIBITED | MUST + audit log | MUST enforce (non-empty) | MUST |

A sink kind is a config-driven attribute of a deployed process, not a separate
process type. Idempotency checks on re-delivered events are a sink-side
obligation (production / archival).

**Issuer allow-list (local, not "mutual").** `sink.allow-issuers` matches a
consumed credential's issuer DID against segment-aware glob patterns
(`allowlist`, default-distrust). production/archival require a non-empty list
(an empty one denies everything — caught at boot). This is the consumer-side
half; the publisher-side half is the chainmanager subscription allow-list. Each
is its own local config — there is no spec-defined federation-layer negotiated
list yet (gap-backlog). Previous "mutual allow-list MUST" wording overstated a
mechanism the protocol has not defined.

**Receipt.** A receipt-issuing sink (`sink.receipt.issuer`, MAY for production /
MUST for archival) signs a `provin:sink-receipt` credential per consumed event —
chain-preserving over the consumed credential, `inputHash == outputHash` (it
transforms nothing). It is registered local-first (VC store → tlog → audit queue)
and only then optionally published remotely, so a receipt is never externally
visible without a local audit trail. Relying parties reach it via ResolveVC /
ListAuditStatuses / bundle export.

## Reference implementation: console/ (observation-only)

Subscribes to an output subject, verifies each received VC (signature / DID
resolution / schema axes), and writes one NDJSON record per event to stdout —
development and inspection tooling. Vendor sinks (EDC, warehouses, …) live in
extension repositories implementing `pipeline/contract`.

## Reference implementation: file/ (durable NDJSON stream)

The same line shape as `console/` (by construction — it embeds the console
writer over an append-mode file handle), delivered to a file a consumer can
tail without scraping process stdout. Selected per sink loop via
`sink.output { type = "file", path = ... }`; loops sharing one path share one
writer, so lines never interleave. Evidence-qualified records include their
EvidenceView inline. The writer uses an append syscall but no per-record
`fsync`; it proves process-level delivery, not power-loss durability.

## Evidence-qualified Agent delivery (opt-in)

A production or archival sink can enable the `agent-access` block. The runtime
then replaces the adjacent verdict as the delivery decision source with a
synchronous exact-view appraisal. It calls the writer only after the selected
origin-to-head spine verifies, the local versioned profile returns `ACCEPT`,
the issuer is admitted, and the actual payload bytes match the head
credential's `outputHash`.

```hocon
sink {
  kind = "production"
  verification-strategy = "adjacent"
  upstream-endpoint = "https://publisher.example"
  allow-issuers = ["did:dplaax:publisher.example:org:acme:pipeline:p:process:x"]
  agent-access {
    boundary-id = "provin-agent-delivery@1"
    decision-profile-id = "purpose-first-agent-access@1"
    required-scopes = ["LINEAR_ATTESTATION@1"]
  }
  output { type = "file", path = "/var/provin/agent-delivery.ndjson" }
}
```

The NDJSON record carries `evidenceView` and `delivery`. The latter binds the
payload digest, head `outputHash`, exact EvidenceViewID, local decision, and
boundary ID. Partial or unversioned configuration is a boot error. The shipped
profile rejects console output; embedders may inject a dedicated Agent writer
and must evaluate that writer's authentication and persistence separately.

The current selection policy is `projected-chain@1`: resolve each predecessor
body address to the local or explicitly declared upstream registry's projected
signed variant, verify the complete selection once, and fix every
`(BodyAddress, WireVariantID)` in the manifest. It does not enumerate all wire
variants or implement bounded-DAG/global-minimum selection.
