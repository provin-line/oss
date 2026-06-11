# sink — Sink Process: Chain Termination

The Sink Process type: consumes pipeline output, verifies it, and writes
to the outside world. The VC chain terminates inside the network — a sink produces
no in-network output.

## Conventions

- Sinks verify what they consume (typically full-chain strategy — the sink is the
  last in-network observer) and surface the verification verdict alongside the
  payload in whatever they emit externally.
- A sink never re-publishes to pipeline subjects; doing so would make it a
  Chained Process or Source Process in disguise.

## Sink kinds (deploy-layer attribute, `contract.SinkKind`)

| Kind | invalid emit | reject | mutual allow-list | receipt |
|---|---|---|---|---|
| observation-only | MAY | not required | relaxed | not required |
| production | PROHIBITED | MUST | MUST enforce | MAY |
| archival | PROHIBITED | MUST + audit log | MUST enforce | MUST |

A sink kind is a config-driven attribute of a deployed process, not a separate
process type. Idempotency checks on re-delivered events are a sink-side
obligation (production / archival).

## Reference implementation: console/ (observation-only)

Subscribes to an output subject, verifies each received VC (signature / DID
resolution / schema axes), and writes one NDJSON record per event to stdout —
development and inspection tooling. Vendor sinks (EDC, warehouses, …) live in
extension repositories implementing `pipeline/contract`.
