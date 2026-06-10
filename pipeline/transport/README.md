# transport — Pub-Sub Abstraction

The messaging boundary between Pipeline Components: `Publisher` / `Subscriber`
interfaces and the consume-process-publish runtime loop driving a component's
processor.

## Conventions

- This is the **Hub swap point** for the pub-sub backend: `nats/` (JetStream) is the
  OSS default; SQS/SNS and others replace it without touching component logic.
- Subject naming, credentials, and connection lifecycle (drain on shutdown,
  flush-after-subscribe) live here — components never import a broker client
  directly.
- The runtime loop is intentionally minimal: synchronous per-message processing,
  publish on "passed", drop-with-log on "filtered"/"error". Retry / dead-letter
  policies plug in at this seam, not inside components.
- Cross-organization wiring (imports/exports between accounts) is **not** this
  package's job — that belongs to the network chainmanager's `InfraOperator`.
