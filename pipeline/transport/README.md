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
- **Payload delivery modes**: inside their own organization, components always
  produce the full (inline) envelope. The per-subscription agreed mode
  (`inline` / `by-reference` — see the `Envelope` contract and the chainmanager
  `Subscription` record) is applied at the cross-organization export seam,
  where each backend realizes it its own way (per-mode subjects / topics, or a
  stripping transform). Stripping the payload for by-reference delivery is
  one-way cheap; the reverse is impossible without a fetch.
- **Emission logging**: the publisher side records each published event
  (credential hash + sequence number) to a `tlog` log — the "what was
  delivered" record the audit reconciliation model depends on. The recorded
  identity is delivery-form-independent: the same event yields the same record
  whether it was delivered inline or by reference. Retention for the audit
  horizon is a deployment obligation.
