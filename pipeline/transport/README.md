# transport — Pub-Sub Abstraction

The messaging boundary between Pipeline Processes: `Publisher` / `Subscriber`
interfaces and the consume-process-publish runtime loop driving a process's
event processor.

## Conventions

- This is the **Hub swap point** for the pub-sub backend: `nats/` (JetStream) is the
  OSS default; SQS/SNS and others replace it without touching process logic.
- `envelopecodec/` is the wire codec for pipeline envelopes (the reference
  implementation of `contract.EnvelopeCodec`, over `dplaax.pipeline.v1`). It is
  stateless and subscription-agnostic: wire absence of the payload maps to nil
  (by-reference); whether absence is legitimate is decided by the layer that knows
  the subscription's agreed delivery mode, never by the codec. Fail-closed on empty
  inline payloads (marshal side) and on zero sequence numbers (both directions).
  Reversal condition for the codec-external mode check: if the runtime-loop work
  reveals no single layer knows the delivery mode, add a mode-aware wrapper as a
  pure addition — never push the check into this codec.
- Subject naming, credentials, and connection lifecycle (drain on shutdown,
  flush-after-subscribe) live here — processes never import a broker client
  directly.
- The runtime loop is intentionally minimal: synchronous per-message processing,
  publish on "passed" (producing processes only — a terminating process writes
  externally and publishes nothing), drop-with-log on "filtered"/"error".
  Retry / dead-letter policies plug in at this seam, not inside processes.
  `Loop` (in `loop.go`) implements `contract.Process` and drives one subscription:
  - **Sequence-on-success**: the publisher-assigned sequence number is advanced
    only after a successful `Publish` call; a failed publish reuses the same
    number on the next attempt, so in normal operation the publisher never
    creates a gap by its own failure. A gap in the subscriber's view is
    evidence to investigate — POSSIBLE LOSS (at-most-once transport, or a
    producer crash inside the emit window; see `Emitter`) — not an automatic
    foul-play verdict, and distinct from the worse signal of a repeated number
    with different content. Handlers are sequential per subscription
    (Subscriber contract), so reuse-on-failure is race-free without a mutex.
  - **Emission append-after-publish**: the emission log entry (credential hash +
    sequence number) is appended to the `tlog` *after* a successful `Publish`.
    `Append` receives a detached context (`context.WithoutCancel`) so that
    ctx cancellation at graceful shutdown cannot abort recording an event that
    has already been delivered. `Process` keeps the cancellable ctx — a stuck
    processor must remain interruptible. If `Append` fails the event was
    already delivered — the gap is the publisher's own audit-defense loss;
    the sequence counter still advances. A crash between `Publish` and
    `Append` creates an un-recorded delivery window (PoC posture — persistent
    WAL is the follow-up).
  - **sequenceNo encoding**: the sequence number in the emission record JSON is
    encoded as a string (`"1"`, not `1`) — survives IEEE-754 JSON consumers
    whose integer precision is limited to 2^53.
  - **In-memory sequence restart**: the counter resets to 1 on process restart,
    violating cross-restart monotonicity from a subscriber's view. Accepted PoC
    posture (same family as wireauth's in-memory nonce store); persistent
    sequence state is the follow-up.
  - **Sink loops**: a `ChainTerminating` loop publishes nothing; wiring a
    `Publisher`, `Codec`, or `Emission` to a sink is a misconfiguration
    (`ErrSinkWithPublisher`).
- Cross-organization wiring (imports/exports between accounts) is **not** this
  package's job — that belongs to the network chainmanager's `InfraOperator`.
- **Payload delivery modes**: inside their own organization, processes always
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
