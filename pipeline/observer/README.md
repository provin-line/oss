# observer — Process Event Observers

`ProcessObserver` implementations notified after each processed event
(`OnProcessComplete(ctx, ProcessEvent)`).

## Status

The **extension point is live**: `contract.ProcessObserver` is defined, every
runtime (`ingest`, `aggregate`, `chained`, `sink`) carries an `Observers` config
field, and observers are invoked fire-and-forget after every outcome. The two
subpackages here are **planned, not yet implemented** (empty placeholders):

- `logobserver/` — (planned) structured logging of event fields.
- `vcobserver/` — (planned) a store-backed observer. The audit-critical storage
  paths ship WITHOUT it today: issued credentials are published to the network
  VC store by the data-plane wiring's VC-store client (`cmd/standalone`,
  `vc-store-endpoint`), and verified ingress credentials are persisted via
  `contract.IngressVCStore` — see below.

## Conventions

- Observers are **fire-and-forget**: failures are logged, never propagated into the
  processing path — observation must not affect pipeline outcomes.
- The ingress-VC store obligation (processes that verify must store what they
  verified) is a synchronous lifecycle obligation — `contract.IngressVCStore`,
  called between verification and transformation; a store failure fails the
  event. It is NOT an observer: only the observation events themselves are
  fire-and-forget.
