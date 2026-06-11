# observer — Process Event Observers

`ProcessObserver` implementations notified after each processed event
(`OnProcessComplete(ctx, ProcessEvent)`).

## Conventions

- Observers are **fire-and-forget**: failures are logged, never propagated into the
  processing path — observation must not affect pipeline outcomes.
- `logobserver/` — structured logging of event fields.
- `vcobserver/` — stores issued VCs (and verified ingress VCs) to the network's
  VCResolver service for audit reachability. Proto ↔ domain conversion here is
  guarded by a canonical-hash round-trip comparison: silent precision loss in the
  payload (`structpb` collapsing large integers) must fail loudly rather than ship a
  VC whose receiver-side canonicalization diverges from the issuer's.
- The ingress-VC store obligation (processes that verify must store what they
  verified) is satisfied by `vcobserver`'s ingress store.
