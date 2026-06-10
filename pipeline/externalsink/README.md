# externalsink — Chain-Terminating Component

The External Sink component type: consumes pipeline output, verifies it, and writes
to the outside world. The VC chain terminates inside the network — a sink produces
no in-network output.

## Conventions

- Sinks verify what they consume (typically full-chain strategy — the sink is the
  last in-network observer) and surface the verification verdict alongside the
  payload in whatever they emit externally.
- A sink never re-publishes to pipeline subjects; doing so would make it a
  FilterConvert or Origin Source in disguise.

## Reference implementation: console/

Subscribes to an output subject, verifies each received VC (signature / DID
resolution / schema axes), and writes one NDJSON record per event to stdout —
development and inspection tooling. Vendor sinks (EDC, warehouses, …) live in
extension repositories implementing `pipeline/contract`.
