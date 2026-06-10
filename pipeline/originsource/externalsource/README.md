# externalsource — Origin Source Mechanics: External Ingestion

Ingestion from outside the pipeline network. The trigger is never a
Pipeline-conformant predecessor event (HTTP push, file arrival, poll, or the arrival
of a non-conformant external credential), so per the trigger rule the emitted
credential is a FirstDrop — a pure chain origin.

**Boundary translation** is a special form of this mechanics: an external-ecosystem
credential (SCITT, GAIA-X, …) arrives, is validated by the adapter's own logic, and
is re-signed as a dplaax FirstDrop. Any linkage to the external credential is a
data-payload concern, never a credential field.

## Reference implementation: apipush/

HTTP push endpoint (`POST /push`, JSON only, bounded body size) publishing to the
component's input queue, plus `GET /health`. Signing-path note: the PoC reference
implementation publishes raw payloads for a downstream FilterConvert chain head
configured with verification strategy `none`; a self-contained signing variant
(emitting the FirstDrop itself) conforms to `pipeline/contract` the same way.

Other external-source mechanics (file readers, schedulers/pollers, archive replay)
follow the same shape and may live here or in extension repositories.
