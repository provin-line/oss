# externalsource — Origin Source Variant, N = 0

Ingestion from outside the pipeline network. No Pipeline-conformant input, therefore
no `derived_from` / `source_root` commitments — the emitted FirstDrop is a pure chain
origin.

## Reference implementation: apipush/

HTTP push endpoint (`POST /push`, JSON only, bounded body size) publishing to the
component's input queue, plus `GET /health`. Signing-path note: the PoC reference
implementation publishes raw payloads for a downstream FilterConvert chain head
configured with verification strategy `none`; a self-contained signing variant
(emitting the FirstDrop itself) conforms to `pipeline/contract` the same way.

Other external-source mechanics (file readers, schedulers/pollers, archive replay)
follow the same shape and may live here or in extension repositories.
