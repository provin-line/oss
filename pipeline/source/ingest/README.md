# ingest — Source Process Mechanics: External Ingestion

Ingestion from outside the pipeline network. The trigger is never a
Pipeline-conformant predecessor event (HTTP push, file arrival, poll, or the arrival
of a non-conformant external credential), so per the trigger rule the emitted
credential is a FirstDrop — a pure chain origin.

**Boundary translation** is a special form of this mechanics: an external-ecosystem
credential (SCITT, GAIA-X, …) arrives, is validated by the adapter's own logic, and
is re-signed as a dplaax FirstDrop. Any linkage to the external credential is a
data-payload concern, never a credential field.

## External DID Source pattern

The DID-source flavor of boundary translation, as a contract. The trigger is the
arrival of a credential signed under a foreign DID method (`did:webvh`,
`did:web`, …). The ingesting process:

1. resolves the foreign DID and verifies the external credential's signature
   **at ingestion time** — the one point where a point-in-time resolution is
   structurally sufficient;
2. emits a FirstDrop whose **payload** carries the ingestion evidence under a
   registered ingestion schema (pinned by SchemaRef): the external credential
   (or its digest), the resolution material it was verified against, the
   verdict, and the verification time. Embedding the resolution material keeps
   the signature check re-runnable offline forever; what remains the ingester's
   accountable claim is that the material was authentically served at that time;
3. claims `provin:convert` (boundary translation's typical claim).

This is **accountable boundary translation, not audit continuation**: the chain
does not extend backwards, `derived_from` never names foreign issuers, and
responsibility for the external input terminates at the ingesting Owner
(audit.attribution.origin-default). "Which system did this enter from" is
answered by the ingestion schema's required fields — hash-bound payload,
schema-governed, not a credential field. Source methods with verifiable key
history (T2) make the attested verification independently re-checkable; T3
sources leave the document-authenticity claim resting on the ingester's
accountability (see DID method tiers in the glossary).

## Reference implementation: apipush/

HTTP push endpoint (`POST /push`, JSON only, bounded body size) publishing to the
process's input queue, plus `GET /health`. Signing-path note: the HTTP endpoint is
a transport adapter (a Subscriber) that publishes raw payloads to a downstream
**Source Process** runtime — the FirstDrop signer in [`ingest.go`](ingest.go),
which verifies nothing (`VerificationNone` is definitional for a Source) and signs
the bytes verbatim. A self-contained variant fusing the endpoint and the signer
into one process conforms to `pipeline/contract` the same way.

The signing runtime is **transform-free** by design: filter / convert / enrich is
the Chained Process's responsibility, so re-shaping for boundary translation is the
adapter's own logic *before* the bytes reach the signer (above). Letting a Source
transform would, by symmetry, do the same to the Sink and collapse the
Source / Chained / Sink distinction into a single do-everything process.

Other external-source mechanics (file readers, schedulers/pollers, archive replay)
follow the same shape and may live here or in extension repositories.
