# schema — Payload Validation Against Registered Schemas

The client-side contract of the schema registry: `Validator` —
`Validate(ctx, payload, ref vc.SchemaRef) error`. A process's optional input
and output schema checks are both expressed with this one interface; injecting
no validator skips the check.

## Conventions

- Resolution of a `SchemaRef` (the content-addressed fetch of the schema
  document) is the implementation's concern, never the caller's.
- Implementations live in subpackages, mirroring `resolver/`:
  - `local/` — filesystem / embedded schema store (PoC fixtures, in-org
    deployments). Lands with the config/cmd wiring work.
  - a registry-backed client (SchemaService) lands with the network layer.
- The verifier-side resolve-and-compare obligation (`credential.schema-ref`)
  will share this package when the verifier work lands.

## Limits

The JSON Schema library is `internal/jsonschema`, a copy of
`santhosh-tekuri/jsonschema` with patches: a work budget, an error for a
number it cannot read where upstream panics, and compiling a schema in time
about linear in its size, its check against its metaschema within a work budget
(its README). Each refusal names the bound it hit.

This package does not bound a schema's size: its caller does, as the
network's schema registration does at 1 MiB (the bound of a document request).
The bounds below grow with the schema's size, and so does what a schema costs:
one of 1 MiB keeps at most about 170 MB once compiled, and the worst shapes
measured are compiled or refused in at most about 0.8 s (below).

- A number in a schema or a payload: at most 256 bytes, with its exponent part
  (after `e` or `E`) within ±400. The library reads numbers as exact rationals,
  at a cost that grows with the exponent: the budget charges it on a payload,
  and this bound keeps it small where a schema is compiled.
- A schema: nested at most 64 levels deep (each object, array and scalar is
  a level); at most 4,096 objects and booleans and one per 8 bytes of the
  schema, counted wherever they are (in a `default` or an example too: a
  `$ref` can make any of them a subschema); and its JSON pointers and URLs,
  summed, at most 2^16 bytes and 16 per byte of the schema: each value's
  pointer, counted as the library keeps it in a location, escaped for a
  URL, and each URL its ids and references resolve to (`$id`, draft-04's
  `id`, `$ref`, `$dynamicRef`, `$recursiveRef`), escaped. A reference by a
  pointer whose array index is not written as RFC 6901 writes one (`00`,
  `+0`, `-0`, `01`) is not found. It is checked against its metaschema
  within a work budget of 2^20 steps plus 16 per byte of the schema. The
  library's work per subschema grows with its depth, and it keeps a
  subschema of about 1 KB, with its pointer and location, for each object
  or boolean; a registered schema is kept compiled. Within these bounds a
  schema of 1 MiB keeps at most about 170 MB once compiled (the worst shapes
  measured keep 127 MB and compile in at most about 0.5 s; one the
  metaschema's budget refuses is refused in at most about 0.8 s). SchemaStore's
  schemas nest at most 23 deep, hold at most one object or boolean per 40
  bytes, their pointers and URLs come to at most 4.03 bytes per byte, and
  their metaschema checks need at most 11.5% of the budget.
- A payload: nested at most 512 levels deep. The library's work per step
  grows with nesting.
- A payload against a schema: validated within a work budget of 2^20 steps
  plus 16 per byte of the payload. A step is about one schema applied to one
  value, or one byte, property, item or value the library reads, compares or
  walks (`internal/jsonschema` states it). Two ordinary schemas took 1.0 and
  1.6 steps per byte (its `BenchmarkValidateWithBudget`); schemas layered on
  one value take more. A payload that needs more is refused, and so is one
  that would apply schemas within one another more than 10,000 deep (the
  library's `MaxNesting`). What the budget does not count (the work per step
  that grows with nesting, a format check beyond the string's length) is
  bounded by the depth bound above or by the string's length.

Nor does this package bound a payload's size: its caller does. A payload's
work budget grows with its size, and so does what a validation costs
(darwin/arm64, go1.27.1). Of the shapes measured, an ordinary schema accepts
a payload of 1 MiB in about 30 ms and one of 64 MiB in about 2 s; the
costliest, a pattern of about 8,192 instructions matched against each string
of an array, is refused at the budget in about 0.8 s for 1 MiB and 51 s for
64 MiB. A step takes at most about 112 ns (a step of matching such a
pattern; `schema/internal/schemadoc`), so the budget bounds the validation
itself at about 2 s for 1 MiB and 2 minutes for 64 MiB. Decoding the
payload, before the budget applies, takes time and memory that grow with its
size too: the heaviest shapes measured, a dense array of empty objects or of
zeros, take about 70 ms and hold about 40 MB at their peak for 1 MiB, and
about 5 s and 2.5 GB for 64 MiB.

None of the shipped binaries sets a `Validator` (`cmd/pipeline` builds its
loops through `pipeline/runtime`, which sets none): only a caller composing
`pipeline/chained` itself checks payloads against a schema, with a step's
`InputValidator` and `OutputValidator`. In that step:

- `InputValidator` checks a payload its `Codec` decoded inline, which
  `envelopecodec`'s `Limits.MaxInlinePayloadSize` bounds, or its
  `PayloadResolver` fetched by reference, which
  `network/pkg/services/payloadresolver/client` bounds by `Config.MaxBytes`
  (its `DefaultMaxBytes`, 64 MiB, when that is not set); another resolver
  bounds what it chooses to.
- `OutputValidator` checks the step's `Converter`'s output, which nothing in
  the pipeline bounds but that `Converter` (with none, it is the input
  payload).

Where a payload comes in, the shipped runtime takes these bounds from:

- `pipeline.max-push-body-size` (1 MiB by default): a body pushed over HTTP
  to a source loop, and a source loop's raw input over the transport;
- `pipeline.max-inline-payload-size` (1 MiB by default): an inline payload in
  an envelope a loop receives over the transport;
- by reference: the resolver's 64 MiB, which `cmd/pipeline` keeps.
