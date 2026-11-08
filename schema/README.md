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
`santhosh-tekuri/jsonschema` with a work budget added, and an error for a
number it cannot read where upstream panics (its README). Each
refusal names the bound it hit.

- A number in a schema or a payload: at most 256 bytes, with its exponent part
  (after `e` or `E`) within ±400. The library reads numbers as exact rationals,
  at a cost that grows with the exponent: the budget charges it on a payload,
  and this bound keeps it small where a schema is compiled.
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
