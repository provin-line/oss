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

The JSON Schema library (`santhosh-tekuri/jsonschema`) reads numbers as exact
rationals and does not bound its own work, so the checks here bound what they
hand it. Each refusal names the bound it hit.

- A number in a schema or a payload: at most 256 bytes, with its exponent part
  (after `e` or `E`) within ±400.
- A payload: nested at most 512 levels deep.
- A payload against a schema: its JSON values times the schema's `enum`
  entries and `const` values at most 2 000 000. A small payload may meet a
  large `enum`; a large one, a small `enum`.

These bounds cut some shapes of the library's work. They do not bound it for
every schema and payload, which needs a work budget inside the library; that
is planned, and its setting will replace them.
