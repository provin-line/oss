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
