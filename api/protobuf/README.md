# api/protobuf — Protocol Definitions

Proto definitions for the dplaax protocol, managed with `buf`.

## Namespace

```
dplaax.did.v1       DIDService, SignerService + DID Document / delegation messages
dplaax.schema.v1    SchemaService (immutable, append-only registry)
dplaax.chain.v1     ChainService (operator) + ChainPeerService (internet-facing, L2-auth)
dplaax.vc.v1        VCResolverService (provenance chain resolution)
dplaax.pipeline.v1  transport messages only (PipelinePassCredential wire form, configs)
```

## Conventions

- Generated code is **committed** under `gen/` — contributors build without `buf`;
  regeneration is `make proto`.
- Authorization policy is declared on RPCs via method options (resource + action);
  the server-side interceptor enforces them (L1). `ChainPeerService` RPCs carry no L1
  policy — they authenticate exclusively via the embedded `AuthProof` message (L2
  wire-signing).
- Wire messages for VC bodies must round-trip through canonicalization without
  precision loss; conversions are guarded by canonical-hash comparison (see
  `canon`).
- `syntax = "proto3"` is a deliberate, normative choice in `dplaax.pipeline.v1`:
  the provin profile's empty/absent payload reasoning relies on proto3 implicit
  field presence. Migrating to editions changes presence semantics and is a
  profile discussion, not a tooling upgrade.
- The pipeline envelope carries the credential as its JSON document (bytes), not
  as a structured message: unknown signed-scope members must survive transport
  byte-faithfully at the canonical level, which field projection cannot honor.
