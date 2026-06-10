# docs/

| Directory | Contents |
|---|---|
| `architecture/` | System overview, component peer catalog, deployment models |
| `concepts/` | Provenance model (L1/L2/L3 trust layers), pipeline processing, schema rules |
| `protocol/` | Service API specs (DID registry, ChainManager, VC resolver), auth spec (L1/L2) |
| `did/` | `did:dplaax` method specification |

[GLOSSARY.md](GLOSSARY.md) defines the term vocabulary. Definitions are
responsibility-based and never carry implementation values — concrete catalogs and
constants live in package contracts and the dPLaaX spec.

Docs state design intent. When code and docs diverge, fix one in the same PR that
creates the divergence — stale architecture docs were a recurring failure mode in the
predecessor project.
