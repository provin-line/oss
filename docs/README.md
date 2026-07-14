# docs/

| Directory | Contents |
|---|---|
| `architecture/` | [System overview](architecture/overview.md), [process peer catalog](architecture/processes.md), [deployment models](architecture/deployment.md) |
| `concepts/` | [Audit obligations](concepts/audit-obligations.md); provenance model, pipeline processing, and schema rules are *planned* (trust layers are introduced in the [overview](architecture/overview.md#trust-layers) meanwhile) |
| `protocol/` | [Service API surfaces](protocol/services.md) (incl. endpoint derivation), [auth spec L1/L2](protocol/auth.md) |
| `did/` | [`did:dplaax` method specification](did/method.md) |

[GLOSSARY.md](GLOSSARY.md) defines the term vocabulary. Definitions are
responsibility-based and never carry implementation values — concrete catalogs and
constants live in package contracts and the dPLaaX spec.

Docs state design intent. When code and docs diverge, fix one in the same PR that
creates the divergence — stale architecture docs were a recurring failure mode in the
predecessor project.
