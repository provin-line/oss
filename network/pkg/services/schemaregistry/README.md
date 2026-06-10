# schemaregistry — Immutable Schema Registry

Append-only registry of pipeline data schemas.

## Rules

- **Immutable + append-only**: a registered version never changes; deprecation is a
  soft flag that filters listings, never a deletion.
- Version is content-addressed and auto-assigned: `YYYY-MM-DD-{sha256(format+body)[:6]}`.
- **No "latest" resolution, by design.** Pipelines pin exact versions; every VC embeds
  its `schema` reference (`name:version`). Implicit version drift between pipeline
  stages is the failure mode this rule exists to prevent.
- `store/yamlstore/` lays out `schemas/{name}/{version[-prerelease]}.yaml` with
  safe-segment path guards.
