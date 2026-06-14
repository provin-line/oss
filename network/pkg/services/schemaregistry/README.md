# schemaregistry — Immutable Schema Registry

Append-only registry of pipeline data schemas.

## Rules

- **Immutable + append-only**: a registered version never changes; deprecation is a
  soft flag that filters listings, never a deletion.
- Version is content-addressed and auto-assigned: `YYYY-MM-DD-{hash16}`, where
  `hash16` is the first 16 hex chars (64 bits) of a SHA-256 over a
  domain-separated `(format, body, prerelease)` encoding. The hash covers
  prerelease, so the version is a complete unique key and `prerelease` is
  listing/display metadata, not a separate key dimension.
- **No "latest" resolution, by design.** Pipelines pin exact versions; every VC embeds
  its `schema` reference (`name:version`). Implicit version drift between pipeline
  stages is the failure mode this rule exists to prevent.
- Schema bodies are compile-validated at registration (JsonSchema: strict-decode,
  Draft 2020-12, external `$ref` denied) so the registry never holds a schema a
  downstream validator would reject.
- `store/yamlstore/` lays out `{name}/{version}.yaml` under its root dir, with
  safe-segment path guards. The standalone binary roots it at `schemas/` under
  the data dir (so the deployed layout is `schemas/{name}/{version}.yaml`).
