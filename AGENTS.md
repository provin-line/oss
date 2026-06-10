# AGENTS.md — Development Guidelines

Guidance for AI agents and contributors working on provin OSS.

## Project shape

- Go module: `github.com/provin-line/oss` (Go 1.25+)
- Protocol namespace: `dplaax` (proto packages `dplaax.*.v1`, DID method `did:dplaax`)
- Product namespace: `provin` (CLI, images)
- No database, anywhere. Persistent state is YAML files; ephemeral state is in-memory.

## Layer rules (enforced by review)

1. `packages/` is pure domain: no imports of `gen/`, `network/`, `pipeline/`, `cmd/`.
2. `network/` and `pipeline/` never import each other; they interact over the wire.
3. Every network service follows handler → service → store:
   - handler: proto ↔ domain conversion + Connect error mapping only
   - service: domain logic; no proto types
   - store: persistence behind an interface; no validation logic
4. Public surface (exported identifiers, package names, directory names, proto fields,
   CLI flags, config keys) is named for the layer's **responsibility**, not its current
   implementation.

## Wire-protocol integrity conventions

These exist because a cross-implementation hash divergence ("partition trap") breaks
verification silently — treat them as hard rules:

- JSON decoding on any protocol path goes through the strict decoder in
  `packages/canon` (duplicate-key rejection, trailing-data rejection, `UseNumber`).
  Direct `json.Unmarshal` on protocol paths requires a `decoder-hygiene-exempt`
  comment explaining why precision/duplicates cannot matter there.
- Integers above 2^53 must survive round-trips. Any proto/struct conversion that could
  lose precision must be guarded by a canonical-hash round-trip comparison.
- JSON-LD contexts are embedded at compile time, never fetched at runtime.
- Zero values fail closed (lifecycle phases, axis statuses, allowlists).

## Build & test

```
make build   # all binaries → dist/
make test    # go test ./...
make lint    # go vet + hygiene scripts
make proto   # regenerate gen/ (requires buf; generated code is committed)
```

## Out of scope for this repository

- Benchmarks (separate repository)
- Extension adapters — EDC, Kafka, SNS, etc. (separate repositories implementing
  `pipeline/contract`)
