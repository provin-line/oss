# provin OSS

Decentralized data pipeline engine implementing the **dplaax protocol** — every data
transformation is cryptographically signed as a W3C Verifiable Credential, forming a
provenance chain that any participant can verify independently. DB-free, YAML-driven,
self-hostable.

> **Status: PoC skeleton.** Directory structure and per-layer conventions are in place;
> interfaces and implementations land incrementally.

## Naming

| Surface | Name | Where it appears |
|---|---|---|
| Protocol | `dplaax` | proto namespace (`dplaax.*.v1`), DID method (`did:dplaax`), JSON-LD context IRIs |
| Product | `provin` | this repository, CLI binary (`provin`), Docker images |

PoC-ness is expressed in the **registry segment** of DIDs (e.g.
`did:dplaax:poc.dplaax.io:org:acme`), never in the method name — so provenance chains
survive the PoC → production transition.

## Layout

```
api/protobuf/   protocol definitions (buf; namespace dplaax.*.v1)
gen/            generated code (committed — buf not required to build)
packages/       shared libraries (pure domain; depends on nothing else in this repo)
network/        registry & coordination server (single binary)
pipeline/       Pipeline Component peer catalog + shared mechanics
cmd/provin/     operator CLI
docs/           architecture / concepts / protocol / did
scripts/        CI hygiene checks
```

## Dependency direction (strict, one-way)

```
cmd/  network/  pipeline/          (consumers)
        │
        ▼
    packages/                      (pure domain; no proto, no internal deps)
        ▲
        │
      gen/  ◄── api/protobuf       (wire types; consumed by network/pipeline/cmd only)
```

`packages/` never imports `gen/`. `network/` and `pipeline/` never import each other —
they interact exclusively over the wire (ConnectRPC / NATS).

## Pipeline Component model

A pipeline is a graph composition of four **peer** component types — none is privileged:

| Type | Definitional property |
|---|---|
| FilterConvert | Stateless 1:1 transformation; preserves the VC chain |
| Origin Source | Emits a new FirstDrop VC (cuts the chain) |
| External Sink | Terminates the chain; writes to the outside world |
| Custom | Conforms to the Pipeline Contract on at least one I/O side |

See [pipeline/README.md](pipeline/README.md). Extension adapters live in **separate
repositories** and implement [pipeline/contract](pipeline/contract/).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
