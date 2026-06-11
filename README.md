# provin OSS

Decentralized data pipeline engine — the **`provin` wire profile** (reference
implementation) of the **dPLaaX protocol**. Every data transformation is
cryptographically signed as a W3C Verifiable Credential, forming a linear provenance
chain that any participant can verify independently. DB-free, YAML-driven,
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

```text
api/protobuf/   protocol definitions (buf; namespace dplaax.*.v1)
gen/            generated code (committed — buf not required to build)
network/        registry & coordination server (single binary)
pipeline/       Pipeline Component peer catalog + shared mechanics
cmd/provin/     operator CLI
docs/           architecture / concepts / protocol / did
scripts/        CI hygiene checks
```

The remaining top-level directories are the **library packages** — pure domain
libraries consumed by `network/`, `pipeline/`, and `cmd/` (see
[Library packages](#library-packages)).

## Dependency direction (strict, one-way)

```text
cmd/  network/  pipeline/          (consumers)
        │
        ▼
  library packages                 (pure domain; no proto, no internal deps)
        ▲
        │
      gen/  ◄── api/protobuf       (wire types; consumed by network/pipeline/cmd only)
```

Library packages never import `gen/`. `network/` and `pipeline/` never import each
other — they interact exclusively over the wire (ConnectRPC / NATS).

## Library packages

- **No internal dependencies**: no library package imports `gen/`, `network/`,
  `pipeline/`, or `cmd/`. Proto-generated types never appear here.
- **One-way consumption**: consumers depend on library packages; never the reverse.
- Interfaces here are the stable contracts of the system. Renaming or reshaping an
  exported identifier in this layer is a breaking change for every consumer.

| Package | Responsibility |
|---|---|
| `did/` | `did:dplaax` method: parsing, DID Document model, validation, public-key extraction |
| `canon/` | Canonicalization of signing scopes: JCS (RFC 8785), URDNA2015, strict JSON decoding |
| `vc/` | W3C VC Data Integrity: credential model, builder, verifier, cryptosuites, trust policy |
| `crypto/` | Key generation / signing / verification interfaces + Ed25519 implementation |
| `delegation/` | Owner-signed delegation credentials for Pipeline/Process DIDs |
| `resolver/` | DID Document resolution interface + local / grpc / multi implementations |
| `keystore/` | Private-key storage contract (KMS-model boundary) |
| `tlog/` | Per-organization transparency log: append-only, tamper-evident record sequences (audit substrate) |
| `hoconconfig/` | Three-layer HOCON configuration loader |
| `orgverify/` | DNS-based organization identity verification |

Internal dependency DAG (within the library layer):

```text
vc ──► did, canon, crypto
delegation ──► vc, did, crypto
resolver ──► did
orgverify ──► did, resolver
keystore ──► crypto
tlog ──► crypto
```

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
