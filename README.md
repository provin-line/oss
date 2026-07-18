# provin OSS

Decentralized data pipeline engine — the **`provin` wire profile** (reference
implementation) of the **dPLaaX protocol**. Every data transformation is
cryptographically signed as a W3C Verifiable Credential, forming a linear provenance
chain that any participant can verify independently. DB-free, YAML-driven,
self-hostable.

Self-hosting a node means standing up its authorization layer too: the node is
fail-closed and needs a policy decision point (PDP). For an authenticated stack —
real `auth.provider` + policy-verifier + node + NATS in one command, driving a
record to a `VERIFIED` verdict — see [`deploy/quickstart/`](deploy/quickstart/README.md).
The PDP backend is pluggable (`o3co` | `opa` | `cedar` | `static`); `static` is an
authorization allow-list, **not authentication** (see
[network/README.md](network/README.md#pdp-backends--the-locus-of-authentication)).

> **Status: PoC skeleton.** Directory structure and per-layer conventions are in place;
> interfaces and implementations land incrementally.

## Naming

| Surface | Name | Where it appears |
|---|---|---|
| Protocol | `dplaax` | proto namespace (`dplaax.*.v1`), DID method (`did:dplaax`), JSON-LD context IRIs |
| Product | `provin` | this repository, CLI binary (`provin`), Docker images |

PoC-ness is expressed in the **registry segment** of DIDs (e.g.
`did:dplaax:poc.dplaax.dev:org:acme`), never in the method name — so provenance chains
survive the PoC → production transition.

## Layout

```text
api/protobuf/   protocol definitions (buf; namespace dplaax.*.v1)
gen/            generated code (committed — buf not required to build)
network/        registry & coordination services (control-plane library + handlers)
pipeline/       Pipeline Process peer catalog + shared mechanics
cmd/network/    network node binary (registry control plane only)
cmd/standalone/ all-in-one node binary (control plane + data plane) — deprecated;
                being replaced by cmd/network + the pipeline runtime
cmd/provin/     operator CLI
conformance/    provin profile conformance vectors + harness (test-only)
docs/           architecture / concepts / protocol / did
scripts/        lint hygiene checks (run by `make lint`)
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
| `did/` | DID domain: W3C document model, method dispatch (`MethodOf`); the `did:dplaax` method (T1) in `did/dplaax` |
| `canon/` | Canonicalization of signing scopes: JCS (RFC 8785), URDNA2015, strict JSON decoding |
| `vc/` | W3C VC Data Integrity: credential model, builder, verifier, cryptosuites, confidence axes |
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

## Pipeline Process model

A pipeline is a graph composition of four **peer** process types — none is privileged:

| Type | Definitional property |
|---|---|
| Chained Process | Stateless 1:1 transformation; preserves the VC chain |
| Source Process | Emits a new FirstDrop VC (cuts the chain) |
| Sink Process | Terminates the chain; writes to the outside world |
| Custom Process | Conforms to the Pipeline Contract on at least one I/O side |

See [pipeline/README.md](pipeline/README.md). Extension adapters live in **separate
repositories** and implement [pipeline/contract](pipeline/contract/).

## Stability and versioning

This repository is `0.x` ([SemVer](https://semver.org/spec/v2.0.0.html)); see
[CHANGELOG.md](CHANGELOG.md) for releases. Two surfaces have different
stability promises:

- **The v0 credential wire is frozen** — every byte that participates in a
  credential signature: the credential `@context` set (embedded,
  digest-pinned), the Data Integrity proof algorithm, both cryptosuites
  (`eddsa-jcs-2022` default, `eddsa-rdfc-2022` opt-in) and their
  canonicalizations, and the source-commitment form. Changing any of these
  breaks proof compatibility with already-issued credentials and is a
  next-MAJOR change. The freeze is enforced by tests (official W3C
  vc-di-eddsa vectors, KATs, context sha256 pins), not by process — see the
  freeze declaration in the CHANGELOG for the exact scope, including the
  signed views it deliberately does NOT cover (tlog checkpoints, wire-auth,
  lifecycle hashes).
- **Exported Go API and configuration keys** may still change between `0.x`
  minor releases. The first frozen API surface is declared at `1.0`, after
  the feature set is complete and has survived a real deployment soak.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
