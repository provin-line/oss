# packages/ — Shared Library Layer

Pure domain libraries consumed by `network/`, `pipeline/`, and `cmd/`.

## Layer rules

- **No internal dependencies**: nothing under `packages/` imports `gen/`, `network/`,
  `pipeline/`, or `cmd/`. Proto-generated types never appear here.
- **One-way consumption**: consumers depend on `packages/`; never the reverse.
- Interfaces here are the stable contracts of the system. Renaming or reshaping an
  exported identifier in this layer is a breaking change for every consumer.

## Package map

| Package | Responsibility |
|---|---|
| `did/` | `did:dplaax` method: parsing, DID Document model, validation, public-key extraction |
| `canon/` | Canonicalization of signing scopes: JCS (RFC 8785), URDNA2015, strict JSON decoding |
| `merkle/` | RFC 6962 Merkle tree commitments (`source_root`) |
| `vc/` | W3C VC Data Integrity: credential model, builder, verifier, cryptosuites, trust policy |
| `crypto/` | Key generation / signing / verification interfaces + Ed25519 implementation |
| `delegation/` | Owner-signed delegation credentials for Pipeline/Process DIDs |
| `resolver/` | DID Document resolution interface + local / grpc / multi implementations |
| `keystore/` | Private-key storage contract (KMS-model boundary) |
| `hoconconfig/` | Three-layer HOCON configuration loader |
| `orgverify/` | DNS-based organization identity verification |

Internal dependency DAG (within `packages/`):

```
vc ──► did, canon, crypto, merkle
delegation ──► vc, did, crypto
resolver ──► did
orgverify ──► did, resolver
keystore ──► crypto
```
