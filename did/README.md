# did — did:dplaax Method

DID parsing, the DID Document model, semantic validation, and public-key extraction
for the `did:dplaax` method.

## Syntax

```
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath}]
```

- `registry` is a **domain name** (e.g. `poc.dplaax.io`); resolution URL derives from it
  (`https://{registry}/did/...`). Environment (PoC / production) is expressed here,
  never in the method name — W3C DID Core §3.1 restricts method names to `[a-z0-9]`.
- Hierarchy: Owner DID (no resource path) → Pipeline DID (`:pipeline:{id}`) →
  Process DID (`:pipeline:{id}:process:{id}`).

## Conventions

- **Parser is syntax-only.** Semantic classification lives in methods
  (`IsOwner` / `IsPipeline` / `IsProcess`); new resource types add a classifier method
  and a case in the known-pattern validator — the parser does not change.
- Every segment is validated against a safe-segment rule (`[a-zA-Z0-9._-]+`, no
  dot-only segments) so DID segments can be used to build storage paths without
  path-traversal risk. Consumers must still call the exported safety check before
  composing paths.
- **Public-key extraction from a DID Document lives here, once.** No consumer
  maintains its own copy (a known source of drift in the predecessor codebase).

## Planned contents

- `DID` type + `Parse` / classifier methods / validation
- `DIDDocument`, `VerificationMethod`, `ServiceEndpoint` models
- `ExtractPublicKey(doc, keyID)` — JWK (OKP/Ed25519) extraction with
  verification-relationship checks
