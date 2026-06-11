# dplaax — did:dplaax Method

The profile's T1 native DID method: parsing, the segment grammar, and
semantic validation. This is the **only method admitted on the
credential-issuance plane** — every Process / Pipeline / Owner DID behind a
`PipelinePassCredential`'s `issuer` is `did:dplaax`. The method-agnostic
DID Document model and dispatch live in the parent `did` package.

## Syntax

```text
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
