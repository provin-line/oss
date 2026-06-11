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

## Registration & identity binding

Owner DIDs are issued by the federation registry named in the identifier
(`poc.dplaax.io` in the PoC). The verification bar for registration —
organization verification, the T1 property — is federation governance, not
protocol: presenting control of an outward identity such as `did:web` is a
natural input, but domain control alone is T3-grade evidence and does not
substitute for it.

When the applicant presents an outward DID at registration, the registry
records the binding and a snapshot of the resolved outward DID document in
its append-only lifecycle log. The Owner identity binding (see the glossary)
is then **registry-witnessed from birth** rather than self-asserted, and that
snapshot is the baseline auditors compare against to detect later domain
takeover. Binding addition, rotation, and loss of the outward domain are
lifecycle events recorded in the same log — addition and rotation snapshot
the newly resolved outward document, re-baselining the comparison; none of
them touch attribution.

Lifecycle-log recording is the registry's obligation; the PoC `didregistry`
stages it (per-record yamlstore today, the tlog substrate as the follow-up —
see `network/pkg/services/didregistry`).

The registry domain itself is the discovery mechanism, not the trust anchor:
verifiers ultimately rely on the registry's append-only log (signed
checkpoints), and chain verification never depends on a registry surviving —
chain links are content commitments.

## Conventions

- **Parser is syntax-only.** Semantic classification lives in methods
  (`IsOwner` / `IsPipeline` / `IsProcess`); new resource types add a classifier method
  and a case in the known-pattern validator — the parser does not change.
- Every segment is validated against a safe-segment rule (`[a-zA-Z0-9._-]+`, no
  dot-only segments) so DID segments can be used to build storage paths without
  path-traversal risk. Consumers must still call the exported safety check before
  composing paths.
