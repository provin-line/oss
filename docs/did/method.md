# The `did:dplaax` DID method

`did:dplaax` is the dPLaaX protocol's native DID method — the only method
admitted on the credential-issuance plane (owner, pipeline, and process
identities behind a `PipelinePassCredential`'s issuer). This document is
the method specification, structured after the W3C DID Core method
requirements. The implementation lives in
[`did/dplaax`](../../did/dplaax/) (grammar) and the DID registry service;
when this specification and the implementation diverge, one of them is
wrong and must be fixed in the same change.

**Status**: the method is served by PoC registries today. PoC-ness is
expressed in the **registry segment** (e.g.
`did:dplaax:poc.dplaax.dev:org:acme`), never in the method name, so
identifiers survive the PoC → production transition.

## Method name

`dplaax`.

## Method-specific identifier

### Syntax

```text
did:dplaax:{registry}:{accountType}:{accountId}[:{resourcePath…}]
```

- `{registry}` — the DNS name of the authoritative registry
  (e.g. `poc.dplaax.dev`). Resolution URLs derive from it.
- `{accountType}` — the account namespace; `org` is the only supported
  type today.
- `{accountId}` — the account identifier within the registry.
- `{resourcePath…}` — optional colon-separated resource segments.
  Two patterns are defined:
  - Pipeline: `…:pipeline:{pipelineId}`
  - Process: `…:pipeline:{pipelineId}:process:{processId}`

Every segment must satisfy the **safe-segment rule**: `[a-zA-Z0-9._-]+`,
and not composed solely of dots. The rule exists so DID-derived segments
can participate in storage paths without traversal risk; parsing fails
closed on any violation.

### Encoding, case, and normalization

- **Percent-encoding is rejected**, not normalized: `%` is outside the
  safe-segment alphabet, so an encoded identifier fails to parse.
- **Case is preserved**; no normalization is applied anywhere in the
  identifier. Note the consequence for the registry segment: it is used
  as a DNS name for resolution, and DNS is case-insensitive, so
  `did:dplaax:Example.com:…` and `did:dplaax:example.com:…` are
  *different DIDs* that resolve through the *same* host. Registries and
  issuers SHOULD use lowercase registry segments; relying parties MUST
  compare DIDs byte-for-byte (no case folding).

### Allocation and uniqueness

The registry named in the identifier is the allocation authority:

- `{accountId}` is unique within a registry — owner registration of an
  existing id with different content is rejected (exact re-submission is
  idempotent success).
- Pipeline and process ids are unique under their parent — issuance into
  a taken namespace slot is rejected.
- Global uniqueness therefore reduces to DNS uniqueness of the registry
  name.

## DID documents

Documents are integrity-protected JSON: the canonical (JCS) hash of the
document is recorded as a snapshot into the registry's **append-only
lifecycle log** at every lifecycle event. Documents preserve unknown
members across round-trips, so the recorded hash commits to members this
implementation does not model — a registry cannot silently substitute
document state without diverging from its own log.

- **Verification methods** — two encodings are read, selected by `type`,
  and the pairing is **exclusive**: `Multikey` ↔ `publicKeyMultibase`
  (multibase base58btc `z`, multicodec `ed25519-pub` 0xed01 + 32 key
  bytes) and `JsonWebKey2020` ↔ `publicKeyJwk`. A method carrying the
  encoding its type does not name, both encodings at once, or an unknown
  type is rejected. This read contract is part of the frozen credential
  wire (see CHANGELOG). Documents this registry issues use the JWK form;
  Multikey is the interop read path.
- **Key roles** — issued pipeline/process documents carry two
  verification methods: `#signing` (assertion — credential issuance) and
  `#auth` (authentication — L2 wireauth proofs).
- **Services** — documents may advertise per-subject service endpoints
  (`#vc-resolver`, `#audit`); the matching and derivation rules are
  specified in [protocol/services.md](../protocol/services.md#service-advertisements-and-endpoint-derivation).

## Operations

| Operation | Mechanism | Authorization |
| --- | --- | --- |
| Create (owner) | `RegisterOwner` with a complete, **self-signed** document — the proof demonstrates control of the document's own key | L1 policy + the document proof |
| Create (pipeline / process) | `IssuePipeline` / `IssueProcess`: the registry verifies an **owner-signed delegation credential** bound to exactly the target DID, requires the owner (and, for a process, the parent pipeline) to be active, then **generates** the `#auth`/`#signing` keypairs and assembles the document (`controller` = the structural parent) | L1 policy + delegation verification |
| Read / Resolve | `ResolveDID` RPC (L1) or the public resolution route (below) | open read on the public route |
| Update / key rotation | **Not supported.** There is no document-update or key-rotation operation | — |
| Recovery | **Not supported.** | — |
| Revoke | `UpdateStatus` with the single accepted status `revoked` — irreversible and idempotent; appends a `revoke` lifecycle event. A revoked owner can no longer mint pipelines/processes; a revoked pipeline can no longer parent processes | L1 policy (**no controller signature in the request** — the PDP is the authority) |
| Deactivate (W3C sense) | Not exposed as such — revocation is the only terminal state, and it does **not** alter or unpublish the document (see below) | — |

**Revocation discovery is the relying party's job**: public resolution
returns the stored document *without consulting lifecycle status*. A
relying party that needs liveness reads the **lifecycle log**
(`ReadLifecycleLog`): an append-only, hash-snapshot event sequence per
DID with two event types — `register` (owner registration and
pipeline/process issuance alike) and `revoke`. This is deliberate — the
document is evidence of what was registered; the log is evidence of what
happened to it.

## Resolution

Documents resolve over HTTPS from the registry named in the identifier:

```text
https://{registry}/did/{accountType}/{accountId}[/{resourcePath…}]/did.json
```

The path carries the segments **after** the registry (the host carries
the registry); path segments are joined with `/`. Example:

```text
did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1
→ https://poc.dplaax.dev/did/org/acme/pipeline/p1/did.json
```

The route is deliberately **unauthenticated** (W3C-style open read),
returns `application/did+json`, answers 400 for malformed DIDs and 404
for misses. Deployments may override the `https://{registry}` base
per registry (split horizons, private networks) — see
[deployment.md](../architecture/deployment.md#load-bearing-configuration).

### Response authenticity

A resolver's trust chain has three legs:

1. **Transport authority** — HTTPS to the registry host named in the DID
   (or an explicitly configured override base).
2. **Identity check** — the resolver MUST verify the returned document's
   `id` equals the requested DID (the reference resolver rejects
   mismatches).
3. **Historical consistency** — the document's JCS hash is snapshotted in
   the append-only lifecycle log, so substitution by a registry is
   detectable by anyone who reads the log — a registry that swaps
   documents diverges from its own published history.

## Security and privacy considerations

- **Operation authentication.** Owner creation proves key control via the
  self-signed document. Issuance proves owner intent via the delegation
  credential. Revocation, however, is authorized by the L1 policy layer
  (registry operation), not by a controller signature — a deployment's
  PDP policy is part of the method's trust base.
- **Registry compromise.** A compromised registry can serve fabricated
  documents for *new* DIDs and can revoke or refuse service; it cannot
  silently rewrite history that relying parties have already anchored —
  document hashes live in the append-only lifecycle log, and divergence
  is detectable. It CAN present different logs to different readers
  (no cross-registry witnessing in the PoC); treat the log as
  tamper-*evident*, not tamper-*proof*.
- **Replay / modification / deletion.** Resolution responses carry no
  freshness proof; a network attacker able to defeat HTTPS could replay
  an older (e.g. pre-revocation) document. Relying parties needing
  stronger guarantees must consult the lifecycle log over an independent
  channel.
- **Availability.** One registry serves each DID (single authority, PoC
  posture); its unavailability suspends resolution for its namespace.
- **Key rotation.** Unsupported: a compromised subject key cannot be
  rotated — the subject must be revoked and a new DID issued. Plan
  identifier lifecycles accordingly.
- **Correlation and exposure.** DIDs publicly expose organizational
  structure (org → pipelines → processes), and service advertisements
  expose endpoint URLs. Do not encode sensitive names into ids; use the
  split-horizon overrides where internal endpoints must not leak.

The repository-wide threat model and reporting process are SECURITY.md's
scope; this section covers only method-specific considerations.
