# Service API surfaces

The protocol definitions (`api/protobuf/dplaax/*/v1`) are the normative RPC
contracts — per-RPC request/response shapes and their authorization policy
options live there and in the generated code. This page is the source of
truth for **responsibilities and relying-party contracts**: which surfaces
exist, how each is authenticated, and what a consumer may depend on.
Authentication layers themselves are specified in [auth.md](auth.md).

## HTTP surface

A provin node is two separately deployed binaries, each with its own HTTP
listener (`provin.network.core.listen-addr`); nothing below is ever served
on a shared listener. Gate legend: **L1** = bearer + PDP interceptors; **L2**
= per-RPC wireauth proof; **PDP** = L1-style decision on a raw-HTTP route;
**public** = deliberately unauthenticated.

### `cmd/network` (control plane)

| Surface | Gate | Responsibility |
| --- | --- | --- |
| `dplaax.schema.v1.SchemaService` | L1 | schema registration, retrieval, deprecation (content-hash-referenced JSON Schemas) |
| `dplaax.did.v1.DIDService` | L1 | `did:dplaax` lifecycle: owner registration, pipeline/process issuance, resolution, delegation reads, revocation, lifecycle-log reads |
| `dplaax.signer.v1.SignerService` | L1 | registry-held key signing (VC and raw) for DIDs whose keys the registry generated |
| `dplaax.vc.v1.VCResolverService` | L1 | content-addressed credential store: `StoreVC`, `ResolveVC`, exact variant fetch (`ResolveVariant`, `ListVariants`), successor listing |
| `dplaax.audit.v1.AuditService` | L1 | per-head audit verdicts (`GetAuditStatus`, `ListAuditStatuses`) and consumed-source receipts (`GetConsumedSources`) |
| `dplaax.tlog.v1.TlogService` | L1 | emission-log checkpoints and record reads (transparency-log exposure) |
| `dplaax.chain.v1.ChainService` | L1 | operator-side chain management: subscriptions, allow-lists |
| `dplaax.chain.v1.ChainPeerService` | **L2** | internet-facing peer coordination: publisher info, subscription registration, disconnect |
| `dplaax.payload.v1.PayloadService` | **L2** | internet-facing by-reference payload serving (`ResolvePayload`, streaming) |
| `GET /did/{accountType}/{accountId}[/{resourcePath…}]/did.json` | public | W3C-style DID resolution ([did/method.md](../did/method.md)) |

### `cmd/pipeline` (data plane)

| Surface | Gate | Responsibility |
| --- | --- | --- |
| `POST /ingest/{loop}/push` | PDP | HTTP push ingest into a push-enabled source loop |
| `GET /ingest/{loop}/health` | public | per-loop ingest readiness probe |
| `GET /healthz`, `GET /readyz` | public | liveness / readiness — owned by [deployment.md](../architecture/deployment.md#health-endpoints) |

### `cmd/network` also mounts

| Surface | Gate | Responsibility |
| --- | --- | --- |
| `GET /healthz`, `GET /readyz` | public | its own independent liveness / readiness instance, on its own listener |
| `GET /metrics` | public, **config-gated (default off)** | OpenTelemetry counters; mounted outside the service handler composition — owned by [deployment.md](../architecture/deployment.md#metrics). Not yet mounted by `cmd/pipeline` (tracked follow-up) |

Two structural facts a relying party may depend on:

- The two L2 surfaces carry **no L1 interceptor** — their trust is the
  per-RPC wireauth proof, so they work across organizations without a
  shared token authority ([auth.md](auth.md)).
- `/metrics` is never mounted by the service composition itself; it exists
  only when the deployment enables it.

## Service notes (what consumers may rely on)

- **DIDService / resolution route** — the RPC `ResolveDID` is L1-gated;
  the raw-HTTP route is the open-read W3C-style surface serving the same
  canonical document (`application/did+json`). Both serve the document
  as stored — **lifecycle status is not consulted on resolution**;
  revocation is discovered from the lifecycle log
  ([did/method.md — operations](../did/method.md#operations)).
- **VCResolverService** — content-addressed and immutable: a stored
  credential is retrievable by its content hash; `ListSuccessors` inverts
  `previousCredential` links known to this store. A store answers only
  for what it holds — absence is not global non-existence.

  One body may hold several **variants** — signed forms of the same claims —
  because re-issuing a proof leaves the body, and every `previousCredential`
  link to it, untouched. The set is append-only: admitting a variant never
  evicts another, so a later proof cannot displace an earlier one and an
  earlier one cannot exclude a later one. `ResolveVC` answers by body and is
  therefore **provisional**: it serves a deterministic choice over the
  variants held at that moment, and names which one it served — a different
  variant may win once the set grows. Anything that must reproduce a verdict
  fetches the exact bytes with `ResolveVariant`; equivalence is not identity
  when what is being checked is a signature.
- **AuditService** — verdicts are the *audit runner's* durable records:
  linear-chain confidence plus (for aggregate heads with local receipts) a
  distinct source-commitment verdict. A verdict names what was checked at
  a locus; it is not a global truth oracle.
- **TlogService** — serves signed checkpoints and records of the
  producer-side emission logs; consumers reconcile sequence coverage
  against delivery to bound loss claims.
- **SignerService** — signs only with registry-held keys (keys the
  registry generated for issued pipeline/process DIDs). Owner keys are
  client-held; the registry never sees them.
- **ChainPeerService / PayloadService** — the cross-organization seam.
  Registration/disconnect mutate durable relationship state and leave
  counterparty-signed relationship evidence; payload serving enforces
  allow-list admission on every fetch.

## Service advertisements and endpoint derivation

**Normative for the provin v0 profile.** These are operational routing
rules: they may evolve during 0.x with CHANGELOG notice and are **not**
part of the frozen credential wire (see the CHANGELOG's "v0 credential
wire freeze declaration").

A `did:dplaax` document may advertise per-subject service endpoints:

| Fragment | `type` | Advertises |
| --- | --- | --- |
| `#vc-resolver` | `VCResolver` | where this subject's issued credentials are resolvable (VCResolverService base URL) |
| `#audit` | `AuditService` | where audit verdicts/receipts for this subject's emissions are served |

**Matching rule (shared by all consumers):** a service entry matches only
when its `type` matches AND its `id` is exactly the fragment
(`#vc-resolver` / `#audit`) or exactly `{subjectDID}{fragment}`. An id
that is some *other* URI merely ending in the fragment is someone else's
identifier — it never matches, neither as a capture nor as ambiguity.
Two or more matches: **error** (ambiguity fails closed). Exactly one
match with an empty endpoint: **error** (a present advertisement must be
usable — no silent fallback past it).

**Derivation order per consumer:**

- **Bundle export (`provin bundle export`)** — for credentials:
  `--vc-resolver-base <registry>=<url>` override → advertisement
  (**required**: zero matches is an error). For audit receipts:
  `--audit-base <registry>=<url>` override → advertisement → legacy
  fallback (`--did-base` map, else `https://{registry}`). The asymmetry
  is deliberate: receipt routing predates the advertisement and documents
  issued before it must keep exporting.
- **Batch chain assembly (in-node predecessor resolution)** — the
  consumed credential's upstream hint first. Only a **connection error**
  falls through to the issuer's `#vc-resolver` advertisement (exactly one
  required; no CLI override, no registry fallback); a hinted store that
  *answers* NotFound is a miss — the entry is retried, not rerouted. An
  unresolvable issuer keeps the hole queued for the audit runner to
  bound.

The overrides are the **split-horizon seam**: an advertised URL is
canonical inside the emitting network and may be unreachable from
outside (the quickstart advertises `http://node:8443`; a host-run CLI
overrides with `--vc-resolver-base`/`--audit-base` to
`http://localhost:8443`).

## Freeze boundary

The **credential Data Integrity wire** (contexts, proof algorithm,
canonicalization, source-commitment form, verification-method read
contracts) is frozen and test-enforced — see CHANGELOG. Everything on
this page — RPC surfaces, routing, derivation order, metric names — is
the **operational surface**: stable names, 0.x-mutable with CHANGELOG
notice.
