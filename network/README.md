# network/ — Registry & Coordination Server

The dplaax network services, exposed over ConnectRPC (h2c) by the node binary
(`cmd/standalone`, which also runs the pipeline data plane):

| Service | Responsibility |
|---|---|
| DIDService | `did:dplaax` lifecycle: owner registration, pipeline/process issuance, resolution |
| SignerService | KMS-model Ed25519 signing — private keys never leave this process |
| SchemaService | Immutable, append-only schema registry |
| ChainService | Operator-facing pipeline chain management (subscribe / allow-list) |
| ChainPeerService | Internet-facing cross-organization peer protocol (L2 wire-signed) |
| VCResolverService | Provenance-chain VC storage and async cross-registry resolution |

Plus raw HTTP: W3C DID resolution (`GET /did/.../did.json`), `GET /healthz`
(liveness, static), and `GET /readyz` (readiness — dependency-aware: evidence
store, broker connection when a data plane runs, external PDP reachability).

## State model: DB-free

All durable state is plain files under a configurable data dir: YAML for
control-plane records (DID documents, keys, schemas, subscriptions, allow-lists)
and a file-backed evidence dir for the VC store (credentials, resolution pool,
audit queue, verdicts — `vcresolver/filestore` + `auditor/filestore`). Nonce store
and infra-operator state are in-memory (PoC posture — restart implications are
documented per service). Storage sits behind a seam; swapping files for
PostgreSQL is a Hub-side replacement, not a fork.

For the VC store that seam is `vcresolver.VariantBackend`, DELIBERATELY below
the semantics: a backend places named bytes and reports whether a name was
taken, while identity, canonical validation, write-once admission and the
body-only projection are enforced once in `vcresolver.VariantStore`, which every
backend sits behind. So a new substrate implements six methods and inherits the
rules rather than re-promising them — and cannot weaken them by getting one
wrong. What a backend still owes is what only storage can: atomic create,
faithful read-back, and exhaustive listing.

Deployments in the audit-reachable conformance class (source commitments, see
[pipeline/source](../pipeline/source/README.md)) additionally require a
**durable** VC store: retrospective audits resolve claimed source credentials long
after issuance. The file-backed store the standalone node wires satisfies that
retention (subject to operational backup); the in-memory store
(`vcresolver/memstore`) is test scaffolding and satisfies only the plain PoC
posture.

## Two-layer authentication

- **L1 (operator-facing)**: per-RPC policy options (resource + action) enforced by
  `pkg/auth` — the PEP that wires the o3co authorization interceptors against a
  configured policy-verifier (PDP). Token issuance and the policy decision are
  external (the dPLaaX `auth.provider` / `auth.policy-verifier` services);
  `pkg/auth` itself decides no policy and verifies no JWT signature.
- **L2 (peer-facing)**: every ChainPeerService RPC carries an `AuthProof` — Ed25519
  signature over a JCS-canonicalized view, with nonce replay protection and a restart
  epoch barrier. Implemented in `pkg/services/chainmanager/wireauth`. **There is no
  auth-off mode for L2.** L2 is independent of the PDP — it needs no policy-verifier.

### PDP backends & the locus of authentication

L1 authorization is a three-way separation: **token issuance** (`auth.provider`),
the **decision** (the PDP), and **enforcement** (`pkg/auth`, in-process here). The
node only depends on a PDP, selected by `provin.network.auth.backend` — every
backend is fail-closed (missing required config → the node does not boot):

| backend | decision point | authenticates the caller? |
| --- | --- | --- |
| `o3co` (default) | external o3co `auth.policy-verifier` | **yes** — verifies the JWT |
| `opa` | external Open Policy Agent | yes, if the policy checks the token |
| `cedar` | external Cedar-agent | principal = the **raw bearer** (no JWT verification unless the policy adds it) |
| `static` | in-process allow-list | **no** — checks bearer *presence* only, never validity |

`static` is authorization, **not authentication**: use it only where the perimeter
already authenticates (single-tenant / dev), never where the PDP is expected to
identify the caller. See `pkg/auth/reference.conf` for the config surface and the
per-backend godoc.

For an authenticated self-host — a real `auth.provider` + real policy-verifier +
node + NATS in one command, walking a record to a `VERIFIED` audit verdict — see
[`deploy/quickstart/`](../deploy/quickstart/README.md). Its README also covers the
**first-owner bootstrap** (the chicken-and-egg where `RegisterOwner` is L1-gated
but the DID grant needs an already-registered owner) and its production options.

## Layout

```
cmd/standalone/   binary: config load, DI wiring, mux registration
config/           application.conf (operator layer)
pkg/core/         merged config model, secret resolution, SSRF-resistant URL checks
pkg/auth/         L1 JWT verification + authorization interceptor
pkg/services/     one package per service — see pkg/services/README.md
```
