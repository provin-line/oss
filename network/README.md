# network/ — Registry & Coordination Server

A single standalone binary (`network/cmd/standalone`) exposing the dplaax network
services over ConnectRPC (h2c):

| Service | Responsibility |
|---|---|
| DIDService | `did:dplaax` lifecycle: owner registration, pipeline/process issuance, resolution |
| SignerService | KMS-model Ed25519 signing — private keys never leave this process |
| SchemaService | Immutable, append-only schema registry |
| ChainService | Operator-facing pipeline chain management (subscribe / allow-list) |
| ChainPeerService | Internet-facing cross-organization peer protocol (L2 wire-signed) |
| VCResolverService | Provenance-chain VC storage and async cross-registry resolution |

Plus raw HTTP: W3C DID resolution (`GET /did/.../did.json`) and `GET /healthz`.

## State model: DB-free

All durable state is YAML files under a configurable data dir (DID documents, keys,
schemas, subscriptions, allow-lists). VC store, nonce store, and infra-operator state
are in-memory (PoC posture — restart implications are documented per service).
Storage sits behind store interfaces; swapping YAML for PostgreSQL is a Hub-side
replacement, not a fork.

Deployments in the audit-reachable conformance class (source commitments, see
[pipeline/source](../pipeline/source/README.md)) additionally require a
**durable** VC store: retrospective audits resolve claimed source credentials long
after issuance, and an in-memory store cannot honor that retention. The in-memory
store satisfies only the plain PoC posture.

## Two-layer authentication

- **L1 (operator-facing)**: per-RPC policy options (resource + action) enforced by
  `pkg/auth` — the PEP that wires the o3co authorization interceptors against a
  configured policy-verifier (PDP). Token issuance and the policy decision are
  external (the dPLaaX `auth.provider` / `auth.policy-verifier` services);
  `pkg/auth` itself decides no policy and verifies no JWT signature.
- **L2 (peer-facing)**: every ChainPeerService RPC carries an `AuthProof` — Ed25519
  signature over a JCS-canonicalized view, with nonce replay protection and a restart
  epoch barrier. Implemented in `pkg/services/chainmanager/wireauth`. **There is no
  auth-off mode for L2.**

## Layout

```
cmd/standalone/   binary: config load, DI wiring, mux registration
config/           application.conf (operator layer)
pkg/core/         merged config model, secret resolution, SSRF-resistant URL checks
pkg/auth/         L1 JWT verification + authorization interceptor
pkg/services/     one package per service — see pkg/services/README.md
```
