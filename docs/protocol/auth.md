# Auth layers (L1 / L2)

Two authentication layers guard the RPC surfaces, and a third layer — the
provenance chain itself — carries the data trust. Each answers a different
question; none substitutes for another
([overview — trust layers](../architecture/overview.md#trust-layers)).
This page is the protocol view: what each layer proves and what a
deployment must provide. The enforcement catalogs (interceptor wiring,
config keys, per-backend behavior) are owned by
[network/README.md](../../network/README.md#two-layer-authentication) and
[network/pkg/auth](../../network/pkg/auth/README.md).

## L1 — API access (bearer + PDP)

L1 answers: *may this caller invoke this RPC?* It is a three-way
separation:

| Role | Component | Notes |
| --- | --- | --- |
| Token issuance (authN) | external `auth.provider` | DID-grant OAuth; issues an identity JWT (`sub` = owner DID) |
| Decision (authZ) | external PDP | pluggable backend: `o3co` (default) \| `opa` \| `cedar` \| `static` |
| Enforcement (PEP) | in-process interceptors | read the per-RPC policy option (`resource` + `action`), call the PDP, allow/deny |

Facts a deployment must internalize:

- **Policy is declared per-RPC in the proto** (the `o3co.authz.v1.policy`
  method option). A descriptor test asserts every protected service
  annotates all its RPCs — an unprotected RPC fails the build, not the
  perimeter.
- **The locus of authentication varies by backend.** `o3co` verifies the
  JWT; `static` checks bearer *presence* only — it is an authorization
  allow-list, **not authentication**. Use `static` only where the
  perimeter already authenticates. See the backend table in
  network/README.md.
- **Fail-closed at boot**: for the external backends (`o3co` / `opa` /
  `cedar`) a missing or scheme-less PDP URL is a boot error, never an
  open server. `static` deliberately needs no PDP URL — its allow-list
  is in-process, and an empty allow-list is deny-all.

## L2 — peer wire proof (wireauth)

L2 answers: *did this named peer really send this request?* It guards the
internet-facing, cross-organization surfaces (`ChainPeerService`,
`PayloadService`), which deliberately carry **no L1 interceptor**: peers
in different organizations share no token authority, so trust must ride
in the request itself. **There is no auth-off mode for L2.**

Each RPC carries a proof over the request it authenticates:

- an Ed25519 **signature over a canonical (JCS) view** of exactly
  `{signerDID, op, v, nonce, issuedAt, fields}` — `v` is the frozen view
  version (currently `1`; any other version is rejected), `issuedAt` is
  RFC 3339 at second precision, `op` is the RPC's view discriminator and
  `fields` its business object, both reconstructed by the verifier
  **from the request being served, never from the proof**. Binding
  `signerDID` into the signed bytes means a shared-key DID alias cannot
  reuse another DID's signature;
- the signer's key is resolved **through the signer's DID document**
  (`#auth` verification method) — cross-registry, no pre-shared keys;
- **replay defense**: single-use nonces within an acceptance window
  (asymmetric clock-skew tolerance — larger toward the past than the
  future), plus a **restart epoch barrier** so an in-memory nonce store
  reset cannot re-admit pre-restart proofs (a guarantee that holds under a
  non-backward-stepping clock; a clock stepped back across a restart — NTP
  step, VM snapshot restore — can reopen the window, closed post-v0 with
  the durable nonce store below). Inside the boot window this
  barrier also rejects a *legitimate* fresh proof; the handler returns a
  **retryable `Unavailable`** (never a permanent `Unauthenticated`), and a
  conforming peer recovers by a bounded, re-signing retry. On retry-budget
  exhaustion — or a peer whose clock skew exceeds the budget — the racing
  call is dropped: an accepted PoC-posture residual loss, closed post-v0
  alongside a durable nonce store;
- ordered verification: structural checks → time bounds → key resolution
  → signature → authorization → nonce record **last**, so a forgery can
  never burn a legitimate signer's nonce;
- an optional per-op **authorizer** (signer-to-actor policy) runs only
  after signature verification — it never sees unauthenticated input.

Verified relationship mutations (subscription registration, disconnect)
additionally leave **relationship evidence**: the counterparty-signed
request and the verifying key material are retained durably, so the
relationship's existence is provable later without trusting the peer
([audit-obligations](../concepts/audit-obligations.md); rotation:
[deployment.md](../architecture/deployment.md#evidence-log-rotation)).

## How L3 relates

L1/L2 are transport trust; L3 — Data Integrity proofs, content-addressed
chain links, transparency logs, audit verdicts — is data trust. The
independence claim is precise: **cryptographic provenance verification**
(credential signatures, content hashes, chain structure) does not depend
on L1/L2 having been honest. What *does* depend on L2: peer
authorization, relationship evidence, by-reference payload availability,
and the completeness of what a given node ever received to audit. A
threat-model treatment of these surfaces is SECURITY.md's scope, not this
page's.
