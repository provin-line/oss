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
- **A stream is checked when it opens, then at most every 5 seconds**: a
  unary RPC is checked once. A stream with a policy (today `RetainPayload`)
  is checked before its handler runs, and after that on a message sent or
  received at least 5 seconds after the last check began, not on every
  message. A permission withdrawn, or a token that expires, while a stream
  is open ends it at the first such message.
- **The locus of authentication varies by backend.** `o3co` verifies the
  JWT; `static` checks bearer *presence* only — it is an authorization
  allow-list, **not authentication**. Use `static` only where the
  perimeter already authenticates. See the backend table in
  network/README.md.
- **Fail-closed at boot**: for the external backends (`o3co` / `opa` /
  `cedar`) a missing or scheme-less PDP URL is a boot error, never an
  open server. `static` deliberately needs no PDP URL — its allow-list
  is in-process, and an empty allow-list is deny-all.
- **Plaintext PDP calls are opt-in**: `http://` to anything but loopback is
  refused unless the endpoint's `host:port` is listed in
  `provin.network.auth.plain-internal` (default empty). A listed endpoint is
  reached only at a private address.
- **`cedar` verifies the caller's JWT in the node**: a Cedar agent
  authenticates nothing, so `provin.network.auth.cedar.jwt.*` (issuer,
  audience, and exactly one of `jwks-url` / `secret`) is required, and the
  principal asked about is the verified token's `sub` (which must be non-empty).
  The token's `typ` must be the one RFC 9068 gives an access token, `at+jwt`
  or `application/at+jwt` (in any ASCII case), and it must carry `exp` and
  `iat`, the latter not ahead of the node's clock beyond the 30-second leeway.
  Other claims RFC 9068 lists, such as `jti` and `client_id`, are not required.
  The token must be a compact JWS in its one spelling, and its claims are read
  under the repository's strict JSON rules (no duplicate keys, valid Unicode,
  no keys of one object that differ only in case).
  The JWKS is cached 10 minutes and refetched at most every 30 seconds; while a
  refetch fails, the expired set still verifies known `kid`s for another 30
  minutes, so a withdrawn key can be trusted for up to 40 minutes during a JWKS
  outage (a token the set holds no key for is never accepted).
- **PDP outage is `Unavailable`, not a refusal of the caller**: when the PDP
  cannot answer (unreachable, timeout, HTTP 429/502/503/504) an L1-guarded RPC
  fails with ConnectRPC `Unavailable` (previously `Internal`), and the pipeline's
  push endpoint (`/ingest/<name>/…`) answers **503 with `Retry-After`**
  (previously 403). A PDP that answers badly (HTTP 500, malformed body) is still
  `Internal` / 403. Under the `cedar` backend a token that fails verification is
  `Unauthenticated` (push: 403, no wire retry), but a node that cannot fetch the
  issuer's key set has not judged the token, and reports `Unavailable` as well
  (push: 503 with `Retry-After`): the latest fetch failed, for whatever reason
  (unreachable, a TLS failure, past its 5-second timeout, any status but 200, or
  a body over 1 MiB or not a key set), and the node holds no set within its
  grace, or one with no key that fits the token (by `kid`, algorithm and use).
  A fetch that retrying does not fix (a 404, a certificate the node does not
  trust) is `Unavailable` too, unlike a PDP's HTTP 500: the Cedar endpoint lets
  the token check only refuse the token or report that it cannot answer. The
  node fetches again at most every 30 seconds, so a retry sooner than that gets
  the same answer. A token the set the latest fetch returned has no key for is
  `Unauthenticated`. A caller whose own context ends while the node waits for
  the key set gets `Canceled` / `DeadlineExceeded`, as on the other paths.
  Callers may retry `Unavailable` with backoff; the pipeline's
  own wire retry now retries L1-guarded RPCs through a PDP outage within its
  bounded budget.

## L2 — peer wire proof (wireauth)

L2 answers: *did this named peer really send this request?* It guards the
internet-facing, cross-organization surfaces (`ChainPeerService`,
`PayloadService`), which deliberately carry **no L1 interceptor**: peers
in different organizations share no token authority, so trust must ride
in the request itself. **There is no auth-off mode for L2.**

Each RPC carries a proof over the request it authenticates:

- an Ed25519 **signature over a canonical (JCS) view** of exactly
  `{signerDID, aud, op, v, nonce, issuedAt, fields}` — `v` is the view
  version (currently `2`), which the proof also carries (`view_version`),
  `aud` is the
  **audience**, the registry ID of the node the request is sent to,
  `issuedAt` is RFC 3339 at second precision, `op` is the RPC's view
  discriminator and `fields` its business object, both reconstructed by the
  verifier **from the request being served, never from the proof**. Binding
  `signerDID` into the signed bytes means a shared-key DID alias cannot
  reuse another DID's signature; binding `aud` means a proof made for one
  node does not verify at another;
- **the view version is checked first**: a node's verifier accepts only the
  versions it is configured to, by default the current one, and never
  version 1, which binds no audience; it refuses any other version before
  it resolves the signer, and rebuilds the view of the proof's version;
- **the audience is checked next**: a node's verifier accepts only a proof
  whose audience is exactly its own `provin.network.registry.id`. It checks
  this with the structural checks, before it resolves the signer, and
  rebuilds the view with its own registry ID, so a proof for another node
  spends no nonce there and a rewritten audience fails the signature. The
  check uses nothing of the request's URL or `Host`, so a node behind a
  proxy or under another name checks the same way;
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
- ordered verification: structural checks (the view version and the
  audience among them) → time bounds → key resolution → signature →
  authorization → nonce record **last**, so neither a forgery nor a proof
  for another node or another view version can burn a legitimate signer's
  nonce; the nonce store refuses a nonce that reaches it after the proof's
  expiry;
- an optional per-op **authorizer** (signer-to-actor policy) runs only
  after signature verification — it never sees unauthenticated input.

Four design decisions shape the proof; the code and its tests cite them by
these names:

- **D-w1 — the view binds the signer DID.** Two DIDs may list the same
  `#auth` key: an alias, or a DID document that names another party's key.
  Because `signerDID` is part of the signed bytes, a proof signed as one of
  them does not verify as the other (the unknown-key-share defense).
- **D-w10 — nonces are recorded per signer.** The nonce store's key is
  `(signerDID, nonce)`: a nonce means something only relative to its
  signer. Two signers that use the same nonce do not collide, and one
  signer cannot spend another's nonce by using it first.
- **D-w11 — the fields hold strings, booleans, `null`, and objects and
  arrays of those.** A number travels as a decimal string. A Go `int` and
  `float64` of the same value canonicalize to different bytes, and JCS
  number serialization is an interoperability hazard on a frozen
  cross-organization wire; fields without numbers have one byte form.
- **D-w12 — the view binds the audience.** A proof names the node it is
  for, by that node's registry ID, and the view binds it: a proof a node
  received does not verify at a node of another registry. A sender takes the
  audience from the same source as the endpoint:
  - a pipeline's own node (`vc-store-endpoint`): one audience for every
    proof the pipeline sends it, decided at start — the registry segment
    every DID it signs those proofs as shares, as a pipeline publishes to its
    own registry's node; signers of two registries keep it from starting
    unless `node-registry` names the node's registry;
  - a by-reference upstream (a loop's `upstream-endpoint`): the registry
    segment of the loop's upstream pipeline DID (`ingress-subject`, or an
    aggregate ingress's `subject`), whose node holds that pipeline's
    payloads;
  - a publisher's `#chain-manager` endpoint: the registry segment of the
    publisher DID, whose registry publishes that endpoint in the DID
    document. A registry's `#chain-manager` endpoint is served by that
    registry's node.

  The registry segment of a DID is its node's audience
  (`wireauth.AudienceForDID`). `node-registry` and `upstream-registry` name
  the registry where the node at that endpoint is another registry's. The
  sender pairs an endpoint with its audience; a wire proof does not authenticate that pairing, so an
  endpoint pointed at the wrong node hands that node a proof its paired node
  accepts while it is fresh
  ([deployment.md](../architecture/deployment.md#wire-proof-audience)).

D-w1, D-w10, D-w12, and that the nonce is recorded only after the signature
verifies, are checked against a Dolev-Yao attacker in the Tamarin model
`verification/tamarin/wireauth.spthy` (see
[verification/README.md](../../verification/README.md)).

A nonce is single-use **per verifier**. Two verifiers that share one
audience, each with a nonce store of its own, would each accept the same
proof once; so the L2 surfaces of one registry are served by **one network
process** ([deployment.md](../architecture/deployment.md#wire-proof-audience)).

Verified relationship mutations (subscription registration, disconnect)
additionally leave **relationship evidence**: the counterparty-signed
request, its audience, the view version it was verified under, and the
verifying key material are retained durably, so the relationship's
existence is provable later without trusting the peer
([audit-obligations](../concepts/audit-obligations.md); rotation:
[deployment.md](../architecture/deployment.md#evidence-log-rotation)). A
record of view version `1`, written before the view bound the audience, has
no audience and is re-verified against the version 1 view
`{signerDID, op, v, nonce, issuedAt, fields}`.

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
