# chainmanager — Pipeline Chain Connection Management

Control plane for all cross-pipeline connections. Required in every network. Serves
two distinct surfaces backed by one service:

| Surface | Service | Auth | RPCs |
|---|---|---|---|
| Operator-facing | ChainService | L1 JWT | Subscribe / Unsubscribe / ListSubscriptions / UpdateAllowList |
| Internet-facing | ChainPeerService | **L2 wireauth only** | GetPublisherInfo / RegisterSubscription / Disconnect |

## Connection flow (subscriber-initiated)

1. Operator calls `Subscribe` on the subscriber's chainmanager.
2. Subscriber CM resolves the publisher's DID Document (`#chain-manager` endpoint),
   validates the endpoint URL (SSRF guard), and calls `GetPublisherInfo`
   (light allow-list check + the publisher's offered payload-delivery modes)
   then `RegisterSubscription` (full allow-list + L2 signature; the signed view
   carries the requested payload-delivery mode, making the request
   non-repudiable — a mode the publisher does not offer is a typed rejection at
   this step, never a silent runtime fallback) on the publisher CM.
3. Both sides drive their `InfraOperator` to wire the transport
   (publisher: export; subscriber: import), applying the agreed
   payload-delivery mode at the export seam.

Allow-lists are DID glob patterns; trust model is default-distrust / opt-in.

Payload delivery (`inline` / `by-reference`, default `by-reference`) is agreed
per subscription and immutable for its lifetime — changing mode means a new
subscription. See the `Subscription` record contract (`store/`) and the
`Envelope` contract (`pipeline/contract`).

## infra/ — transport abstraction

`InfraOperator` (AddExport / RemoveExport / AddImport / RemoveImport / PublishType)
is the Hub swap point for the pub-sub backend. Implementations:

- `nats/` — dynamic NATS account-claims JWT management (requires full-resolver mode)
- `noop/` — debug/testing only; must be impossible to wire in non-debug builds

## wireauth/ — L2 peer authentication

Every ChainPeerService RPC carries an `AuthProof`: Ed25519 signature over a
JCS-canonicalized per-RPC view (op discriminator + view version + nonce + issuedAt +
business fields). Verification is an ordered pipeline — cheap fail-fast checks first,
signature verification late, nonce recorded **only after** signature success (a failed
forgery must not burn a legitimate signer's nonce):

1. missing-proof fail-fast → 2. issuedAt truncation → 3. restart epoch barrier →
4. acceptance window (asymmetric past/skew) → 5. key resolution via DID Document
(`#auth`, authentication relationship + controller match) → 6. signer-to-actor
authorization → 7. canonical-bytes rebuild → 8. Ed25519 verify → 9. nonce record.

**L2 identities and the audit horizon.** The signed view is access control at
the moment of the call, but the stored record doubles as audit evidence for the
audit horizon. When a deployment admits web-anchored DID methods for L2 parties
(e.g. did:web consumers), the CM records a snapshot of the resolved DID
document (the key binding) alongside the signed view in its tlog — the
signature stays re-verifiable against the snapshotted key forever, and the only
residual claim is that the binding was authentically served at registration
time. Methods with verifiable key history close that residue; audit-sensitive
deployments restrict L2 parties to T1/T2 (see DID method tiers in the
glossary).

In-memory nonce store + restart epoch barrier is the accepted PoC posture (persistent
nonce store is a documented follow-up). All wireauth failures are typed sentinel
errors; handlers map them with `errors.Is`.
