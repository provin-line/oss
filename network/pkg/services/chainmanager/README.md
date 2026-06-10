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
   (light allow-list check) then `RegisterSubscription` (full allow-list + L2
   signature) on the publisher CM.
3. Both sides drive their `InfraOperator` to wire the transport
   (publisher: export; subscriber: import).

Allow-lists are DID glob patterns; trust model is default-distrust / opt-in.

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
(`#auth-key`, authentication relationship + controller match) → 6. signer-to-actor
authorization → 7. canonical-bytes rebuild → 8. Ed25519 verify → 9. nonce record.

In-memory nonce store + restart epoch barrier is the accepted PoC posture (persistent
nonce store is a documented follow-up). All wireauth failures are typed sentinel
errors; handlers map them with `errors.Is`.
