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

**Empty-mode compatibility callout**: an unspecified request mode is
NORMALIZED to by-reference, not to inline. A serving publisher now genuinely
offers by-reference (see below), so an empty/omitted mode request that used
to be a typed rejection now SUCCEEDS as a by-reference agreement. This is a
behavior change, not a compatibility alias: the consumer side must be
configured for by-reference (`payload-delivery = "by-reference"` config key +
a `PayloadResolver`) or the ingress will reject every event as a delivery
violation. An older client that wants inline must request it explicitly —
omitting the mode no longer means "give me inline."

## Mode-scoped export subjects and the subscriber-side rename

The export seam cannot transform a NATS message in flight (an account
export/import is a routing grant, not a payload transform), so it applies the
agreed payload-delivery mode STRUCTURALLY, by mapping the mode to a distinct
wire subject:

- `subjectForMode(publisherDID, mode)` (service-internal): `inline` exports
  the plain `publisherDID`; `by-reference` exports `"byref." + publisherDID`
  (`ByReferenceSubjectPrefix`, exported so a producing loop
  (`pipeline/runtime/dataplane.go`, via `wireprofile`'s alias) can bind its
  dual-emit stripped-form publish to
  the EXACT same subject, without duplicating the prefix convention). Prefix,
  not suffix: a dplaax DID's registry segment may itself contain dots, so a
  suffix scheme cannot rule out colliding with a DID that happens to end in a
  matching segment without a grammar proof; a prefix partitions cleanly on
  the first token. The function doubles as the NATS-subject-safety validator
  for `publisherDID` (whitespace / `*` / `>` / an empty dot-segment all fail
  closed with `ErrUnsafeSubject`) — `requirePipelineDID` only proves DID
  shape, never wire-subject safety.
- The publisher's export ref-count is keyed on the EXPORTED SUBJECT, not
  `publisherDID`: an inline and a by-reference subscription of the same
  publisher export different subjects and ref-count independently — one
  mode's teardown never touches the other's export, and two subscribers on
  the SAME mode/subject share one export (idempotent `AddExport`).
- **Teardown is driven by the STORED subject, never recomputed**:
  `Disconnect` removes `sub.ConnectionInfo["subject"]` — the subject
  `AddExport` actually returned at registration time — rather than
  re-deriving it from `PayloadDelivery`/`subjectForMode`. This makes teardown
  correct for a legacy record too: every subscription created before this
  mode-application landed was exported on the PLAIN subject regardless of
  its agreed mode (the export seam did not yet apply the mode), so
  `ConnectionInfo["subject"]` is what must be removed, not what the current
  mapping would compute today. A record with no stored subject is a damaged
  record; `Disconnect` fails closed (`ErrExportSubjectMissing`) rather than
  guessing.
- **Subscriber-side rename**: `Subscribe`'s `AddImport` renames the remote
  subject to a LOCAL subject that is always the plain `publisherDID` —
  inline's remote already IS `publisherDID` (a no-op rename); by-reference's
  remote is `"byref." + publisherDID`, renamed back to the plain DID. The
  consuming loop's `ingress-subject` config is therefore mode-independent: it
  never has to name or know about the `"byref."` prefix, and a subscription's
  mode can change (a new subscription, since mode is per-subscription
  immutable) without touching loop config.
- **Mixed-mode invariant**: because both modes' remotes rename to the SAME
  local subject, one subscriber account holding an inline AND a by-reference
  subscription to the SAME publisher at once would receive both forms on one
  local subject (duplicate processing + a delivery-violation reject).
  Enforced on both sides: `Subscribe` (subscriber side, authoritative)
  rejects a second subscription to a publisher it already subscribes to,
  under ANY mode (`ErrDuplicateSubscription` — change mode via Unsubscribe
  then re-Subscribe); `RegisterSubscription` (publisher side,
  defense-in-depth) rejects a registration for a
  (subscriberDID, publisherDID) pair that already holds a DIFFERENT mode
  (`ErrMixedModeSubscription`). Different SUBSCRIBERS may hold different
  modes to the same publisher freely — the invariant is scoped to one
  subscriber/publisher pair, not the publisher alone.
- **Upgrade sequence for legacy stored by-reference subscriptions**: a
  subscription registered before this slice, whose stored mode reads
  by-reference (or empty — the pre-existing default), was actually exported
  on the plain subject; the data path does not migrate automatically (mode
  is per-subscription immutable — PoC posture). To pick up real by-reference
  delivery: `Unsubscribe` the old subscription from the subscriber side (it
  drives the publisher's `Disconnect`, which removes the plain export via the
  stored-subject teardown above, cleanly — no leak) and re-`Subscribe` with
  an explicit `"by-reference"` request.

## infra/ — transport abstraction

`InfraOperator` (AddExport / RemoveExport / AddImport / RemoveImport / PublishType)
is the Hub swap point for the pub-sub backend. Implementations:

- `nats/` — dynamic NATS account-claims JWT management (requires full-resolver mode)
- `noop/` — debug/testing only; must be impossible to wire in non-debug builds

## wireauth/ — L2 peer authentication

Every ChainPeerService RPC carries an `AuthProof` (the proto message; the Go
library type is `wireauth.Proof`): Ed25519 signature over a
JCS-canonicalized per-RPC view (**signerDID** + op discriminator + view version +
nonce + issuedAt + business fields). Binding `signerDID` into the signed bytes
closes unknown-key-share: a DID alias that shares another DID's `#auth` key cannot
reuse its signature. Verification is an ordered pipeline — cheap fail-fast checks
first, signature verification late, **authorization after the signature** (so
policy never runs on an unauthenticated caller — no allow-list oracle), nonce
recorded **only after** signature success (a failed forgery must not burn a
legitimate signer's nonce):

1. structural / malformed fail-fast (missing proof; empty op; oversized nonce;
   non-second-precision issuedAt rejected, not truncated — sub-second precision
   would let the window check be shifted without changing the signed bytes;
   fields value-grammar) → 2. restart epoch barrier (ceiled to the next whole
   second) → 3. acceptance window (asymmetric past/skew) → 4. key resolution via
   DID Document (`#auth`, authentication relationship + controller match) →
   5. canonical-bytes rebuild → 6. Ed25519 verify → 7. signer-to-actor
   authorization (over an immutable snapshot of the resolved doc + fields) →
   8. nonce record.

**L2 identities and the audit horizon.** The signed view is access control at
the moment of the call, but the stored record doubles as audit evidence for the
audit horizon (see evidence/ below). When a deployment admits web-anchored DID
methods for L2 parties (e.g. did:web consumers), the CM records a snapshot of
the resolved DID document (the key binding) alongside the signed view — the
signature stays re-verifiable against the snapshotted key forever, and the only
residual claim is that the binding was authentically served at registration
time. Methods with verifiable key history close that residue; audit-sensitive
deployments restrict L2 parties to T1/T2 (see DID method tiers in the
glossary).

In-memory nonce store + restart epoch barrier is the accepted PoC posture (persistent
nonce store is a documented follow-up). All wireauth failures are typed sentinel
errors; handlers map them with `errors.Is`.

## evidence/ — relationship-evidence log

`evidence.Log` (`New(tlog.Log) *Log`) is the durable, append-only retained
record of a counterparty-signed control-plane request plus the key material
used to verify it (transfer.relationship.record): `Record` JSON-marshals an
`evidence.Record` (op, signerDID, nonce, issuedAt, signature, the exact signed
fields, and a `KeyMaterial` snapshot of the verifying key) and appends it;
`Get`/`Size` read it back. Durability, append-only ordering, and tamper-
evidence all come from the wrapped `tlog.Log` (filelog in production); this
package owns only the retained shape.

The handler wires it in as an optional capability: `NewPeerWithEvidence(svc, v,
rec)` configures a `RelationshipRecorder` (nil = disabled, `NewPeer`'s
behavior unchanged), and `cmd/network` wires a durable filelog under
`chain/relationship-evidence`. RegisterSubscription and Disconnect each record
evidence AFTER the domain call succeeds — so a rejected/failed relationship
change (unknown publisher, ownership failure) is never retained as an
established relationship; a record failure then surfaces as `Internal`
(fail-closed) after the domain mutation. The retained record carries the
signed-view version (`wireauth.ViewVersion`, the `"v"` member of the JCS view),
the exact signed fields, and the key material — extracted from the resolved DID
document exactly as the verifier resolved it (`did.ExtractPublicKey` under the
`#auth` `RelationshipAuthentication` relationship) — so a third party can
reconstruct the signed view and re-verify the counterparty signature from the
record alone.
