package chainmanager

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/netexcerpt"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// Direction values for store.Subscription. An empty stored value reads as
// directionPublisher (backward compatibility — see store.Subscription.Direction).
const (
	directionPublisher  = "publisher"
	directionSubscriber = "subscriber"
)

// Subscriber-surface sentinels (mapped to connect codes by the operator handler).
var (
	// ErrSubscriberUnconfigured is returned when a subscriber op is called on a
	// Service built without the resolver/peer-client/infra trio — a server
	// misconfiguration, distinct from ErrInfraUnavailable.
	ErrSubscriberUnconfigured = errors.New("chainmanager: subscriber side not configured")
	// ErrRemotePeer wraps a failure of an outbound ChainPeerService call. The
	// underlying *connect.Error is preserved in the chain so the handler can pass
	// the remote code through.
	ErrRemotePeer = errors.New("chainmanager: remote peer call failed")
	// ErrInvalidSubscriberDID is returned when the subscriber DID is not a
	// parseable dplaax DID — a fast local fail-closed before any signed round-trip.
	ErrInvalidSubscriberDID = errors.New("chainmanager: invalid subscriber DID")
	// ErrDuplicateSubscription is returned when Subscribe is called for a
	// publisherDID this CM already holds a subscriber-direction subscription
	// for, under ANY mode (the authoritative half of the mixed-mode
	// invariant): both inline and by-reference remotes rename to the SAME
	// local subject (see importTargets/AddImport below), so holding two
	// subscriptions to one publisher at once would deliver duplicate/mixed
	// forms on that one local subject. Mode is per-subscription immutable —
	// changing it means Unsubscribe then re-Subscribe.
	ErrDuplicateSubscription = errors.New("chainmanager: already subscribed to this publisher")
)

// DIDResolver resolves a DID to its DID Document — here, the publisher's, to read
// its #chain-manager service endpoint. It mirrors wireauth.DIDResolver's shape so
// the single concrete resolver satisfies both without an adapter; it is
// declared in the domain to keep the dependency pointing inward.
//
// Resolve returns a non-nil document or a non-nil error, never both nil, as
// resolver.Resolver's Resolve does.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// Peer is the node at the other end of the subscriber's calls: the endpoint
// the calls go to (its #chain-manager endpoint) and the audience their proofs
// name (wireauth.AudienceForDID of the publisher DID whose document
// publishes the endpoint). The two come from one source and travel together.
type Peer struct {
	Endpoint string
	Audience string
}

// PeerClient is the outbound side of the connection flow: the RPCs this CM calls
// on a remote publisher's ChainPeerService, at peer. The implementation signs
// each call with wireauth for peer.Audience and dials peer.Endpoint through an
// SSRF-guarded HTTP client (the domain holds no crypto material). Disconnect
// returns store.ErrNotFound when the remote has no such subscription, so
// teardown can treat it as already-done (idempotent).
type PeerClient interface {
	GetPublisherInfo(ctx context.Context, peer Peer, subscriberDID, publisherDID string) (publishType string, modes []string, err error)
	RegisterSubscription(ctx context.Context, peer Peer, subscriberDID, publisherDID, requestedMode string) (remoteID string, connInfo map[string]string, publishType, agreedMode string, err error)
	Disconnect(ctx context.Context, peer Peer, remoteSubscriptionID string) error
}

// WithDIDResolver supplies the resolver the subscriber flow uses to find a
// publisher's #chain-manager endpoint.
func WithDIDResolver(r DIDResolver) Option { return func(s *Service) { s.resolver = r } }

// WithPeerClient supplies the outbound peer client. The service layer depends on
// the PeerClient interface only; assembling a concrete client (from a signer +
// guarded transport) belongs to the composition layer (AGENTS.md layer rule 3 —
// no wire/proto types in the service).
func WithPeerClient(c PeerClient) Option { return func(s *Service) { s.peer = c } }

// WithEndpointGuard supplies the SSRF guard for the endpoint preflight. When
// unset, the subscriber flow uses a strict default guard (fail-closed).
func WithEndpointGuard(g *core.URLGuard) Option { return func(s *Service) { s.guard = g } }

// directionOf returns a record's direction, normalizing the empty default to
// directionPublisher (records written before the field existed are publisher).
func directionOf(s *store.Subscription) string {
	if s.Direction == "" {
		return directionPublisher
	}
	return s.Direction
}

// endpointGuard returns the configured guard or a strict default (fail-closed).
func (s *Service) endpointGuard() *core.URLGuard {
	if s.guard != nil {
		return s.guard
	}
	return core.NewURLGuard()
}

// Subscribe connects a local subscriber to a remote publisher: resolve the
// publisher's #chain-manager endpoint, SSRF-guard it, discover + negotiate the
// payload mode, register over the remote ChainPeerService, wire the transport
// import, and persist a subscriber-direction record. The infra/store mutations
// are serialized under the Service mutex with compensation: if AddImport
// or the local persist fails after the remote already registered, the export the
// remote created is best-effort torn down (RemoveImport + remote Disconnect) so
// no orphan import nor dangling remote subscription survives.
func (s *Service) Subscribe(ctx context.Context, subscriberDID, publisherDID, requestedMode string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.resolver == nil || s.peer == nil || s.infra == nil {
		return "", ErrSubscriberUnconfigured
	}
	if err := requirePipelineDID(publisherDID); err != nil {
		return "", err
	}
	// Fast local fail-closed on the subscriber DID before any signed round-trip:
	// a malformed DID would only burn a nonce and be rejected remotely.
	if _, err := dplaax.Parse(subscriberDID); err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrInvalidSubscriberDID, netexcerpt.ValueText(subscriberDID), err)
	}
	// Mixed-mode invariant, subscriber side (authoritative): reject before
	// any remote round-trip if a subscription to this publisher already exists,
	// under any mode.
	if err := s.rejectDuplicateSubscription(publisherDID); err != nil {
		return "", err
	}

	peer, err := s.resolveTarget(ctx, publisherDID)
	if err != nil {
		return "", err
	}

	// Discover + negotiate before committing: a mode the publisher does not offer
	// is rejected locally (no wasted registration / nonce). An empty request
	// normalizes to by-reference (the wire negotiation default), so it succeeds
	// here exactly when the publisher serves payloads (offeredPayloadModes);
	// otherwise it is rejected and the subscriber must request "inline".
	_, modes, err := s.peer.GetPublisherInfo(ctx, peer, subscriberDID, publisherDID)
	if err != nil {
		return "", fmt.Errorf("%w: get publisher info: %w", ErrRemotePeer, err)
	}
	if err := assertModeOffered(requestedMode, modes); err != nil {
		return "", err
	}

	id, err := newSubscriptionID()
	if err != nil {
		return "", err
	}

	remoteID, connInfo, publishType, agreedMode, err := s.peer.RegisterSubscription(ctx, peer, subscriberDID, publisherDID, requestedMode)
	if err != nil {
		return "", fmt.Errorf("%w: register subscription: %w", ErrRemotePeer, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-run the duplicate check UNDER the lock (the pre-RPC check above is a
	// fast-fail only): two concurrent Subscribes to the same publisher can both
	// pass the unlocked check before either persists, and would import both
	// mode subjects renamed onto the same local subject — the mixed-delivery
	// state the mixed-mode invariant forbids. The loser
	// compensates its already-committed remote registration.
	if err := s.rejectDuplicateSubscription(publisherDID); err != nil {
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", err
	}

	// The connection info is another organization's: it is held to the keys
	// and characters this side uses before anything is wired or stored.
	if err := checkConnectionInfo(connInfo); err != nil {
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", fmt.Errorf("%w: %v", ErrRemotePeer, err)
	}
	remoteSubject, remoteAccountKey := importTargets(connInfo)
	// The remote-supplied import subject is asserted against what THIS side
	// derives for the agreed mode before any local wiring: a buggy or lying
	// publisher must not be able to steer the subscriber's import to an
	// arbitrary subject in its account (renamed onto publisherDID, it would be
	// consumed as if it were the publisher's output).
	wantSubject, err := subjectForMode(publisherDID, agreedMode)
	if err != nil {
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", err
	}
	if remoteSubject != wantSubject {
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", fmt.Errorf("%w: publisher returned import subject %q, want %q for mode %q", ErrRemotePeer, remoteSubject, wantSubject, agreedMode)
	}
	// Ref-count the shared import by remote subject (mirror the publisher export
	// ref-count): only the first subscriber for a subject creates the import, so
	// only the first should compensate by removing it.
	first, err := s.isFirstImportForSubject(remoteSubject)
	if err != nil {
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", err
	}
	// localSubject = publisherDID (the rename onto one local subject), NOT
	// remoteSubject: inline's
	// remote is already publisherDID (a no-op rename), while by-reference's
	// remote is ByReferenceSubjectPrefix+publisherDID — renaming it back to the
	// plain publisherDID is what lets the consuming loop's ingress-subject
	// config stay mode-independent (the loop never has to know or express
	// "byref."). AddImport's renaming-import capability makes this a pure
	// config-side absorption; no new wire concept.
	if err := s.infra.AddImport(remoteSubject, remoteAccountKey, publisherDID); err != nil {
		// the remote already registered → undo it (best-effort, fresh context).
		_ = s.peer.Disconnect(compensationCtx(ctx), peer, remoteID)
		return "", fmt.Errorf("chainmanager: add import: %w", err)
	}

	sub := &store.Subscription{
		ID:              id,
		SubscriberDID:   subscriberDID,
		PublisherDID:    publisherDID,
		PublishType:     publishType,
		PayloadDelivery: agreedMode,
		ConnectionInfo:  connInfo,
		Created:         time.Now().UTC(),
		Direction:       directionSubscriber,
		RemoteID:        remoteID,
	}
	if err := s.subs.Save(sub); err != nil {
		// undo the remote registration always, and the local import only if we
		// created it (a sibling subscriber still depends on a shared import).
		// Compensation runs on a fresh context so a canceled caller still reaches
		// the publisher.
		cctx := compensationCtx(ctx)
		if first {
			_ = s.infra.RemoveImport(remoteSubject, remoteAccountKey)
		}
		_ = s.peer.Disconnect(cctx, peer, remoteID)
		return "", fmt.Errorf("chainmanager: persist subscription: %w", err)
	}
	return id, nil
}

// Unsubscribe tears down a subscriber-direction subscription the operator holds.
// The operator is already L1-authorized (chain/unsubscribe), so there is no
// per-caller owner check here; the remote publisher still enforces its own owner
// check on the signed Disconnect. Order: remote Disconnect (remote NotFound is
// success — idempotent) → RemoveImport → local Delete last, so a partial failure
// is fully retryable and never orphans the import.
func (s *Service) Unsubscribe(ctx context.Context, subscriptionID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.resolver == nil || s.peer == nil || s.infra == nil {
		return ErrSubscriberUnconfigured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sub, err := s.subs.Get(subscriptionID)
	if err != nil {
		return err // store.ErrNotFound for an absent id
	}
	if directionOf(sub) != directionSubscriber {
		// Not the operator's own subscription — keep id-space disjoint from the
		// publisher surface (a publisher-direction record is invisible here).
		return store.ErrNotFound
	}

	peer, err := s.resolveTarget(ctx, sub.PublisherDID)
	if err != nil {
		return err
	}
	if err := s.peer.Disconnect(ctx, peer, sub.RemoteID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: remote disconnect: %w", ErrRemotePeer, err)
	}
	remoteSubject, remoteAccountKey := importTargets(sub.ConnectionInfo)
	// Ref-count: tear the shared import down only when this is the last subscriber
	// for the subject (mirrors the publisher export ref-count). This
	// record is still stored, so count>=1; ==1 means it is the last.
	count, err := s.countImportsForSubject(remoteSubject)
	if err != nil {
		return err
	}
	if count <= 1 {
		if err := s.infra.RemoveImport(remoteSubject, remoteAccountKey); err != nil {
			return fmt.Errorf("chainmanager: remove import: %w", err)
		}
	}
	return s.subs.Delete(subscriptionID)
}

// compensationCtx returns a context detached from the caller's cancellation (but
// preserving its values) for best-effort teardown after a remote side-effect has
// already happened: a canceled/timed-out caller must not prevent the compensating
// Disconnect/RemoveImport from reaching the publisher. The detached
// context has no deadline; peerclient bounds every call to a publisher itself.
func compensationCtx(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// isFirstImportForSubject reports whether no subscriber-direction record yet
// references remoteSubject (so this Subscribe is the one creating the import).
func (s *Service) isFirstImportForSubject(remoteSubject string) (bool, error) {
	n, err := s.countImportsForSubject(remoteSubject)
	return n == 0, err
}

// countImportsForSubject counts subscriber-direction records whose connection
// targets remoteSubject — the import ref-count.
func (s *Service) countImportsForSubject(remoteSubject string) (int, error) {
	all, err := s.subs.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sub := range all {
		if directionOf(sub) != directionSubscriber {
			continue
		}
		if subj, _ := importTargets(sub.ConnectionInfo); subj == remoteSubject {
			n++
		}
	}
	return n, nil
}

// resolveTarget resolves publisherDID to the peer serving it: its
// #chain-manager endpoint, after the SSRF preflight, with the audience of
// publisherDID's node (wireauth.AudienceForDID). The registry that answers
// for publisherDID's document serves its #chain-manager endpoint, so the
// endpoint and the audience come from the same source.
func (s *Service) resolveTarget(ctx context.Context, publisherDID string) (Peer, error) {
	audience, err := wireauth.AudienceForDID(publisherDID)
	if err != nil {
		return Peer{}, fmt.Errorf("%w: publisher DID: %w", ErrRemotePeer, err)
	}
	doc, err := s.resolver.Resolve(ctx, publisherDID)
	if err != nil {
		return Peer{}, fmt.Errorf("%w: resolve publisher DID: %v", ErrRemotePeer, err)
	}
	endpoint, err := resolveChainManagerEndpoint(doc, publisherDID)
	if err != nil {
		return Peer{}, err
	}
	if err := checkEndpointAllowed(ctx, s.endpointGuard(), endpoint); err != nil {
		return Peer{}, err
	}
	return Peer{Endpoint: endpoint, Audience: audience}, nil
}

// assertModeOffered rejects a requested mode the publisher does not list. An
// empty request is NORMALIZED to by-reference (the wire negotiation default)
// before the check — it is not accepted unconditionally. So when the publisher
// does not offer by-reference, an empty or explicit by-reference request is
// rejected locally, before any wasted registration.
func assertModeOffered(requested string, offered []string) error {
	mode := requested
	if mode == "" {
		mode = "by-reference"
	}
	for _, m := range offered {
		if m == mode {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrPayloadModeUnsupported, mode)
}

// connectionInfoKeys are the keys a publisher's connection info may carry:
// those the NATS transport writes (infra/nats AddExport).
var connectionInfoKeys = map[string]bool{"subject": true, "account": true, "url": true, "publishType": true}

// connectionInfoValue is the form of a connection-info value: empty, or a
// letter or digit followed by at most 999 of the characters a URL, a NATS
// subject or account key, or a DID uses. The subscription store keeps every
// such value as written.
var connectionInfoValue = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9._~:/?@!$&'()*+,;=%\[\]-]{0,999})?$`)

// checkConnectionInfo refuses connection info from a publisher with a key
// this side does not use or a value outside connectionInfoValue.
func checkConnectionInfo(info map[string]string) error {
	for k, v := range info {
		if !connectionInfoKeys[k] {
			return fmt.Errorf("publisher returned connection info with an unknown key %s", netexcerpt.ValueText(k))
		}
		if !connectionInfoValue.MatchString(v) {
			return fmt.Errorf("publisher returned connection info %q with a value outside the allowed form", k)
		}
	}
	return nil
}

// importTargets derives the AddImport/RemoveImport REMOTE-side arguments from
// a publisher's connection_info — the local subject is NOT derived here (see
// Subscribe: localSubject = publisherDID, the rename onto one local subject). A richer
// subject scheme beyond the mode-scoped prefix is not implemented.
func importTargets(connInfo map[string]string) (remoteSubject, remoteAccountKey string) {
	return connInfo["subject"], connInfo["account"]
}

// rejectDuplicateSubscription enforces the subscriber-side, AUTHORITATIVE
// half of the mixed-mode invariant: Subscribe is rejected if a
// subscriber-direction subscription to publisherDID already exists, under any
// mode.
func (s *Service) rejectDuplicateSubscription(publisherDID string) error {
	all, err := s.subs.List()
	if err != nil {
		return err
	}
	for _, sub := range all {
		if directionOf(sub) == directionSubscriber && sub.PublisherDID == publisherDID {
			return fmt.Errorf("%w: %q", ErrDuplicateSubscription, publisherDID)
		}
	}
	return nil
}
