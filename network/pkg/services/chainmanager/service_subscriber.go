package chainmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
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
	// ErrRemotePeer wraps a failure of an outbound ChainPeerService call.
	ErrRemotePeer = errors.New("chainmanager: remote peer call failed")
)

// DIDResolver resolves a DID to its DID Document — here, the publisher's, to read
// its #chain-manager service endpoint. It mirrors wireauth.DIDResolver's shape so
// the single concrete resolver (C2) satisfies both without an adapter; it is
// declared in the domain to keep the dependency pointing inward.
type DIDResolver interface {
	Resolve(ctx context.Context, did string) (*did.DIDDocument, error)
}

// PeerClient is the outbound side of the connection flow: the RPCs this CM calls
// on a remote publisher's ChainPeerService. The implementation signs each call
// with wireauth and dials through an SSRF-guarded HTTP client (the domain holds
// no crypto material). Disconnect returns store.ErrNotFound when the remote has
// no such subscription, so teardown can treat it as already-done (idempotent).
type PeerClient interface {
	GetPublisherInfo(ctx context.Context, endpoint, subscriberDID, publisherDID string) (publishType string, modes []string, err error)
	RegisterSubscription(ctx context.Context, endpoint, subscriberDID, publisherDID, requestedMode string) (remoteID string, connInfo map[string]string, publishType, agreedMode string, err error)
	Disconnect(ctx context.Context, endpoint, remoteSubscriptionID string) error
}

// WithDIDResolver supplies the resolver the subscriber flow uses to find a
// publisher's #chain-manager endpoint.
func WithDIDResolver(r DIDResolver) Option { return func(s *Service) { s.resolver = r } }

// WithPeerClient supplies the outbound peer client.
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
// are serialized under the Service mutex with compensation (D-s5): if AddImport
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

	endpoint, err := s.resolveEndpoint(ctx, publisherDID)
	if err != nil {
		return "", err
	}

	// Discover + negotiate before committing: a mode the publisher does not offer
	// is rejected locally (no wasted registration / nonce). Empty means
	// by-reference, which every publisher offers.
	_, modes, err := s.peer.GetPublisherInfo(ctx, endpoint, subscriberDID, publisherDID)
	if err != nil {
		return "", fmt.Errorf("%w: get publisher info: %v", ErrRemotePeer, err)
	}
	if err := assertModeOffered(requestedMode, modes); err != nil {
		return "", err
	}

	id, err := newSubscriptionID()
	if err != nil {
		return "", err
	}

	remoteID, connInfo, publishType, agreedMode, err := s.peer.RegisterSubscription(ctx, endpoint, subscriberDID, publisherDID, requestedMode)
	if err != nil {
		return "", fmt.Errorf("%w: register subscription: %v", ErrRemotePeer, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	remoteSubject, remoteAccountKey := importTargets(connInfo)
	if err := s.infra.AddImport(remoteSubject, remoteAccountKey, remoteSubject); err != nil {
		// the remote already registered → undo it (best-effort).
		_ = s.peer.Disconnect(ctx, endpoint, remoteID)
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
		// undo both the local import and the remote registration (best-effort).
		_ = s.infra.RemoveImport(remoteSubject, remoteAccountKey)
		_ = s.peer.Disconnect(ctx, endpoint, remoteID)
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

	endpoint, err := s.resolveEndpoint(ctx, sub.PublisherDID)
	if err != nil {
		return err
	}
	if err := s.peer.Disconnect(ctx, endpoint, sub.RemoteID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: remote disconnect: %v", ErrRemotePeer, err)
	}
	remoteSubject, remoteAccountKey := importTargets(sub.ConnectionInfo)
	if err := s.infra.RemoveImport(remoteSubject, remoteAccountKey); err != nil {
		return fmt.Errorf("chainmanager: remove import: %w", err)
	}
	return s.subs.Delete(subscriptionID)
}

// resolveEndpoint resolves publisherDID to its #chain-manager endpoint and runs
// the SSRF preflight.
func (s *Service) resolveEndpoint(ctx context.Context, publisherDID string) (string, error) {
	doc, err := s.resolver.Resolve(ctx, publisherDID)
	if err != nil {
		return "", fmt.Errorf("%w: resolve publisher DID: %v", ErrRemotePeer, err)
	}
	endpoint, err := resolveChainManagerEndpoint(doc, publisherDID)
	if err != nil {
		return "", err
	}
	if err := checkEndpointAllowed(ctx, s.endpointGuard(), endpoint); err != nil {
		return "", err
	}
	return endpoint, nil
}

// assertModeOffered rejects a non-empty requested mode the publisher does not
// list. Empty (by-reference, the conservative default) is always accepted.
func assertModeOffered(requested string, offered []string) error {
	if requested == "" {
		return nil
	}
	for _, m := range offered {
		if m == requested {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrPayloadModeUnsupported, requested)
}

// importTargets derives the AddImport/RemoveImport arguments from a publisher's
// connection_info. PoC naming is 1:1 (local subject = remote subject); a richer
// subject scheme is deferred (C2).
func importTargets(connInfo map[string]string) (remoteSubject, remoteAccountKey string) {
	return connInfo["subject"], connInfo["account"]
}
