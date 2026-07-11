package chainmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/provin-line/oss/allowlist"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// Peer-surface sentinels (mapped to connect codes by the peer handler).
var (
	// ErrNotAdmitted is returned when a caller is not admitted by the publisher's
	// allow-list (default-distrust).
	ErrNotAdmitted = errors.New("chainmanager: not admitted by allow-list")
	// ErrNotOwner is returned when a Disconnect caller does not own the subscription.
	ErrNotOwner = errors.New("chainmanager: not the subscription owner")
	// ErrPayloadModeUnsupported is returned when a requested payload-delivery mode
	// is not offered by this publisher.
	ErrPayloadModeUnsupported = errors.New("chainmanager: payload-delivery mode not supported")
	// ErrInfraUnavailable is returned when a peer operation is called on a Service
	// constructed without an infra.Operator — a server misconfiguration.
	ErrInfraUnavailable = errors.New("chainmanager: infra operator not configured")
)

// exportSeamAppliesDeliveryMode reports whether the cross-organization export
// seam applies the agreed payload-delivery mode (stripping the payload for a
// by-reference subscription). It is false: mode application at the export seam
// is not yet implemented (gap-backlog: export-seam mode application, the (d)
// residual of by-reference delivery). Until it lands, advertising the
// by-reference mode would be false advertising — a subscription could be agreed
// and signed, yet every event would arrive inline and fail at the consumer — so
// offeredPayloadModes withholds it even on a serving node. Flip this to true
// when the export seam gains mode application.
const exportSeamAppliesDeliveryMode = false

// offeredPayloadModes derives the payload-delivery modes this CM advertises.
// "inline" is always offered. "by-reference" additionally requires BOTH this
// node serving payloads AND the export seam applying the mode; the latter is not
// implemented (exportSeamAppliesDeliveryMode), so by-reference is currently never
// advertised — replacing the earlier PoC-fixed set that advertised a mode whose
// subscriptions were guaranteed to fail.
func (s *Service) offeredPayloadModes() []string {
	modes := []string{"inline"}
	if s.payloadServing && exportSeamAppliesDeliveryMode {
		modes = append(modes, "by-reference")
	}
	return modes
}

// PublisherInfo returns the publisher's transport type and offered
// payload-delivery modes, after admitting callerDID against the publisher's
// allow-list (the light check, default-distrust). It mutates nothing.
func (s *Service) PublisherInfo(ctx context.Context, publisherDID, callerDID string) (string, []string, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if s.infra == nil {
		return "", nil, ErrInfraUnavailable
	}
	if err := s.admit(publisherDID, callerDID); err != nil {
		return "", nil, err
	}
	return s.infra.PublishType(), s.offeredPayloadModes(), nil
}

// RegisterSubscription admits the subscriber, negotiates the payload mode,
// provisions the publisher export, and persists the subscription. The
// infra-touching lifecycle is serialized (D-p8): the export is shared per
// publisher subject (idempotent AddExport), and a Save failure for the first
// subscription compensates by removing the export it just created.
func (s *Service) RegisterSubscription(ctx context.Context, subscriberDID, publisherDID, requestedMode string) (*store.Subscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.infra == nil {
		return nil, ErrInfraUnavailable
	}
	if err := s.admit(publisherDID, subscriberDID); err != nil {
		return nil, err
	}
	mode, err := negotiatePayloadMode(requestedMode, s.offeredPayloadModes())
	if err != nil {
		return nil, err
	}
	id, err := newSubscriptionID()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	first, err := s.isFirstForPublisher(publisherDID)
	if err != nil {
		return nil, err
	}
	connInfo, err := s.infra.AddExport(publisherDID)
	if err != nil {
		return nil, fmt.Errorf("chainmanager: add export: %w", err)
	}
	sub := &store.Subscription{
		ID:              id,
		SubscriberDID:   subscriberDID,
		PublisherDID:    publisherDID,
		PublishType:     s.infra.PublishType(),
		PayloadDelivery: mode,
		ConnectionInfo:  connInfo,
		Created:         time.Now().UTC(),
		Direction:       directionPublisher,
	}
	if err := s.subs.Save(sub); err != nil {
		// Compensate only the export we just created (don't tear down an export a
		// sibling subscription already depends on).
		if first {
			_ = s.infra.RemoveExport(publisherDID)
		}
		return nil, fmt.Errorf("chainmanager: persist subscription: %w", err)
	}
	return sub, nil
}

// Disconnect removes a subscription the caller owns and, only when it was the
// last subscription for that publisher, tears down the export (D-p8 ref-count).
func (s *Service) Disconnect(ctx context.Context, subscriptionID, callerDID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.infra == nil {
		return ErrInfraUnavailable
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sub, err := s.subs.Get(subscriptionID)
	if err != nil {
		return err // store.ErrNotFound for an absent id
	}
	if directionOf(sub) != directionPublisher {
		// A subscriber-direction record belongs to the operator's Unsubscribe
		// surface, not the peer Disconnect surface — keep the id-spaces disjoint.
		return store.ErrNotFound
	}
	if sub.SubscriberDID != callerDID {
		return ErrNotOwner
	}
	// Tear down the export BEFORE the irreversible Delete, and only when this is
	// the last subscription for the publisher. Ordering matters (Codex/Claude
	// convergent): if RemoveExport ran after Delete and then failed, the
	// subscription would be gone while the export lingered (a retry would hit
	// NotFound and never clean it up). With RemoveExport first — and idempotent
	// (D-p8) — a RemoveExport failure leaves the subscription intact (fully
	// retryable, no orphan), and a Delete failure after a successful RemoveExport
	// is recovered by a retry that re-runs the idempotent RemoveExport then Delete.
	count, err := s.countForPublisher(sub.PublisherDID)
	if err != nil {
		return err
	}
	if count <= 1 { // this subscription is still stored, so count>=1; ==1 means it is the last
		if err := s.infra.RemoveExport(sub.PublisherDID); err != nil {
			return fmt.Errorf("chainmanager: remove export: %w", err)
		}
	}
	return s.subs.Delete(subscriptionID)
}

// Admit reports whether callerDID is admitted by pipelineDID's allow-list,
// returning nil on a match and ErrNotAdmitted on none (or a malformed
// pipelineDID as ErrInvalidPipelineDID). It is the exported form of the
// default-distrust admission the peer surface applies at subscription time,
// shared with the by-reference payload serving boundary (payloadresolver), which
// admits a caller against any owner pipeline's allow-list. It is read-only.
func (s *Service) Admit(pipelineDID, callerDID string) error {
	return s.admit(pipelineDID, callerDID)
}

// admit validates the publisher key and matches callerDID against the publisher's
// allow-list. Default-distrust: an empty rule set or no match is ErrNotAdmitted.
func (s *Service) admit(publisherDID, callerDID string) error {
	if err := requirePipelineDID(publisherDID); err != nil {
		return err
	}
	rules, err := s.allows.Get(publisherDID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		ok, err := allowlist.Match(r.Pattern, callerDID)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrNotAdmitted
}

// isFirstForPublisher reports whether no subscription yet references publisherDID
// (so this RegisterSubscription is the one creating the export).
func (s *Service) isFirstForPublisher(publisherDID string) (bool, error) {
	n, err := s.countForPublisher(publisherDID)
	return n == 0, err
}

func (s *Service) countForPublisher(publisherDID string) (int, error) {
	all, err := s.subs.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sub := range all {
		// Only publisher-direction records back an export; subscriber-direction
		// records (this CM's own subscriptions) must not inflate the ref-count.
		if directionOf(sub) == directionPublisher && sub.PublisherDID == publisherDID {
			n++
		}
	}
	return n, nil
}

// negotiatePayloadMode resolves a requested mode against the offered set. An
// empty request is NORMALIZED to by-reference (the wire negotiation default)
// BEFORE the offered-modes check — it is not accepted unconditionally. So when
// by-reference is not offered (the current posture, see offeredPayloadModes), an
// empty or explicit by-reference request is ErrPayloadModeUnsupported, never a
// silently-agreed subscription that would fail every event.
func negotiatePayloadMode(requested string, offered []string) (string, error) {
	mode := requested
	if mode == "" {
		mode = "by-reference"
	}
	for _, m := range offered {
		if m == mode {
			return mode, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrPayloadModeUnsupported, mode)
}

// newSubscriptionID returns a fresh crypto-random hex id.
func newSubscriptionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chainmanager: generate subscription id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
