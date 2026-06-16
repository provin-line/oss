package chainmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/allowlist"
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

// supportedPayloadModes is the PoC-fixed set of payload-delivery modes this CM
// offers (slice-11 D-p7). Per-publisher configurability is a later refinement.
var supportedPayloadModes = []string{"by-reference", "inline"}

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
	modes := append([]string(nil), supportedPayloadModes...)
	return s.infra.PublishType(), modes, nil
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
	mode, err := negotiatePayloadMode(requestedMode)
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
	if sub.SubscriberDID != callerDID {
		return ErrNotOwner
	}
	if err := s.subs.Delete(subscriptionID); err != nil {
		return err
	}
	last, err := s.isLastForPublisher(sub.PublisherDID)
	if err != nil {
		return err
	}
	if last {
		if err := s.infra.RemoveExport(sub.PublisherDID); err != nil {
			return fmt.Errorf("chainmanager: remove export: %w", err)
		}
	}
	return nil
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

// isLastForPublisher reports whether no subscription remains for publisherDID
// (called after the Delete, so a zero count means the export can be removed).
func (s *Service) isLastForPublisher(publisherDID string) (bool, error) {
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
		if sub.PublisherDID == publisherDID {
			n++
		}
	}
	return n, nil
}

// negotiatePayloadMode resolves a requested mode against the offered set: empty
// means by-reference (the conservative default); a mode not offered is
// ErrPayloadModeUnsupported (a typed rejection, never a silent fallback).
func negotiatePayloadMode(requested string) (string, error) {
	if requested == "" {
		return "by-reference", nil
	}
	for _, m := range supportedPayloadModes {
		if m == requested {
			return requested, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrPayloadModeUnsupported, requested)
}

// newSubscriptionID returns a fresh crypto-random hex id.
func newSubscriptionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chainmanager: generate subscription id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
