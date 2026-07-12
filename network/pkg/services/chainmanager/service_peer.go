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
	// ErrMixedModeSubscription is returned when RegisterSubscription is called
	// for a (subscriberDID, publisherDID) pair that already has a
	// publisher-direction subscription under a DIFFERENT payload-delivery mode
	// (D-4). Both modes' remote subjects rename to the SAME local subject on
	// the subscriber side (Subscribe), so a subscriber account holding both
	// forms at once would receive duplicate/mixed delivery on one local
	// subject. The subscriber-side Subscribe check (ErrDuplicateSubscription)
	// is authoritative; this is defense-in-depth for a publisher whose caller
	// does not go through this CM's own Subscribe. Registering the SAME mode
	// twice for the same pair is unaffected (no invariant against
	// exact-duplicate registrations pre-existed this check).
	ErrMixedModeSubscription = errors.New("chainmanager: an existing subscription for this subscriber/publisher pair uses a different payload-delivery mode")
	// ErrExportSubjectMissing is returned when Disconnect is asked to tear
	// down a publisher-direction subscription record whose
	// ConnectionInfo["subject"] is empty — the field RegisterSubscription
	// always populates from the infra.Operator's own AddExport return value.
	// An empty value means the stored record is damaged; Disconnect fails
	// closed (never guesses a subject to remove, never silently skips
	// teardown) and requires manual cleanup (D-3).
	ErrExportSubjectMissing = errors.New("chainmanager: subscription record has no exported subject on file")
)

// exportSeamAppliesDeliveryMode reports whether the cross-organization export
// seam applies the agreed payload-delivery mode (stripping the payload for a
// by-reference subscription). It is true: the seam now applies the mode
// STRUCTURALLY, not by transforming NATS messages in flight (account
// export/import cannot rewrite a payload) — RegisterSubscription maps the
// agreed mode to a distinct wire subject (subjectForMode: inline rides the
// plain publisher DID, by-reference rides the ByReferenceSubjectPrefix-prefixed
// form), and a serving node's producing loops dual-emit onto BOTH subjects
// (transport.Emitter's WithStrippedPublisher capability), so a subscriber's
// account only ever imports the subject its agreed mode grants. "Applying the
// mode" and "advertising it honestly" are therefore the same fact once
// RegisterSubscription and dual-emit both exist — there is no longer a
// configuration that advertises by-reference without wiring it.
//
// noop/dev posture: this derivation is transport-agnostic (it does not
// branch on infra.Operator's PublishType) — the noop operator is dev-build
// gated and its export/import are themselves no-ops, so the asymmetry
// between "the mode is advertised" and "the seam enforces nothing" is
// confined to dev builds; a production deployment only ever runs the nats
// operator, where the derivation and the enforcement agree.
const exportSeamAppliesDeliveryMode = true

// offeredPayloadModes derives the payload-delivery modes this CM advertises.
// "inline" is always offered. "by-reference" additionally requires BOTH this
// node serving payloads AND the export seam applying the mode
// (exportSeamAppliesDeliveryMode, now structurally true — see its doc).
func (s *Service) offeredPayloadModes() []string {
	modes := []string{"inline"}
	// The runtime health gate (byRefHealthy), when configured, additionally
	// suppresses by-reference while this node's stripped-publish emission is
	// failing — so a node stops advertising a mode it can no longer honestly
	// serve. Evaluated once; nil means health monitoring is not configured.
	healthy := s.byRefHealthy == nil || s.byRefHealthy()
	if s.payloadServing && exportSeamAppliesDeliveryMode && healthy {
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
// maps the mode to its wire subject (subjectForMode — D-2/D-3), provisions
// the publisher export, and persists the subscription. The infra-touching
// lifecycle is serialized (D-p8): the export is shared per EXPORTED SUBJECT
// (idempotent AddExport; ref-count key is the subject, not publisherDID — an
// inline and a by-reference subscription of the same publisher export
// different subjects), and a Save failure for the first subscription
// compensates by removing the export it just created. A registration for a
// (subscriberDID, publisherDID) pair that already holds a subscription under
// a DIFFERENT mode is rejected (ErrMixedModeSubscription — D-4 defense in
// depth).
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
	subject, err := subjectForMode(publisherDID, mode)
	if err != nil {
		return nil, err
	}
	id, err := newSubscriptionID()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.rejectMixedMode(subscriberDID, publisherDID, mode); err != nil {
		return nil, err
	}

	first, err := s.isFirstForSubject(subject)
	if err != nil {
		return nil, err
	}
	connInfo, err := s.infra.AddExport(subject)
	if err != nil {
		return nil, fmt.Errorf("chainmanager: add export: %w", err)
	}
	// connInfo["subject"] is load-bearing: the ref-count and Disconnect key on
	// the STORED subject (D-3), so a record persisted without it would never be
	// counted and could only fail closed at teardown. Fail closed HERE instead
	// (compensating the export we may have just created) — an Operator that
	// omits the key violates the AddExport contract (infra.Operator doc).
	if connInfo["subject"] == "" {
		if first {
			_ = s.infra.RemoveExport(subject)
		}
		return nil, fmt.Errorf("%w: operator %q returned no connectionInfo[\"subject\"]", ErrExportSubjectMissing, s.infra.PublishType())
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
			_ = s.infra.RemoveExport(subject)
		}
		return nil, fmt.Errorf("chainmanager: persist subscription: %w", err)
	}
	return sub, nil
}

// Disconnect removes a subscription the caller owns and, only when it was the
// last subscription sharing that subject, tears down the export (D-p8
// ref-count). The export torn down is the subject STORED at
// sub.ConnectionInfo["subject"] — the subject AddExport actually returned at
// registration — NEVER recomputed from PayloadDelivery/subjectForMode (D-3).
// This is what makes teardown correct for a legacy record (pre-dual-emit: the
// actual export was always the plain subject, regardless of the agreed mode
// recorded in PayloadDelivery): it removes what was ACTUALLY exported, not
// what the current mode→subject mapping would compute today. A record with no
// stored subject is a damaged record; Disconnect fails closed
// (ErrExportSubjectMissing) rather than guessing.
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
	subject := sub.ConnectionInfo["subject"]
	if subject == "" {
		return fmt.Errorf("%w: subscription %q", ErrExportSubjectMissing, subscriptionID)
	}
	// Tear down the export BEFORE the irreversible Delete, and only when this is
	// the last subscription sharing subject. Ordering matters (Codex/Claude
	// convergent): if RemoveExport ran after Delete and then failed, the
	// subscription would be gone while the export lingered (a retry would hit
	// NotFound and never clean it up). With RemoveExport first — and idempotent
	// (D-p8) — a RemoveExport failure leaves the subscription intact (fully
	// retryable, no orphan), and a Delete failure after a successful RemoveExport
	// is recovered by a retry that re-runs the idempotent RemoveExport then Delete.
	count, err := s.countForSubject(subject)
	if err != nil {
		return err
	}
	if count <= 1 { // this subscription is still stored, so count>=1; ==1 means it is the last
		if err := s.infra.RemoveExport(subject); err != nil {
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

// isFirstForSubject reports whether no publisher-direction subscription yet
// exports subject (so this RegisterSubscription is the one creating the
// export). The ref-count KEY is the exported subject (D-3), not publisherDID:
// an inline and a by-reference registration of the same publisher export
// DIFFERENT subjects (subjectForMode) and must ref-count independently.
func (s *Service) isFirstForSubject(subject string) (bool, error) {
	n, err := s.countForSubject(subject)
	return n == 0, err
}

// countForSubject counts publisher-direction subscriptions whose STORED
// ConnectionInfo["subject"] equals subject — the export ref-count, keyed by
// what was actually exported (matches Disconnect's teardown key, D-3).
func (s *Service) countForSubject(subject string) (int, error) {
	all, err := s.subs.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sub := range all {
		// Only publisher-direction records back an export; subscriber-direction
		// records (this CM's own subscriptions) must not inflate the ref-count.
		if directionOf(sub) == directionPublisher && sub.ConnectionInfo["subject"] == subject {
			n++
		}
	}
	return n, nil
}

// rejectMixedMode enforces the publisher-side half of the mixed-mode
// invariant (D-4 defense-in-depth): a (subscriberDID, publisherDID) pair that
// already has a publisher-direction subscription under a DIFFERENT
// payload-delivery mode is rejected. The SAME mode registered again for the
// same pair is not a conflict.
func (s *Service) rejectMixedMode(subscriberDID, publisherDID, mode string) error {
	all, err := s.subs.List()
	if err != nil {
		return err
	}
	for _, sub := range all {
		if directionOf(sub) != directionPublisher {
			continue
		}
		if sub.SubscriberDID != subscriberDID || sub.PublisherDID != publisherDID {
			continue
		}
		if existing := normalizeStoredMode(sub.PayloadDelivery); existing != mode {
			return fmt.Errorf("%w: subscriber %q publisher %q existing mode %q, requested %q",
				ErrMixedModeSubscription, subscriberDID, publisherDID, existing, mode)
		}
	}
	return nil
}

// normalizeStoredMode maps a stored (possibly legacy-empty) PayloadDelivery
// to its concrete mode string — empty means by-reference (store.Subscription
// doc: the conservative negotiation default).
func normalizeStoredMode(pd string) string {
	if pd == "" {
		return "by-reference"
	}
	return pd
}

// negotiatePayloadMode resolves a requested mode against the offered set. An
// empty request is NORMALIZED to by-reference (the wire negotiation default)
// BEFORE the offered-modes check — it is not accepted unconditionally. So on a
// non-serving publisher (see offeredPayloadModes), an empty or explicit
// by-reference request is ErrPayloadModeUnsupported, never a silently-agreed
// subscription that would fail every event; on a serving publisher both now
// succeed as by-reference agreements.
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
