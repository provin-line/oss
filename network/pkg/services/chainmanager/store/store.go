// Package store defines the persistence contracts of the chain manager:
// subscriptions and allow-lists.
package store

import (
	"errors"
	"time"
)

// ErrNotFound is returned for misses. Handlers map it with errors.Is.
var ErrNotFound = errors.New("chainmanager: not found")

// Subscription is one established pipeline chain connection.
type Subscription struct {
	ID            string
	SubscriberDID string
	PublisherDID  string
	// PublishType names the transport backing the connection (e.g. "nats").
	PublishType string
	// PayloadDelivery is the subscription's AGREED payload delivery mode:
	// "inline" (payload bytes ride in the envelope) or "by-reference"
	// (hash-only envelope; the subscriber fetches payload bytes from the
	// publisher's serving boundary by content hash). Empty means
	// by-reference — the conservative default: hash-only is the normative
	// semantics, and payload bytes are never shipped without explicit
	// agreement. The requested mode rides the L2-signed
	// RegisterSubscription view (non-repudiable); a mode the publisher
	// does not offer is rejected with a typed error at wiring time. The
	// mode is immutable for the subscription's lifetime — changing it
	// means a new subscription.
	PayloadDelivery string
	// ConnectionInfo carries transport-specific connection parameters as
	// returned by the publisher's infra operator.
	ConnectionInfo map[string]string
	Created        time.Time
}

// AllowRule is one allow-list entry: a DID glob pattern
// (e.g. "did:dplaax:*:org:acme:*"). The trust model is default-distrust —
// no rules means no subscribers.
type AllowRule struct {
	Pattern string
}

// SubscriptionStore persists subscriptions.
type SubscriptionStore interface {
	Save(s *Subscription) error
	Get(id string) (*Subscription, error)
	Delete(id string) error
	List() ([]*Subscription, error)
}

// AllowListStore persists per-pipeline allow-lists. Save replaces the full
// rule set (full-replacement semantics, matching the operator API).
type AllowListStore interface {
	Save(pipelineDID string, rules []AllowRule) error
	Get(pipelineDID string) ([]AllowRule, error)
}
