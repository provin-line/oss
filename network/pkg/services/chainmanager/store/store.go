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
	// Direction distinguishes the two edges a CM holds: "publisher" (a remote
	// subscriber registered against a local pipeline — the export side) and
	// "subscriber" (this CM subscribed a local pipeline to a remote publisher —
	// the import side). An empty value reads as "publisher" for backward
	// compatibility with records written before this field existed.
	Direction string
	// RemoteID is the publisher-side subscription id, set only on "subscriber"
	// records: the remote ChainPeerService keys its owner check on this id, so it
	// is what a teardown Disconnect must carry.
	RemoteID string
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
