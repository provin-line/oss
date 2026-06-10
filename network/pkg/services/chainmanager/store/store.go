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
