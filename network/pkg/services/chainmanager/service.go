package chainmanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/allowlist"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// ErrInvalidPipelineDID is returned when an allow-list key is not a parseable
// dplaax pipeline DID. The domain raises this typed sentinel itself rather than
// relying on the store: the AllowListStore contract defines no typed invalid-key
// error (memstore accepts any key; yamlstore rejects with an untyped formatted
// error), so a store-dependent check would be unmappable by errors.Is and would
// behave differently per implementation.
var ErrInvalidPipelineDID = errors.New("chainmanager: invalid pipeline DID")

// Service is the chainmanager domain service. This slice (B1) implements the
// operator-facing operations (ListSubscriptions, UpdateAllowList); the peer
// operations and an infra.Operator dependency are added in B2.
type Service struct {
	subs   store.SubscriptionStore
	allows store.AllowListStore
}

// New returns a Service backed by the given stores.
func New(subs store.SubscriptionStore, allows store.AllowListStore) *Service {
	return &Service{subs: subs, allows: allows}
}

// ListSubscriptions returns the subscriptions this CM holds. An empty store
// yields an empty slice, not an error.
func (s *Service) ListSubscriptions(ctx context.Context) ([]*store.Subscription, error) {
	return s.subs.List()
}

// UpdateAllowList replaces the allow-list of pipelineDID with the rules built
// from patterns. It is all-or-nothing: the key and every pattern are validated
// before any write, so a single invalid input fails the whole call with the
// stored allow-list untouched. The key must be a parseable dplaax pipeline DID
// (ErrInvalidPipelineDID otherwise); each pattern must be a valid trust pattern
// (allowlist.ErrInvalidPattern otherwise). On success the rule set fully replaces
// the prior one.
func (s *Service) UpdateAllowList(ctx context.Context, pipelineDID string, patterns []string) error {
	d, err := dplaax.Parse(pipelineDID)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidPipelineDID, pipelineDID, err)
	}
	if !d.IsPipeline() {
		return fmt.Errorf("%w: %q is not a pipeline DID", ErrInvalidPipelineDID, pipelineDID)
	}
	rules := make([]store.AllowRule, len(patterns))
	for i, p := range patterns {
		if err := allowlist.ValidatePattern(p); err != nil {
			return fmt.Errorf("allow-list rule %d: %w", i, err)
		}
		rules[i] = store.AllowRule{Pattern: p}
	}
	return s.allows.Save(pipelineDID, rules)
}
