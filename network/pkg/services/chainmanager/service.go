package chainmanager

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/allowlist"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// ErrInvalidPipelineDID is returned when an allow-list key is not a parseable
// dplaax pipeline DID. The domain raises this typed sentinel itself rather than
// relying on the store: the AllowListStore contract defines no typed invalid-key
// error (memstore accepts any key; yamlstore rejects with an untyped formatted
// error), so a store-dependent check would be unmappable by errors.Is and would
// behave differently per implementation.
var ErrInvalidPipelineDID = errors.New("chainmanager: invalid pipeline DID")

// Service is the chainmanager domain service. It serves both the operator-facing
// operations (ListSubscriptions, UpdateAllowList) and the publisher-side peer
// operations (PublisherInfo, RegisterSubscription, Disconnect). The peer
// operations require an infra.Operator, supplied via WithInfraOperator; a Service
// constructed without one serves the operator surface and rejects peer calls with
// ErrInfraUnavailable.
type Service struct {
	subs   store.SubscriptionStore
	allows store.AllowListStore
	infra  infra.Operator // nil unless WithInfraOperator was passed

	// Subscriber-side dependencies (the outbound connection flow). All three are
	// required for Subscribe/Unsubscribe; a Service missing any rejects those
	// calls with ErrSubscriberUnconfigured. guard defaults to a strict
	// core.URLGuard so the SSRF preflight fails closed when none is supplied.
	resolver DIDResolver
	peer     PeerClient
	guard    *core.URLGuard

	// mu serializes the infra-touching peer lifecycle (RegisterSubscription /
	// Disconnect / Subscribe / Unsubscribe): their export/import ref-counting is a
	// check-then-act sequence across several store calls, which the per-method
	// store locks (and the mutex-less yamlstore) do NOT make atomic. The
	// operator-surface methods are lock-free.
	mu sync.Mutex
}

// Option configures a Service at construction.
type Option func(*Service)

// WithInfraOperator supplies the transport operator the peer operations require.
func WithInfraOperator(op infra.Operator) Option {
	return func(s *Service) { s.infra = op }
}

// New returns a Service backed by the given stores. Pass WithInfraOperator to
// enable the peer operations.
func New(subs store.SubscriptionStore, allows store.AllowListStore, opts ...Option) *Service {
	s := &Service{subs: subs, allows: allows}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// requirePipelineDID validates that s parses as a dplaax pipeline DID, returning
// ErrInvalidPipelineDID otherwise. It is the single validation path shared by the
// operator (UpdateAllowList) and peer (admission) surfaces.
func requirePipelineDID(didStr string) error {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidPipelineDID, didStr, err)
	}
	if !d.IsPipeline() {
		return fmt.Errorf("%w: %q is not a pipeline DID", ErrInvalidPipelineDID, didStr)
	}
	return nil
}

// ListSubscriptions returns the operator's own subscriptions — the
// subscriber-direction records ("what am I subscribed to"; slice-12 D-s6 option
// a). Publisher-direction records (who subscribed to a local pipeline) are a
// separate concern and excluded. An empty result yields an empty slice, not an
// error.
func (s *Service) ListSubscriptions(ctx context.Context) ([]*store.Subscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	all, err := s.subs.List()
	if err != nil {
		return nil, err
	}
	out := make([]*store.Subscription, 0, len(all))
	for _, sub := range all {
		if directionOf(sub) == directionSubscriber {
			out = append(out, sub)
		}
	}
	return out, nil
}

// UpdateAllowList replaces the allow-list of pipelineDID with the rules built
// from patterns. It is all-or-nothing: the key and every pattern are validated
// before any write, so a single invalid input fails the whole call with the
// stored allow-list untouched. The key must be a parseable dplaax pipeline DID
// (ErrInvalidPipelineDID otherwise); each pattern must be a valid trust pattern
// (allowlist.ErrInvalidPattern otherwise). On success the rule set fully replaces
// the prior one. An already-canceled context is honored at entry, before any
// validation or write, so a disconnected/timed-out caller never mutates state.
func (s *Service) UpdateAllowList(ctx context.Context, pipelineDID string, patterns []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requirePipelineDID(pipelineDID); err != nil {
		return err
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
