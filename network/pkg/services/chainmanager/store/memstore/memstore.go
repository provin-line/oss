// Package memstore is the in-memory chainmanager store: SubscriptionStore and
// AllowListStore backed by mutex-guarded maps. State is lost on restart (PoC /
// tests); durable deployments use the yamlstore (or its successor) instead.
//
// Every Save/Get/List deep-copies the mutable fields it crosses the boundary
// with — Subscription.ConnectionInfo and the []AllowRule slices — so a caller
// can never mutate stored state outside the mutex by holding onto a reference it
// passed in or got back. This is the isolation the yamlstore gets for free by
// round-tripping through disk (slice-9 Codex Medium).
package memstore

import (
	"sync"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// SubscriptionStore is an in-memory store.SubscriptionStore keyed by id.
type SubscriptionStore struct {
	mu sync.RWMutex
	m  map[string]*store.Subscription
}

var _ store.SubscriptionStore = (*SubscriptionStore)(nil)

// NewSubscriptionStore returns an empty SubscriptionStore.
func NewSubscriptionStore() *SubscriptionStore {
	return &SubscriptionStore{m: make(map[string]*store.Subscription)}
}

func (s *SubscriptionStore) Save(sub *store.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sub.ID] = copySubscription(sub)
	return nil
}

func (s *SubscriptionStore) Get(id string) (*store.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return copySubscription(sub), nil
}

func (s *SubscriptionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func (s *SubscriptionStore) List() ([]*store.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Subscription, 0, len(s.m))
	for _, sub := range s.m {
		out = append(out, copySubscription(sub))
	}
	return out, nil
}

// copySubscription returns a deep copy: the struct value plus a fresh
// ConnectionInfo map so the copy shares no mutable state with the original.
func copySubscription(sub *store.Subscription) *store.Subscription {
	c := *sub
	if sub.ConnectionInfo != nil {
		c.ConnectionInfo = make(map[string]string, len(sub.ConnectionInfo))
		for k, v := range sub.ConnectionInfo {
			c.ConnectionInfo[k] = v
		}
	}
	return &c
}

// AllowListStore is an in-memory store.AllowListStore keyed by pipeline DID, with
// full-replacement Save.
type AllowListStore struct {
	mu sync.RWMutex
	m  map[string][]store.AllowRule
}

var _ store.AllowListStore = (*AllowListStore)(nil)

// NewAllowListStore returns an empty AllowListStore.
func NewAllowListStore() *AllowListStore {
	return &AllowListStore{m: make(map[string][]store.AllowRule)}
}

func (s *AllowListStore) Save(pipelineDID string, rules []store.AllowRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[pipelineDID] = copyRules(rules)
	return nil
}

// Get returns the pipeline's rules. An absent allow-list is empty, not an error
// (default-distrust: no rules means no subscribers).
func (s *AllowListStore) Get(pipelineDID string) ([]store.AllowRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules, ok := s.m[pipelineDID]
	if !ok {
		return nil, nil
	}
	return copyRules(rules), nil
}

// copyRules returns a fresh slice; AllowRule is a value type, so a slice copy is
// a deep copy.
func copyRules(rules []store.AllowRule) []store.AllowRule {
	if rules == nil {
		return nil
	}
	out := make([]store.AllowRule, len(rules))
	copy(out, rules)
	return out
}
