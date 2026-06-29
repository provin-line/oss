// Package memstore is the in-memory PoC implementation of the vcresolver Store
// and Pool. State is lost on restart (the chain re-fills as new VCs arrive);
// audit-reachable deployments require the durable substrate instead.
package memstore

import (
	"fmt"
	"sync"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// Store is an in-memory vcresolver.Store keyed by content address.
type Store struct {
	mu sync.RWMutex
	m  map[string]*vc.PipelinePassCredential
}

var _ vcresolver.Store = (*Store)(nil)

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{m: make(map[string]*vc.PipelinePassCredential)}
}

// Put stores cred at hash (overwriting is harmless — content-addressed, so the
// same hash carries the same body).
func (s *Store) Put(hash string, cred *vc.PipelinePassCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[hash] = cred
	return nil
}

// Get returns the VC at hash, or vcresolver.ErrNotFound.
func (s *Store) Get(hash string) (*vc.PipelinePassCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[hash]
	if !ok {
		return nil, vcresolver.ErrNotFound
	}
	return c, nil
}

// Pool is an in-memory vcresolver.Pool: newest-first, deduped/upserted by hash.
type Pool struct {
	mu     sync.Mutex
	order  []string // hashes, newest first
	byHash map[string]vcresolver.UnresolvedEntry
}

var _ vcresolver.Pool = (*Pool)(nil)

// NewPool returns an empty Pool.
func NewPool() *Pool {
	return &Pool{byHash: make(map[string]vcresolver.UnresolvedEntry)}
}

// Add upserts e keyed by Hash: a new hole is prepended (newest-first); a
// re-added hole is not duplicated but has its empty UpstreamEndpoint /
// ReferrerIssuer filled from e (a non-empty hint is never clobbered with an
// empty one), preserving RetryCount and keeping the MINIMUM AssemblyDepth (the
// shortest path to any head wins). A non-positive AssemblyDepth is rejected: a
// real hole is always >= 1 (StoreVC enqueues at assemblyDepth+1), so a 0 from a
// misconstructed entry must not be admitted and win keep-min.
func (p *Pool) Add(e vcresolver.UnresolvedEntry) error {
	if e.AssemblyDepth < 1 {
		return fmt.Errorf("%w: AssemblyDepth %d must be >= 1", vcresolver.ErrInvalidArgument, e.AssemblyDepth)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.byHash[e.Hash]; ok {
		if existing.UpstreamEndpoint == "" {
			existing.UpstreamEndpoint = e.UpstreamEndpoint
		}
		if existing.ReferrerIssuer == "" {
			existing.ReferrerIssuer = e.ReferrerIssuer
		}
		if e.AssemblyDepth < existing.AssemblyDepth {
			existing.AssemblyDepth = e.AssemblyDepth
		}
		p.byHash[e.Hash] = existing
		return nil
	}
	p.byHash[e.Hash] = e
	p.order = append([]string{e.Hash}, p.order...)
	return nil
}

// Get returns the entry at hash and whether it is present. The batch resolver re-reads
// the live entry before acting, since an earlier entry in the same drain may have lowered
// this one's AssemblyDepth (keep-min) or resolved it.
func (p *Pool) Get(hash string) (vcresolver.UnresolvedEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byHash[hash]
	return e, ok
}

// ListNewest returns up to n entries, newest first.
func (p *Pool) ListNewest(n int) ([]vcresolver.UnresolvedEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]vcresolver.UnresolvedEntry, 0)
	for _, h := range p.order {
		if len(out) >= n {
			break
		}
		out = append(out, p.byHash[h])
	}
	return out, nil
}

// Remove drops the entry at hash. Removing an absent hash is a no-op.
func (p *Pool) Remove(hash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.byHash[hash]; !ok {
		return nil
	}
	delete(p.byHash, hash)
	for i, h := range p.order {
		if h == hash {
			p.order = append(p.order[:i], p.order[i+1:]...)
			break
		}
	}
	return nil
}

// IncrementRetry bumps the retry counter for hash, or vcresolver.ErrNotFound.
func (p *Pool) IncrementRetry(hash string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byHash[hash]
	if !ok {
		return vcresolver.ErrNotFound
	}
	e.RetryCount++
	p.byHash[hash] = e
	return nil
}

// Has reports whether a hole is currently queued — the read-only liveness signal the audit
// runner consults before finalizing an Indeterminate verdict (slice-17h, D-17h-4).
func (p *Pool) Has(hash string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.byHash[hash]
	return ok
}

// Len reports the number of queued holes.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byHash)
}
