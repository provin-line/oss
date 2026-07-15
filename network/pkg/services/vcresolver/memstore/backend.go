package memstore

import (
	"sort"
	"sync"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
)

// Backend is the in-memory vcresolver.VariantBackend: named bytes and nothing
// else. What the names mean, whether the bytes are canonical, and which
// variant a body projects are all decided in vcresolver.VariantStore — this
// type could not answer any of those questions and is not asked to.
//
// State is lost on restart (the chain re-fills as new VCs arrive);
// audit-reachable deployments require the durable substrate instead.
type Backend struct {
	mu         sync.RWMutex
	variants   map[string]map[string][]byte
	projection map[string][]byte
}

var _ vcresolver.VariantBackend = (*Backend)(nil)

// NewBackend returns an empty Backend.
func NewBackend() *Backend {
	return &Backend{
		variants:   make(map[string]map[string][]byte),
		projection: make(map[string][]byte),
	}
}

// clone copies wire. Every byte crossing this boundary is copied in both
// directions: a map holding a caller's slice would let that caller keep
// writing into "immutable" storage through the alias, which is the one way an
// in-memory backend can break write-once without ever calling a write method.
func clone(wire []byte) []byte { return append([]byte(nil), wire...) }

// PutIfAbsent implements vcresolver.VariantBackend. The lock makes create and
// test-for-existence one step, so two concurrent puts of one name cannot both
// see it absent.
func (b *Backend) PutIfAbsent(bodyHex, variantHex string, wire []byte) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	set := b.variants[bodyHex]
	if set == nil {
		set = make(map[string][]byte)
		b.variants[bodyHex] = set
	}
	if _, ok := set[variantHex]; ok {
		return true, nil
	}
	set[variantHex] = clone(wire)
	return false, nil
}

// ReadVariant implements vcresolver.VariantBackend.
func (b *Backend) ReadVariant(bodyHex, variantHex string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	wire, ok := b.variants[bodyHex][variantHex]
	if !ok {
		return nil, vcresolver.ErrNotFound
	}
	return clone(wire), nil
}

// ListVariantHexes implements vcresolver.VariantBackend.
func (b *Backend) ListVariantHexes(bodyHex, fromExclusive string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return page(keysAfter(b.variants[bodyHex], fromExclusive), limit), nil
}

// ReadProjection implements vcresolver.VariantBackend.
func (b *Backend) ReadProjection(bodyHex string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	wire, ok := b.projection[bodyHex]
	if !ok {
		return nil, vcresolver.ErrNotFound
	}
	return clone(wire), nil
}

// WriteProjection implements vcresolver.VariantBackend.
func (b *Backend) WriteProjection(bodyHex string, wire []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.projection[bodyHex] = clone(wire)
	return nil
}

// ListBodyHexes implements vcresolver.VariantBackend: the union of bodies
// known through a projection and bodies known through a variant. A crash
// between the two writes leaves a body in only one of them, and a body missing
// from this enumeration would read to the forward index as having no
// successors.
func (b *Backend) ListBodyHexes(fromExclusive string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	seen := make(map[string]bool, len(b.variants)+len(b.projection))
	for h := range b.variants {
		if h > fromExclusive && len(b.variants[h]) > 0 {
			seen[h] = true
		}
	}
	for h := range b.projection {
		if h > fromExclusive {
			seen[h] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return page(out, limit), nil
}

// keysAfter returns m's keys strictly after fromExclusive, sorted.
func keysAfter(m map[string][]byte, fromExclusive string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k > fromExclusive {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// page truncates to limit. Callers pass an exhaustive sorted set, so a short
// return means exhausted — the full-page rule the listing contract requires.
func page(sorted []string, limit int) []string {
	if len(sorted) > limit {
		return sorted[:limit]
	}
	return sorted
}
