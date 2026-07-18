package auditor

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
)

// ReceiptStore records, per emitted aggregate head, the exact set of consumed source content
// addresses that produced its SourceCommitment (slice-17o D-17o-2). The aggregate runtime
// writes it at emit (from the pooled set that computed SourceRoot, before the pool is
// cleared); the audit runner reads it to gather the consumed sources for
// VerifySourceCommitment. The receipt is an untrusted discovery LOCATOR — a wrong receipt
// yields Failed/Indeterminate (the resolved sources will not recompute the signed root),
// never a false Verified.
type ReceiptStore interface {
	// Put canonicalizes consumedHashes (sorted, deduplicated — see CanonicalizeConsumedSet;
	// an empty set or an empty-string member is an error) and records it for an emitted
	// head. First-write-wins: the first successful Put for a head pins its canonical
	// consumed set. A later Put whose canonical set is identical is a no-op (idempotent —
	// this is what makes aggregate re-emit retries safe). A later Put with a DIFFERENT
	// canonical set returns a wrapped ErrReceiptConflict; the recorded set is never
	// overwritten.
	Put(headHash string, consumedHashes []string) error
	// Get returns the consumed source content addresses for headHash. Absence is a
	// wrapped ErrNotFound — the coverage gate: no receipt → the head is audited
	// linear-only. Any OTHER error is a damaged/unreadable receipt and must surface
	// (the runner's corrupt-receipt fail-closed branch), never read as absence — a
	// damaged receipt silently downgrading an aggregate audit to linear-only would
	// present a weaker verdict class as intended coverage.
	Get(headHash string) ([]string, error)
}

// ErrReceiptConflict is returned by ReceiptStore.Put when headHash already has a recorded
// consumed-set receipt whose canonical content differs from the set being written. The safety
// property this enforces: a recorded commitment set never silently changes — the first
// successful Put for a head pins its consumed set, only a canonically-identical replay is
// tolerated afterward (idempotent, covering aggregate re-emit retries), and anything else is
// reported as a conflict rather than applied as a silent overwrite.
var ErrReceiptConflict = errors.New("auditor: receipt already recorded with a different consumed set")

// CanonicalizeConsumedSet sorts and deduplicates a receipt's consumed source content addresses
// into the canonical form ReceiptStore.Put persists and compares against. It rejects a set that
// is empty after dedup and any empty-string member. Both ReceiptStore implementations
// (MemReceiptStore and filestore.ReceiptStore) call this so canonicalization cannot drift
// between them.
func CanonicalizeConsumedSet(hashes []string) ([]string, error) {
	cp := make([]string, len(hashes))
	copy(cp, hashes)
	sort.Strings(cp)
	out := make([]string, 0, len(cp))
	for i, addr := range cp {
		if addr == "" {
			return nil, errors.New("auditor: consumed set contains an empty-string address")
		}
		if i == 0 || addr != cp[i-1] {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("auditor: consumed set is empty")
	}
	return out, nil
}

// MemReceiptStore is the in-memory ReceiptStore.
type MemReceiptStore struct {
	mu sync.RWMutex
	m  map[string][]string
}

var _ ReceiptStore = (*MemReceiptStore)(nil)

// NewMemReceiptStore returns an empty MemReceiptStore.
func NewMemReceiptStore() *MemReceiptStore {
	return &MemReceiptStore{m: make(map[string][]string)}
}

// Put canonicalizes consumedHashes and applies first-write-wins arbitration (see the
// ReceiptStore.Put doc): the canonical form is a defensive copy, so a later mutation of the
// caller's backing array cannot corrupt the receipt.
func (s *MemReceiptStore) Put(headHash string, consumedHashes []string) error {
	canonical, err := CanonicalizeConsumedSet(consumedHashes)
	if err != nil {
		return fmt.Errorf("auditor: put receipt for %q: %w", headHash, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.m[headHash]; ok {
		if reflect.DeepEqual(existing, canonical) {
			return nil // canonically-identical replay — idempotent
		}
		return fmt.Errorf("%w: head %q", ErrReceiptConflict, headHash)
	}
	s.m[headHash] = canonical
	return nil
}

// Get returns the consumed source content addresses for headHash, or a wrapped
// ErrNotFound when no receipt exists.
func (s *MemReceiptStore) Get(headHash string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[headHash]
	if !ok {
		return nil, fmt.Errorf("%w: no receipt for %q", ErrNotFound, headHash)
	}
	return c, nil
}
