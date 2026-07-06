package auditor

import (
	"fmt"
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
	// Put records the consumed source content addresses for an emitted head. Idempotent
	// (the latest write wins over immutable content).
	Put(headHash string, consumedHashes []string) error
	// Get returns the consumed source content addresses for headHash. Absence is a
	// wrapped ErrNotFound — the coverage gate: no receipt → the head is audited
	// linear-only. Any OTHER error is a damaged/unreadable receipt and must surface
	// (the runner's corrupt-receipt fail-closed branch), never read as absence — a
	// damaged receipt silently downgrading an aggregate audit to linear-only would
	// present a weaker verdict class as intended coverage.
	Get(headHash string) ([]string, error)
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

// Put records a defensive copy of consumedHashes for headHash (the runtime may reuse the
// backing array, so the receipt must not alias it).
func (s *MemReceiptStore) Put(headHash string, consumedHashes []string) error {
	cp := make([]string, len(consumedHashes))
	copy(cp, consumedHashes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[headHash] = cp
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
