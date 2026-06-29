package auditor

import (
	"fmt"
	"sync"
)

// AuditCandidate is one queued consumed head awaiting audit: its content address and the
// number of audit attempts so far (the backstop counter for a persistently-indeterminate
// NON-hole verdict; a hole's liveness is governed by the unresolved pool, not this count).
type AuditCandidate struct {
	HeadHash string
	Attempts int
}

// AuditQueue is the consumed-head registry seam: ingress registers a head, the Runner
// lists newest-first, removes on a terminal (or resolver-abandoned) verdict, and bumps the
// attempt counter on a non-hole indeterminate.
type AuditQueue interface {
	Add(headHash string) error
	ListNewest(n int) ([]AuditCandidate, error)
	Remove(headHash string) error
	IncrementAttempt(headHash string) error
}

// ErrNotQueued is returned by IncrementAttempt for a hash that is not queued.
var ErrNotQueued = fmt.Errorf("auditor: head not queued")

// MemQueue is the in-memory AuditQueue: newest-first, deduped by hash (a re-registered
// head keeps its existing Attempts — re-consuming the same content address must not reset
// audit progress).
type MemQueue struct {
	mu     sync.Mutex
	order  []string       // head hashes, newest first
	byHash map[string]int // head hash -> attempts
}

var _ AuditQueue = (*MemQueue)(nil)

// NewMemQueue returns an empty MemQueue.
func NewMemQueue() *MemQueue {
	return &MemQueue{byHash: make(map[string]int)}
}

// Add registers headHash newest-first; a re-add is a no-op that preserves Attempts.
func (q *MemQueue) Add(headHash string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.byHash[headHash]; ok {
		return nil
	}
	q.byHash[headHash] = 0
	q.order = append([]string{headHash}, q.order...)
	return nil
}

// ListNewest returns up to n candidates, newest first.
func (q *MemQueue) ListNewest(n int) ([]AuditCandidate, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]AuditCandidate, 0)
	for _, h := range q.order {
		if len(out) >= n {
			break
		}
		out = append(out, AuditCandidate{HeadHash: h, Attempts: q.byHash[h]})
	}
	return out, nil
}

// Remove drops headHash; removing an absent hash is a no-op.
func (q *MemQueue) Remove(headHash string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.byHash[headHash]; !ok {
		return nil
	}
	delete(q.byHash, headHash)
	for i, h := range q.order {
		if h == headHash {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
	return nil
}

// IncrementAttempt bumps the attempt counter for headHash, or ErrNotQueued if absent.
func (q *MemQueue) IncrementAttempt(headHash string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.byHash[headHash]; !ok {
		return ErrNotQueued
	}
	q.byHash[headHash]++
	return nil
}

// Len reports the number of queued heads.
func (q *MemQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.byHash)
}
