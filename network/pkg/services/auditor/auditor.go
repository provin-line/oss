// Package auditor is the verdict half of the async chain-audit path (slice-17h): a
// background Runner drains a registry of consumed chain heads, assembles each chain from
// the LOCAL store (the substrate slice-17g fills) by reusing chainwalk over a local-store
// resolver, runs vc.VerifyChain (L1 proofs + chain structure + origin), and records a
// per-head audit status (three-state + per-axis + coverage).
//
// It is purely additive: it verifies and records, mutating nothing the batch resolver
// owns. A still-unfilled hole is an Indeterminate verdict (verdict-not-yet-computable, not
// Failed); it is finalized only when the missing predecessor is in neither the store nor
// the unresolved pool (the resolver has given up). Deep consumed-set (SourceCommitment)
// verification is out of this slice — every record's Scope marks SourceCommitmentEvaluated
// false, so a linear-only verdict can never be read as a full aggregate one.
package auditor

import (
	"sync"
	"time"

	"github.com/provin-line/oss/vc"
)

// AuditScope records what an AuditRecord's verdict actually covers, so a reader (the
// slice-17i API) can never present a linear-only verdict as a full aggregate one. 17h
// always sets SourceCommitmentEvaluated false (the consumed-set check is a later slice).
type AuditScope struct {
	// LinearChain reports that the previousCredential spine was verified (always true in 17h).
	LinearChain bool
	// SourceCommitmentEvaluated reports that the consumed-set / SourceCommitment was deeply
	// verified (always false in 17h — that is the aggregate-audit extension).
	SourceCommitmentEvaluated bool
}

// AuditRecord is the recorded verdict for one head: the vc.VerifyChain projection plus
// coverage and the audit time. For a real verdict the Overall/Axes/Notations are verbatim
// from VerifyChain; for an assembly hole they are a synthetic Indeterminate (all axes
// explicitly Indeterminate — the AxisResult zero value is Failed, so it must be set).
type AuditRecord struct {
	Overall   vc.ConfidenceState
	Axes      vc.AxisResult
	Notations []string
	Scope     AuditScope
	AuditedAt time.Time
}

// StatusStore records the latest audit verdict per head. In-memory for the PoC.
type StatusStore interface {
	Put(headHash string, rec AuditRecord) error
	Get(headHash string) (AuditRecord, bool)
}

// MemStatusStore is the in-memory StatusStore (lost on restart; re-audited as heads
// re-register).
type MemStatusStore struct {
	mu sync.RWMutex
	m  map[string]AuditRecord
}

var _ StatusStore = (*MemStatusStore)(nil)

// NewMemStatusStore returns an empty MemStatusStore.
func NewMemStatusStore() *MemStatusStore {
	return &MemStatusStore{m: make(map[string]AuditRecord)}
}

// Put records rec for headHash (overwriting the prior verdict — the latest audit wins).
func (s *MemStatusStore) Put(headHash string, rec AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[headHash] = rec
	return nil
}

// Get returns the recorded verdict for headHash and whether one exists.
func (s *MemStatusStore) Get(headHash string) (AuditRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[headHash]
	return rec, ok
}
