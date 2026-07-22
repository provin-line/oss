package auditor

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/provin-line/oss/network/pkg/services/auditor/wirecontract"
	"github.com/provin-line/oss/vc"
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
	// an empty set or an empty-string member is an error) and records it, together with
	// registrantDID, for an emitted head. First-write-wins: the first successful Put for a
	// head pins its canonical consumed set AND registrantDID together. A later Put whose
	// canonical set is identical is a no-op (idempotent — this is what makes aggregate
	// re-emit retries safe) that does NOT overwrite the recorded registrantDID, even when
	// the replay's registrantDID differs from the one originally recorded — only the FIRST
	// successful write ever sets it. A later Put with a DIFFERENT canonical set returns a
	// wrapped ErrReceiptConflict; the recorded set (and registrant) is never overwritten.
	// The conflict rule stays content-only: registrantDID never participates in the
	// conflict comparison, only the consumed set does.
	//
	// registrantDID is the DID registering this evidence (an AUDIT-TRAIL fact recorded
	// alongside the receipt): the wireauth-proven caller DID on the RPC path, the emitting
	// credential's own issuer (Process) DID on the in-process emission path. Empty is
	// allowed — a caller with no identity in scope records "" rather than fabricating one.
	// Recording registrantDID is NOT an ownership check: Put never rejects a Put whose
	// registrantDID differs from anything about the head itself (e.g. the credential's own
	// issuer). Binding the recorded registrant to head ownership is a later contract stage.
	Put(headHash string, registrantDID string, consumedHashes []string) error
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

// CanonicalizeConsumedSet points at wirecontract.CanonicalizeConsumedSet —
// moved into the leaf wirecontract package (PR3b Task 2) so a client-only
// consumer need not import this service root; this alias keeps existing
// call sites (MemReceiptStore.Put below, filestore.ReceiptStore,
// EvidenceService.Register, the handler) unchanged. See
// wirecontract.CanonicalizeConsumedSet for the full doc.
var CanonicalizeConsumedSet = wirecontract.CanonicalizeConsumedSet

// isContentAddress delegates to the exported grammar predicate (vc.IsContentAddress) — the ONE
// definition every content-address check in this package converges on (headHash validation in
// service.go and evidence.go, receipt entries here and in service.go's GetConsumed, the
// source-commitment gather in runner.go). Living beside CanonicalizeConsumedSet keeps the
// tightest coupling — the canonicalizer's per-member grammar enforcement — textually adjacent
// to the predicate it enforces.
func isContentAddress(s string) bool { return vc.IsContentAddress(s) }

// memReceipt is one recorded head's canonical consumed set plus the registrant DID recorded
// alongside it at first write (see ReceiptStore.Put's doc).
type memReceipt struct {
	consumed   []string
	registrant string
}

// MemReceiptStore is the in-memory ReceiptStore.
type MemReceiptStore struct {
	mu sync.RWMutex
	m  map[string]memReceipt
}

var _ ReceiptStore = (*MemReceiptStore)(nil)

// NewMemReceiptStore returns an empty MemReceiptStore.
func NewMemReceiptStore() *MemReceiptStore {
	return &MemReceiptStore{m: make(map[string]memReceipt)}
}

// Put canonicalizes consumedHashes and applies first-write-wins arbitration (see the
// ReceiptStore.Put doc): the canonical form is a defensive copy, so a later mutation of the
// caller's backing array cannot corrupt the receipt. registrantDID is recorded ONLY on the
// first successful write for a head — a canonically-identical replay is a no-op and leaves
// the originally-recorded registrantDID untouched, even if this call's registrantDID differs.
func (s *MemReceiptStore) Put(headHash string, registrantDID string, consumedHashes []string) error {
	canonical, err := CanonicalizeConsumedSet(consumedHashes)
	if err != nil {
		return fmt.Errorf("auditor: put receipt for %q: %w", headHash, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.m[headHash]; ok {
		if reflect.DeepEqual(existing.consumed, canonical) {
			return nil // canonically-identical replay — idempotent, registrant untouched
		}
		return fmt.Errorf("%w: head %q", ErrReceiptConflict, headHash)
	}
	s.m[headHash] = memReceipt{consumed: canonical, registrant: registrantDID}
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
	return c.consumed, nil
}

// registrantDID is an unexported test-visible accessor for the registrant recorded
// alongside headHash's receipt (empty string + false if no receipt is recorded at all). It
// exists solely so this package's own tests can observe first-write-wins registrant
// arbitration on the mem store — nothing in production reads a recorded registrant back
// (the file envelope is the audit record; see ReceiptStore.Put's doc on why no public
// reader exists yet).
func (s *MemReceiptStore) registrantDID(headHash string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.m[headHash]
	return r.registrant, ok
}
