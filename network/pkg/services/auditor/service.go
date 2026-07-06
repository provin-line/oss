package auditor

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/vc"
)

// Read-service sentinel errors. The AuditService handler maps these to Connect codes
// (errors.Is, never string matching), keeping domain logic out of the transport layer
// (AGENTS.md: handler = proto↔domain + error mapping only; service = domain logic).
var (
	// ErrNotFound is a well-formed head with no recorded verdict yet.
	ErrNotFound = errors.New("auditor: no verdict recorded")
	// ErrInvalidArgument is a malformed content address.
	ErrInvalidArgument = errors.New("auditor: invalid argument")
)

// StatusService is the read service for recorded audit verdicts: it validates the head
// content address and reads the status store, returning sentinel errors for the handler
// to map. It owns the domain logic (validation + lookup); the store is pure persistence
// and the handler is pure proto↔domain conversion.
type StatusService struct {
	store StatusStore
}

// NewStatusService returns a StatusService backed by store.
func NewStatusService(store StatusStore) *StatusService {
	return &StatusService{store: store}
}

// GetStatus returns the latest recorded verdict for headHash. A malformed content address
// is ErrInvalidArgument; a well-formed head with no recorded verdict is ErrNotFound.
func (s *StatusService) GetStatus(ctx context.Context, headHash string) (AuditRecord, error) {
	if !isContentAddress(headHash) {
		return AuditRecord{}, fmt.Errorf("%w: head_hash %q is not a sha256:<hex> content address", ErrInvalidArgument, headHash)
	}
	rec, err := s.store.Get(headHash)
	if err != nil {
		// ErrNotFound passes through wrapped (the handler serves not_found);
		// any other error is a damaged record and surfaces as internal —
		// never as absence.
		return AuditRecord{}, fmt.Errorf("audit status for %q: %w", headHash, err)
	}
	return rec, nil
}

// isContentAddress delegates to the exported grammar predicate
// (vc.IsContentAddress) — the convergence point slice-7 §4 and the API
// responsibility review predicted for the per-service copies.
func isContentAddress(s string) bool { return vc.IsContentAddress(s) }
