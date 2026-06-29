package auditor

import (
	"context"
	"errors"
	"fmt"
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
	rec, ok := s.store.Get(headHash)
	if !ok {
		return AuditRecord{}, fmt.Errorf("%w: %q", ErrNotFound, headHash)
	}
	return rec, nil
}

// isContentAddress reports whether s is a "sha256:<64 lowercase hex>" address — the same
// predicate vcresolver applies (duplicated, not exported across the package boundary: a
// stable 4-line rule is not worth widening another service's API for).
func isContentAddress(s string) bool {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 || s[:len(prefix)] != prefix {
		return false
	}
	for _, r := range s[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
