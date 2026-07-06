package auditor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

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

// StatusService is the read service for the auditor's recorded evidence: the
// per-head verdicts (point lookup + enumeration) and the consumed-source
// receipts. It validates inputs and reads the stores, returning sentinel
// errors for the handler to map; the stores are pure persistence and the
// handler is pure proto↔domain conversion.
type StatusService struct {
	store    StatusStore
	receipts ReceiptReader
}

// NewStatusService returns a StatusService over the verdict store and the
// receipt reader — the service that serves audit evidence owns both
// evidence reads.
func NewStatusService(store StatusStore, receipts ReceiptReader) *StatusService {
	return &StatusService{store: store, receipts: receipts}
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

// ListStatuses returns one scan page of recorded verdicts: up to scanLimit
// store entries strictly after fromExclusive (lexicographic), narrowed to
// those whose AuditedAt lies within [after, before] (inclusive; a zero bound
// is open). The page is bounded by SCAN progress, not matches — lastScanned
// is the cursor for the next call and more reports whether the store may
// hold entries past it, so a filtered listing always advances (the
// pagination convention). A Damaged entry bypasses the time filter: it has
// no readable timestamp, and a caller narrowing by time must still learn
// that part of the record set is unreadable.
func (s *StatusService) ListStatuses(ctx context.Context, fromExclusive string, scanLimit int, after, before time.Time) (entries []HeadStatus, lastScanned string, more bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, "", false, err
	}
	if scanLimit <= 0 {
		return nil, "", false, fmt.Errorf("%w: scan limit %d is not positive", ErrInvalidArgument, scanLimit)
	}
	page, err := s.store.List(fromExclusive, scanLimit)
	if err != nil {
		return nil, "", false, fmt.Errorf("list audit statuses: %w", err)
	}
	for _, e := range page {
		if !e.Damaged {
			if !after.IsZero() && e.Record.AuditedAt.Before(after) {
				continue
			}
			if !before.IsZero() && e.Record.AuditedAt.After(before) {
				continue
			}
		}
		entries = append(entries, e)
	}
	if len(page) == scanLimit {
		return entries, page[len(page)-1].Head, true, nil
	}
	return entries, "", false, nil
}

// GetConsumed returns one page of the recorded receipt for headHash: the
// consumed source content addresses, lexicographic (the receipt is a set —
// storage order is not contractual), strictly after fromExclusive, up to
// limit; next is the continuation cursor ("" when exhausted). A missing
// receipt passes ErrNotFound through (no consumed-set coverage recorded on
// this node); a receipt entry that is not a content address is DAMAGE and
// surfaces as an error — it must never leak to a consumer.
func (s *StatusService) GetConsumed(ctx context.Context, headHash, fromExclusive string, limit int) (page []string, next string, err error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if !isContentAddress(headHash) {
		return nil, "", fmt.Errorf("%w: head_hash %q is not a sha256:<hex> content address", ErrInvalidArgument, headHash)
	}
	if limit <= 0 {
		return nil, "", fmt.Errorf("%w: limit %d is not positive", ErrInvalidArgument, limit)
	}
	consumed, err := s.receipts.Get(headHash)
	if err != nil {
		// ErrNotFound passes through wrapped (the handler serves not_found);
		// any other error is a damaged receipt and surfaces as internal.
		return nil, "", fmt.Errorf("consumed sources for %q: %w", headHash, err)
	}
	sorted := make([]string, 0, len(consumed))
	for _, c := range consumed {
		if !isContentAddress(c) {
			return nil, "", fmt.Errorf("damaged receipt for %q: entry %q is not a content address", headHash, c)
		}
		if c > fromExclusive {
			sorted = append(sorted, c)
		}
	}
	sort.Strings(sorted)
	if len(sorted) > limit {
		return sorted[:limit], sorted[limit-1], nil
	}
	return sorted, "", nil
}

// isContentAddress delegates to the exported grammar predicate
// (vc.IsContentAddress) — the convergence point slice-7 §4 and the API
// responsibility review predicted for the per-service copies.
func isContentAddress(s string) bool { return vc.IsContentAddress(s) }
