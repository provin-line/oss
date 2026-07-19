package auditor_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

var validHash = "sha256:" + strings.Repeat("a", 64)

// GetStatus owns the domain logic: validate the content address, then read the store.
// A malformed hash is ErrInvalidArgument BEFORE any lookup; a well-formed miss is
// ErrNotFound; a hit returns the record verbatim.
func TestStatusService_GetStatus(t *testing.T) {
	store := auditor.NewMemStatusStore()
	svc := auditor.NewStatusService(store, auditor.NewMemReceiptStore())
	ctx := context.Background()

	// Malformed → ErrInvalidArgument (checked before the store, so a primed store is moot).
	for _, bad := range []string{"", "not-a-hash", "sha256:short", "sha256:" + strings.Repeat("A", 64)} {
		if _, err := svc.GetStatus(ctx, bad); !errors.Is(err, auditor.ErrInvalidArgument) {
			t.Errorf("hash %q: err = %v, want ErrInvalidArgument", bad, err)
		}
	}

	// Well-formed but absent → ErrNotFound.
	if _, err := svc.GetStatus(ctx, validHash); !errors.Is(err, auditor.ErrNotFound) {
		t.Errorf("absent: err = %v, want ErrNotFound", err)
	}

	// Hit → record verbatim.
	want := auditor.AuditRecord{
		Overall:   vc.ConfidenceVerified,
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Unix(1700000000, 0).UTC(),
	}
	if err := store.Put(validHash, want); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetStatus(ctx, validHash)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if got.Overall != want.Overall || got.Scope != want.Scope || !got.AuditedAt.Equal(want.AuditedAt) {
		t.Errorf("GetStatus = %+v, want %+v", got, want)
	}
}

func hashOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func recordAt(ts time.Time) auditor.AuditRecord {
	return auditor.AuditRecord{
		Overall:   vc.ConfidenceVerified,
		Axes:      vc.AxisResult{DataIntegrity: vc.ConfidenceVerified, SignerAuthenticity: vc.ConfidenceVerified, ChainConsistency: vc.ConfidenceVerified},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: ts,
	}
}

// ListStatuses pages by SCAN progress (the pagination convention): a
// time-filtered page may return fewer matches than the scan budget, with the
// last scanned head as the cursor, so filtered listings always advance.
func TestStatusService_ListStatuses(t *testing.T) {
	store := auditor.NewMemStatusStore()
	svc := auditor.NewStatusService(store, auditor.NewMemReceiptStore())
	day := func(d int) time.Time { return time.Date(2026, 7, d, 0, 0, 0, 0, time.UTC) }
	// Hashes sort a < b < c < d; timestamps deliberately do NOT follow hash order.
	if err := store.Put(hashOf('a'), recordAt(day(3))); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(hashOf('b'), recordAt(day(1))); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(hashOf('c'), recordAt(day(5))); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(hashOf('d'), recordAt(day(2))); err != nil {
		t.Fatal(err)
	}

	// Unfiltered, one scan page covering everything: exhausted (no cursor).
	entries, last, more, err := svc.ListStatuses(context.Background(), "", 10, time.Time{}, time.Time{})
	if err != nil || more || last != "" {
		t.Fatalf("unfiltered: last=%q more=%v err=%v", last, more, err)
	}
	if len(entries) != 4 || entries[0].Head != hashOf('a') || entries[3].Head != hashOf('d') {
		t.Fatalf("unfiltered entries = %+v, want a..d", entries)
	}

	// Scan budget smaller than the store: cursor = last SCANNED head.
	entries, last, more, err = svc.ListStatuses(context.Background(), "", 2, time.Time{}, time.Time{})
	if err != nil || !more || last != hashOf('b') || len(entries) != 2 {
		t.Fatalf("page1: entries=%d last=%q more=%v err=%v, want 2/%q/true", len(entries), last, more, err, hashOf('b'))
	}

	// Time filter [day2, day3]: matches b? b=day1 no; a=day3 yes; d=day2 yes.
	// Inclusive bounds. Scan budget 10 → one page, entries a and d only.
	entries, _, more, err = svc.ListStatuses(context.Background(), "", 10, day(2), day(3))
	if err != nil || more {
		t.Fatalf("filtered: more=%v err=%v", more, err)
	}
	if len(entries) != 2 || entries[0].Head != hashOf('a') || entries[1].Head != hashOf('d') {
		t.Fatalf("filtered entries = %+v, want [a d]", entries)
	}

	// Filtered with scan budget 1: the first page scans only 'a' (match),
	// cursor advances regardless of match count — no livelock.
	entries, last, more, err = svc.ListStatuses(context.Background(), "", 1, day(4), time.Time{})
	if err != nil || !more || last != hashOf('a') || len(entries) != 0 {
		t.Fatalf("filtered scan page: entries=%d last=%q more=%v err=%v, want 0/%q/true", len(entries), last, more, err, hashOf('a'))
	}
}

// A damaged entry ignores time filters: a caller narrowing by time must
// still learn that part of the record set is unreadable.
func TestStatusService_ListStatuses_DamagedBypassesFilters(t *testing.T) {
	store := &listDamageStatus{MemStatusStore: auditor.NewMemStatusStore(), damaged: hashOf('b')}
	svc := auditor.NewStatusService(store, auditor.NewMemReceiptStore())
	if err := store.Put(hashOf('a'), recordAt(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(hashOf('b'), recordAt(time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC))); err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) // excludes every intact record
	entries, _, _, err := svc.ListStatuses(context.Background(), "", 10, after, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Head != hashOf('b') || !entries[0].Damaged {
		t.Fatalf("entries = %+v, want only the damaged head", entries)
	}
}

// listDamageStatus marks one head Damaged in List output.
type listDamageStatus struct {
	*auditor.MemStatusStore
	damaged string
}

func (s *listDamageStatus) List(fromExclusive string, limit int) ([]auditor.HeadStatus, error) {
	entries, err := s.MemStatusStore.List(fromExclusive, limit)
	for i := range entries {
		if entries[i].Head == s.damaged {
			entries[i] = auditor.HeadStatus{Head: s.damaged, Damaged: true}
		}
	}
	return entries, err
}

// GetConsumed pages the receipt lexicographically and validates every served
// entry: a corrupt receipt must never leak malformed hashes.
func TestStatusService_GetConsumed(t *testing.T) {
	receipts := auditor.NewMemReceiptStore()
	svc := auditor.NewStatusService(auditor.NewMemStatusStore(), receipts)

	if _, _, err := svc.GetConsumed(context.Background(), "not-a-hash", "", 10); !errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("malformed head: err=%v, want ErrInvalidArgument", err)
	}
	if _, _, err := svc.GetConsumed(context.Background(), validHash, "", 10); !errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("no receipt: err=%v, want ErrNotFound", err)
	}

	consumed := []string{hashOf('c'), hashOf('a'), hashOf('b')} // unsorted on purpose
	if err := receipts.Put(validHash, "", consumed); err != nil {
		t.Fatal(err)
	}
	page, next, err := svc.GetConsumed(context.Background(), validHash, "", 2)
	if err != nil || len(page) != 2 || page[0] != hashOf('a') || page[1] != hashOf('b') || next != hashOf('b') {
		t.Fatalf("page1 = %v next=%q err=%v, want [a b]/b", page, next, err)
	}
	page, next, err = svc.GetConsumed(context.Background(), validHash, next, 2)
	if err != nil || len(page) != 1 || page[0] != hashOf('c') || next != "" {
		t.Fatalf("page2 = %v next=%q err=%v, want [c]/\"\"", page, next, err)
	}

	// A receipt entry that is not a content address is damage (internal), not data.
	// ReceiptStore.Put now ENFORCES the content-address grammar per member
	// (CanonicalizeConsumedSet), so a corrupt entry can no longer arrive through Put at
	// all — it can only arrive out-of-band (e.g. a tampered file read back by a durable
	// store). Simulate that with a stub reader returning an already-malformed entry
	// list directly from Get, bypassing Put's validation entirely; GetConsumed's own
	// per-entry validation must still catch it.
	garbageHead := hashOf('d')
	corruptSvc := auditor.NewStatusService(auditor.NewMemStatusStore(), corruptReceiptStub{head: garbageHead, entries: []string{"garbage-entry"}})
	if _, _, err := corruptSvc.GetConsumed(context.Background(), garbageHead, "", 10); err == nil || errors.Is(err, auditor.ErrNotFound) || errors.Is(err, auditor.ErrInvalidArgument) {
		t.Fatalf("corrupt receipt: err=%v, want a distinct damage error", err)
	}
}

// corruptReceiptStub is a minimal ReceiptReader returning a FIXED entry list for one head,
// bypassing ReceiptStore.Put's content-address grammar enforcement entirely — the seam for
// simulating an out-of-band corrupted receipt (e.g. a tampered file) that a durable store's
// Get would read back as-is.
type corruptReceiptStub struct {
	head    string
	entries []string
}

func (c corruptReceiptStub) Get(h string) ([]string, error) {
	if h != c.head {
		return nil, fmt.Errorf("%w: no receipt for %q", auditor.ErrNotFound, h)
	}
	return c.entries, nil
}
