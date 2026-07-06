// Package storecontract is the shared behavioral suite for auditor
// StatusStore, ReceiptStore, and AuditQueue implementations: the mem and file
// stores both run it, so their semantics (sentinel errors, dedup, attempt
// preservation, ordering) cannot drift apart silently. Implementation-specific
// behavior (restart survival, damage handling) stays in each package's tests.
package storecontract

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

// Hash returns a distinct well-formed content address per one-byte seed.
func Hash(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

// Record returns a fully-populated Verified record (a shape every legitimate
// writer produces: non-zero AuditedAt, linear scope).
func Record() auditor.AuditRecord {
	v := vc.ConfidenceVerified
	return auditor.AuditRecord{
		Overall:   v,
		Axes:      vc.AxisResult{DataIntegrity: v, SignerAuthenticity: v, ChainConsistency: v},
		Notations: []string{"n1"},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
}

// StatusStore runs the StatusStore contract against a fresh implementation.
func StatusStore(t *testing.T, newStore func(t *testing.T) auditor.StatusStore) {
	t.Helper()
	s := newStore(t)
	h := Hash(1)
	if _, err := s.Get(h); !errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	rec := Record()
	if err := s.Put(h, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("roundtrip mismatch:\n got = %+v\nwant = %+v", got, rec)
	}
	// The abandon lifecycle marker round-trips: an implementation that drops it
	// would resurrect the "retrying or gave up?" ambiguity it exists to kill.
	ab := Record()
	ab.Overall = vc.ConfidenceIndeterminate
	ab.Axes = vc.AxisResult{
		DataIntegrity:      vc.ConfidenceIndeterminate,
		SignerAuthenticity: vc.ConfidenceIndeterminate,
		ChainConsistency:   vc.ConfidenceIndeterminate,
	}
	ab.Notations = []string{"audit abandoned: exhausted 3 attempts (head unreadable)"}
	ab.Abandoned = true
	hAb := Hash(2)
	if err := s.Put(hAb, ab); err != nil {
		t.Fatalf("Put(abandoned): %v", err)
	}
	if got, err := s.Get(hAb); err != nil || !got.Abandoned {
		t.Fatalf("abandoned roundtrip: got %+v (err %v), want Abandoned=true", got, err)
	}

	// Latest audit wins.
	rec2 := rec
	rec2.Overall = vc.ConfidenceFailed
	if err := s.Put(h, rec2); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(h); err != nil || got.Overall != vc.ConfidenceFailed {
		t.Fatalf("overwrite: got %+v (err %v), want Failed", got, err)
	}
}

// ReceiptStore runs the ReceiptStore contract against a fresh implementation.
func ReceiptStore(t *testing.T, newStore func(t *testing.T) auditor.ReceiptStore) {
	t.Helper()
	s := newStore(t)
	h := Hash(2)
	if _, err := s.Get(h); !errors.Is(err, auditor.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	consumed := []string{Hash(3), Hash(4)}
	if err := s.Put(h, consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed[0] = "clobbered" // the stored copy must not alias the caller's slice
	got, err := s.Get(h)
	if err != nil || len(got) != 2 || got[0] != Hash(3) || got[1] != Hash(4) {
		t.Fatalf("roundtrip = %v (err %v)", got, err)
	}
}

// Queue runs the AuditQueue contract against a fresh implementation.
func Queue(t *testing.T, newQueue func(t *testing.T) auditor.AuditQueue) {
	t.Helper()
	q := newQueue(t)
	// Len is not on the AuditQueue interface but both implementations carry it.
	qlen := func() int { return q.(interface{ Len() int }).Len() }
	h1, h2 := Hash(5), Hash(6)
	if err := q.Add(h1); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(h2); err != nil {
		t.Fatal(err)
	}
	if err := q.IncrementAttempt(h1); err != nil {
		t.Fatal(err)
	}
	// Re-add is a dedup no-op preserving attempts and position.
	if err := q.Add(h1); err != nil {
		t.Fatal(err)
	}
	list, err := q.ListNewest(10)
	if err != nil || len(list) != 2 || list[0].HeadHash != h2 || list[1].HeadHash != h1 || list[1].Attempts != 1 {
		t.Fatalf("list = %+v (err %v), want newest-first h2,h1(attempts=1)", list, err)
	}
	if one, err := q.ListNewest(1); err != nil || len(one) != 1 || one[0].HeadHash != h2 {
		t.Fatalf("ListNewest(1) = %+v (err %v)", one, err)
	}
	if qlen() != 2 {
		t.Fatalf("Len = %d, want 2", qlen())
	}
	if err := q.Remove(Hash(7)); err != nil {
		t.Errorf("Remove absent: want no-op, got %v", err)
	}
	if err := q.IncrementAttempt(Hash(8)); !errors.Is(err, auditor.ErrNotQueued) {
		t.Errorf("IncrementAttempt absent: want ErrNotQueued, got %v", err)
	}
	if err := q.Remove(h2); err != nil {
		t.Fatal(err)
	}
	if qlen() != 1 {
		t.Fatalf("post-remove Len = %d, want 1", qlen())
	}
}
