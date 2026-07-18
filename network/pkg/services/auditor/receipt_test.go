package auditor

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The receipt is the emit-time discovery locator (slice-17o D-17o-2): it maps an emitted
// aggregate head's content address to the exact set of consumed source content addresses,
// captured by the aggregate runtime from the pooled set that computed SourceRoot. The audit
// runner reads it to gather the consumed sources for VerifySourceCommitment.

// addr builds a well-formed sha256:<hex> content address from a single repeated hex digit —
// readable enough to tell fixtures apart, and its ordering matches ordinary string order
// (addr("b") < addr("c")) since every fixture shares the same length.
func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

func TestMemReceiptStore_RoundTrip(t *testing.T) {
	s := NewMemReceiptStore()
	head := "sha256:aaa"
	consumed := []string{addr("b"), addr("c")}
	if err := s.Put(head, consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(head)
	if err != nil {
		t.Fatal("Get: want ok=true for a stored head")
	}
	if !reflect.DeepEqual(got, consumed) {
		t.Errorf("Get = %v, want %v", got, consumed)
	}
}

func TestMemReceiptStore_AbsentMiss(t *testing.T) {
	s := NewMemReceiptStore()
	if _, err := s.Get("sha256:missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: want ErrNotFound for an unstored head, got %v", err)
	}
}

// The stored slice is defensively copied so a later mutation of the caller's slice cannot
// corrupt the receipt (the runtime reuses buffers).
func TestMemReceiptStore_Isolation(t *testing.T) {
	s := NewMemReceiptStore()
	consumed := []string{addr("b"), addr("c")}
	if err := s.Put("sha256:aaa", consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed[0] = "sha256:MUTATED"
	got, _ := s.Get("sha256:aaa")
	if got[0] != addr("b") {
		t.Errorf("Get[0] = %q, want unchanged %q (receipt must copy on Put)", got[0], addr("b"))
	}
}

// The frozen contract (D1): Put canonicalizes (sort, dedup) and is first-write-wins. A
// canonically-identical replay (including a permuted one) is an idempotent no-op — this is
// what makes aggregate re-emit retries safe. A canonically-different Put is a conflict: the
// recorded set is pinned by the first successful write and never silently changes.
func TestMemReceiptStore_CanonicalizationAndFirstWriteWins(t *testing.T) {
	s := NewMemReceiptStore()
	head := "sha256:aaa"

	// Unsorted + duplicated input canonicalizes to a sorted, deduped stored set.
	if err := s.Put(head, []string{addr("c"), addr("b"), addr("b")}); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	want := []string{addr("b"), addr("c")}
	if got, err := s.Get(head); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after canonicalizing Put = %v (err %v), want %v", got, err, want)
	}

	// Identical replay (same canonical form) is a no-op.
	if err := s.Put(head, []string{addr("b"), addr("c")}); err != nil {
		t.Fatalf("identical replay: want nil, got %v", err)
	}
	if got, _ := s.Get(head); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after identical replay = %v, want unchanged %v", got, want)
	}

	// Permuted-but-equal (canonicalizes to the same set) is also a no-op.
	if err := s.Put(head, []string{addr("c"), addr("b")}); err != nil {
		t.Fatalf("permuted-but-equal replay: want nil, got %v", err)
	}
	if got, _ := s.Get(head); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after permuted-but-equal replay = %v, want unchanged %v", got, want)
	}

	// A different canonical set is a conflict — the recorded set is never overwritten.
	err := s.Put(head, []string{addr("d")})
	if !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("different set: want ErrReceiptConflict, got %v", err)
	}
	if got, _ := s.Get(head); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get after rejected conflicting Put = %v, want unchanged %v", got, want)
	}
}

// The canonicalizer enforces the content-address grammar per member (sha256:<64hex>) — a
// caller-controlled malformed member must never pin an irreversible receipt: every reader
// downstream (GetConsumedSources, the source-commitment auditor) treats a damaged/malformed
// entry as fail-closed damage, and a "\n"-bearing member would otherwise let two DIFFERENT
// consumed sets collide under the same joined signed view (the wireauth handler's
// deterministic "\n" join over the canonical set) — the grammar's fixed length and hex-only
// alphabet are what make that join collision-free.
func TestMemReceiptStore_PutValidation(t *testing.T) {
	tests := []struct {
		name string
		in   []string
	}{
		{"empty set", []string{}},
		{"nil set", nil},
		{"empty-string member", []string{addr("a"), ""}},
		{"non-address member", []string{addr("a"), "not-a-content-hash"}},
		{"newline-bearing member", []string{addr("a"), addr("b") + "\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemReceiptStore()
			if err := s.Put("sha256:aaa", tt.in); err == nil {
				t.Fatalf("Put(%v): want error", tt.in)
			}
		})
	}
}
