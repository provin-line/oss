package auditor

import (
	"reflect"
	"testing"
)

// The receipt is the emit-time discovery locator (slice-17o D-17o-2): it maps an emitted
// aggregate head's content address to the exact set of consumed source content addresses,
// captured by the aggregate runtime from the pooled set that computed SourceRoot. The audit
// runner reads it to gather the consumed sources for VerifySourceCommitment.

func TestMemReceiptStore_RoundTrip(t *testing.T) {
	s := NewMemReceiptStore()
	head := "sha256:aaa"
	consumed := []string{"sha256:b", "sha256:c"}
	if err := s.Put(head, consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get(head)
	if !ok {
		t.Fatal("Get: want ok=true for a stored head")
	}
	if !reflect.DeepEqual(got, consumed) {
		t.Errorf("Get = %v, want %v", got, consumed)
	}
}

func TestMemReceiptStore_AbsentMiss(t *testing.T) {
	s := NewMemReceiptStore()
	if _, ok := s.Get("sha256:missing"); ok {
		t.Error("Get: want ok=false for an unstored head")
	}
}

// The stored slice is defensively copied so a later mutation of the caller's slice cannot
// corrupt the receipt (the runtime reuses buffers).
func TestMemReceiptStore_Isolation(t *testing.T) {
	s := NewMemReceiptStore()
	consumed := []string{"sha256:b", "sha256:c"}
	if err := s.Put("sha256:aaa", consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed[0] = "sha256:MUTATED"
	got, _ := s.Get("sha256:aaa")
	if got[0] != "sha256:b" {
		t.Errorf("Get[0] = %q, want unchanged sha256:b (receipt must copy on Put)", got[0])
	}
}
