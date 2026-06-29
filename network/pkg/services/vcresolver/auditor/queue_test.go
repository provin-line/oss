package auditor_test

import (
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver/auditor"
)

func candidates(t *testing.T, q *auditor.MemQueue) map[string]int {
	t.Helper()
	l, err := q.ListNewest(100)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]int, len(l))
	for _, c := range l {
		m[c.HeadHash] = c.Attempts
	}
	return m
}

func TestMemQueue_NewestFirst_DedupRemoveIncrement(t *testing.T) {
	q := auditor.NewMemQueue()
	_ = q.Add("h1")
	_ = q.Add("h2")
	if q.Len() != 2 {
		t.Fatalf("len = %d, want 2", q.Len())
	}
	// Newest-first: h2 then h1.
	list, _ := q.ListNewest(10)
	if len(list) != 2 || list[0].HeadHash != "h2" || list[1].HeadHash != "h1" {
		t.Fatalf("order = %+v", list)
	}
	if one, _ := q.ListNewest(1); len(one) != 1 || one[0].HeadHash != "h2" {
		t.Fatalf("ListNewest(1) = %+v", one)
	}

	// IncrementAttempt, then a re-add must NOT reset attempts (re-consumption preserves progress).
	if err := q.IncrementAttempt("h1"); err != nil {
		t.Fatalf("IncrementAttempt: %v", err)
	}
	_ = q.Add("h1")
	if got := candidates(t, q); got["h1"] != 1 {
		t.Errorf("re-add reset attempts: h1 = %d, want 1", got["h1"])
	}
	if q.Len() != 2 {
		t.Fatalf("re-add duplicated: len = %d, want 2", q.Len())
	}

	// IncrementAttempt on absent → ErrNotQueued.
	if err := q.IncrementAttempt("absent"); !errors.Is(err, auditor.ErrNotQueued) {
		t.Errorf("increment absent: want ErrNotQueued, got %v", err)
	}

	// Remove.
	if err := q.Remove("h2"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if q.Len() != 1 {
		t.Fatalf("after remove: len = %d, want 1", q.Len())
	}
	if err := q.Remove("absent"); err != nil {
		t.Errorf("Remove absent: want nil, got %v", err)
	}
}
