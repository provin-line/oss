package memstore_test

import (
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

func TestStore_PutGetNotFound(t *testing.T) {
	s := memstore.NewStore()
	if _, err := s.Get("sha256:x"); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	cred := &vc.PipelinePassCredential{}
	if err := s.Put("sha256:abc", cred); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get("sha256:abc")
	if err != nil || got != cred {
		t.Fatalf("Get: got %v err %v", got, err)
	}
}

func TestPool_NewestFirst_Upsert_RetryRemove(t *testing.T) {
	p := memstore.NewPool()
	_ = p.Add(vcresolver.UnresolvedEntry{Hash: "h1", UpstreamEndpoint: "", ReferrerIssuer: "did:a"})
	_ = p.Add(vcresolver.UnresolvedEntry{Hash: "h2", UpstreamEndpoint: "https://u2"})
	if p.Len() != 2 {
		t.Fatalf("len = %d, want 2", p.Len())
	}
	// Newest-first: h2 then h1.
	list, _ := p.ListNewest(10)
	if len(list) != 2 || list[0].Hash != "h2" || list[1].Hash != "h1" {
		t.Fatalf("order = %+v", list)
	}
	// ListNewest bound.
	if one, _ := p.ListNewest(1); len(one) != 1 || one[0].Hash != "h2" {
		t.Fatalf("ListNewest(1) = %+v", one)
	}

	// Upsert: re-add h1 with a usable endpoint fills the empty hint; no dup.
	_ = p.Add(vcresolver.UnresolvedEntry{Hash: "h1", UpstreamEndpoint: "https://u1"})
	if p.Len() != 2 {
		t.Fatalf("upsert duplicated: len = %d", p.Len())
	}
	// Non-empty referrer is not clobbered by an empty one.
	_ = p.Add(vcresolver.UnresolvedEntry{Hash: "h1", ReferrerIssuer: ""})
	var h1 vcresolver.UnresolvedEntry
	for _, e := range mustList(t, p) {
		if e.Hash == "h1" {
			h1 = e
		}
	}
	if h1.UpstreamEndpoint != "https://u1" || h1.ReferrerIssuer != "did:a" {
		t.Fatalf("upsert-merge wrong: %+v", h1)
	}

	// IncrementRetry + Remove.
	if err := p.IncrementRetry("h2"); err != nil {
		t.Fatalf("IncrementRetry: %v", err)
	}
	if err := p.IncrementRetry("absent"); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("IncrementRetry absent: want ErrNotFound, got %v", err)
	}
	if err := p.Remove("h2"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if p.Len() != 1 {
		t.Fatalf("after remove: len = %d, want 1", p.Len())
	}
	if err := p.Remove("absent"); err != nil {
		t.Errorf("Remove absent: want nil, got %v", err)
	}
}

func mustList(t *testing.T, p *memstore.Pool) []vcresolver.UnresolvedEntry {
	t.Helper()
	l, err := p.ListNewest(100)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
