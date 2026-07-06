// Package storecontract is the shared behavioral suite for vcresolver Store
// and Pool implementations: the mem and file stores both run it, so their
// semantics (upsert merge, ordering, sentinel errors) cannot drift apart
// silently — the parity the evidence-persistence spec pins. Implementation-
// specific behavior (restart survival, damage handling) stays in each
// package's own tests.
package storecontract

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// Hash returns a distinct well-formed content address per one-byte seed (both
// implementations accept only content-address keys, so the suite uses them).
func Hash(b byte) string { return "sha256:" + strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

// Credential builds a minimal wire-form credential whose Hash() works.
func Credential(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	return CredentialWithProcess(t, "s1")
}

// CredentialWithProcess builds a minimal wire-form credential with the given
// processId — distinct ids yield distinct content addresses, which the
// enumeration contract needs.
func CredentialWithProcess(t *testing.T, processID string) *vc.PipelinePassCredential {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": processID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	// Test-support fixture built from bytes this function just marshaled —
	// no untrusted input (decoder-hygiene-exempt).
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// Store runs the Store contract against a fresh implementation.
func Store(t *testing.T, newStore func(t *testing.T) vcresolver.Store) {
	t.Helper()
	s := newStore(t)
	cred := Credential(t)
	h, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(h); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
	if err := s.Put(h, cred); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gh, err := got.Hash(); err != nil || gh != h {
		t.Fatalf("roundtrip hash = %q (err %v), want %q", gh, err, h)
	}

	// Enumeration: ListHashes in lexicographic order regardless of insertion
	// order, exclusive cursor, limit — the primitive the forward index and
	// any future export/GC path build on.
	lister := newStore(t)
	var addrs []string
	for _, id := range []string{"pD", "pA", "pC", "pB"} {
		c := CredentialWithProcess(t, id)
		ch, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if err := lister.Put(ch, c); err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, ch)
	}
	sort.Strings(addrs)
	all, err := lister.ListHashes("", 10)
	if err != nil {
		t.Fatalf("ListHashes: %v", err)
	}
	if !reflect.DeepEqual(all, addrs) {
		t.Fatalf("ListHashes(\"\", 10) = %v, want %v", all, addrs)
	}
	page, err := lister.ListHashes(addrs[0], 2)
	if err != nil || !reflect.DeepEqual(page, addrs[1:3]) {
		t.Fatalf("ListHashes(after first, 2) = %v (err %v), want %v", page, err, addrs[1:3])
	}
	if rest, err := lister.ListHashes(addrs[3], 5); err != nil || len(rest) != 0 {
		t.Fatalf("ListHashes past the end = %v (err %v), want empty", rest, err)
	}
	if none, err := newStore(t).ListHashes("", 5); err != nil || len(none) != 0 {
		t.Fatalf("ListHashes on empty store = %v (err %v), want empty", none, err)
	}
}

// Pool runs the Pool contract against a fresh implementation: newest-first
// ordering, bounded listing, the upsert merge (dedup by hash, empty-hint fill,
// no clobbering a non-empty hint, minimum depth, retry preserved), depth
// validation, and the absent-key behaviors.
func Pool(t *testing.T, newPool func(t *testing.T) vcresolver.Pool) {
	t.Helper()
	p := newPool(t)
	h1, h2 := Hash(1), Hash(2)

	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, ReferrerIssuer: "did:a", AssemblyDepth: 3}); err != nil {
		t.Fatalf("Add h1: %v", err)
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h2, UpstreamEndpoint: "https://u2", AssemblyDepth: 1}); err != nil {
		t.Fatalf("Add h2: %v", err)
	}
	if p.Len() != 2 {
		t.Fatalf("Len = %d, want 2", p.Len())
	}
	list, err := p.ListNewest(10)
	if err != nil || len(list) != 2 || list[0].Hash != h2 || list[1].Hash != h1 {
		t.Fatalf("order = %+v (err %v), want newest-first h2,h1", list, err)
	}
	if one, err := p.ListNewest(1); err != nil || len(one) != 1 || one[0].Hash != h2 {
		t.Fatalf("ListNewest(1) = %+v (err %v)", one, err)
	}

	// Upsert merge: fills the empty endpoint, keeps the non-empty referrer,
	// keeps the minimum depth, preserves retry count, never duplicates.
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, UpstreamEndpoint: "https://u1", AssemblyDepth: 2}); err != nil {
		t.Fatal(err)
	}
	if err := p.IncrementRetry(h1); err != nil {
		t.Fatal(err)
	}
	if err := p.Add(vcresolver.UnresolvedEntry{Hash: h1, ReferrerIssuer: "", AssemblyDepth: 5}); err != nil {
		t.Fatal(err)
	}
	if p.Len() != 2 {
		t.Fatalf("upsert duplicated: Len = %d", p.Len())
	}
	var h1e vcresolver.UnresolvedEntry
	list, _ = p.ListNewest(10)
	for _, e := range list {
		if e.Hash == h1 {
			h1e = e
		}
	}
	if h1e.UpstreamEndpoint != "https://u1" || h1e.ReferrerIssuer != "did:a" || h1e.AssemblyDepth != 2 || h1e.RetryCount != 1 {
		t.Fatalf("upsert-merge wrong: %+v", h1e)
	}

	if err := p.Add(vcresolver.UnresolvedEntry{Hash: Hash(3), AssemblyDepth: 0}); err == nil {
		t.Error("AssemblyDepth 0: want error")
	}
	if err := p.Remove(Hash(4)); err != nil {
		t.Errorf("Remove absent: want no-op, got %v", err)
	}
	if err := p.IncrementRetry(Hash(5)); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("IncrementRetry absent: want ErrNotFound, got %v", err)
	}
	if err := p.Remove(h2); err != nil {
		t.Fatalf("Remove h2: %v", err)
	}
	if p.Len() != 1 {
		t.Fatalf("post-remove Len = %d, want 1", p.Len())
	}
}
