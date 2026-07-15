// Package storecontract is the shared behavioral suite for vcresolver backend
// and Pool implementations: the mem and file versions both run it, so their
// semantics (atomic create, upsert merge, ordering, sentinel errors) cannot
// drift apart silently — the parity the evidence-persistence spec pins.
// Implementation-specific behavior (restart survival, damage handling) stays in
// each package's own tests.
//
// The suite asks a BACKEND nothing about identity, canonicality, write-once or
// projection winners: those are enforced in vcresolver.VariantStore, above
// every backend, so asserting them here would test one implementation twice and
// imply a backend could get them wrong. See backend.go.
package storecontract

import (
	"encoding/json"
	"errors"
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
