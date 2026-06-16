package vcresolver_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
)

const issuer = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:proc1"

func newSvc() *vcresolver.Service {
	return vcresolver.New(memstore.NewStore(), memstore.NewPool())
}

// vcBytes builds a minimal VC. prev sets credentialSubject.previousCredential
// (any type — pass a string for a valid link, a non-string to exercise the
// malformed path); nil omits it.
func vcBytes(t *testing.T, issuerDID string, prev any) []byte {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != nil {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuerDID,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStoreVC_StoreAndResolve(t *testing.T) {
	svc := newSvc()
	hash, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "")
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("hash = %q, want sha256: prefix", hash)
	}
	got, err := svc.ResolveVC(context.Background(), hash)
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	if got.Issuer() != issuer {
		t.Errorf("issuer = %q, want %q", got.Issuer(), issuer)
	}
}

func TestStoreVC_EnqueuesUnheldPredecessor(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)
	prev := "sha256:" + strings.Repeat("a", 64)

	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "https://up.example/vc"); err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if pool.Len() != 1 {
		t.Fatalf("pool len = %d, want 1", pool.Len())
	}
	list, _ := pool.ListNewest(1)
	if list[0].Hash != prev || list[0].UpstreamEndpoint != "https://up.example/vc" || list[0].ReferrerIssuer != issuer {
		t.Errorf("entry = %+v", list[0])
	}
}

func TestStoreVC_HeldPredecessor_NoEnqueue(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)

	// Store the predecessor first, then a successor referencing it.
	prevHash, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, nil), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prevHash), ""); err != nil {
		t.Fatalf("StoreVC successor: %v", err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (predecessor held)", pool.Len())
	}
}

func TestStoreVC_RejectsMalformedPrev(t *testing.T) {
	svc := newSvc()
	cases := map[string]any{
		"non-string previousCredential":  123,
		"bad-grammar previousCredential": "not-a-hash",
		"short hex":                      "sha256:abc",
	}
	for name, prev := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), "")
			if !errors.Is(err, vcresolver.ErrInvalidArgument) {
				t.Errorf("%s: want ErrInvalidArgument, got %v", name, err)
			}
		})
	}
}

func TestStoreVC_Idempotent(t *testing.T) {
	store := memstore.NewStore()
	svc := vcresolver.New(store, memstore.NewPool())
	b := vcBytes(t, issuer, nil)
	h1, _ := svc.StoreVC(context.Background(), b, "")
	h2, err := svc.StoreVC(context.Background(), b, "")
	if err != nil || h1 != h2 {
		t.Fatalf("idempotent: h1=%q h2=%q err=%v", h1, h2, err)
	}
}

func TestResolveVC_Errors(t *testing.T) {
	svc := newSvc()
	if _, err := svc.ResolveVC(context.Background(), "not-a-hash"); !errors.Is(err, vcresolver.ErrInvalidArgument) {
		t.Errorf("bad hash: want ErrInvalidArgument, got %v", err)
	}
	wellFormedAbsent := "sha256:" + strings.Repeat("b", 64)
	if _, err := svc.ResolveVC(context.Background(), wellFormedAbsent); !errors.Is(err, vcresolver.ErrNotFound) {
		t.Errorf("absent: want ErrNotFound, got %v", err)
	}
}

func TestStoreVC_UpsertRepairsHint(t *testing.T) {
	store := memstore.NewStore()
	pool := memstore.NewPool()
	svc := vcresolver.New(store, pool)
	prev := "sha256:" + strings.Repeat("c", 64)

	// First referrer supplies no upstream hint.
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, issuer, prev), ""); err != nil {
		t.Fatal(err)
	}
	// A second, distinct referrer of the same hole supplies the hint.
	other := issuer + "x"
	if _, err := svc.StoreVC(context.Background(), vcBytes(t, other, prev), "https://up.example/vc"); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 1 {
		t.Fatalf("pool len = %d, want 1 (deduped)", pool.Len())
	}
	list, _ := pool.ListNewest(1)
	if list[0].UpstreamEndpoint != "https://up.example/vc" {
		t.Errorf("hint not repaired: %+v", list[0])
	}
}
