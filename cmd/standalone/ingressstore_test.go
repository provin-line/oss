package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

// ingressTestIssuer is the issuer DID used in ingress store unit tests.
const ingressTestIssuer = "did:dplaax:reg:org:upstream:pipeline:p1:process:proc1"

// makeIngressCred builds a PipelinePassCredential for ingress-store tests.
// When prevAddr is non-empty it is set as previousCredential in credentialSubject.
func makeIngressCred(t *testing.T, prevAddr any) *vc.PipelinePassCredential {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prevAddr != nil {
		subject["previousCredential"] = prevAddr
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            ingressTestIssuer,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatalf("marshal cred: %v", err)
	}
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("unmarshal cred: %v", err)
	}
	return &c
}

// newTestIngressSetup returns a serviceIngressStore backed by a real vcresolver.Service
// together with the underlying memstore Pool and the audit queue so tests can inspect both.
func newTestIngressSetup() (*serviceIngressStore, *vcresolver.Service, *memstore.Pool, *auditor.MemQueue) {
	pool := memstore.NewPool()
	svc := vcresolver.New(memstore.NewStore(), pool)
	queue := auditor.NewMemQueue()
	store := &serviceIngressStore{store: svc, audit: queue}
	return store, svc, pool, queue
}

// TestServiceIngressStore_RegistersHeadForAudit asserts the stored head's content address
// is registered in the audit queue (slice-17h, D-17h-2).
func TestServiceIngressStore_RegistersHeadForAudit(t *testing.T) {
	store, _, _, queue := newTestIngressSetup()

	cred := makeIngressCred(t, nil)
	want, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.StoreIngressVC(context.Background(), cred, ""); err != nil {
		t.Fatalf("StoreIngressVC: %v", err)
	}
	cands, _ := queue.ListNewest(10)
	if len(cands) != 1 || cands[0].HeadHash != want {
		t.Errorf("audit queue = %+v, want one entry for %q", cands, want)
	}
}

// TestServiceIngressStore_AuditRegisterFailsClosed asserts a registration failure makes
// StoreIngressVC fail (fail-closed — never continue without the audit trail).
func TestServiceIngressStore_AuditRegisterFailsClosed(t *testing.T) {
	pool := memstore.NewPool()
	svc := vcresolver.New(memstore.NewStore(), pool)
	store := &serviceIngressStore{store: svc, audit: failingRegistrar{}}

	cred := makeIngressCred(t, nil)
	if err := store.StoreIngressVC(context.Background(), cred, ""); err == nil {
		t.Fatal("StoreIngressVC: want error on audit registration failure, got nil")
	}
}

type failingRegistrar struct{}

func (failingRegistrar) Add(string) error { return errRegister }

var errRegister = fmt.Errorf("register boom")

// TestServiceIngressStore_AbsentPredecessorEnqueuesPoolEntry asserts that storing
// an ingress VC whose predecessor is absent leaves exactly one pool entry for that
// predecessor, carrying the passed upstream-endpoint and the VC's issuer as ReferrerIssuer.
func TestServiceIngressStore_AbsentPredecessorEnqueuesPoolEntry(t *testing.T) {
	store, _, pool, _ := newTestIngressSetup()

	prevAddr := "sha256:" + strings.Repeat("a", 64)
	cred := makeIngressCred(t, prevAddr)
	const upstream = "https://upstream.example/pipelines/p1"

	if err := store.StoreIngressVC(context.Background(), cred, upstream); err != nil {
		t.Fatalf("StoreIngressVC: %v", err)
	}

	if got := pool.Len(); got != 1 {
		t.Fatalf("pool.Len() = %d, want 1", got)
	}
	entries, err := pool.ListNewest(1)
	if err != nil {
		t.Fatalf("pool.ListNewest: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("pool entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Hash != prevAddr {
		t.Errorf("entry.Hash = %q, want %q", e.Hash, prevAddr)
	}
	if e.UpstreamEndpoint != upstream {
		t.Errorf("entry.UpstreamEndpoint = %q, want %q", e.UpstreamEndpoint, upstream)
	}
	if e.ReferrerIssuer != ingressTestIssuer {
		t.Errorf("entry.ReferrerIssuer = %q, want %q", e.ReferrerIssuer, ingressTestIssuer)
	}
}

// TestServiceIngressStore_OriginVCEnqueuesNothing asserts that an origin VC (no
// previousCredential) does not enqueue anything — pool stays empty.
func TestServiceIngressStore_OriginVCEnqueuesNothing(t *testing.T) {
	store, _, pool, _ := newTestIngressSetup()

	cred := makeIngressCred(t, nil)
	if err := store.StoreIngressVC(context.Background(), cred, ""); err != nil {
		t.Fatalf("StoreIngressVC(origin): %v", err)
	}
	if got := pool.Len(); got != 0 {
		t.Fatalf("pool.Len() = %d, want 0 for origin VC", got)
	}
}

// TestServiceIngressStore_StoredVCIsResolvable asserts the ingress VC is retrievable
// via svc.ResolveVC at the content address returned by cred.Hash().
func TestServiceIngressStore_StoredVCIsResolvable(t *testing.T) {
	store, svc, _, _ := newTestIngressSetup()

	cred := makeIngressCred(t, nil)
	want, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if err := store.StoreIngressVC(context.Background(), cred, ""); err != nil {
		t.Fatalf("StoreIngressVC: %v", err)
	}

	got, err := svc.ResolveVC(context.Background(), want)
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	gotHash, err := got.Hash()
	if err != nil {
		t.Fatalf("resolved Hash: %v", err)
	}
	if gotHash != want {
		t.Errorf("resolved hash = %q, want %q", gotHash, want)
	}
}

// TestServiceIngressStore_OutOfOrder asserts that storing a successor before its
// predecessor enqueues the hole, and then storing the predecessor removes it.
func TestServiceIngressStore_OutOfOrder(t *testing.T) {
	store, _, pool, _ := newTestIngressSetup()
	ctx := context.Background()

	// Build predecessor and successor credentials.
	pred := makeIngressCred(t, nil)
	predHash, err := pred.Hash()
	if err != nil {
		t.Fatalf("pred Hash: %v", err)
	}
	succ := makeIngressCred(t, predHash)

	// Store successor first — predecessor is absent, pool must have 1 entry.
	if err := store.StoreIngressVC(ctx, succ, "https://up.example"); err != nil {
		t.Fatalf("StoreIngressVC(succ): %v", err)
	}
	if got := pool.Len(); got != 1 {
		t.Fatalf("after succ: pool.Len() = %d, want 1", got)
	}

	// Now store the predecessor — the hole is filled, pool must have 0 entries.
	if err := store.StoreIngressVC(ctx, pred, ""); err != nil {
		t.Fatalf("StoreIngressVC(pred): %v", err)
	}
	if got := pool.Len(); got != 0 {
		t.Fatalf("after pred: pool.Len() = %d, want 0", got)
	}
}

// TestServiceIngressStore_MalformedPreviousCredential pins D-17f-6: a VC carrying
// a non-content-address previousCredential string is rejected by StoreVC, so
// StoreIngressVC returns an error (fail-closed).
func TestServiceIngressStore_MalformedPreviousCredential(t *testing.T) {
	store, _, _, _ := newTestIngressSetup()

	cred := makeIngressCred(t, "not-a-hash")
	err := store.StoreIngressVC(context.Background(), cred, "https://up.example")
	if err == nil {
		t.Fatal("StoreIngressVC(malformed previousCredential): want error, got nil")
	}
}
