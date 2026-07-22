package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

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

// newTestIngressSetup returns a serviceIngressStore backed by the package's
// fakeVCStore (deterministic sha256-of-bytes body address) together with the
// audit queue so tests can inspect it.
//
// The predecessor-pool / resolvability / out-of-order-draining /
// malformed-previousCredential semantics that used to be exercised here
// against a REAL *vcresolver.Service are network/pkg/services/vcresolver's
// own behavior (serviceIngressStore is a thin pass-through over
// IngressStorer), already covered by that package's own test suite
// (vcresolver_test.go: TestStoreVC_EnqueuesUnheldPredecessor,
// TestStoreVC_RejectsMalformedPrev, TestStoreVC_OutOfOrder_RemovesResolvedHole,
// TestStoreVC_StoreAndResolve, TestStoreVC_NullPreviousCredential_AcceptedAsOrigin,
// et al.) — this package no longer imports network/pkg/services/vcresolver at
// all (network/ and pipeline/ never import each other, AGENTS.md rule 2), so
// those tests moved with the type they test, not duplicated here. What
// remains is serviceIngressStore's OWN added value: does it forward the
// store's returned body address to the audit registrar, and is that
// registration fail-closed.
func newTestIngressSetup() (*serviceIngressStore, *memAuditQueue) {
	queue := newMemAuditQueue()
	s := &serviceIngressStore{store: fakeVCStore{}, audit: queue}
	return s, queue
}

// TestServiceIngressStore_RegistersHeadForAudit asserts the stored head's content address
// is registered in the audit queue (slice-17h, D-17h-2).
func TestServiceIngressStore_RegistersHeadForAudit(t *testing.T) {
	store, queue := newTestIngressSetup()

	cred := makeIngressCred(t, nil)
	want, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.StoreIngressVC(context.Background(), cred, ""); err != nil {
		t.Fatalf("StoreIngressVC: %v", err)
	}
	if len(queue.heads) != 1 || queue.heads[0].BodyAddress != want {
		t.Errorf("audit queue = %+v, want one entry for %q", queue.heads, want)
	}
}

// TestServiceIngressStore_RegistersWireVariantID asserts the seam widening
// (task-3): the audit registrar receives the FULL StoredHead the store
// returned, not just the body address — a future wire audit registration
// needs the variant id, and this is where it would otherwise silently be
// dropped.
func TestServiceIngressStore_RegistersWireVariantID(t *testing.T) {
	store, queue := newTestIngressSetup()

	cred := makeIngressCred(t, nil)
	want, err := cred.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := store.StoreIngressVC(context.Background(), cred, ""); err != nil {
		t.Fatalf("StoreIngressVC: %v", err)
	}
	wantVariant := "wire:v1:jcs-rfc8785:" + want
	if len(queue.heads) != 1 || queue.heads[0].WireVariantID != wantVariant {
		t.Errorf("audit queue = %+v, want one entry with WireVariantID %q", queue.heads, wantVariant)
	}
}

// TestServiceIngressStore_AuditRegisterFailsClosed asserts a registration failure makes
// StoreIngressVC fail (fail-closed — never continue without the audit trail).
func TestServiceIngressStore_AuditRegisterFailsClosed(t *testing.T) {
	store := &serviceIngressStore{store: fakeVCStore{}, audit: failingRegistrar{}}

	cred := makeIngressCred(t, nil)
	if err := store.StoreIngressVC(context.Background(), cred, ""); err == nil {
		t.Fatal("StoreIngressVC: want error on audit registration failure, got nil")
	}
}

type failingRegistrar struct{}

func (failingRegistrar) Add(StoredHead) error { return errRegister }

var errRegister = fmt.Errorf("register boom")
