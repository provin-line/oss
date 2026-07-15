package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// --- fakes ------------------------------------------------------------------

type fakeChainSigner struct {
	gotInputHash   string
	gotOutputHash  string
	gotPredecessor *vc.PipelinePassCredential
	receipt        *vc.PipelinePassCredential
	err            error
}

func (f *fakeChainSigner) SignChainPreserving(_ context.Context, _ []byte, inputHash, outputHash string, predecessor *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	f.gotInputHash = inputHash
	f.gotOutputHash = outputHash
	f.gotPredecessor = predecessor
	if f.err != nil {
		return nil, f.err
	}
	return f.receipt, nil
}

type fakeLocalStore struct {
	calls int
	head  string
	err   error
	order *[]string
}

func (f *fakeLocalStore) StoreVC(_ context.Context, _ []byte, _ string, _ int) (vcresolver.StoreVCResult, error) {
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "local")
	}
	return vcresolver.StoreVCResult{BodyAddress: f.head}, f.err
}

type fakeReceiptLog struct {
	calls int
	err   error
	order *[]string
}

func (f *fakeReceiptLog) Append(_ context.Context, _ []byte) (*tlog.Record, error) {
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "tlog")
	}
	if f.err != nil {
		return nil, f.err
	}
	return &tlog.Record{Index: 0}, nil
}
func (f *fakeReceiptLog) Get(context.Context, uint64) (*tlog.Record, error) { return nil, nil }
func (f *fakeReceiptLog) Size(context.Context) (uint64, error)              { return 0, nil }
func (f *fakeReceiptLog) Checkpoint(context.Context) (*tlog.Checkpoint, error) {
	return nil, nil
}

type fakeAuditReg struct {
	added []string
	err   error
	order *[]string
}

func (f *fakeAuditReg) Add(headHash string) error {
	f.added = append(f.added, headHash)
	if f.order != nil {
		*f.order = append(*f.order, "audit")
	}
	return f.err
}

type fakeRemotePublisher struct {
	calls int
	order *[]string
}

func (f *fakeRemotePublisher) StoreCredential(_ context.Context, cred *vc.PipelinePassCredential, _ string) (vcresolverclient.StoredCredential, error) {
	f.calls++
	if f.order != nil {
		*f.order = append(*f.order, "remote")
	}
	body, _ := cred.Hash()
	variant, _ := cred.WireVariantID()
	return vcresolverclient.StoredCredential{BodyAddress: body, WireVariantID: variant}, nil
}

// --- fixtures ---------------------------------------------------------------

func receiptTestCred(t *testing.T, issuer, outputHash string) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "proc",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          outputHash,
		},
	})
	if err != nil {
		t.Fatalf("receiptTestCred: %v", err)
	}
	return cred
}

// --- tests ------------------------------------------------------------------

func TestSinkReceiptRegistrar_IssueReceipt(t *testing.T) {
	const consumedOut = "sha256:aa"
	consumed := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:up", consumedOut)
	receipt := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:sink", consumedOut)

	var order []string
	signer := &fakeChainSigner{receipt: receipt}
	local := &fakeLocalStore{head: "sha256:receipthead", order: &order}
	rl := &fakeReceiptLog{order: &order}
	audit := &fakeAuditReg{order: &order}
	remote := &fakeRemotePublisher{order: &order}

	r := &sinkReceiptRegistrar{signer: signer, local: local, receiptLog: rl, audit: audit, publisher: remote}
	if err := r.IssueReceipt(context.Background(), consumed); err != nil {
		t.Fatalf("IssueReceipt: %v", err)
	}

	// The receipt asserts identity: input == output == consumed's outputHash,
	// linking the consumed credential as predecessor.
	if signer.gotInputHash != consumedOut || signer.gotOutputHash != consumedOut {
		t.Errorf("sign hashes = (%q,%q), want both %q", signer.gotInputHash, signer.gotOutputHash, consumedOut)
	}
	if ch, _ := consumed.Hash(); func() string { h, _ := signer.gotPredecessor.Hash(); return h }() != ch {
		t.Errorf("predecessor != consumed credential")
	}
	// All four steps ran, and the audit head is the local store's head.
	if local.calls != 1 || rl.calls != 1 || len(audit.added) != 1 || remote.calls != 1 {
		t.Errorf("calls: local=%d tlog=%d audit=%d remote=%d, want 1/1/1/1", local.calls, rl.calls, len(audit.added), remote.calls)
	}
	if audit.added[0] != "sha256:receipthead" {
		t.Errorf("audit head = %q, want the local store head", audit.added[0])
	}
	// Ordering is load-bearing: local audit trail BEFORE remote visibility.
	want := []string{"local", "tlog", "audit", "remote"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestSinkReceiptRegistrar_NoRemoteOK(t *testing.T) {
	consumed := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:up", "sha256:bb")
	receipt := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:sink", "sha256:bb")
	r := &sinkReceiptRegistrar{
		signer:     &fakeChainSigner{receipt: receipt},
		local:      &fakeLocalStore{head: "sha256:h"},
		receiptLog: &fakeReceiptLog{},
		audit:      &fakeAuditReg{},
		publisher:  nil, // no remote configured
	}
	if err := r.IssueReceipt(context.Background(), consumed); err != nil {
		t.Fatalf("IssueReceipt (no remote): %v", err)
	}
}

func TestSinkReceiptRegistrar_LocalStoreFailStopsBeforeAudit(t *testing.T) {
	consumed := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:up", "sha256:cc")
	receipt := receiptTestCred(t, "did:dplaax:reg:org:acme:pipeline:p:process:sink", "sha256:cc")
	audit := &fakeAuditReg{}
	remote := &fakeRemotePublisher{}
	r := &sinkReceiptRegistrar{
		signer:     &fakeChainSigner{receipt: receipt},
		local:      &fakeLocalStore{err: errors.New("store down")},
		receiptLog: &fakeReceiptLog{},
		audit:      audit,
		publisher:  remote,
	}
	if err := r.IssueReceipt(context.Background(), consumed); err == nil {
		t.Fatal("IssueReceipt: want error on local store failure")
	}
	if len(audit.added) != 0 || remote.calls != 0 {
		t.Errorf("audit/remote ran after local store failed: audit=%d remote=%d (want 0/0)", len(audit.added), remote.calls)
	}
}
