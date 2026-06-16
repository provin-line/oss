package yamlstore_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
)

const (
	ownerDID    = "did:dplaax:poc.dplaax.io:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1"
	processDID  = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:proc1"
)

func newStore(t *testing.T) *yamlstore.Store {
	t.Helper()
	return yamlstore.New(t.TempDir())
}

func mustParse(t *testing.T, s string) *dplaax.DID {
	t.Helper()
	d, err := dplaax.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return d
}

func doc(id, controller string) *did.DIDDocument {
	return did.New(did.DocumentFields{ID: id, Controller: controller})
}

func sampleDelegation(subject string) *delegation.DelegationCredential {
	return &delegation.DelegationCredential{
		Context:           []string{"https://www.w3.org/ns/credentials/v2"},
		Type:              []string{"VerifiableCredential", "DelegationCredential"},
		Issuer:            ownerDID,
		ValidFrom:         time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC),
		CredentialSubject: delegation.DelegationSubject{ID: subject, DelegatedBy: ownerDID},
	}
}

func TestSaveOwner_ResolveRoundTrip(t *testing.T) {
	s := newStore(t)
	d := mustParse(t, ownerDID)
	if err := s.SaveOwner(d, doc(ownerDID, ownerDID)); err != nil {
		t.Fatalf("SaveOwner: %v", err)
	}
	got, err := s.Resolve(d)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID() != ownerDID {
		t.Errorf("resolved ID=%q, want %q", got.ID(), ownerDID)
	}
	if st, err := s.GetStatus(d); err != nil || st != store.StatusActive {
		t.Errorf("GetStatus=%q,%v; want active", st, err)
	}
}

func TestSaveOwner_DuplicateIsErrExists(t *testing.T) {
	s := newStore(t)
	d := mustParse(t, ownerDID)
	if err := s.SaveOwner(d, doc(ownerDID, ownerDID)); err != nil {
		t.Fatalf("SaveOwner: %v", err)
	}
	err := s.SaveOwner(d, doc(ownerDID, ownerDID))
	if !errors.Is(err, store.ErrExists) {
		t.Errorf("re-register: want ErrExists, got %v", err)
	}
}

func TestSavePipelineProcess_DelegationRoundTrip(t *testing.T) {
	s := newStore(t)
	owner := mustParse(t, ownerDID)
	pipe := mustParse(t, pipelineDID)
	proc := mustParse(t, processDID)
	if err := s.SaveOwner(owner, doc(ownerDID, ownerDID)); err != nil {
		t.Fatalf("SaveOwner: %v", err)
	}
	if err := s.SavePipeline(pipe, doc(pipelineDID, ownerDID), sampleDelegation(pipelineDID)); err != nil {
		t.Fatalf("SavePipeline: %v", err)
	}
	if err := s.SaveProcess(proc, doc(processDID, pipelineDID), sampleDelegation(processDID)); err != nil {
		t.Fatalf("SaveProcess: %v", err)
	}

	gotDoc, err := s.Resolve(proc)
	if err != nil || gotDoc.ID() != processDID {
		t.Fatalf("Resolve process: %q,%v", gotDoc, err)
	}
	gotDlg, err := s.ResolveDelegation(proc)
	if err != nil {
		t.Fatalf("ResolveDelegation: %v", err)
	}
	if gotDlg.CredentialSubject.ID != processDID || gotDlg.Issuer != ownerDID {
		t.Errorf("delegation round-trip mismatch: %+v", gotDlg.CredentialSubject)
	}
}

func TestResolve_NotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.Resolve(mustParse(t, ownerDID)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Resolve absent: want ErrNotFound, got %v", err)
	}
	if _, err := s.ResolveDelegation(mustParse(t, pipelineDID)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ResolveDelegation absent: want ErrNotFound, got %v", err)
	}
}

func TestUpdateStatus_RevokeAndAbsent(t *testing.T) {
	s := newStore(t)
	d := mustParse(t, ownerDID)
	if err := s.SaveOwner(d, doc(ownerDID, ownerDID)); err != nil {
		t.Fatalf("SaveOwner: %v", err)
	}
	if err := s.UpdateStatus(d, store.StatusRevoked); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if st, _ := s.GetStatus(d); st != store.StatusRevoked {
		t.Errorf("status=%q, want revoked", st)
	}
	// Revoking an absent DID is ErrNotFound (the document is the existence marker).
	if err := s.UpdateStatus(mustParse(t, pipelineDID), store.StatusRevoked); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("UpdateStatus absent: want ErrNotFound, got %v", err)
	}
}

func TestListPipelinesProcesses(t *testing.T) {
	s := newStore(t)
	owner := mustParse(t, ownerDID)
	pipe := mustParse(t, pipelineDID)
	proc := mustParse(t, processDID)
	if err := s.SaveOwner(owner, doc(ownerDID, ownerDID)); err != nil {
		t.Fatal(err)
	}
	// Empty before any issuance.
	if got, err := s.ListPipelines(owner); err != nil || len(got) != 0 {
		t.Fatalf("ListPipelines empty: %v,%v", got, err)
	}
	if err := s.SavePipeline(pipe, doc(pipelineDID, ownerDID), sampleDelegation(pipelineDID)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProcess(proc, doc(processDID, pipelineDID), sampleDelegation(processDID)); err != nil {
		t.Fatal(err)
	}
	pipes, err := s.ListPipelines(owner)
	if err != nil || len(pipes) != 1 || pipes[0].DID != pipelineDID || pipes[0].Status != store.StatusActive {
		t.Fatalf("ListPipelines: %+v, %v", pipes, err)
	}
	procs, err := s.ListProcesses(pipe)
	if err != nil || len(procs) != 1 || procs[0].DID != processDID {
		t.Fatalf("ListProcesses: %+v, %v", procs, err)
	}
}

func TestLifecycle_AppendReadInOrder(t *testing.T) {
	s := newStore(t)
	d := mustParse(t, ownerDID)
	if err := s.SaveOwner(d, doc(ownerDID, ownerDID)); err != nil {
		t.Fatal(err)
	}
	// Empty log is not an error.
	if evs, err := s.ReadLifecycleLog(d); err != nil || len(evs) != 0 {
		t.Fatalf("empty log: %v,%v", evs, err)
	}
	register := store.LifecycleEvent{
		EventType:       "register",
		DIDDocSnapshot:  "sha256:aaa",
		OutwardSnapshot: []byte("outward-doc-bytes"),
		WitnessSource:   "self-asserted",
		WitnessedAt:     time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC),
	}
	revoke := store.LifecycleEvent{
		EventType:      "revoke",
		DIDDocSnapshot: "sha256:bbb",
		WitnessSource:  "self-asserted",
		WitnessedAt:    time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC),
		PrevEventHash:  "sha256:event0",
	}
	if err := s.AppendLifecycleEvent(d, register); err != nil {
		t.Fatalf("append register: %v", err)
	}
	if err := s.AppendLifecycleEvent(d, revoke); err != nil {
		t.Fatalf("append revoke: %v", err)
	}
	evs, err := s.ReadLifecycleLog(d)
	if err != nil {
		t.Fatalf("ReadLifecycleLog: %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("log length=%d, want 2", len(evs))
	}
	if evs[0].EventType != "register" || evs[1].EventType != "revoke" {
		t.Errorf("append order not preserved: %q, %q", evs[0].EventType, evs[1].EventType)
	}
	if !bytes.Equal(evs[0].OutwardSnapshot, []byte("outward-doc-bytes")) {
		t.Errorf("outward snapshot round-trip mismatch: %q", evs[0].OutwardSnapshot)
	}
	if !evs[0].WitnessedAt.Equal(register.WitnessedAt) {
		t.Errorf("witnessedAt round-trip: got %v, want %v", evs[0].WitnessedAt, register.WitnessedAt)
	}
	if evs[1].PrevEventHash != "sha256:event0" {
		t.Errorf("prevEventHash round-trip: %q", evs[1].PrevEventHash)
	}
}

func TestPathGuard_RejectsTraversalSegment(t *testing.T) {
	s := newStore(t)
	// A DID whose accountId is a traversal segment must be rejected before any
	// path is built (defense-in-depth: Parse already enforces the safe-segment
	// rule, but the store guards independently).
	evil := &dplaax.DID{Method: "dplaax", Registry: "poc.dplaax.io", AccountType: "org", AccountID: ".."}
	if err := s.SaveOwner(evil, doc("x", "x")); err == nil {
		t.Error("SaveOwner with a traversal accountId: want error")
	}
	if _, err := s.Resolve(evil); err == nil {
		t.Error("Resolve with a traversal accountId: want error")
	}
}

func TestSaveShapeGuards(t *testing.T) {
	s := newStore(t)
	owner := mustParse(t, ownerDID)
	pipe := mustParse(t, pipelineDID)
	// SaveOwner rejects a non-owner DID; SavePipeline rejects a non-pipeline DID.
	if err := s.SaveOwner(pipe, doc(pipelineDID, ownerDID)); err == nil {
		t.Error("SaveOwner with a pipeline DID: want error")
	}
	if err := s.SavePipeline(owner, doc(ownerDID, ownerDID), sampleDelegation(ownerDID)); err == nil {
		t.Error("SavePipeline with an owner DID: want error")
	}
}
