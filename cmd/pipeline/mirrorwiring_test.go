package main

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
)

// ─────────────────────────────────────────────────────────────────────────
// mirrorClientFactory — cache-per-DID (pure, no network), mirrors
// TestAuditClientFactory_CachesPerDID in wiring_test.go exactly.
// ─────────────────────────────────────────────────────────────────────────

func TestMirrorClientFactory_CachesPerDID(t *testing.T) {
	f := newMirrorClientFactory(nil, "http://example.invalid", "", http.DefaultClient)
	a1 := f.For("did:dplaax:reg:org:acme:pipeline:a:process:p1")
	a2 := f.For("did:dplaax:reg:org:acme:pipeline:a:process:p1")
	if a1 != a2 {
		t.Error("For(sameDID) returned two different clients, want the cached one")
	}
	b1 := f.For("did:dplaax:reg:org:acme:pipeline:b:process:p1")
	if a1 == b1 {
		t.Error("For(differentDID) returned the SAME client as another DID")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// buildShippers — one shipper per custody log entry, wired to a MirrorClient
// requested under that entry's OWN checkpoint-signer DID (D-T3). Uses a real
// filelog.Log (a fake log would not exercise the CheckpointAt-backed capless
// batching tlogship depends on, mirroring tlogship's own test rationale) and
// a spy mirrorClientFor recording which DID each shipper was built with.
// ─────────────────────────────────────────────────────────────────────────

const (
	mwSignerA = "did:dplaax:reg:org:acme:pipeline:a:process:iss-a"
	mwSignerB = "did:dplaax:reg:org:acme:pipeline:b:process:iss-b"
)

func TestBuildShippers_OneShipperPerCustodyLogWithCorrectSigner(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	genEd25519Key(t, ks, mwSignerA, keystore.KeyIDSigning)
	genEd25519Key(t, ks, mwSignerB, keystore.KeyIDSigning)

	logA := newTestFilelog(t, ks, mwSignerA, "log-a")
	logB := newTestFilelog(t, ks, mwSignerB, "log-b")
	if _, err := logA.Append(context.Background(), []byte("a0")); err != nil {
		t.Fatalf("append log-a: %v", err)
	}
	if _, err := logB.Append(context.Background(), []byte("b0")); err != nil {
		t.Fatalf("append log-b: %v", err)
	}

	custody := []pipelineruntime.CustodyLog{
		{LogID: "log-a", Log: logA, Signer: pipelineruntime.IssuerConfig{DID: mwSignerA}},
		{LogID: "log-b", Log: logB, Signer: pipelineruntime.IssuerConfig{DID: mwSignerB}},
	}

	var mu sync.Mutex
	var requestedDIDs []string
	spies := map[string]*spyMirrorClient{}
	mirrorClientFor := func(signerDID string) tlogship.MirrorClient {
		mu.Lock()
		defer mu.Unlock()
		requestedDIDs = append(requestedDIDs, signerDID)
		c := &spyMirrorClient{}
		spies[signerDID] = c
		return c
	}

	tm := pipelineconfig.TlogMirrorConfig{MaxBatchRecords: 10, MaxBatchBytes: 1 << 20, FlushInterval: time.Hour}
	shippers, err := buildShippers(custody, mirrorClientFor, tm)
	if err != nil {
		t.Fatalf("buildShippers: %v", err)
	}
	if len(shippers) != 2 {
		t.Fatalf("shippers = %d, want 2 (one per custody entry)", len(shippers))
	}

	sort.Strings(requestedDIDs)
	wantDIDs := []string{mwSignerA, mwSignerB}
	if len(requestedDIDs) != 2 || requestedDIDs[0] != wantDIDs[0] || requestedDIDs[1] != wantDIDs[1] {
		t.Fatalf("mirrorClientFor requested DIDs = %v, want exactly %v", requestedDIDs, wantDIDs)
	}

	// Prove each shipper is wired to the log/client it OWNS, not swapped:
	// draining shipper[0] must only ever call the spy built for log-a's
	// signer, shipping log-a's own record under log-a's own logID.
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, sh := range shippers {
		if err := sh.Drain(drainCtx); err != nil {
			t.Fatalf("Drain: %v", err)
		}
	}

	spyA, spyB := spies[mwSignerA], spies[mwSignerB]
	ackedA, callsA := spyA.snapshot()
	ackedB, callsB := spyB.snapshot()
	if ackedA != 1 {
		t.Errorf("spy for %s acked = %d, want 1", mwSignerA, ackedA)
	}
	if ackedB != 1 {
		t.Errorf("spy for %s acked = %d, want 1", mwSignerB, ackedB)
	}
	assertOnlyLogID(t, callsA, "log-a")
	assertOnlyLogID(t, callsB, "log-b")
}

func assertOnlyLogID(t *testing.T, calls []spiedMirrorCall, wantLogID string) {
	t.Helper()
	for _, c := range calls {
		if c.logID != wantLogID {
			t.Errorf("call %+v: logID = %q, want %q (a shipper called the wrong client, or a client saw the wrong log)", c, c.logID, wantLogID)
		}
	}
}

func TestBuildShippers_EmptyCustodyYieldsNoShippers(t *testing.T) {
	shippers, err := buildShippers(nil, func(string) tlogship.MirrorClient { return &spyMirrorClient{} }, pipelineconfig.TlogMirrorConfig{MaxBatchRecords: 1, MaxBatchBytes: 1})
	if err != nil {
		t.Fatalf("buildShippers(empty): %v", err)
	}
	if len(shippers) != 0 {
		t.Fatalf("shippers = %d, want 0", len(shippers))
	}
}
