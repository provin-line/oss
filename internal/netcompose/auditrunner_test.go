package netcompose

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// ingressTestIssuer is the issuer DID used by makeIngressCred below.
const ingressTestIssuer = "did:dplaax:reg:org:upstream:pipeline:p1:process:proc1"

// makeIngressCred builds a PipelinePassCredential for this file's runner tests.
// When prevAddr is non-empty it is set as previousCredential in credentialSubject.
//
// Originally duplicated from cmd/standalone/ingressstore_test.go's helper of
// the same name (Task 4 moved this file into internal/netcompose beside the
// code it exercises, but that package's own tests still needed a copy too,
// and identifiers declared in a _test.go file are invisible outside that
// package's own test binary — there is no alias (compat.go or otherwise)
// that reaches a _test.go symbol across a package boundary). cmd/standalone
// is gone (PR3c), but this copy remains this package's own fixture. Kept
// byte-for-byte equivalent to the original (only the issuer DID constant's
// name changed, to avoid implying it is ingress-store-specific).
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

func auditCfg(loops []pipelineconfig.LoopConfig) *pipelineconfig.Config {
	return &pipelineconfig.Config{
		Loops:         loops,
		BatchResolver: pipelineconfig.BatchResolverConfig{Interval: time.Second, BatchSize: 16, MaxRetries: 3, MaxDepth: 1024},
		AuditRunner:   pipelineconfig.AuditRunnerConfig{Interval: 5 * time.Millisecond, BatchSize: 16, MaxAttempts: 5},
	}
}

// BuildAuditRunner builds unconditionally from its args now (Task 9): the "does this node
// have a consuming loop" gate moved to the composition roots (cmd/network always
// builds, since it never has a local loop to gate on). A
// source-only or zero-loop config therefore returns a non-nil runner just like a
// sink/chained config — the builder itself no longer inspects pipeCfg.HasConsumingLoop().
func TestBuildAuditRunner_BuildsUnconditionally(t *testing.T) {
	for _, tc := range []struct {
		name  string
		loops []pipelineconfig.LoopConfig
	}{
		{"source-only", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSource}}},
		{"sink", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}},
		{"chained", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleChained}}},
		{"no-loops", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := memstore.NewPool()
			svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
			r, err := BuildAuditRunner(auditor.NewMemQueue(), auditor.NewMemStatusStore(), auditor.NewMemReceiptStore(), svc, pool, local.New(), nil,
				auditCfg(tc.loops))
			if err != nil {
				t.Fatalf("BuildAuditRunner: %v", err)
			}
			if r == nil {
				t.Error("runner is nil, want non-nil (the builder builds unconditionally now)")
			}
		})
	}
}

func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

// End-to-end through the production wiring (localChainResolver → real chainwalk → real
// vc.Verifier → real memstore.Pool.Has): a consumed head linking an absent predecessor
// audits to Indeterminate and is RETAINED while the hole stays queued, then is FINALIZED
// and dequeued once the resolver abandons the hole (pool.Has → false). No DID graph is
// needed — chainwalk hits the hole during assembly, before any proof verification.
func TestAuditRunner_Integration_HoleLivenessFinalize(t *testing.T) {
	ctx := context.Background()
	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()

	// A consumed head linking an absent predecessor: StoreVC enqueues the hole in the pool.
	hole := "sha256:" + strings.Repeat("a", 64)
	head := makeIngressCred(t, hole)
	headBytes, err := head.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(ctx, headBytes, "", 0); err != nil {
		t.Fatal(err)
	}
	headHash, _ := head.Hash()
	if err := queue.Add(headHash); err != nil {
		t.Fatal(err)
	}
	if !pool.Has(hole) {
		t.Fatalf("precondition: hole not queued in pool")
	}

	r, err := BuildAuditRunner(queue, status, auditor.NewMemReceiptStore(), svc, pool, local.New(), nil, auditCfg([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}))
	if err != nil || r == nil {
		t.Fatalf("BuildAuditRunner: r=%v err=%v", r, err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = r.Run(runCtx) }()

	// While the hole is queued: recorded Indeterminate (all axes), head RETAINED.
	waitUntil(t, func() bool {
		rec, err := status.Get(headHash)
		return err == nil && rec.Overall == vc.ConfidenceIndeterminate
	}, "head recorded Indeterminate")
	rec, _ := status.Get(headHash)
	i := vc.ConfidenceIndeterminate
	if rec.Axes != (vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i}) {
		t.Errorf("synthetic axes = %+v, want all Indeterminate", rec.Axes)
	}
	if !rec.Scope.LinearChain || rec.Scope.SourceCommitmentEvaluated {
		t.Errorf("scope = %+v, want linear-only", rec.Scope)
	}
	if queue.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (retained while hole queued)", queue.Len())
	}

	// Resolver abandons the hole → finalized (via the attempt grace) and dequeued.
	if err := pool.Remove(hole); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return queue.Len() == 0 }, "head finalized and dequeued after hole abandoned")
}

// End-to-end through the production wiring to a TERMINAL verdict via the REAL vc.Verifier
// (not a fake ChainVerifier): a complete single-credential chain whose head is unsigned
// fails signer-authenticity, so VerifyChain returns Failed — the runner records it and
// dequeues. This exercises the runner→real-chainwalk→real-verifier composition end to end
// (the Verified path is the same runner code; a full DID graph is the capstones' job).
func TestAuditRunner_Integration_RealVerifyTerminal(t *testing.T) {
	ctx := context.Background()
	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()

	// An unsigned origin credential (no previousCredential → complete chain; no proof →
	// signer-authenticity fails definitively → Failed).
	head := makeIngressCred(t, nil)
	headBytes, err := head.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StoreVC(ctx, headBytes, "", 0); err != nil {
		t.Fatal(err)
	}
	headHash, _ := head.Hash()
	if err := queue.Add(headHash); err != nil {
		t.Fatal(err)
	}

	r, err := BuildAuditRunner(queue, status, auditor.NewMemReceiptStore(), svc, pool, local.New(), nil, auditCfg([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}))
	if err != nil || r == nil {
		t.Fatalf("BuildAuditRunner: r=%v err=%v", r, err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = r.Run(runCtx) }()

	waitUntil(t, func() bool {
		rec, err := status.Get(headHash)
		return err == nil && rec.Overall == vc.ConfidenceFailed
	}, "head recorded a terminal Failed verdict via the real verifier")
	waitUntil(t, func() bool { return queue.Len() == 0 }, "terminal verdict dequeued the head")
}
