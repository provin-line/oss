package auditor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

// --- fakes ---

// holeErr is a test ChainVerifier error satisfying auditor.HoleError (mirrors the shape a
// chain-walk hole error has, without importing the pipeline package — layer rule).
type holeErr struct{ hash string }

func (e holeErr) Error() string          { return "unresolved predecessor " + e.hash }
func (e holeErr) UnresolvedHash() string { return e.hash }

type fakeCV struct {
	fn func() (*vc.VerifyResult, error)
}

func (f fakeCV) VerifyChain(_ context.Context, _ *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return f.fn()
}

type fakeHeads struct {
	m map[string]*vc.PipelinePassCredential
}

var errNotInStore = errors.New("not in store")

func (f fakeHeads) ResolveVC(_ context.Context, h string) (*vc.PipelinePassCredential, error) {
	if c, ok := f.m[h]; ok {
		return c, nil
	}
	return nil, errNotInStore
}

type fakePool struct{ has map[string]bool }

func (f fakePool) Has(h string) bool { return f.has[h] }

func verifiedResult() *vc.VerifyResult {
	v := vc.ConfidenceVerified
	return &vc.VerifyResult{Overall: v, Axes: vc.AxisResult{DataIntegrity: v, SignerAuthenticity: v, ChainConsistency: v}}
}

func failedResult() *vc.VerifyResult {
	return &vc.VerifyResult{Overall: vc.ConfidenceFailed, Axes: vc.AxisResult{DataIntegrity: vc.ConfidenceFailed}}
}

func indeterminateResult() *vc.VerifyResult {
	i := vc.ConfidenceIndeterminate
	return &vc.VerifyResult{Overall: i, Axes: vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i}}
}

const headH = "sha256:head"

// newRunner wires a Runner over real queue+status and the given fakes, with the head
// already registered and resolvable (unless overridden).
func newRunner(t *testing.T, cv ChainVerifier, heads HeadResolver, pool PoolLiveness, cfg Config) (*Runner, *MemQueue, *MemStatusStore) {
	t.Helper()
	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	r, err := New(q, heads, cv, status, pool, cfg, WithClock(func() time.Time { return time.Unix(0, 0) }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, q, status
}

func headStore() fakeHeads {
	return fakeHeads{m: map[string]*vc.PipelinePassCredential{headH: {}}}
}

func okCfg() Config { return Config{Interval: time.Second, BatchSize: 16, MaxAttempts: 3} }

func TestNew_RejectsNilAndBadConfig(t *testing.T) {
	q := NewMemQueue()
	heads := headStore()
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	status := NewMemStatusStore()
	pool := fakePool{}
	good := okCfg()

	if _, err := New(nil, heads, cv, status, pool, good); err == nil {
		t.Error("nil queue: want error")
	}
	if _, err := New(q, nil, cv, status, pool, good); err == nil {
		t.Error("nil heads: want error")
	}
	if _, err := New(q, heads, nil, status, pool, good); err == nil {
		t.Error("nil cv: want error")
	}
	if _, err := New(q, heads, cv, nil, pool, good); err == nil {
		t.Error("nil status: want error")
	}
	if _, err := New(q, heads, cv, status, nil, good); err == nil {
		t.Error("nil pool: want error")
	}
	for name, c := range map[string]Config{
		"interval":    {Interval: 0, BatchSize: 1, MaxAttempts: 1},
		"batchSize":   {Interval: time.Second, BatchSize: 0, MaxAttempts: 1},
		"maxAttempts": {Interval: time.Second, BatchSize: 1, MaxAttempts: 0},
	} {
		if _, err := New(q, heads, cv, status, pool, c); err == nil {
			t.Errorf("bad config %s: want error", name)
		}
	}
	if _, err := New(q, heads, cv, status, pool, good); err != nil {
		t.Errorf("valid: unexpected error %v", err)
	}
}

func TestAuditOne_CompleteVerified_RecordsAndDequeues(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, okCfg())

	if err := r.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, err := status.Get(headH)
	if err != nil || rec.Overall != vc.ConfidenceVerified {
		t.Errorf("status = %+v err=%v, want Verified", rec, err)
	}
	if !rec.Scope.LinearChain || rec.Scope.SourceCommitmentEvaluated {
		t.Errorf("scope = %+v, want {LinearChain:true, SourceCommitmentEvaluated:false}", rec.Scope)
	}
	if q.Len() != 0 {
		t.Errorf("queue len = %d, want 0 (terminal dequeued)", q.Len())
	}
}

func TestAuditOne_CompleteFailed_RecordsAndDequeues(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return failedResult(), nil }}
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, okCfg())

	_ = r.drainOnce(context.Background())
	if rec, _ := status.Get(headH); rec.Overall != vc.ConfidenceFailed {
		t.Errorf("Overall = %v, want Failed", rec.Overall)
	}
	if q.Len() != 0 {
		t.Errorf("queue len = %d, want 0", q.Len())
	}
}

// A non-hole Indeterminate (assembled chain, e.g. unresolvable signer DID) is retained and
// bounded by the attempt backstop.
func TestAuditOne_NonHoleIndeterminate_BackstopDrops(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return indeterminateResult(), nil }}
	cfg := okCfg()
	cfg.MaxAttempts = 2
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, cfg)
	ctx := context.Background()

	_ = r.drainOnce(ctx) // attempts 0 → 1, retained
	if q.Len() != 1 {
		t.Fatalf("after tick 1: queue len = %d, want 1", q.Len())
	}
	if rec, _ := status.Get(headH); rec.Overall != vc.ConfidenceIndeterminate {
		t.Errorf("Overall = %v, want Indeterminate", rec.Overall)
	}
	_ = r.drainOnce(ctx) // attempts 1 → drop (1+1 >= 2)
	if q.Len() != 0 {
		t.Errorf("after tick 2: queue len = %d, want 0 (backstop dropped)", q.Len())
	}
}

// A hole still queued in the pool → synthetic Indeterminate (all axes Indeterminate),
// retained, attempt NOT incremented.
func TestAuditOne_HoleInPool_RetainedNoAttemptBurn(t *testing.T) {
	const hole = "sha256:hole"
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) {
		return nil, holeErr{hash: hole}
	}}
	pool := fakePool{has: map[string]bool{hole: true}}
	r, q, status := newRunner(t, cv, headStore(), pool, okCfg())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_ = r.drainOnce(ctx)
	}
	rec, err := status.Get(headH)
	if err != nil || rec.Overall != vc.ConfidenceIndeterminate {
		t.Fatalf("status = %+v (err %v), want Indeterminate", rec, err)
	}
	i := vc.ConfidenceIndeterminate
	if rec.Axes != (vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i}) {
		t.Errorf("synthetic axes = %+v, want all Indeterminate (NOT zero-value Failed)", rec.Axes)
	}
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (retained while hole queued)", q.Len())
	}
	if cands, _ := q.ListNewest(1); cands[0].Attempts != 0 {
		t.Errorf("attempts = %d, want 0 (hole liveness must not burn attempts)", cands[0].Attempts)
	}
}

// A hole that has since appeared in the store → retained (next tick completes the chain).
func TestAuditOne_HoleAppearedInStore_Retained(t *testing.T) {
	const hole = "sha256:hole"
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) {
		return nil, holeErr{hash: hole}
	}}
	heads := fakeHeads{m: map[string]*vc.PipelinePassCredential{headH: {}, hole: {}}} // hole now in store
	r, q, _ := newRunner(t, cv, heads, fakePool{}, okCfg())                           // pool.Has(hole)=false

	_ = r.drainOnce(context.Background())
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (hole in store → retained, not finalized)", q.Len())
	}
}

// A hole abandoned by the resolver (in neither store nor pool) → Indeterminate, finalized
// via the attempt grace (NOT a single observation — that would race the StoreVC Put/Add
// window, Codex P2). One drain records Indeterminate and bumps but retains; the head is
// dequeued only after max-attempts consecutive abandoned observations.
func TestAuditOne_HoleAbandoned_FinalizedAfterGrace(t *testing.T) {
	const hole = "sha256:hole"
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) {
		return nil, holeErr{hash: hole}
	}}
	cfg := okCfg()                                                 // MaxAttempts = 3
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, cfg) // hole in neither store nor pool
	ctx := context.Background()

	_ = r.drainOnce(ctx) // attempts 0 → 1: recorded Indeterminate, RETAINED (no race-finalize)
	if rec, _ := status.Get(headH); rec.Overall != vc.ConfidenceIndeterminate {
		t.Errorf("Overall = %v, want Indeterminate", rec.Overall)
	}
	if q.Len() != 1 {
		t.Fatalf("after one observation: queue len = %d, want 1 (grace, not immediate finalize)", q.Len())
	}
	_ = r.drainOnce(ctx) // attempts 1 → 2
	_ = r.drainOnce(ctx) // attempts 2 → finalize (2+1 >= 3), dequeued
	if q.Len() != 0 {
		t.Errorf("after max-attempts abandoned observations: queue len = %d, want 0", q.Len())
	}
}

// A failing StatusStore.Put must NOT dequeue the head — the audit is retried, not lost (Codex).
func TestAuditOne_StatusWriteFailure_RetainsHead(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	q := NewMemQueue()
	_ = q.Add(headH)
	r, err := New(q, headStore(), cv, failingStatus{}, fakePool{}, okCfg(), WithClock(func() time.Time { return time.Unix(0, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.drainOnce(context.Background())
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (status write failed → head retained)", q.Len())
	}
}

type failingStatus struct{}

func (failingStatus) Put(string, AuditRecord) error { return errors.New("status boom") }
func (failingStatus) Get(h string) (AuditRecord, error) {
	return AuditRecord{}, fmt.Errorf("%w: %q", ErrNotFound, h)
}

// A head already holding a terminal verdict is dequeued without re-verifying (Codex #4).
func TestAuditOne_TerminalReRegistration_NotReaudited(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) {
		t.Fatal("VerifyChain must not be called for an already-terminal head")
		return nil, nil
	}}
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, okCfg())
	_ = status.Put(headH, AuditRecord{Overall: vc.ConfidenceVerified, Scope: AuditScope{LinearChain: true}})

	_ = r.drainOnce(context.Background())
	if q.Len() != 0 {
		t.Errorf("queue len = %d, want 0 (terminal re-registration dequeued)", q.Len())
	}
}

// Context cancellation mid-tick records nothing and leaves the head queued.
func TestAuditOne_CtxCancelDuringVerify_RecordsNothing(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return nil, context.Canceled }}
	r, q, status := newRunner(t, cv, headStore(), fakePool{}, okCfg())

	_ = r.drainOnce(context.Background())
	if _, err := status.Get(headH); err == nil {
		t.Error("recorded a verdict on context cancellation; want none")
	}
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (retained on cancel)", q.Len())
	}
}
