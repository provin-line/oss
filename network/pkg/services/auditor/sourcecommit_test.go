package auditor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

// --- source-commitment fakes (slice-17o) ---

type fakeReceipts struct{ m map[string][]string }

func (f fakeReceipts) Get(h string) ([]string, error) {
	c, ok := f.m[h]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, h)
	}
	return c, nil
}

type fakeSCV struct {
	state      vc.ConfidenceState
	err        error
	calls      int
	gotSources int
}

func (f *fakeSCV) VerifySourceCommitment(_ context.Context, _ *vc.PipelinePassCredential, sources []*vc.PipelinePassCredential) (vc.ConfidenceState, error) {
	f.calls++
	f.gotSources = len(sources)
	return f.state, f.err
}

const (
	scSrc1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	scSrc2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// newRunnerSC wires a Runner with the source-commitment capability enabled (slice-17o
// WithSourceCommitment), the head registered, and headStore extended with the two sources.
func newRunnerSC(t *testing.T, cv ChainVerifier, receipts ReceiptReader, scv SourceCommitmentVerifier, extraHeads map[string]*vc.PipelinePassCredential) (*Runner, *MemQueue, *MemStatusStore) {
	t.Helper()
	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	m := map[string]*vc.PipelinePassCredential{headH: {}}
	for h, c := range extraHeads {
		m[h] = c
	}
	r, err := New(q, fakeHeads{m: m}, cv, status, fakePool{}, okCfg(),
		WithClock(func() time.Time { return time.Unix(0, 0) }),
		WithSourceCommitment(receipts, scv))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, q, status
}

// An aggregate head with a local receipt whose sources all resolve → the runner records a
// DISTINCT source-commitment Verified alongside the linear verdict, in one record, flips
// SourceCommitmentEvaluated, and dequeues (terminal).
func TestAuditOne_SourceCommitment_Verified(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	receipts := fakeReceipts{m: map[string][]string{headH: {scSrc1, scSrc2}}}
	heads := map[string]*vc.PipelinePassCredential{scSrc1: {}, scSrc2: {}}
	r, q, status := newRunnerSC(t, cv, receipts, scv, heads)

	if err := r.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, err := status.Get(headH)
	if err != nil {
		t.Fatal("no record")
	}
	if rec.Overall != vc.ConfidenceVerified {
		t.Errorf("linear Overall = %v, want Verified (unchanged)", rec.Overall)
	}
	if rec.SourceCommitment != vc.ConfidenceVerified {
		t.Errorf("SourceCommitment = %v, want Verified", rec.SourceCommitment)
	}
	if !rec.Scope.LinearChain || !rec.Scope.SourceCommitmentEvaluated {
		t.Errorf("scope = %+v, want both true", rec.Scope)
	}
	if len(rec.SourceCommitmentNotations) == 0 {
		t.Error("want a source-commitment locus notation")
	}
	if scv.gotSources != 2 {
		t.Errorf("verifier got %d sources, want 2 (both receipt hashes resolved)", scv.gotSources)
	}
	if q.Len() != 0 {
		t.Errorf("queue len = %d, want 0 (terminal dequeued)", q.Len())
	}
}

// When only a subset of the receipt's sources resolves locally, the runner MUST NOT trust
// the verifier's subset result — a subset recompute can spuriously match (false Verified) or
// spuriously mismatch (false Failed). It records Indeterminate WITHOUT calling the verifier
// and retains the head for retry (Codex P1/P2, Claude Important). Here the verifier is armed
// to return Verified (the dangerous case); the runner must still record Indeterminate.
func TestAuditOne_SourceCommitment_PartialResolves_IndeterminateNotTrustingSubset(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified} // armed to (wrongly) confirm a subset
	receipts := fakeReceipts{m: map[string][]string{headH: {scSrc1, scSrc2}}}
	heads := map[string]*vc.PipelinePassCredential{scSrc1: {}} // scSrc2 not resolvable
	r, q, status := newRunnerSC(t, cv, receipts, scv, heads)

	_ = r.drainOnce(context.Background())
	rec, _ := status.Get(headH)
	if rec.SourceCommitment != vc.ConfidenceIndeterminate {
		t.Errorf("SourceCommitment = %v, want Indeterminate (subset must not be trusted)", rec.SourceCommitment)
	}
	if !rec.Scope.SourceCommitmentEvaluated {
		t.Error("SourceCommitmentEvaluated must be true (a real, if partial, evaluation)")
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d times, want 0 (incomplete receipt → no subset verify)", scv.calls)
	}
	// The head is RETAINED (not dequeued) despite the terminal linear verdict, so it can be
	// re-evaluated when the missing source arrives.
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (SC Indeterminate retains the head)", q.Len())
	}
}

// A source-commitment Indeterminate (incomplete receipt) retains the head across a terminal
// linear verdict, and once the missing source appears the next drain flips it to Verified and
// dequeues — the SC verdict participates in the retry lifecycle (Codex P2, Claude Important).
func TestAuditOne_SourceCommitment_IndeterminateRetainsThenVerifies(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	receipts := fakeReceipts{m: map[string][]string{headH: {scSrc1, scSrc2}}}
	// First: scSrc2 missing → SC Indeterminate, retained.
	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	heads := &mutableHeads{m: map[string]*vc.PipelinePassCredential{headH: {}, scSrc1: {}}}
	r, err := New(q, heads, cv, status, fakePool{}, okCfg(),
		WithClock(func() time.Time { return time.Unix(0, 0) }),
		WithSourceCommitment(receipts, scv))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = r.drainOnce(context.Background())
	if rec, _ := status.Get(headH); rec.SourceCommitment != vc.ConfidenceIndeterminate {
		t.Fatalf("first drain SourceCommitment = %v, want Indeterminate", rec.SourceCommitment)
	}
	if q.Len() != 1 {
		t.Fatalf("first drain queue len = %d, want 1 (retained)", q.Len())
	}

	// The missing source arrives; the next drain resolves the full set → Verified, dequeued.
	heads.m[scSrc2] = &vc.PipelinePassCredential{}
	_ = r.drainOnce(context.Background())
	rec, _ := status.Get(headH)
	if rec.SourceCommitment != vc.ConfidenceVerified {
		t.Errorf("second drain SourceCommitment = %v, want Verified", rec.SourceCommitment)
	}
	if q.Len() != 0 {
		t.Errorf("second drain queue len = %d, want 0 (now fully terminal)", q.Len())
	}
}

// A context cancellation while resolving a consumed source aborts the tick: nothing is
// recorded and the head stays queued (mirrors the linear ctx-cancel discipline).
func TestAuditOne_SourceCommitment_CtxCancelDuringResolve_RecordsNothing(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	receipts := fakeReceipts{m: map[string][]string{headH: {scSrc1}}}
	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	heads := ctxCancelHeads{ok: map[string]*vc.PipelinePassCredential{headH: {}}, cancel: scSrc1}
	r, err := New(q, heads, cv, status, fakePool{}, okCfg(),
		WithClock(func() time.Time { return time.Unix(0, 0) }),
		WithSourceCommitment(receipts, scv))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = r.drainOnce(context.Background())
	if _, err := status.Get(headH); err == nil {
		t.Error("recorded a verdict despite ctx cancel during source resolve; want none")
	}
	if q.Len() != 1 {
		t.Errorf("queue len = %d, want 1 (retained on cancel)", q.Len())
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d, want 0 (aborted before verify)", scv.calls)
	}
}

// mutableHeads is a HeadResolver whose backing map can be mutated between drains.
type mutableHeads struct {
	m map[string]*vc.PipelinePassCredential
}

func (h *mutableHeads) ResolveVC(_ context.Context, hash string) (*vc.PipelinePassCredential, error) {
	if c, ok := h.m[hash]; ok {
		return c, nil
	}
	return nil, errNotInStore
}

// ctxCancelHeads resolves ok hashes but returns context.Canceled for the `cancel` hash.
type ctxCancelHeads struct {
	ok     map[string]*vc.PipelinePassCredential
	cancel string
}

func (h ctxCancelHeads) ResolveVC(_ context.Context, hash string) (*vc.PipelinePassCredential, error) {
	if hash == h.cancel {
		return nil, context.Canceled
	}
	if c, ok := h.ok[hash]; ok {
		return c, nil
	}
	return nil, errNotInStore
}

// The verifier returns Failed (root mismatch / omission) → recorded, flag set, dequeued.
func TestAuditOne_SourceCommitment_Failed(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceFailed}
	receipts := fakeReceipts{m: map[string][]string{headH: {scSrc1}}}
	heads := map[string]*vc.PipelinePassCredential{scSrc1: {}}
	r, q, status := newRunnerSC(t, cv, receipts, scv, heads)

	_ = r.drainOnce(context.Background())
	rec, _ := status.Get(headH)
	if rec.SourceCommitment != vc.ConfidenceFailed {
		t.Errorf("SourceCommitment = %v, want Failed", rec.SourceCommitment)
	}
	if !rec.Scope.SourceCommitmentEvaluated {
		t.Error("flag must be set for a Failed source verdict")
	}
	if q.Len() != 0 {
		t.Errorf("queue len = %d, want 0", q.Len())
	}
}

// No local receipt (a downstream/non-emitting node auditing a consumed aggregate head) →
// linear-only; the source-commitment step is skipped and the flag stays false.
func TestAuditOne_SourceCommitment_NoReceipt_LinearOnly(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	receipts := fakeReceipts{m: map[string][]string{}} // no receipt for headH
	r, _, status := newRunnerSC(t, cv, receipts, scv, nil)

	_ = r.drainOnce(context.Background())
	rec, _ := status.Get(headH)
	if rec.Scope.SourceCommitmentEvaluated {
		t.Error("no receipt → SourceCommitmentEvaluated must stay false (linear-only)")
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d times, want 0 (no receipt → no evaluation)", scv.calls)
	}
}

// A receipt carrying a malformed content address is a corrupt receipt → fail-closed Failed,
// without calling the verifier (D-17o-6 decision table).
func TestAuditOne_SourceCommitment_CorruptReceipt_Failed(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	receipts := fakeReceipts{m: map[string][]string{headH: {"not-a-content-hash"}}}
	r, _, status := newRunnerSC(t, cv, receipts, scv, nil)

	_ = r.drainOnce(context.Background())
	rec, _ := status.Get(headH)
	if rec.SourceCommitment != vc.ConfidenceFailed {
		t.Errorf("SourceCommitment = %v, want Failed (corrupt receipt)", rec.SourceCommitment)
	}
	if !rec.Scope.SourceCommitmentEvaluated {
		t.Error("corrupt receipt is an evaluated (Failed) verdict → flag set")
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d times, want 0 (corrupt receipt short-circuits)", scv.calls)
	}
}
