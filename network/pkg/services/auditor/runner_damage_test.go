package auditor

// Damage-path behaviors of the error-sentinel store contracts (the
// evidence-persistence slice's Codex-High-1 gate): damage must never be read
// as absence anywhere in the audit path.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// damagedStatus fails Get with a NON-ErrNotFound error (a damaged verdict
// entry) but records Puts normally.
type damagedStatus struct {
	*MemStatusStore
	damaged map[string]bool
}

func (s *damagedStatus) Get(h string) (AuditRecord, error) {
	if s.damaged[h] {
		return AuditRecord{}, errors.New("damaged verdict entry")
	}
	return s.MemStatusStore.Get(h)
}

// A damaged prior verdict must NOT be trusted (no dequeue-without-verify) and
// must NOT abort the head: the runner re-audits from evidence and overwrites
// the record — repair, not trust in the file.
func TestAuditOne_DamagedVerdict_ReauditsAndRepairs(t *testing.T) {
	verifies := 0
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { verifies++; return verifiedResult(), nil }}
	q := NewMemQueue()
	_ = q.Add(headH)
	status := &damagedStatus{MemStatusStore: NewMemStatusStore(), damaged: map[string]bool{headH: true}}
	r, err := New(q, headStore(), cv, status, fakePool{}, okCfg(), WithClock(func() time.Time { return time.Unix(0, 0) }))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if verifies != 1 {
		t.Fatalf("VerifyChain calls = %d, want 1 (damaged verdict must trigger a re-audit)", verifies)
	}
	// The repaired verdict was recorded (read through the inner store, which
	// the damage shim does not intercept for Put).
	if rec, err := status.MemStatusStore.Get(headH); err != nil || rec.Overall != vc.ConfidenceVerified {
		t.Fatalf("repaired verdict = %+v (err %v), want Verified", rec, err)
	}
}

// damagedReceipts fails Get with a NON-ErrNotFound error: a receipt exists but
// cannot be read.
type damagedReceipts struct{}

func (damagedReceipts) Get(string) ([]string, error) { return nil, errors.New("damaged receipt entry") }

// A damaged receipt fails the consumed-set verdict CLOSED (SourceCommitment =
// Failed, scope evaluated) — never a silent downgrade to linear-only.
func TestAuditOne_DamagedReceipt_FailsClosedNotLinearOnly(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) { return verifiedResult(), nil }}
	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	r, err := New(q, headStore(), cv, status, fakePool{}, okCfg(),
		WithClock(func() time.Time { return time.Unix(0, 0) }),
		WithSourceCommitment(damagedReceipts{}, scv))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec, err := status.Get(headH)
	if err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if !rec.Scope.SourceCommitmentEvaluated || rec.SourceCommitment != vc.ConfidenceFailed {
		t.Fatalf("scope=%+v sc=%v, want evaluated + Failed (damage must not read as linear-only)", rec.Scope, rec.SourceCommitment)
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d times on a damaged receipt, want 0", scv.calls)
	}
}

// unreadableHeads fails ResolveVC with a NON-ErrNotFound error (a damaged
// evidence file), vs the definitive-miss sentinel.
type unreadableHeads struct{}

func (unreadableHeads) ResolveVC(context.Context, string) (*vc.PipelinePassCredential, error) {
	return nil, errors.New("damaged credential entry")
}

type missingHeads struct{}

func (missingHeads) ResolveVC(context.Context, string) (*vc.PipelinePassCredential, error) {
	return nil, fmt.Errorf("%w: gone", vcresolver.ErrNotFound)
}

// An unreadable head is retained (attempt-bounded), never silently dequeued;
// a definitive miss is dropped as a stale registration — the split the
// durable store makes meaningful.
func TestAuditOne_HeadUnreadableRetained_MissDropped(t *testing.T) {
	cv := fakeCV{fn: func() (*vc.VerifyResult, error) {
		t.Fatal("VerifyChain must not be called without a resolvable head")
		return nil, nil
	}}

	q := NewMemQueue()
	_ = q.Add(headH)
	status := NewMemStatusStore()
	r, err := New(q, unreadableHeads{}, cv, status, fakePool{}, okCfg())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 1 {
		t.Fatalf("unreadable head: queue len = %d, want 1 (retained)", q.Len())
	}
	list, _ := q.ListNewest(1)
	if len(list) != 1 || list[0].Attempts != 1 {
		t.Fatalf("unreadable head: attempts = %+v, want 1 (attempt-bounded retry)", list)
	}

	q2 := NewMemQueue()
	_ = q2.Add(headH)
	r2, err := New(q2, missingHeads{}, cv, status, fakePool{}, okCfg())
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.drainOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q2.Len() != 0 {
		t.Fatalf("missing head: queue len = %d, want 0 (stale registration dropped)", q2.Len())
	}
}

// A damaged verdict store read surfaces from the status SERVICE as a
// non-notfound error (the RPC layer maps it to internal, never not_found).
func TestGetStatus_DamageIsNotNotFound(t *testing.T) {
	head := "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	status := &damagedStatus{MemStatusStore: NewMemStatusStore(), damaged: map[string]bool{head: true}}
	svc := NewStatusService(status)
	_, err := svc.GetStatus(context.Background(), head)
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("damaged verdict via GetStatus: want a non-notfound error, got %v", err)
	}
}
