// Package chainwalk_test tests the resolver-walk ChainVerifier.
//
// Test strategy: a fake CredentialResolver (an in-memory content-address →
// credential map standing in for the future network VC resolver) and a fake
// ChainCore (records the assembled chain it receives and returns a canned
// verdict). Credentials are real vc.PipelinePassCredentials linked by content
// address, so the walk is exercised against genuine Hash()/PreviousCredential()
// machinery — the assembly logic is what this package owns; the per-credential
// and chain-structure verification is the injected core's concern (the real one
// is vc.Verifier, currently a stub pending the resolver/crypto layer).
package chainwalk_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/pipeline/provenance/chainwalk"
	"github.com/provin-line/oss/vc"
)

// compile-time: *ChainVerifier must implement provenance.ChainVerifier.
var _ provenance.ChainVerifier = (*chainwalk.ChainVerifier)(nil)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeResolver struct {
	byAddr map[string]*vc.PipelinePassCredential
	calls  []string
	err    error
}

func (f *fakeResolver) ResolveCredential(_ context.Context, contentAddr string) (*vc.PipelinePassCredential, error) {
	f.calls = append(f.calls, contentAddr)
	if f.err != nil {
		return nil, f.err
	}
	cred, ok := f.byAddr[contentAddr]
	if !ok {
		return nil, errors.New("not found")
	}
	return cred, nil
}

type fakeCore struct {
	gotChain []*vc.PipelinePassCredential
	result   *vc.VerifyResult
	err      error
}

func (f *fakeCore) VerifyChain(_ context.Context, chain []*vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	f.gotChain = chain
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

// ---------------------------------------------------------------------------
// Helpers — build credentials linked by content address
// ---------------------------------------------------------------------------

func firstDrop(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:origin",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "origin",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          "sha256:" + repeat64('a'),
		},
	})
	if err != nil {
		t.Fatalf("firstDrop: %v", err)
	}
	return cred
}

// linkedTo builds a chain-preserving credential whose previousCredential is the
// content address of pred.
func linkedTo(t *testing.T, pred *vc.PipelinePassCredential, processID string) *vc.PipelinePassCredential {
	t.Helper()
	predAddr, err := pred.Hash()
	if err != nil {
		t.Fatalf("pred.Hash: %v", err)
	}
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:" + processID,
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           processID,
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          "sha256:" + repeat64('b'),
		},
		PreviousCredential: predAddr,
	})
	if err != nil {
		t.Fatalf("linkedTo: %v", err)
	}
	return cred
}

func repeat64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func addrOf(t *testing.T, c *vc.PipelinePassCredential) string {
	t.Helper()
	a, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	return a
}

func verified() *vc.VerifyResult { return &vc.VerifyResult{Overall: vc.ConfidenceVerified} }

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	res := &fakeResolver{}
	core := &fakeCore{result: verified()}

	if _, err := chainwalk.New(nil, core); err == nil {
		t.Error("nil resolver: expected error")
	}
	if _, err := chainwalk.New(res, nil); err == nil {
		t.Error("nil core: expected error")
	}
	if _, err := chainwalk.New(res, core); err != nil {
		t.Errorf("valid config: unexpected error %v", err)
	}
}

// ---------------------------------------------------------------------------
// Single FirstDrop head — no walk, core sees [head]
// ---------------------------------------------------------------------------

func TestVerifyChain_FirstDropHead_NoWalk(t *testing.T) {
	head := firstDrop(t)
	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
	core := &fakeCore{result: verified()}

	cv, _ := chainwalk.New(res, core)
	got, err := cv.VerifyChain(context.Background(), head)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if got.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall=%v, want ConfidenceVerified (core verdict returned verbatim)", got.Overall)
	}
	// No resolution: a FirstDrop has no predecessor.
	if len(res.calls) != 0 {
		t.Errorf("resolver called %d times for a FirstDrop head, want 0", len(res.calls))
	}
	if len(core.gotChain) != 1 || core.gotChain[0] != head {
		t.Errorf("core chain=%v, want exactly [head]", core.gotChain)
	}
}

// ---------------------------------------------------------------------------
// Two-hop chain assembled origin-first
// ---------------------------------------------------------------------------

func TestVerifyChain_TwoHops_AssembledOriginFirst(t *testing.T) {
	origin := firstDrop(t)
	mid := linkedTo(t, origin, "mid")
	head := linkedTo(t, mid, "head")

	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{
		addrOf(t, origin): origin,
		addrOf(t, mid):    mid,
	}}
	core := &fakeCore{result: verified()}

	cv, _ := chainwalk.New(res, core)
	got, err := cv.VerifyChain(context.Background(), head)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if got.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall=%v, want ConfidenceVerified", got.Overall)
	}
	// The core must receive the chain origin-first: [origin, mid, head].
	if len(core.gotChain) != 3 {
		t.Fatalf("core chain len=%d, want 3", len(core.gotChain))
	}
	if core.gotChain[0] != origin || core.gotChain[1] != mid || core.gotChain[2] != head {
		t.Errorf("core chain order wrong: want [origin, mid, head], got [%p %p %p] vs origin=%p mid=%p head=%p",
			core.gotChain[0], core.gotChain[1], core.gotChain[2], origin, mid, head)
	}
}

// ---------------------------------------------------------------------------
// Hole (unresolvable predecessor) → Go error, never a verdict
// ---------------------------------------------------------------------------

func TestVerifyChain_Hole_GoError(t *testing.T) {
	origin := firstDrop(t)
	head := linkedTo(t, origin, "head")

	// Resolver does NOT hold origin — the chain has a hole.
	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
	core := &fakeCore{result: verified()}

	cv, _ := chainwalk.New(res, core)
	got, err := cv.VerifyChain(context.Background(), head)
	if err == nil {
		t.Fatal("expected Go error on chain hole, got nil")
	}
	if got != nil {
		t.Errorf("result=%v, want nil alongside the hole error", got)
	}
	// The core must not be asked to verify an incomplete chain.
	if core.gotChain != nil {
		t.Error("core must not be called when the chain cannot be assembled")
	}
}

// ---------------------------------------------------------------------------
// Resolver context cancellation propagates as a Go error
// ---------------------------------------------------------------------------

func TestVerifyChain_ResolverCancellation_PropagatesGoError(t *testing.T) {
	origin := firstDrop(t)
	head := linkedTo(t, origin, "head")

	res := &fakeResolver{err: context.Canceled}
	core := &fakeCore{result: verified()}

	cv, _ := chainwalk.New(res, core)
	_, err := cv.VerifyChain(context.Background(), head)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled propagated", err)
	}
}

// Pre-flight cancellation returns ctx.Err before any work.
func TestVerifyChain_PreCancelled_GoError(t *testing.T) {
	head := firstDrop(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
	core := &fakeCore{result: verified()}
	cv, _ := chainwalk.New(res, core)

	_, err := cv.VerifyChain(ctx, head)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if len(res.calls) != 0 {
		t.Error("resolver must not be called after pre-flight cancellation")
	}
}

// ---------------------------------------------------------------------------
// Cycle detection → Go error (never loops forever)
// ---------------------------------------------------------------------------

func TestVerifyChain_Cycle_GoError(t *testing.T) {
	// head points at xAddr; the resolver returns, for xAddr, a credential whose
	// previousCredential points back at head's own content address. The walk
	// must break this resolution loop via its seen-set, not spin forever.
	head := linkedTo(t, firstDrop(t), "head")
	headAddr := addrOf(t, head)
	xAddr := head.PreviousCredential()

	loopBack, err := vc.New(vc.CredentialFields{
		Issuer:    "did:example:loopback",
		ValidFrom: time.Now(),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p",
			ProcessID:           "loopback",
			TransformationClaim: vc.ClaimConvert,
			OutputHash:          "sha256:" + repeat64('e'),
		},
		PreviousCredential: headAddr, // closes the loop back to head
	})
	if err != nil {
		t.Fatalf("loopBack: %v", err)
	}

	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{xAddr: loopBack}}
	cv, _ := chainwalk.New(res, &fakeCore{result: verified()})

	// Walk: head.prev=xAddr → loopBack.prev=headAddr → headAddr already seen → cycle.
	if _, err := cv.VerifyChain(context.Background(), head); err == nil {
		t.Fatal("expected Go error on cycle, got nil (walk must not loop forever)")
	}
}

// ---------------------------------------------------------------------------
// Max-depth bound → Go error
// ---------------------------------------------------------------------------

func TestVerifyChain_MaxDepthExceeded_GoError(t *testing.T) {
	// A chain of 3 against a MaxDepth of 2 must be rejected.
	origin := firstDrop(t)
	mid := linkedTo(t, origin, "mid")
	head := linkedTo(t, mid, "head")

	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{
		addrOf(t, origin): origin,
		addrOf(t, mid):    mid,
	}}
	core := &fakeCore{result: verified()}

	cv, err := chainwalk.New(res, core, chainwalk.WithMaxDepth(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := cv.VerifyChain(context.Background(), head); err == nil {
		t.Fatal("expected Go error when the chain exceeds MaxDepth, got nil")
	}
}

// ---------------------------------------------------------------------------
// nil head → Go error (programmer error, not a verdict)
// ---------------------------------------------------------------------------

func TestVerifyChain_NilHead_GoError(t *testing.T) {
	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
	core := &fakeCore{result: verified()}
	cv, _ := chainwalk.New(res, core)

	if _, err := cv.VerifyChain(context.Background(), nil); err == nil {
		t.Fatal("expected Go error on nil head, got nil")
	}
}

// ---------------------------------------------------------------------------
// Core verdict returned verbatim (failed, indeterminate)
// ---------------------------------------------------------------------------

func TestVerifyChain_CoreVerdictReturnedVerbatim(t *testing.T) {
	for _, want := range []vc.ConfidenceState{vc.ConfidenceFailed, vc.ConfidenceIndeterminate} {
		head := firstDrop(t)
		res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
		core := &fakeCore{result: &vc.VerifyResult{Overall: want}}
		cv, _ := chainwalk.New(res, core)

		got, err := cv.VerifyChain(context.Background(), head)
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if got.Overall != want {
			t.Errorf("Overall=%v, want %v (core verdict must pass through unchanged)", got.Overall, want)
		}
	}
}

// Core transport error propagates as a Go error.
func TestVerifyChain_CoreError_GoError(t *testing.T) {
	head := firstDrop(t)
	res := &fakeResolver{byAddr: map[string]*vc.PipelinePassCredential{}}
	core := &fakeCore{err: errors.New("core unavailable")}
	cv, _ := chainwalk.New(res, core)

	if _, err := cv.VerifyChain(context.Background(), head); err == nil {
		t.Fatal("expected Go error when the core fails, got nil")
	}
}
