package auditor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

// --- fakes for the consume-locus verifier (slice-17q) ---

type fakeSourceResolver struct {
	byHash map[string]*vc.PipelinePassCredential
	errs   map[string]error // hash -> error the resolver returns (ErrSourceNotFound / transient / ctx)
	calls  int
}

func (f *fakeSourceResolver) Resolve(_ context.Context, h string) (*vc.PipelinePassCredential, error) {
	f.calls++
	if e, ok := f.errs[h]; ok {
		return nil, e
	}
	if c, ok := f.byHash[h]; ok {
		return c, nil
	}
	return nil, ErrSourceNotFound
}

// srcCred builds a minimal source credential and returns it with its content address.
func srcCred(t *testing.T, issuer string) (*vc.PipelinePassCredential, string) {
	t.Helper()
	c, err := vc.New(vc.CredentialFields{
		Issuer:    issuer,
		ValidFrom: time.Unix(0, 0),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "p", ProcessID: "q",
			TransformationClaim: vc.ClaimConvert, OutputHash: "sha256:" + issuer,
		},
	})
	if err != nil {
		t.Fatalf("vc.New(%q): %v", issuer, err)
	}
	h, err := c.Hash()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return c, h
}

func newConsumeVerifier(t *testing.T, scv SourceCommitmentVerifier, src SourceResolver) *ConsumeVerifier {
	t.Helper()
	v, err := NewConsumeVerifier(scv, src)
	if err != nil {
		t.Fatalf("NewConsumeVerifier: %v", err)
	}
	return v
}

// Full fetch, no tamper, verifier Verified → Verified/verified. The verifier is handed exactly
// the fetched sources.
func TestConsumeVerify_FullFetch_Verified(t *testing.T) {
	cA, hA := srcCred(t, "did:example:a")
	cB, hB := srcCred(t, "did:example:b")
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA, hB: cB}}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA, hB})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.State != vc.ConfidenceVerified || verdict.Reason != ReasonVerified {
		t.Errorf("verdict = {%v,%q}, want {Verified,verified}", verdict.State, verdict.Reason)
	}
	if scv.gotSources != 2 {
		t.Errorf("verifier got %d sources, want 2 (full fetched set)", scv.gotSources)
	}
}

// A fetched body whose content hash != the requested hash is a tamper → Failed/mismatch,
// short-circuit (verifier never called).
func TestConsumeVerify_Tamper_FailedMismatch(t *testing.T) {
	cA, _ := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	// Map a DIFFERENT (well-formed) requested hash to cA, whose real content hash differs.
	requested := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{requested: cA}}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{requested})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.State != vc.ConfidenceFailed || verdict.Reason != ReasonMismatch {
		t.Errorf("verdict = {%v,%q}, want {Failed,mismatch}", verdict.State, verdict.Reason)
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d, want 0 (tamper short-circuits)", scv.calls)
	}
}

// A malformed consumed hash is a caller precondition violation → ErrInvalidConsumedHash (a
// fail-closed error, NOT a transient Indeterminate that would loop on retry). The resolver is
// never even consulted.
func TestConsumeVerify_MalformedHash_ErrorFailClosed(t *testing.T) {
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	res := &fakeSourceResolver{}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{"not-a-content-hash"})
	if !errors.Is(err, ErrInvalidConsumedHash) {
		t.Errorf("err = %v, want ErrInvalidConsumedHash", err)
	}
	if verdict.State != 0 {
		t.Errorf("verdict = %+v, want zero (no verdict on invalid input)", verdict)
	}
	if res.calls != 0 {
		t.Errorf("resolver called %d, want 0 (malformed input rejected before fetch)", res.calls)
	}
}

// A non-ctx verifier error over the full set → Failed/mismatch, notation labels it a verifier
// error (not a cryptographic contradiction).
func TestConsumeVerify_VerifierError_Failed(t *testing.T) {
	cA, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceFailed, err: errors.New("duplicate gathered source")}
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA}}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict.State != vc.ConfidenceFailed || verdict.Reason != ReasonMismatch {
		t.Errorf("verdict = {%v,%q}, want {Failed,mismatch}", verdict.State, verdict.Reason)
	}
	if !strings.Contains(verdict.Notation, "verifier error") {
		t.Errorf("notation = %q, want it to label a verifier error", verdict.Notation)
	}
}

// A ctx error from the verifier itself (all sources fetched) → abort, no verdict.
func TestConsumeVerify_VerifierCtxCancel_Aborts(t *testing.T) {
	cA, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceFailed, err: context.Canceled}
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA}}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled (abort)", err)
	}
	if verdict.State != 0 {
		t.Errorf("verdict = %+v, want zero (record nothing on abort)", verdict)
	}
}

// Full fetch but the verifier returns Failed (root mismatch / issuer outside set) → Failed/mismatch.
func TestConsumeVerify_FullFetch_VerifierFailed(t *testing.T) {
	cA, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceFailed}
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA}}
	v := newConsumeVerifier(t, scv, res)

	verdict, _ := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if verdict.State != vc.ConfidenceFailed || verdict.Reason != ReasonMismatch {
		t.Errorf("verdict = {%v,%q}, want {Failed,mismatch}", verdict.State, verdict.Reason)
	}
}

// Full fetch but the verifier returns Indeterminate (fetched set misses a claimed issuer) →
// Indeterminate/incomplete — recorded VERBATIM (Codex #2).
func TestConsumeVerify_FullFetch_VerifierIncomplete(t *testing.T) {
	cA, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceIndeterminate}
	res := &fakeSourceResolver{byHash: map[string]*vc.PipelinePassCredential{hA: cA}}
	v := newConsumeVerifier(t, scv, res)

	verdict, _ := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if verdict.State != vc.ConfidenceIndeterminate || verdict.Reason != ReasonIncomplete {
		t.Errorf("verdict = {%v,%q}, want {Indeterminate,incomplete}", verdict.State, verdict.Reason)
	}
}

// A hash authoritatively not found at the resolver → Indeterminate/orphan, no recompute.
func TestConsumeVerify_Orphan_Indeterminate(t *testing.T) {
	_, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	res := &fakeSourceResolver{errs: map[string]error{hA: ErrSourceNotFound}}
	v := newConsumeVerifier(t, scv, res)

	verdict, _ := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if verdict.State != vc.ConfidenceIndeterminate || verdict.Reason != ReasonOrphan {
		t.Errorf("verdict = {%v,%q}, want {Indeterminate,orphan}", verdict.State, verdict.Reason)
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d, want 0 (no recompute over a partial set)", scv.calls)
	}
}

// A transient/unreachable resolver error → Indeterminate/unavailable, no recompute.
func TestConsumeVerify_Unavailable_Indeterminate(t *testing.T) {
	_, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	res := &fakeSourceResolver{errs: map[string]error{hA: errors.New("dial tcp: connection refused")}}
	v := newConsumeVerifier(t, scv, res)

	verdict, _ := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if verdict.State != vc.ConfidenceIndeterminate || verdict.Reason != ReasonUnavailable {
		t.Errorf("verdict = {%v,%q}, want {Indeterminate,unavailable}", verdict.State, verdict.Reason)
	}
	if scv.calls != 0 {
		t.Errorf("verifier called %d, want 0", scv.calls)
	}
}

// Context cancellation during resolve → abort: return the ctx error and NO verdict (matching
// the emit-locus runner discipline, Codex #4).
func TestConsumeVerify_CtxCancel_AbortsNoVerdict(t *testing.T) {
	_, hA := srcCred(t, "did:example:a")
	scv := &fakeSCV{state: vc.ConfidenceVerified}
	res := &fakeSourceResolver{errs: map[string]error{hA: context.Canceled}}
	v := newConsumeVerifier(t, scv, res)

	verdict, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}, []string{hA})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled (abort)", err)
	}
	if verdict.State != 0 || verdict.Reason != "" {
		t.Errorf("verdict = {%v,%q}, want zero (record nothing on abort)", verdict.State, verdict.Reason)
	}
}

func TestNewConsumeVerifier_RejectsNil(t *testing.T) {
	if _, err := NewConsumeVerifier(nil, &fakeSourceResolver{}); err == nil {
		t.Error("nil scv: want error")
	}
	if _, err := NewConsumeVerifier(&fakeSCV{}, nil); err == nil {
		t.Error("nil resolver: want error")
	}
}
