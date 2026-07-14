package verifycount_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/pipeline/provenance/verifycount"
	"github.com/provin-line/oss/vc"
)

// fakeVerifier returns a scripted (result, error) per call.
type fakeVerifier struct {
	res *vc.VerifyResult
	err error
}

func (f *fakeVerifier) Verify(context.Context, *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	return f.res, f.err
}

func resultWith(overall vc.ConfidenceState) *vc.VerifyResult {
	return &vc.VerifyResult{Overall: overall}
}

// Each verifier API outcome increments exactly its own bucket, and the
// decorator is transparent (result and error pass through unchanged).
func TestVerifier_CountsAPIOutcomes(t *testing.T) {
	inner := &fakeVerifier{}
	v := verifycount.New(inner)
	ctx := context.Background()

	for _, c := range []struct {
		res *vc.VerifyResult
		err error
	}{
		{resultWith(vc.ConfidenceVerified), nil},
		{resultWith(vc.ConfidenceFailed), nil},
		{resultWith(vc.ConfidenceIndeterminate), nil},
		{nil, errors.New("resolver transport: boom")},
	} {
		inner.res, inner.err = c.res, c.err
		res, err := v.Verify(ctx, &vc.PipelinePassCredential{})
		if res != c.res || !errors.Is(err, c.err) {
			t.Fatalf("decorator not transparent: got (%v, %v), want (%v, %v)", res, err, c.res, c.err)
		}
	}

	want := map[string]uint64{"verified": 1, "failed": 1, "indeterminate": 1, "error": 1}
	got := v.Snapshot()
	for k, n := range want {
		if got[k] != n {
			t.Errorf("Snapshot[%q] = %d, want %d (full snapshot: %v)", k, got[k], n, got)
		}
	}
}

// Context-sentinel errors are an interruption, not a verdict and not a
// verifier failure: they are excluded from every bucket.
func TestVerifier_ContextSentinelsNotCounted(t *testing.T) {
	ctx := context.Background()
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		inner := &fakeVerifier{err: sentinel}
		v := verifycount.New(inner)
		if _, err := v.Verify(ctx, &vc.PipelinePassCredential{}); !errors.Is(err, sentinel) {
			t.Fatalf("want sentinel %v passed through, got %v", sentinel, err)
		}
		// A wrapped sentinel must also be excluded (errors.Is semantics).
		inner.err = errors.Join(errors.New("verify aborted"), sentinel)
		if _, err := v.Verify(ctx, &vc.PipelinePassCredential{}); err == nil {
			t.Fatal("want wrapped sentinel passed through")
		}
		for k, n := range v.Snapshot() {
			if n != 0 {
				t.Errorf("sentinel %v: Snapshot[%q] = %d, want 0", sentinel, k, n)
			}
		}
	}
}

// A (nil, nil) return is a Verifier API contract violation: it must not
// vanish from the counts — it lands in "error".
func TestVerifier_NilNilCountsAsError(t *testing.T) {
	v := verifycount.New(&fakeVerifier{})
	if res, err := v.Verify(context.Background(), &vc.PipelinePassCredential{}); res != nil || err != nil {
		t.Fatalf("want (nil, nil) passed through, got (%v, %v)", res, err)
	}
	if got := v.Snapshot()["error"]; got != 1 {
		t.Errorf(`Snapshot["error"] = %d, want 1 (nil-nil anomaly)`, got)
	}
}
