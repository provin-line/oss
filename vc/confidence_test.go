package vc_test

import (
	"context"
	"testing"
	"time"

	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// EvaluateConfidence is the greatest-lower-bound (weakest link) of the three
// axes: any failed → failed; all verified → verified; otherwise indeterminate.
func TestEvaluateConfidence_GLB(t *testing.T) {
	const (
		F = vc.ConfidenceFailed
		I = vc.ConfidenceIndeterminate
		V = vc.ConfidenceVerified
	)
	cases := []struct {
		name             string
		di, sa, cc, want vc.ConfidenceState
	}{
		{"all verified", V, V, V, V},
		{"one failed dominates verified", F, V, V, F},
		{"failed dominates indeterminate", V, F, I, F},
		{"failed in last axis", V, V, F, F},
		{"all failed", F, F, F, F},
		{"one indeterminate, rest verified", V, I, V, I},
		{"all indeterminate", I, I, I, I},
		{"indeterminate but no failed", I, V, I, I},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := vc.EvaluateConfidence(vc.AxisResult{
				DataIntegrity:      c.di,
				SignerAuthenticity: c.sa,
				ChainConsistency:   c.cc,
			})
			if got != c.want {
				t.Errorf("EvaluateConfidence(%v,%v,%v)=%v, want %v", c.di, c.sa, c.cc, got, c.want)
			}
		})
	}
}

// The zero AxisResult (all axes unset → ConfidenceFailed, the zero value) must
// compose to failed: the lattice fails closed.
func TestEvaluateConfidence_ZeroFailsClosed(t *testing.T) {
	if got := vc.EvaluateConfidence(vc.AxisResult{}); got != vc.ConfidenceFailed {
		t.Errorf("EvaluateConfidence(zero)=%v, want ConfidenceFailed (fail-closed)", got)
	}
}

// stubLifecycle is a minimal LifecycleRegistry for plumbing tests.
type stubLifecycle struct {
	phase vc.LifecyclePhase
}

func (s stubLifecycle) PhaseAt(ctx context.Context, id string, t time.Time) (vc.LifecyclePhase, error) {
	return s.phase, nil
}
func (s stubLifecycle) Entries(ctx context.Context, id string) ([]vc.LifecycleEntry, error) {
	return nil, nil
}

// WithLifecycleRegistry is an accepted construction option: NewVerifier wired
// with it returns a usable verifier (the lifecycle behaviour itself is
// exercised in the single-credential Verify tests).
func TestNewVerifier_WithLifecycleRegistry(t *testing.T) {
	v := vc.NewVerifier(local.New(), nil, vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseActive}))
	if v == nil {
		t.Fatal("NewVerifier with WithLifecycleRegistry returned nil")
	}
}
