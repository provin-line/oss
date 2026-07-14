// Package verifycount is a counting decorator over provenance.Verifier: it
// delegates every Verify call unchanged and counts the call's OUTCOME — the
// verifier API result, NOT the consumer's effective verdict (a chained/sink
// runtime maps a non-context Verify error to an indeterminate rejection, an
// aggregate drops the input; this package deliberately measures the seam
// below those policies).
//
// It is the metrics wiring point for per-credential verification (P1-2): the
// composition root wraps the shared verifier once per consuming loop, so
// per-loop attribution falls out of the wrapping, and polls Snapshot from a
// metrics surface — the same poll-from-another-goroutine intent as
// transport.Emitter's counters. Like logobserver, it is dependency-free by
// design: bridging the counts to a concrete metrics system (OpenTelemetry,
// Prometheus, …) is the embedder's concern.
//
// Outcome buckets:
//
//   - "verified" / "failed" / "indeterminate" — the result's Overall
//     confidence when Verify returns a result and a nil error.
//   - "error" — Verify returned a non-nil error that is NOT a context
//     sentinel, or the anomalous (nil, nil) pair (an API contract violation
//     must not vanish from the counts).
//
// A context-sentinel error (errors.Is context.Canceled/DeadlineExceeded) is
// counted nowhere: an interruption is neither a verdict nor a verifier
// failure. Note the limit of that exclusion: vc.Verifier converts resolver
// failures — including a cancellation surfacing mid-resolution — into an
// Indeterminate result with a nil error, so the only interruptions this
// decorator can exclude are the ones that actually error with a sentinel.
package verifycount

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/vc"
)

// Verifier wraps a provenance.Verifier and counts each call's API outcome.
// Construct it with New. Counters are monotonic and safe to read from a
// different goroutine than the ones calling Verify.
type Verifier struct {
	inner provenance.Verifier

	verified      atomic.Uint64
	failed        atomic.Uint64
	indeterminate atomic.Uint64
	errored       atomic.Uint64
}

var _ provenance.Verifier = (*Verifier)(nil)

// New returns a counting decorator over inner.
func New(inner provenance.Verifier) *Verifier {
	return &Verifier{inner: inner}
}

// Verify delegates to the wrapped verifier, counts the outcome (see the
// package doc for the bucket semantics), and returns the inner result and
// error unchanged.
func (v *Verifier) Verify(ctx context.Context, cred *vc.PipelinePassCredential) (*vc.VerifyResult, error) {
	res, err := v.inner.Verify(ctx, cred)
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		// An interruption: neither a verdict nor a verifier failure.
	case err != nil:
		v.errored.Add(1)
	case res == nil:
		// (nil, nil) violates the Verifier contract — count it where it is
		// visible rather than let the anomaly vanish.
		v.errored.Add(1)
	case res.Overall == vc.ConfidenceVerified:
		v.verified.Add(1)
	case res.Overall == vc.ConfidenceFailed:
		v.failed.Add(1)
	default:
		// ConfidenceIndeterminate and any future/unknown confidence: the
		// weakest-link composition already treats "not verified, not failed"
		// as indeterminate, so an unknown value must not vanish either.
		v.indeterminate.Add(1)
	}
	return res, err
}

// Snapshot returns the monotonic outcome counts keyed by
// "verified" | "failed" | "indeterminate" | "error". Every key is always
// present (zero-valued when never hit), so a metrics bridge can register a
// fixed label set.
func (v *Verifier) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"verified":      v.verified.Load(),
		"failed":        v.failed.Load(),
		"indeterminate": v.indeterminate.Load(),
		"error":         v.errored.Load(),
	}
}
