package vc

import (
	"context"
	"time"
)

// LifecycleEntry is one append-only transition record of the lifecycle
// registry: identifier id entered Phase at EffectiveDate. Transitions are
// recorded as new entries; history is never rewritten.
type LifecycleEntry struct {
	// ID is the protocol identifier (cryptosuite or canonicalizer name).
	ID            string
	Phase         LifecyclePhase
	EffectiveDate time.Time
}

// LifecycleRegistry answers "what was the lifecycle phase of identifier id
// at instant t" — t is the credential's proof.created. It is one of the
// snapshot inputs that make verification deterministic: any verifier given
// the same registry snapshot produces the same accept/reject decision.
//
// The published form is an append-only artifact per wire profile, backed by
// tlog; this package owns only the lookup contract.
type LifecycleRegistry interface {
	// PhaseAt returns the phase in effect for id at t. PhaseUnknown
	// (fail-closed) when no entry covers t.
	PhaseAt(ctx context.Context, id string, t time.Time) (LifecyclePhase, error)
	// Entries returns the full transition history for id, for audit.
	Entries(ctx context.Context, id string) ([]LifecycleEntry, error)
}

// WithLifecycleRegistry wires the lifecycle registry consulted during
// signer-authenticity evaluation (Active → verified; Deprecated → verified
// with annotation; Sunset/Unknown → failed).
func WithLifecycleRegistry(r LifecycleRegistry) VerifierOption {
	return func(v *Verifier) { v.lifecycle = r }
}
