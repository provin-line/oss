// Package contract defines the Pipeline Contract — the public contract every
// Pipeline Component conforms to on at least one I/O side. External adapter
// repositories import this package; its stability obligations are the
// strictest in the repository.
//
// The contract is transport-agnostic and VC-implementation-agnostic: it
// depends on packages/vc types only — never on a broker client, never on
// generated proto code.
package contract

import (
	"context"
	"time"

	"github.com/provin-line/oss/packages/vc"
)

// ChainBehavior declares a component's VC chain behaviour on its output
// side. Exactly one applies per output. The zero value is Unknown and is
// never valid — a component that cannot declare its behaviour must not run.
type ChainBehavior int

const (
	ChainBehaviorUnknown ChainBehavior = iota
	// ChainPreserving — output VC carries previousCredential = hash of the
	// input VC (FilterConvert).
	ChainPreserving
	// ChainFirstDrop — output VC has no previousCredential: a fresh chain
	// origin (Origin Source — external ingestion or aggregation). Upstream
	// references are a data-payload concern, never credential fields.
	ChainFirstDrop
	// ChainTerminating — consumes and verifies; produces nothing in-network
	// (External Sink).
	ChainTerminating
)

// VerificationStrategy names the ingress verification a component runs
// before trusting input. The zero value is Unknown and fails closed.
type VerificationStrategy int

const (
	VerificationUnknown VerificationStrategy = iota
	// VerificationNone — first-stage components consuming non-VC input.
	VerificationNone
	// VerificationAdjacent — verify the immediately preceding VC (mandatory
	// at every non-first-stage boundary).
	VerificationAdjacent
	// VerificationFull — verify the full chain (observation tooling, sinks).
	VerificationFull
)

// Status is the outcome of processing one event.
type Status int

const (
	StatusUnknown Status = iota
	StatusPassed
	StatusFiltered
	StatusErrored
)

// Result is the outcome of one Process call.
type Result struct {
	Status Status
	// VC is the issued credential (StatusPassed only).
	VC *vc.PipelinePassCredential
	// Confidence is the ingress verification verdict (when a verification
	// strategy other than None ran).
	Confidence vc.ConfidenceState
	// FilteredAtStep is the index of the filter step that rejected the event
	// (StatusFiltered only).
	FilteredAtStep int
	// Error is the failure description (StatusErrored only) — serializable,
	// not an error value, because results cross process boundaries.
	Error string
}

// Processor turns one input event into one Result. Implementations carry the
// component's full per-event lifecycle (ingress verification, transformation,
// signing, observation).
type Processor interface {
	Process(ctx context.Context, input []byte) (*Result, error)
}

// Component is a runnable pipeline component bound to its transport.
type Component interface {
	// Run consumes and processes events until ctx is cancelled, then drains
	// gracefully.
	Run(ctx context.Context) error
	// ChainBehavior declares the component's output-side chain behaviour.
	// Must return the same non-Unknown value for the component's lifetime.
	ChainBehavior() ChainBehavior
}

// ProcessEvent is the post-processing notification delivered to observers.
type ProcessEvent struct {
	Result *Result
	// InputHash / OutputHash are the sha256 hex digests embedded in the VC.
	InputHash  string
	OutputHash string
	// VCRef is the issued credential's content address ("sha256:<hex>").
	VCRef     string
	Timestamp time.Time
}

// ProcessObserver is notified after each processed event. Observation is
// fire-and-forget: failures are logged by the caller, never propagated into
// the processing path.
type ProcessObserver interface {
	OnProcessComplete(ctx context.Context, ev ProcessEvent) error
}

// IngressVCStore persists verified ingress VCs for audit reachability.
// Components running a verification strategy other than None MUST be
// configured with one — verifying without storing breaks chain audits.
type IngressVCStore interface {
	StoreIngressVC(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) error
}
