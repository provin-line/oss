// Package contract defines the Pipeline Contract — the public contract every
// Pipeline Component conforms to on at least one I/O side. External adapter
// repositories import this package; its stability obligations are the
// strictest in the repository.
//
// The contract is transport-agnostic and VC-implementation-agnostic: it
// depends on vc types only — never on a broker client, never on
// generated proto code.
package contract

import (
	"context"
	"time"

	"github.com/provin-line/oss/vc"
)

// ChainBehavior declares a component's VC chain behaviour on its output
// side. Exactly one applies per output. The zero value is Unknown and is
// never valid — a component that cannot declare its behaviour must not run.
type ChainBehavior int

const (
	ChainBehaviorUnknown ChainBehavior = iota
	// ChainPreserving — output VC carries previousCredential = hash of the
	// input VC (FilterConvert). Deployments in the audit-reachable
	// conformance class additionally attach a vc.SourceCommitment over the
	// full consumed conformant source set, the triggering predecessor
	// included (all-consumed semantics; orthogonal to the chain link).
	ChainPreserving
	// ChainFirstDrop — output VC has no previousCredential: a fresh chain
	// origin (Origin Source — external ingestion or aggregation). The chain
	// carries no upstream link; input manifests are a data-payload concern.
	// Deployments in the audit-reachable conformance class additionally
	// attach a vc.SourceCommitment (an audit attribute over the consumed
	// source set, not a parent link — linearity is unaffected).
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

// StepKind names a step type composable inside a chain-preserving component
// (the provin StepComponent catalog). Steps are stateless per event;
// cross-event state would make the component an Origin Source. The PoC
// implements Convert / Filter / Verifier; Batch and SinkedSource are defined
// for contract completeness and land later.
type StepKind int

const (
	StepUnknown StepKind = iota
	// StepConvert — stateless payload transformation.
	StepConvert
	// StepFilter — stateless conditional pass / drop.
	StepFilter
	// StepVerifier — envelope unmarshal + signature verification + reject.
	StepVerifier
	// StepBatch — batch API call producing fresh output, stateless.
	StepBatch
	// StepSinkedSource — per-event external data fetch: the enrichment step
	// (side-fetched data joined onto the triggering event; chain preserved).
	StepSinkedSource
)

// SinkKind classifies an External Sink deployment by handling discipline.
// It is a config-driven attribute of a deployed component, not a separate
// component type. The zero value is Unknown and is never valid.
type SinkKind int

const (
	SinkKindUnknown SinkKind = iota
	// SinkObservationOnly — MAY emit invalid credentials (inspection
	// tooling); relaxed allow-list; no receipt obligation.
	SinkObservationOnly
	// SinkProduction — invalid emit prohibited; MUST reject; MUST enforce
	// the mutual allow-list; MAY emit receipts.
	SinkProduction
	// SinkArchival — invalid emit prohibited; MUST reject with an audit
	// log; MUST enforce the mutual allow-list; MUST emit receipts.
	SinkArchival
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

// Envelope is the unit carried between components on the transport.
//
// Normative chain semantics (previousCredential links, inputHash/outputHash,
// verification) depend ONLY on the credential and its content hashes — never
// on how the payload travelled. Whether Payload rides inline is a
// per-subscription transport choice: inline suits low-latency small-message
// exchange (A2A); by-reference suits large or confidential payloads (AI
// corpora, supply-chain records), where consumers locate data via the
// credential's hashes (VC resolver / object store). Verifier code is
// identical for both forms.
type Envelope struct {
	Credential *vc.PipelinePassCredential
	// Payload optionally carries the data bytes inline; nil means
	// by-reference delivery.
	Payload []byte
	// SequenceNo is the publisher-assigned, strictly increasing sequence
	// number. It makes append-only emission wire-verifiable: a gap or
	// reordering in a subscriber's view is evidence, not a glitch.
	SequenceNo uint64
}

// EnvelopeCodec marshals envelopes to and from their wire form. The concrete
// wire encoding is pinned at the proto layer; components and external
// adapters depend only on this interface.
type EnvelopeCodec interface {
	MarshalEnvelope(e *Envelope) ([]byte, error)
	UnmarshalEnvelope(data []byte) (*Envelope, error)
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
