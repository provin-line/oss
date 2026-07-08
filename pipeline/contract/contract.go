// Package contract defines the Pipeline Contract — the public contract every
// Pipeline Process conforms to on at least one I/O side. External adapter
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

// ChainBehavior declares a process's VC chain behaviour on its output
// side. Exactly one applies per output. The zero value is Unknown and is
// never valid — a process that cannot declare its behaviour must not run.
type ChainBehavior int

const (
	ChainBehaviorUnknown ChainBehavior = iota
	// ChainPreserving — output VC carries previousCredential = hash of the
	// input VC (Chained Process). Deployments in the audit-reachable
	// conformance class additionally attach a vc.SourceCommitment over the
	// full consumed conformant source set, the triggering predecessor
	// included (all-consumed semantics; orthogonal to the chain link).
	ChainPreserving
	// ChainFirstDrop — output VC has no previousCredential: a fresh chain
	// origin (Source Process — external ingestion or aggregation). The chain
	// carries no upstream link; input manifests are a data-payload concern.
	// Deployments in the audit-reachable conformance class additionally
	// attach a vc.SourceCommitment (an audit attribute over the consumed
	// source set, not a parent link — linearity is unaffected).
	ChainFirstDrop
	// ChainTerminating — consumes and verifies; produces nothing in-network
	// (Sink Process).
	ChainTerminating
)

// VerificationStrategy names the ingress verification a process runs
// before trusting input. The zero value is Unknown and fails closed.
type VerificationStrategy int

const (
	VerificationUnknown VerificationStrategy = iota
	// VerificationNone — processes with no Pipeline-conformant ingress
	// (consuming raw external input only).
	VerificationNone
	// VerificationAdjacent — verify the immediately preceding VC (mandatory
	// at every Pipeline-conformant ingress boundary). Full-chain verification is
	// the async audit runner's job (slice-17h), not a real-time ingress strategy
	// (slice-17j retired the real-time "full" strategy).
	VerificationAdjacent
)

// StepKind names a step type composable inside a Chained Process (the
// provin step catalog). Steps are stateless per event; cross-event state
// would make the process a Source Process. The PoC implements Convert /
// Filter / Verifier; Batch and SinkedSource are defined for contract
// completeness and land later.
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

// SinkKind classifies a Sink Process deployment by handling discipline.
// It is a config-driven attribute of a deployed process, not a separate
// process type. The zero value is Unknown and is never valid.
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
//
// For a ChainTerminating process (Sink Process), StatusPassed means the
// ingress verification ran and the external write completed — it does NOT
// require ConfidenceVerified (an observation-only sink may emit invalid
// credentials); the verdict itself rides Confidence. VC and Payload are nil:
// a sink produces nothing in-network.
type Result struct {
	Status Status
	// VC is the issued credential (StatusPassed on a producing process
	// only).
	VC *vc.PipelinePassCredential
	// Payload is the produced data bytes (StatusPassed on a producing
	// process only): the exact byte string whose sha256 is the VC's
	// outputHash, and it is never empty (profile norm — see Envelope).
	// Processes always produce the full inline form; by-reference
	// stripping happens at the cross-organization export seam, never
	// here. The runtime loop may re-verify the hash identity before
	// publishing; a mismatch is a process bug and fails loudly.
	Payload []byte
	// Confidence is the ingress verification verdict; nil means no
	// verification ran. A process declaring VerificationNone always
	// leaves it nil; under any other strategy it MUST be set for every
	// event arriving on a Pipeline-conformant ingress side, and stays nil
	// only for events arriving on non-conformant input — which is outside
	// the declaration. Absence is a contract-layer concern — the vc
	// confidence lattice itself has no "unknown" state and gains none
	// here.
	Confidence *vc.ConfidenceState
	// FilteredAtStep is the index of the filter step that rejected the event
	// (StatusFiltered only).
	FilteredAtStep int
	// Error is the failure description (StatusErrored only) — serializable,
	// not an error value, because results cross process boundaries.
	Error string
}

// EventProcessor turns one input event into one Result. Implementations carry the
// process's full per-event lifecycle (ingress verification, transformation,
// signing, observation).
//
// EventProcessor is the contract for event-triggered processing — the unit a
// transport runtime loop drives (one input event in, one Result out).
// Implementing it is optional: mechanics that own their trigger (timer /
// window aggregation) implement Process directly and never pass through an
// EventProcessor. First-stage push ingestion is event-triggered in this sense —
// the external push is the event.
type EventProcessor interface {
	Process(ctx context.Context, input []byte) (*Result, error)
}

// Process is a runnable pipeline process bound to its transport. It is
// the only mandatory contract: a conformant implementation exposes Run plus
// the declaration methods.
//
// One Process value represents exactly one pipeline output side (or a
// terminating consumer). A Custom Process with several output sides
// composes one Process per side — which processes a binary hosts is
// decided by their signing paths, never by packaging.
type Process interface {
	// Run consumes and processes events until ctx is cancelled, then drains
	// gracefully.
	Run(ctx context.Context) error
	// ChainBehavior declares the process's output-side chain behaviour.
	// Must return the same non-Unknown value for the process's lifetime.
	ChainBehavior() ChainBehavior
	// VerificationStrategy declares the verification run on every
	// Pipeline-conformant ingress side of this process — a floor
	// obligation applied uniformly, not a per-side enumeration.
	// Non-conformant input (raw external bytes, foreign credentials) is
	// outside this declaration: it is unverifiable by definition; a
	// process with no conformant ingress declares VerificationNone.
	//
	// The value is an instance declaration fixed at construction, not a
	// property of the process type — the same process code may run as
	// a chain head with None and mid-chain with Adjacent. It must return
	// the same non-Unknown value for the process's lifetime.
	//
	// Startup enforcement splits in two: a process declaring a strategy
	// other than None must be configured with an IngressVCStore (a
	// self-contained check), while the legitimacy of a None declaration is
	// checked against deploy wiring metadata at construction time — the
	// declaration alone cannot reveal whether conformant ingress exists.
	VerificationStrategy() VerificationStrategy
}

// Envelope is the unit carried between processes on the transport.
//
// Normative chain semantics (previousCredential links, inputHash/outputHash,
// verification) depend ONLY on the credential and its content hashes — never
// on how the payload travelled. Whether Payload rides inline is a
// per-subscription transport choice: inline suits low-latency small-message
// exchange (A2A) — choose it when the consumer's processing deadline cannot
// absorb a resolver round-trip plus fetch (concrete latency budgets are a
// benchmarks concern, separate repository); by-reference suits large or
// confidential payloads (AI corpora, supply-chain records), where consumers
// fetch data from the publisher's serving boundary by content hash, and
// provenance-only consumers never fetch at all. Verifier code is identical
// for both forms.
//
// The mode is the subscription's AGREED mode, not the subscriber's wish: it
// is negotiated at registration (the requested mode rides the L2-signed
// RegisterSubscription view; a mode the publisher does not offer is a typed
// wiring-time rejection, never a silent runtime fallback) and is immutable
// for the subscription's lifetime. Inside an organization, processes always
// produce the full (inline) envelope; the agreed mode is applied at the
// cross-organization export seam — stripping the payload is one-way cheap.
// Choosing inline does not lift the publisher's audit-side resolver
// obligation; it only takes resolution off the consume hot path.
type Envelope struct {
	Credential *vc.PipelinePassCredential
	// Payload optionally carries the data bytes inline; nil means
	// by-reference delivery.
	//
	// An inline payload is never empty — a producing process MUST emit
	// non-empty payload bytes (profile norm). Empty and absent bytes are
	// indistinguishable on a proto3 wire, so admitting an empty inline
	// payload would make "publisher sent empty" and "payload stripped in
	// error" the same bytes; forbidding it makes an absent payload on an
	// inline-mode subscription a decidable protocol violation.
	// Business-level "empty" output uses an explicit payload
	// representation instead.
	Payload []byte
	// SequenceNo is the publisher-assigned, strictly increasing sequence
	// number. It makes append-only emission wire-verifiable: a gap or
	// reordering in a subscriber's view is evidence to investigate, not a
	// glitch. In normal operation the publisher never creates a gap by its own
	// failure (a failed publish reuses the number), so a gap means POSSIBLE
	// LOSS — at-most-once transport, or a producer crash inside its emit window
	// (see transport.Emitter) — NOT an automatic tamper verdict, and distinct
	// from the worse signal of a repeated number carrying different content.
	SequenceNo uint64
}

// EnvelopeCodec marshals envelopes to and from their wire form. The concrete
// wire encoding is pinned at the proto layer; processes and external
// adapters depend only on this interface.
type EnvelopeCodec interface {
	MarshalEnvelope(e *Envelope) ([]byte, error)
	UnmarshalEnvelope(data []byte) (*Envelope, error)
}

// ProcessEvent is the post-processing notification delivered to observers.
//
// The credential-reference fields are named by ROLE so a generic observer
// never has to infer what a non-empty value means from prose: a producing
// process sets IssuedVCRef (the credential it minted); a terminating Sink
// Process sets ConsumedVCRef (the credential it consumed and terminated).
// At most one is populated per event; the other is empty.
type ProcessEvent struct {
	Result *Result
	// InputHash / OutputHash are sha256 hex digests ("sha256:<hex>"). For a
	// producing process they are the issued credential's input/output hashes.
	// For a terminating Sink Process, InputHash is the hash of the consumed
	// payload (== the consumed credential's outputHash, enforced by the binding
	// gate) and OutputHash is empty — a sink produces nothing in-network.
	InputHash  string
	OutputHash string
	// IssuedVCRef is the content address ("sha256:<hex>") of the credential
	// this process ISSUED. Producing processes (Source, Chained) set it; a
	// terminating Sink Process leaves it empty — it issues nothing.
	IssuedVCRef string
	// ConsumedVCRef is the content address of the credential this process
	// CONSUMED at its terminating boundary — a Sink Process sets it as the
	// audit handle back to the chain it terminated. Producing processes leave
	// it empty: their consumed predecessor is already reachable via the issued
	// credential's previousCredential. Resolution caveat: an observation-only
	// sink does not store the consumed credential for an invalid/indeterminate
	// verdict (store-on-verified), so resolving ConsumedVCRef in that case
	// depends on the credential remaining available upstream.
	ConsumedVCRef string
	Timestamp     time.Time
}

// ProcessObserver is notified after each processed event. Observation is
// fire-and-forget: failures are logged by the caller, never propagated into
// the processing path.
type ProcessObserver interface {
	OnProcessComplete(ctx context.Context, ev ProcessEvent) error
}

// IngressVCStore persists verified ingress VCs for audit reachability.
// Processes running a verification strategy other than None MUST be
// configured with one — verifying without storing breaks chain audits.
// The call is synchronous and sits between successful ingress
// verification and transformation, regardless of the event's eventual
// outcome; an event whose verified input cannot be stored fails
// (StatusErrored) — fail loud, never continue without the audit trail.
// The upstreamEndpoint names where the upstream credential can later be
// fetched from (the publisher's serving boundary): in-org it comes from
// ingress wiring config, cross-org from the subscription record.
type IngressVCStore interface {
	StoreIngressVC(ctx context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) error
}
