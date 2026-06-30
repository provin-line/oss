// Package chained implements the Chained Process event processor.
//
// A Chained Process receives a pipeline-conformant envelope, verifies the
// ingress credential, transforms the payload, signs a chain-preserving output
// credential, and notifies observers. It is the runtime embodiment of
// contract.ChainPreserving + the VerificationAdjacent strategy (full-chain audit
// is the async audit runner's job, slice-17h).
//
// # Strategy constraint
//
// Config.Strategy must be VerificationAdjacent. None (and
// Unknown) are rejected with a typed error that explains the TYPE-SPECIFIC
// constraint: a Chained Process issues chain-preserving credentials, which
// require a verified predecessor per event. A run that cannot identify its
// predecessor is a FirstDrop by the trigger rule and belongs to a Source
// Process runtime. Consequently IngressConformant must also be true; false is
// rejected with the declaration-matrix rationale.
//
// # Fail-closed verification policy (confirmed 2026-06-12)
//
// Only ConfidenceVerified proceeds. Both ConfidenceFailed and
// ConfidenceIndeterminate map to StatusErrored. Observation-class leniency
// (allowing indeterminate through) is a SinkKind property of sinks, never of
// producing processes that append to the chain.
//
// # By-reference payload limitation
//
// A nil Payload in the decoded Envelope (by-reference delivery) is rejected
// with StatusErrored. By-reference ingress fetch is not implemented in the
// PoC Chained runtime; it lands with the resolver client. Tracked limitation.
//
// # Result error split
//
// Domain failures (failed verification, store error, nil payload, schema
// violation, filter error, converter error, strict-decode error, signer error)
// are reported as StatusErrored Results with a non-empty Error string.
// Process returns (result, nil) for all domain failures. The Go error return
// is reserved for context cancellation (ctx.Err()) and internal invariant
// violations where returning a result would be dishonest.
package chained

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/chained/converter"
	"github.com/provin-line/oss/pipeline/chained/filter"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/schema"
	"github.com/provin-line/oss/vc"
)

// ---------------------------------------------------------------------------
// Typed construction errors
// ---------------------------------------------------------------------------

// ErrInvalidStrategy is returned when Config.Strategy is VerificationNone or
// VerificationUnknown. A Chained Process signs chain-preserving credentials
// and requires a verified predecessor for every event; None belongs to Source
// Process runtimes.
var ErrInvalidStrategy = errors.New("chained: strategy must be VerificationAdjacent — " +
	"a Chained Process signs chain-preserving credentials and requires a verified predecessor per event; " +
	"a run without conformant ingress is a FirstDrop and belongs to a Source Process runtime")

// ErrIngressNotConformant is returned when Config.IngressConformant is false.
// The declaration matrix requires ingress-conformant=true when a verification
// strategy other than None is declared; a Chained Process always verifies.
var ErrIngressNotConformant = errors.New("chained: IngressConformant must be true — " +
	"the declaration matrix rejects a Chained Process whose ingress is not pipeline-conformant")

// ErrMissingUpstreamEndpoint is returned when Config.UpstreamEndpoint is empty.
var ErrMissingUpstreamEndpoint = errors.New("chained: UpstreamEndpoint is required")

// ErrMissingCodec is returned when Config.Codec is nil.
var ErrMissingCodec = errors.New("chained: Codec is required")

// ErrMissingStore is returned when Config.Store is nil.
var ErrMissingStore = errors.New("chained: Store is required — verifying without storing breaks chain audits")

// ErrMissingSigner is returned when Config.Signer is nil.
var ErrMissingSigner = errors.New("chained: Signer is required")

// ErrMissingVerifier is returned when Config.Verifier is nil.
var ErrMissingVerifier = errors.New("chained: Verifier is required")

// ErrInputValidatorWithoutRef is returned when InputValidator is set but
// InputSchemaRef is the zero value.
var ErrInputValidatorWithoutRef = errors.New("chained: InputSchemaRef is required when InputValidator is set")

// ErrOutputValidatorWithoutRef is returned when OutputValidator is set but
// OutputSchemaRef is the zero value.
var ErrOutputValidatorWithoutRef = errors.New("chained: OutputSchemaRef is required when OutputValidator is set")

// ---------------------------------------------------------------------------
// Config and Processor
// ---------------------------------------------------------------------------

// Config holds all construction-time configuration for a Chained Process
// event processor.
type Config struct {
	// Strategy must be VerificationAdjacent (the only ingress verification a chained
	// process runs; full-chain audit is the async audit runner's job, slice-17h).
	// VerificationNone and VerificationUnknown are rejected; see ErrInvalidStrategy.
	Strategy contract.VerificationStrategy

	// IngressConformant is the operator co-declaration that the ingress is
	// pipeline-conformant. Must be true for a Chained Process.
	IngressConformant bool

	// UpstreamEndpoint names the publisher's serving boundary from which the
	// ingress VC can later be fetched. Required (non-empty).
	UpstreamEndpoint string

	// Codec decodes the wire-form input envelope. Required.
	Codec contract.EnvelopeCodec

	// Verifier verifies the single immediately-preceding ingress credential. Required.
	Verifier provenance.Verifier

	// Store persists the verified ingress VC before transformation begins.
	// Required (strategy is never None here).
	Store contract.IngressVCStore

	// Signer issues the chain-preserving output credential.
	// Required.
	Signer provenance.ChainedSigner

	// Filters is the ordered list of filter steps. May be empty.
	Filters []filter.Filter

	// Converter transforms the payload. nil = passthrough.
	Converter converter.Converter

	// InputValidator validates the input payload against InputSchemaRef.
	// Optional; nil = check skipped.
	InputValidator schema.Validator

	// InputSchemaRef is required when InputValidator is non-nil.
	InputSchemaRef vc.SchemaRef

	// OutputValidator validates the produced output against OutputSchemaRef.
	// Optional; nil = check skipped.
	OutputValidator schema.Validator

	// OutputSchemaRef is required when OutputValidator is non-nil.
	OutputSchemaRef vc.SchemaRef

	// Observers are notified after every outcome (passed/filtered/errored).
	// Fire-and-forget: observer errors are logged and never propagated.
	Observers []contract.ProcessObserver

	// Logger receives diagnostic output. nil = slog.Default().
	Logger *slog.Logger

	// Now is the clock used for ProcessEvent.Timestamp. nil = time.Now.
	Now func() time.Time
}

// Processor is the Chained Process event processor. Construct with New.
// *Processor implements contract.EventProcessor.
type Processor struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// New validates cfg and returns a ready-to-use Processor, or a typed
// construction error if any required field is missing or any constraint is
// violated.
func New(cfg Config) (*Processor, error) {
	// Strategy constraint: only Adjacent is valid (full-chain audit is the async runner's job).
	if cfg.Strategy != contract.VerificationAdjacent {
		return nil, ErrInvalidStrategy
	}
	// Ingress-conformant: must be true for a Chained Process.
	if !cfg.IngressConformant {
		return nil, ErrIngressNotConformant
	}
	// Required fields.
	if cfg.UpstreamEndpoint == "" {
		return nil, ErrMissingUpstreamEndpoint
	}
	if cfg.Codec == nil {
		return nil, ErrMissingCodec
	}
	if cfg.Store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Signer == nil {
		return nil, ErrMissingSigner
	}
	// Verifier is required (adjacent verification of the preceding credential).
	if cfg.Verifier == nil {
		return nil, ErrMissingVerifier
	}
	// Validator/ref pairs.
	if cfg.InputValidator != nil && cfg.InputSchemaRef == (vc.SchemaRef{}) {
		return nil, ErrInputValidatorWithoutRef
	}
	if cfg.OutputValidator != nil && cfg.OutputSchemaRef == (vc.SchemaRef{}) {
		return nil, ErrOutputValidatorWithoutRef
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Processor{cfg: cfg, logger: logger, now: now}, nil
}

// Process implements contract.EventProcessor: it executes the Chained
// Process lifecycle for one input event, in the order pinned by the
// package README.
//
// Go error semantics: context cancellation and internal invariant
// violations return a Go error. All other failures produce a
// StatusErrored Result with a non-empty Error string and return nil as
// the Go error — the failure is data, not a runtime fault.
func (p *Processor) Process(ctx context.Context, input []byte) (*contract.Result, error) {
	// Check context cancellation before doing any work.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Stage 1 — Decode envelope.
	envelope, err := p.cfg.Codec.UnmarshalEnvelope(input)
	if err != nil {
		return p.errored(ctx, fmt.Sprintf("decode envelope: %v", err), nil, "", ""), nil
	}
	cred := envelope.Credential

	// Stage 2 — Ingress VC verification (adjacent: the immediately-preceding credential).
	// Fail-closed: only ConfidenceVerified proceeds. Full-chain audit is the async audit
	// runner's job (slice-17h), not the real-time relay path.
	verifyResult, err := p.cfg.Verifier.Verify(ctx, cred)
	if err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		// A verification transport error is exactly what indeterminate
		// means: the verdict could not be computed with the current
		// inputs. Record it as such — under a non-None strategy a nil
		// Confidence would falsely read as "no verification ran".
		indeterminate := vc.ConfidenceIndeterminate
		return p.errored(ctx, fmt.Sprintf("verification error: %v", err), &indeterminate, "", ""), nil
	}
	confidence := verifyResult.Overall
	if confidence != vc.ConfidenceVerified {
		// PoC chained policy: fail-closed on both failed and indeterminate.
		// Observation-class leniency belongs to sinks, not producing processes.
		return p.errored(ctx, fmt.Sprintf("verification verdict %v: only ConfidenceVerified proceeds (PoC chained fail-closed policy)", confidence), &confidence, "", ""), nil
	}

	// Stage 3 — Ingress VC store (synchronous; failure = loud drop).
	// The audit trail must be established before transformation begins.
	if err := p.cfg.Store.StoreIngressVC(ctx, cred, p.cfg.UpstreamEndpoint); err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		return p.errored(ctx, fmt.Sprintf("store ingress VC: %v — never continue without the audit trail", err), &confidence, "", ""), nil
	}

	// Stage 4 — Payload extraction.
	// nil Payload = by-reference delivery, not implemented in PoC chained runtime.
	if envelope.Payload == nil {
		return p.errored(ctx, "by-reference ingress fetch is not implemented in the PoC chained runtime (lands with the resolver client)", &confidence, "", ""), nil
	}
	payload := envelope.Payload

	// Stage 4.5 — Payload↔credential binding. The verifier holds only the
	// credential; the runtime is the one party holding both artifacts, so it
	// enforces sha256(payload) == predecessor's declared outputHash here —
	// the earliest point tampered or substituted bytes can be rejected, and
	// the guarantee that this process's own emitted link satisfies chain
	// continuity (outputHash[n] == inputHash[n+1]) by construction.
	subject, err := cred.Subject()
	if err != nil {
		return p.errored(ctx, fmt.Sprintf("predecessor subject unreadable: %v", err), &confidence, "", ""), nil
	}
	if subject.OutputHash == "" {
		return p.errored(ctx, "predecessor declares no outputHash: a producing predecessor must declare one — binding undecidable, fail closed", &confidence, "", ""), nil
	}
	if got := hashBytes(payload); got != subject.OutputHash {
		return p.errored(ctx, fmt.Sprintf("payload does not match the predecessor's outputHash (payload %s, credential declares %s): tampered or substituted bytes", got, subject.OutputHash), &confidence, "", ""), nil
	}

	// Stage 5 — Optional input-schema check.
	if p.cfg.InputValidator != nil {
		if err := p.cfg.InputValidator.Validate(ctx, payload, p.cfg.InputSchemaRef); err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("input schema validation: %v", err), &confidence, "", ""), nil
		}
	}

	// Stage 6 — Ordered filter steps.
	// falsy = StatusFiltered (silent drop); error = StatusErrored (loud drop).
	for i, f := range p.cfg.Filters {
		res, err := f.Apply(ctx, payload)
		if err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("filter[%d] step failure: %v", i, err), &confidence, "", ""), nil
		}
		if !res.Pass {
			r := &contract.Result{
				Status:         contract.StatusFiltered,
				FilteredAtStep: i,
				Confidence:     &confidence,
			}
			p.notify(ctx, r, "", "", "")
			return r, nil
		}
	}

	// Stage 7 — Converter (nil = passthrough).
	var output []byte
	if p.cfg.Converter != nil {
		output, err = p.cfg.Converter.Convert(ctx, payload)
		if err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("converter: %v", err), &confidence, "", ""), nil
		}
	} else {
		output = payload
	}

	// Empty output is a process bug (profile norm: producing processes never
	// emit empty payload).
	if len(output) == 0 {
		return p.errored(ctx, "converter produced empty output: empty payload is a process bug", &confidence, "", ""), nil
	}

	// Stage 8 — Optional output validation.
	if p.cfg.OutputValidator != nil {
		if err := p.cfg.OutputValidator.Validate(ctx, output, p.cfg.OutputSchemaRef); err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("output schema validation: %v", err), &confidence, "", ""), nil
		}
	}

	// Stage 9 — Strict decode of produced output.
	// The converter guarantees valid JSON; this stage is the lifecycle's
	// explicit gate against duplicate keys, trailing data, and precision drift.
	var strictOut interface{}
	if err := canon.NewStrictDecoder(output).Decode(&strictOut); err != nil {
		return p.errored(ctx, fmt.Sprintf("strict decode of converter output: %v", err), &confidence, "", ""), nil
	}

	// Stage 10 — Hash computation.
	// inputHash is over the raw ingress payload bytes;
	// outputHash is over the produced output bytes.
	// Format: "sha256:<64-hex-chars>" — matches vc.PipelinePassCredential.Hash()
	// and jcs.Hash(), both of which use sha256 + hex encoding with "sha256:" prefix.
	inputHash := hashBytes(payload)
	outputHash := hashBytes(output)

	// Stage 11 — Sign: chain-preserving credential.
	// predecessor = the verified ingress credential.
	issuedVC, err := p.cfg.Signer.SignChainPreserving(ctx, output, inputHash, outputHash, cred)
	if err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		return p.errored(ctx, fmt.Sprintf("sign: %v", err), &confidence, inputHash, outputHash), nil
	}

	// Stage 12 — Assemble Result. (Non-empty output is guarded at the
	// converter stage and never mutated afterwards.)
	vcRef, err := issuedVC.Hash()
	if err != nil {
		// A just-signed credential that cannot be hashed is an internal
		// invariant violation — the case the Go error return is reserved
		// for. Never ship an observer event with an empty audit ref.
		return nil, fmt.Errorf("chained: hash of issued credential failed after sign: %w", err)
	}
	r := &contract.Result{
		Status:     contract.StatusPassed,
		VC:         issuedVC,
		Payload:    output,
		Confidence: &confidence,
	}

	// Stage 13 — Observer notification.
	p.notify(ctx, r, inputHash, outputHash, vcRef)

	return r, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isCtxErr reports whether a stage error is a context cancellation or
// deadline — those propagate as the Go error (the documented cancellation
// contract: a cancelled stage is shutdown, not a domain failure, and the
// transport loop must see it to drain).
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// hashBytes returns "sha256:<64-hex-chars>" over data — the content address
// format used by vc.PipelinePassCredential.Hash() and jcs.Hash(). Hashing is
// over the raw bytes, not a canonical JSON encoding; this is the per-stage
// payload hash (inputHash, outputHash in CredentialSubjectFields).
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// errored builds a StatusErrored Result with the given message and calls
// notify. confidence, inputHash, outputHash may be partial (nil/"") when the
// failure occurs before those values are computed.
func (p *Processor) errored(ctx context.Context, msg string, confidence *vc.ConfidenceState, inputHash, outputHash string) *contract.Result {
	r := &contract.Result{
		Status:     contract.StatusErrored,
		Error:      msg,
		Confidence: confidence,
	}
	p.notify(ctx, r, inputHash, outputHash, "")
	return r
}

// notify delivers a ProcessEvent to every registered observer sequentially.
// Observer errors are logged and never propagated; all observers are always
// called regardless of earlier observer failures.
func (p *Processor) notify(ctx context.Context, r *contract.Result, inputHash, outputHash, vcRef string) {
	if len(p.cfg.Observers) == 0 {
		return
	}
	ev := contract.ProcessEvent{
		Result:      r,
		InputHash:   inputHash,
		OutputHash:  outputHash,
		IssuedVCRef: vcRef,
		Timestamp:   p.now(),
	}
	for _, obs := range p.cfg.Observers {
		if err := obs.OnProcessComplete(ctx, ev); err != nil {
			p.logger.Error("observer error", "err", err)
		}
	}
}
