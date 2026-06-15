// Package sink implements the Sink Process runtime: it consumes a
// pipeline-conformant envelope, verifies the credential (or chain), writes the
// payload to an external system, and produces nothing in-network. It is the
// runtime embodiment of contract.ChainTerminating.
//
// # Relationship to the Chained runtime
//
// The sink reuses the Chained runtime's ingress half — decode, strategy-driven
// verification, the payload↔credential binding gate, and the synchronous
// ingress-VC store — but has no transform/sign half. In its place is a single
// external write (Writer). The terminal Result carries a nil VC and nil
// Payload: a sink appends nothing to the chain (contract.Result).
//
// # SinkKind verdict policy
//
// Whether an invalid verdict is written or rejected is the deployed sink's
// SinkKind (contract.SinkKind), not a property of the sink type:
//
//   - observation-only: writes regardless of verdict — inspection tooling MAY
//     surface failed/indeterminate credentials. This is the home of
//     observation leniency, which producing processes never have.
//   - production / archival: fail-closed — only ConfidenceVerified is written;
//     any other verdict is StatusErrored (MUST reject).
//
// Leniency covers the VERIFICATION VERDICT (signature / DID / schema axes)
// only. The payload↔credential binding (sha256(payload) ==
// credentialSubject.outputHash) is a structural-correspondence gate enforced
// UNCONDITIONALLY for every kind: a sink must never emit a record pairing a
// credential with bytes it does not describe, even when surfacing an invalid
// verdict.
//
// # Store-on-verified
//
// The ingress VC is stored only when the verdict is ConfidenceVerified — the
// contract's IngressVCStore persists *verified* ingress VCs. An observation
// sink that writes an invalid-verdict credential does not store it.
//
// # Deferred (PoC posture)
//
// production/archival's receipt issuance (provin:sink-receipt), the mutual
// allow-list enforcement, and archival's reject-with-audit-log obligation are
// not implemented here — they need the network registration / signing layer.
// A production/archival sink built on this runtime enforces the verdict policy
// and the binding gate but is NOT yet conformant to those additional MUSTs.
// By-reference (nil) payload ingress is likewise not implemented; it lands with
// the resolver client.
//
// # Result error split (mirrors chained)
//
// Domain failures (decode, store, binding, write, rejected verdict) are
// StatusErrored Results with a non-empty Error string and a nil Go error.
// Context cancellation returns a Go error.
package sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance"
	"github.com/provin-line/oss/vc"
)

// Record is the unit handed to a Writer: the consumed credential, the
// payload bytes it describes, and the verification verdict to surface
// alongside them.
type Record struct {
	Credential *vc.PipelinePassCredential
	Payload    []byte
	Verdict    *vc.VerifyResult
}

// Writer delivers one consumed event to the external world. Implementations
// (console, warehouse, EDC, …) live in subpackages or extension repositories.
type Writer interface {
	Write(ctx context.Context, rec Record) error
}

// Typed construction errors.
var (
	ErrInvalidStrategy      = errors.New("sink: Strategy must be VerificationAdjacent or VerificationFull — a sink verifies what it consumes")
	ErrInvalidKind          = errors.New("sink: Kind must be a known SinkKind (observation-only / production / archival)")
	ErrMissingCodec         = errors.New("sink: Codec is required")
	ErrMissingStore         = errors.New("sink: Store is required — verifying without storing breaks chain audits")
	ErrMissingWriter        = errors.New("sink: Writer is required")
	ErrMissingUpstream      = errors.New("sink: UpstreamEndpoint is required")
	ErrMissingVerifier      = errors.New("sink: Verifier is required when Strategy is VerificationAdjacent")
	ErrMissingChainVerifier = errors.New("sink: ChainVerifier is required when Strategy is VerificationFull")
)

// Config holds construction-time configuration for a Sink Process runtime.
type Config struct {
	// Strategy must be VerificationAdjacent or VerificationFull.
	Strategy contract.VerificationStrategy
	// Kind is the deployed sink's handling discipline. Must be non-Unknown.
	Kind contract.SinkKind
	// Codec decodes the wire-form input envelope. Required.
	Codec contract.EnvelopeCodec
	// Verifier verifies a single credential. Required for VerificationAdjacent.
	Verifier provenance.Verifier
	// ChainVerifier verifies the full chain from the head. Required for
	// VerificationFull.
	ChainVerifier provenance.ChainVerifier
	// Store persists the verified ingress VC. Required.
	Store contract.IngressVCStore
	// Writer delivers the consumed event externally. Required.
	Writer Writer
	// UpstreamEndpoint names where the ingress VC can later be fetched. Required.
	UpstreamEndpoint string
	// Observers are notified after every outcome (passed/errored).
	Observers []contract.ProcessObserver
	// Logger receives diagnostic output. nil = slog.Default().
	Logger *slog.Logger
	// Now is the clock used for ProcessEvent.Timestamp. nil = time.Now.
	Now func() time.Time
}

// Processor is the Sink Process runtime. Construct with New.
// *Processor implements contract.EventProcessor.
type Processor struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// New validates cfg and returns a ready Processor.
func New(cfg Config) (*Processor, error) {
	if cfg.Strategy != contract.VerificationAdjacent && cfg.Strategy != contract.VerificationFull {
		return nil, ErrInvalidStrategy
	}
	switch cfg.Kind {
	case contract.SinkObservationOnly, contract.SinkProduction, contract.SinkArchival:
		// valid
	default:
		return nil, ErrInvalidKind
	}
	if cfg.Codec == nil {
		return nil, ErrMissingCodec
	}
	if cfg.Store == nil {
		return nil, ErrMissingStore
	}
	if cfg.Writer == nil {
		return nil, ErrMissingWriter
	}
	if cfg.UpstreamEndpoint == "" {
		return nil, ErrMissingUpstream
	}
	if cfg.Strategy == contract.VerificationAdjacent && cfg.Verifier == nil {
		return nil, ErrMissingVerifier
	}
	if cfg.Strategy == contract.VerificationFull && cfg.ChainVerifier == nil {
		return nil, ErrMissingChainVerifier
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

// Process implements contract.EventProcessor for one consumed event.
func (p *Processor) Process(ctx context.Context, input []byte) (*contract.Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Stage 1 — Decode.
	envelope, err := p.cfg.Codec.UnmarshalEnvelope(input)
	if err != nil {
		return p.errored(ctx, fmt.Sprintf("decode envelope: %v", err), nil, "", ""), nil
	}
	cred := envelope.Credential

	// consumedRef is the audit handle to the consumed credential (the head of
	// the chain this sink terminates). Best-effort: a Hash failure on an
	// already-decoded credential is degraded observability, not a reason to fail
	// the write — leave it empty in that case.
	consumedRef := ""
	if cred != nil {
		if h, herr := cred.Hash(); herr == nil {
			consumedRef = h
		}
	}

	// Stage 2 — Verify (strategy-driven).
	var verifyResult *vc.VerifyResult
	switch p.cfg.Strategy {
	case contract.VerificationAdjacent:
		verifyResult, err = p.cfg.Verifier.Verify(ctx, cred)
	case contract.VerificationFull:
		verifyResult, err = p.cfg.ChainVerifier.VerifyChain(ctx, cred)
	}
	if err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		// A verification transport error (resolver outage, chain hole) IS the
		// indeterminate verdict — the verdict could not be computed. Synthesize
		// it and fall through to the SinkKind policy rather than short-circuiting
		// to StatusErrored: observation tooling exists precisely to surface these
		// un-verifiable events (it writes failed/indeterminate), so dropping them
		// here would defeat the observation kind. production/archival still
		// reject indeterminate at Stage 3. The error detail (lost from the
		// verdict, which carries no message) is logged for operators.
		p.logger.Warn("sink: verification error treated as indeterminate", "err", err)
		verifyResult = &vc.VerifyResult{Overall: vc.ConfidenceIndeterminate}
	}
	verdict := verifyResult.Overall

	// Stage 3 — SinkKind verdict policy. Observation writes regardless;
	// production/archival reject any non-verified verdict.
	if p.cfg.Kind != contract.SinkObservationOnly && verdict != vc.ConfidenceVerified {
		return p.errored(ctx, fmt.Sprintf("verification verdict %v: a %v sink rejects non-verified credentials (fail-closed)", verdict, kindName(p.cfg.Kind)), &verdict, consumedRef, ""), nil
	}

	// Stage 4 — Store the ingress VC (only when verified — the store persists
	// verified ingress VCs). Synchronous; failure is a loud drop. This runs
	// BEFORE the binding gate (Stage 6): a verified credential whose payload is
	// later found tampered is still stored — the credential is genuine; only its
	// transport was tampered. (Store-before-binding parity with chained.)
	if verdict == vc.ConfidenceVerified {
		if err := p.cfg.Store.StoreIngressVC(ctx, cred, p.cfg.UpstreamEndpoint); err != nil {
			if isCtxErr(err) {
				return nil, err
			}
			return p.errored(ctx, fmt.Sprintf("store ingress VC: %v — never continue without the audit trail", err), &verdict, consumedRef, ""), nil
		}
	}

	// Stage 5 — Payload extraction. By-reference (nil) ingress fetch is not
	// implemented in the PoC sink runtime.
	if envelope.Payload == nil {
		return p.errored(ctx, "by-reference ingress fetch is not implemented in the PoC sink runtime (lands with the resolver client)", &verdict, consumedRef, ""), nil
	}
	payload := envelope.Payload
	// inputHash is the hash of the bytes flowing into the sink — its observer
	// "input" (and, once binding passes, == the consumed credential's outputHash).
	inputHash := hashBytes(payload)

	// Stage 6 — Payload↔credential binding. Unconditional for every SinkKind:
	// a sink must never emit a record pairing a credential with bytes it does
	// not describe. Observation leniency covers the verdict, not this gate.
	subject, err := cred.Subject()
	if err != nil {
		return p.errored(ctx, fmt.Sprintf("credential subject unreadable: %v", err), &verdict, consumedRef, inputHash), nil
	}
	if subject.OutputHash == "" {
		return p.errored(ctx, "credential declares no outputHash: binding undecidable, fail closed", &verdict, consumedRef, inputHash), nil
	}
	if inputHash != subject.OutputHash {
		return p.errored(ctx, fmt.Sprintf("payload does not match the credential's outputHash (payload %s, credential declares %s): tampered or substituted bytes", inputHash, subject.OutputHash), &verdict, consumedRef, inputHash), nil
	}

	// Stage 7 — External write.
	if err := p.cfg.Writer.Write(ctx, Record{Credential: cred, Payload: payload, Verdict: verifyResult}); err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		return p.errored(ctx, fmt.Sprintf("external write: %v", err), &verdict, consumedRef, inputHash), nil
	}

	// Stage 8 — Terminal Result: a sink produces nothing in-network.
	r := &contract.Result{
		Status:     contract.StatusPassed,
		Confidence: &verdict,
	}
	p.notify(ctx, r, consumedRef, inputHash)
	return r, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func kindName(k contract.SinkKind) string {
	switch k {
	case contract.SinkObservationOnly:
		return "observation-only"
	case contract.SinkProduction:
		return "production"
	case contract.SinkArchival:
		return "archival"
	default:
		return "unknown"
	}
}

func (p *Processor) errored(ctx context.Context, msg string, confidence *vc.ConfidenceState, consumedVCRef, inputHash string) *contract.Result {
	r := &contract.Result{
		Status:     contract.StatusErrored,
		Error:      msg,
		Confidence: confidence,
	}
	p.notify(ctx, r, consumedVCRef, inputHash)
	return r
}

// notify delivers a ProcessEvent to every observer. A sink issues nothing and
// produces nothing in-network, so IssuedVCRef and OutputHash stay empty; the
// audit identity rides ConsumedVCRef (the terminated head credential) and
// InputHash (the consumed payload). consumedVCRef/inputHash may be empty on
// early-failure paths where they are not yet known.
func (p *Processor) notify(ctx context.Context, r *contract.Result, consumedVCRef, inputHash string) {
	if len(p.cfg.Observers) == 0 {
		return
	}
	ev := contract.ProcessEvent{
		Result:        r,
		InputHash:     inputHash,
		ConsumedVCRef: consumedVCRef,
		// IssuedVCRef and OutputHash stay empty: a sink issues and produces nothing.
		Timestamp: p.now(),
	}
	for _, obs := range p.cfg.Observers {
		if err := obs.OnProcessComplete(ctx, ev); err != nil {
			p.logger.Error("observer error", "err", err)
		}
	}
}
