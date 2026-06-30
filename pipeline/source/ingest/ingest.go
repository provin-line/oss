// Package ingest implements the Source Process event processor for external
// ingestion (N=0): raw external bytes become a FirstDrop credential — a fresh
// chain origin.
//
// # What a Source ingest process is NOT
//
// It is the deliberate negative of the Chained Process runtime. It performs no
// ingress verification (there is no Pipeline-conformant predecessor to verify —
// VerificationNone), holds no IngressVCStore (no ingress VC exists to store),
// and runs no payload↔credential binding (no predecessor outputHash to bind
// to). Above all it does NOT transform the payload: transformation (filter /
// convert / enrich) is the Chained Process's definitional responsibility.
// Giving a Source its own transform pipeline would, by symmetry, push the same
// onto the Sink, and the Source / Chained / Sink type distinction would
// dissolve into a single do-everything process. So the runtime keeps the
// origin pure: bytes in, FirstDrop out, output == input.
//
// # Lifecycle
//
//  1. reject a cancelled context (Go error);
//  2. reject empty input (profile norm: a producing process never emits an
//     empty payload — see contract.Envelope);
//  3. gate the bytes through the strict canonical-JSON decoder. A Source signs
//     the bytes it emits, so malformed JSON (duplicate keys, trailing data,
//     precision drift) must never be laundered into a signed FirstDrop. This
//     is the same protocol-boundary gate the Chained runtime applies to its
//     converter output;
//  4. hash the bytes once — verbatim ingestion means output == input, so
//     inputHash == outputHash. This equality is an N=0-ingestion invariant: a
//     single external input exists, so inputHash is present. It is NOT the
//     aggregation FirstDrop, which has no single input (InputHash absent — see
//     vc.CredentialSubjectFields) and commits to its consumed set via a
//     SourceCommitment; that path deliberately does not run through
//     SourceSigner.SignFirstDrop — it gates with the aggregate runtime (see
//     pipeline/provenance/provenance.go);
//  5. sign a FirstDrop over the bytes (SourceSigner.SignFirstDrop);
//  6. notify observers.
//
// The transformationClaim is the signer's concern, not the runtime's:
// SignFirstDrop carries no claim argument, mirroring the Chained runtime's
// SignChainPreserving. External ingestion typically claims provin:convert
// (process.source.firstdrop).
//
// # Boundary translation
//
// Re-shaping a foreign-ecosystem credential into a dplaax FirstDrop payload is
// the ingest ADAPTER's own logic, performed before the bytes reach this
// runtime (see pipeline/source/ingest/README.md). The runtime signs whatever
// canonical bytes it is handed; it does not itself convert.
//
// # Result error split (mirrors chained)
//
// Domain failures (empty input, strict-decode failure, signer error) are
// StatusErrored Results with a non-empty Error string and a nil Go error. The
// Go error return is reserved for context cancellation (ctx.Err()) and
// internal invariant violations (a just-signed credential that cannot be
// hashed) where returning a result would be dishonest.
//
// # Payload profile assumption
//
// The PoC wire profile carries JSON payloads (the chained steps are JSONata;
// the credential body is JCS-canonical JSON). The strict-decode gate enforces
// that at the ingestion boundary. Non-JSON / binary payloads are a profile
// extension, tracked alongside by-reference delivery.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// ErrMissingSigner is returned when Config.Signer is nil.
var ErrMissingSigner = errors.New("ingest: Signer is required")

// firstDropSigner is the narrow signing capability the ingest (N=0) runtime
// exercises — only the FirstDrop path. Depending on this consumer-defined interface
// rather than the wider provenance.SourceSigner keeps the aggregate signing method
// (SignAggregateFirstDrop) off the ingest runtime's surface, so the N=0 origin cannot
// call a path it never uses (interface segregation). A *vcdid.Signer and the
// publishing decorator both satisfy it.
type firstDropSigner interface {
	SignFirstDrop(ctx context.Context, payload []byte, inputHash, outputHash string) (*vc.PipelinePassCredential, error)
}

// Config holds all construction-time configuration for a Source ingest event
// processor. It is deliberately minimal: a Source origin verifies nothing,
// stores nothing, and transforms nothing.
type Config struct {
	// Signer issues the FirstDrop output credential. Required.
	Signer firstDropSigner

	// Observers are notified after every outcome (passed/errored).
	// Fire-and-forget: observer errors are logged and never propagated.
	Observers []contract.ProcessObserver

	// Logger receives diagnostic output. nil = slog.Default().
	Logger *slog.Logger

	// Now is the clock used for ProcessEvent.Timestamp. nil = time.Now.
	Now func() time.Time
}

// Processor is the Source ingest event processor. Construct with New.
// *Processor implements contract.EventProcessor.
type Processor struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// New validates cfg and returns a ready-to-use Processor, or ErrMissingSigner
// if the signer is absent.
func New(cfg Config) (*Processor, error) {
	if cfg.Signer == nil {
		return nil, ErrMissingSigner
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

// Process implements contract.EventProcessor: it executes the Source ingest
// lifecycle for one external input event.
//
// Go error semantics: context cancellation and internal invariant violations
// return a Go error. All other failures produce a StatusErrored Result with a
// non-empty Error string and return nil as the Go error — the failure is data,
// not a runtime fault.
func (p *Processor) Process(ctx context.Context, input []byte) (*contract.Result, error) {
	// Check context cancellation before doing any work.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Stage 1 — Non-empty input guard. A producing process never emits an
	// empty payload (profile norm — see contract.Envelope).
	if len(input) == 0 {
		return p.errored(ctx, "empty input: a Source Process never emits an empty FirstDrop payload (profile norm)", "", ""), nil
	}

	// Stage 2 — Strict canonical-JSON decode gate. A Source signs the bytes it
	// emits; malformed JSON (duplicate keys, trailing data, precision drift)
	// must never be laundered into a signed FirstDrop.
	var strictIn interface{}
	if err := canon.NewStrictDecoder(input).Decode(&strictIn); err != nil {
		return p.errored(ctx, fmt.Sprintf("strict decode of ingest input: %v", err), "", ""), nil
	}

	// Stage 3 — Hash. Verbatim ingestion: output == input, so inputHash and
	// outputHash are the same digest over the same bytes. Format:
	// "sha256:<64-hex-chars>" — matches vc.PipelinePassCredential.Hash().
	hash := hashBytes(input)

	// Stage 4 — Sign: FirstDrop (no predecessor).
	issuedVC, err := p.cfg.Signer.SignFirstDrop(ctx, input, hash, hash)
	if err != nil {
		if isCtxErr(err) {
			return nil, err
		}
		return p.errored(ctx, fmt.Sprintf("sign: %v", err), hash, hash), nil
	}

	// Stage 5 — Assemble Result. Confidence stays nil: VerificationNone, no
	// verification ran (contract.Result).
	vcRef, err := issuedVC.Hash()
	if err != nil {
		// A just-signed credential that cannot be hashed is an internal
		// invariant violation — the case the Go error return is reserved for.
		// Never ship an observer event with an empty audit ref.
		return nil, fmt.Errorf("ingest: hash of issued credential failed after sign: %w", err)
	}
	r := &contract.Result{
		Status:  contract.StatusPassed,
		VC:      issuedVC,
		Payload: input,
	}

	// Stage 6 — Observer notification.
	p.notify(ctx, r, hash, hash, vcRef)

	return r, nil
}

// ---------------------------------------------------------------------------
// Helpers (mirror chained — same content-address format and error discipline)
// ---------------------------------------------------------------------------

// isCtxErr reports whether a stage error is a context cancellation or
// deadline — those propagate as the Go error so the transport loop drains
// instead of treating shutdown as a domain failure.
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// hashBytes returns "sha256:<64-hex-chars>" over data — the content address
// format used by vc.PipelinePassCredential.Hash() and jcs.Hash().
func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// errored builds a StatusErrored Result and notifies observers. A Source
// always leaves Confidence nil (VerificationNone). inputHash / outputHash may
// be empty when the failure occurs before they are computed.
func (p *Processor) errored(ctx context.Context, msg, inputHash, outputHash string) *contract.Result {
	r := &contract.Result{
		Status: contract.StatusErrored,
		Error:  msg,
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
