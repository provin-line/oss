package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/vc"
)

// emissionRecord is the JSON-serializable emission log entry.
// Field order is fixed by the struct declaration — json.Marshal serializes
// fields in declaration order, making the wire representation deterministic.
//
// SequenceNo is string-encoded uint64 — survives IEEE-754 JSON consumers
// whose integer precision is limited to 2^53.
type emissionRecord struct {
	CredentialHash string `json:"credentialHash"`
	SequenceNo     string `json:"sequenceNo"`
}

// Emitter encodes the producing-side emission discipline shared by every
// producing process: marshal the wire envelope with a monotonic sequence
// number, publish, advance the sequence ONLY after a successful publish, then
// append the emission record to the transparency log under a detached context.
// transport.Loop drives it for EventProcessor-based loops; the aggregate Source
// Process runtime (slice-17l) drives it from its own timer Run — one
// implementation, both callers, so the protocol-sensitive ordering lives in one
// place.
//
// Sequence-number discipline: the counter starts at 1 and is advanced ONLY
// after a successful Publish. A failed pre-publish step (nil guard, hash,
// emission-record marshal, codec marshal) or a failed Publish reuses the same
// number on the next attempt — a gap in the subscriber's view is protocol
// evidence of foul play; the publisher must never create one by its own
// failure.
//
// Concurrency: an Emitter is single-goroutine. Callers must serialize Emit
// (Loop's handlers are sequential per subscription; the aggregate's Run
// goroutine is the sole emitter), so the counter is race-free without a mutex.
type Emitter struct {
	pub      Publisher
	codec    contract.EnvelopeCodec
	emission tlog.Log
	logger   *slog.Logger
	seq      uint64
}

// NewEmitter constructs an Emitter, SEEDING the sequence counter from the
// emission log's tail: an empty log starts at 1; a log already holding
// records resumes at lastRecordedSequence+1, so — PROVIDED THE LOG KEPT
// PACE WITH PUBLISHES — a restarted node with a durable log does not fork
// the sequence space (new records claiming numbers the log already carries
// would make "which sequence numbers exist" unanswerable — the
// loss-accounting question the log exists to answer).
//
// Declared residual: Emit's append-after-publish is logged-only on failure
// (and a crash can land between the two), so the tail can lag the counter
// by the tail of un-appended PUBLISHED sequences. A restart then re-issues
// those numbers to NEW events: a reconciling consumer holding the original
// envelope sees the same sequence number committed with a DIFFERENT
// credential hash. That signature means "producer restarted inside a loss
// window", NOT necessarily tampering — reconciliation tooling must treat
// it as an integrity WARNING to investigate, never an automatic tamper
// verdict. Hardening (intent records before publish / a WAL'd counter) is
// the recorded follow-up.
//
// The log is the discipline's own carrier, so recovery needs no external
// seam; a tail record that cannot be read back as an emission record fails
// construction (the open-time damage doctrine extended to the seed).
// A nil logger defaults to slog.Default().
func NewEmitter(ctx context.Context, pub Publisher, codec contract.EnvelopeCodec, emission tlog.Log, logger *slog.Logger) (*Emitter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	seq, err := recoverSequence(ctx, emission)
	if err != nil {
		return nil, err
	}
	return &Emitter{pub: pub, codec: codec, emission: emission, logger: logger, seq: seq}, nil
}

// recoverSequence reads the emission log tail and returns the next sequence
// number (1 for an empty log).
func recoverSequence(ctx context.Context, emission tlog.Log) (uint64, error) {
	size, err := emission.Size(ctx)
	if err != nil {
		return 0, fmt.Errorf("transport: emission log size: %w", err)
	}
	if size == 0 {
		return 1, nil
	}
	tail, err := emission.Get(ctx, size-1)
	if err != nil {
		return 0, fmt.Errorf("transport: emission log tail: %w", err)
	}
	var rec emissionRecord
	if err := canon.NewStrictDecoder(tail.Payload).Decode(&rec); err != nil {
		return 0, fmt.Errorf("transport: emission log tail record damaged: %w", err)
	}
	last, err := strconv.ParseUint(rec.SequenceNo, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("transport: emission log tail sequenceNo %q: %w", rec.SequenceNo, err)
	}
	if last == math.MaxUint64 {
		// last+1 would wrap to 0 — an invalid sequence. An exhausted (or
		// absurdly damaged-but-parseable) tail fails closed.
		return 0, fmt.Errorf("transport: emission log tail sequenceNo %d: sequence space exhausted", last)
	}
	return last + 1, nil
}

// Emit publishes one produced credential+payload and records it on the
// transparency log.
//
// Ordering: VC.Hash() and the emission record are computed BEFORE Publish so a
// hash or marshal failure aborts the attempt without any delivery; only Append
// remains after Publish.
//
// Return semantics: a pre-publish or publish failure returns an error — the
// event was NOT delivered and the sequence is NOT advanced, so the caller may
// surface it and the same number is reused next time. On a successful Publish
// the sequence advances and a subsequent Emission.Append failure is logged-only
// and returns nil: the event WAS delivered, so the gap is the audit-defense
// loss, never retried (a crash between Publish and Append is the PoC posture —
// persistent WAL is the follow-up).
func (e *Emitter) Emit(ctx context.Context, cred *vc.PipelinePassCredential, payload []byte) error {
	next := e.seq

	// In-org producing processes always emit the full inline form
	// (contract.Envelope doc). A nil VC or payload is a caller contract
	// violation — reject before any publish attempt.
	if cred == nil {
		return fmt.Errorf("transport: emit with nil credential (sequenceNo %d)", next)
	}
	if payload == nil {
		return fmt.Errorf("transport: emit with nil payload (sequenceNo %d)", next)
	}

	hash, err := cred.Hash()
	if err != nil {
		return fmt.Errorf("transport: credential hash (sequenceNo %d): %w", next, err)
	}

	// Deterministic by struct declaration order; a local log record, not a
	// signing scope (canonicalizer-hygiene-exempt).
	rec, err := json.Marshal(emissionRecord{
		CredentialHash: hash,
		SequenceNo:     strconv.FormatUint(next, 10),
	})
	if err != nil {
		return fmt.Errorf("transport: marshal emission record (sequenceNo %d): %w", next, err)
	}

	wire, err := e.codec.MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    payload,
		SequenceNo: next,
	})
	if err != nil {
		return fmt.Errorf("transport: marshal envelope (sequenceNo %d): %w", next, err)
	}

	if err := e.pub.Publish(wire); err != nil {
		return fmt.Errorf("transport: publish (sequenceNo %d): %w", next, err)
	}

	// Advance ONLY after a successful publish.
	e.seq = next + 1

	// Append the pre-computed emission record under a detached context so that
	// ctx cancellation at shutdown cannot abort recording a delivered event.
	if _, err := e.emission.Append(context.WithoutCancel(ctx), rec); err != nil {
		e.logger.Error("transport: emission log append failed", "err", err, "sequenceNo", next)
		// Counter already advanced: the event was delivered. The gap is our
		// audit-defense loss. Log loudly; do not re-attempt (PoC posture).
	}
	return nil
}
