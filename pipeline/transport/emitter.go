package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

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

// NewEmitter constructs an Emitter with the sequence counter initialised to 1.
// A nil logger defaults to slog.Default().
func NewEmitter(pub Publisher, codec contract.EnvelopeCodec, emission tlog.Log, logger *slog.Logger) *Emitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Emitter{pub: pub, codec: codec, emission: emission, logger: logger, seq: 1}
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
