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
// number on the next attempt, so in NORMAL operation the publisher never
// creates a gap by its own failure. A gap in the subscriber's view is then
// evidence to investigate — POSSIBLE LOSS, not an automatic tamper verdict
// (a producer crash inside the emit window is one benign cause; see
// NewEmitter's residual).
//
// Concurrency: an Emitter is single-goroutine. Callers must serialize Emit
// (Loop's handlers are sequential per subscription; the aggregate's Run
// goroutine is the sole emitter), so the counter is race-free without a mutex.
// One emitter per log identity: the emission log's single-opener lock is
// cross-PROCESS, so it does not stop two in-process emitters from seeding off
// one log and forking the sequence — the node's output-subject-uniqueness boot
// invariant (one producing loop, one log, one emitter per identity) is what
// prevents that.
type Emitter struct {
	pub      Publisher
	codec    contract.EnvelopeCodec
	emission tlog.Log
	// intent is the emission log's optional durable-sequence-intent capability
	// (nil when the log does not provide it, e.g. memlog). When present, Emit
	// records the sequence it is about to publish BEFORE publishing.
	intent intentLog
	logger *slog.Logger
	seq    uint64
}

// intentLog is the optional durable-sequence-intent capability an Emitter's
// emission log may provide: it records, ahead of the risky publish, the
// sequence number about to be used, so a crash in the append-after-publish
// window can never let recovery re-issue that number to a different event.
// filelog satisfies it structurally; memlog (in-memory, no restart) does not,
// so the Emitter falls back to tail-based recovery. The methods are exported
// names because cross-package structural satisfaction requires it; the
// interface itself stays transport-internal, keeping tlog.Log's contract
// free of this emitter-specific coupling.
type intentLog interface {
	RecordIntent(ctx context.Context, seq uint64) error
	HighestIntent(ctx context.Context) (uint64, error)
}

// NewEmitter constructs an Emitter, SEEDING the sequence counter so a
// restarted node with a durable log never re-issues a sequence number to a
// different event. The next number is max(committed-tail, durable-high-water)
// + 1: the committed tail is the last sequence in the emission log; the
// high-water (when the log provides the intent capability) is the last
// sequence Emit durably recorded BEFORE publishing. Taking the max closes the
// append-after-publish window — a number that was published (or about to be)
// but not yet appended is still skipped on restart. Both an empty log and a
// missing high-water contribute 0.
//
// Reduced residual: the durable high-water closes the dangerous case (a
// restart re-issuing a PUBLISHED number → a reconciling consumer reading the
// collision as tamper). What remains is benign and, in part, irreducible:
//   - a crash between publish and append still leaves that sequence's record
//     ABSENT from the log — an honest GAP the consumer investigates as
//     POSSIBLE LOSS, never a tamper verdict (you cannot durably log an event
//     you crash before logging);
//   - if RecordIntent succeeded, the publish then FAILED, and the process
//     crashed before the reuse-retry, the skipped number is a phantom gap —
//     also read as "possible loss," over-conservative but never wrong.
//
// So a gap in the emitted sequence now means POSSIBLE LOSS (at-most-once
// transport OR a producer crash in the emit window), NOT foul play; in normal
// operation the publisher still never creates a gap by its own failure.
//
// A remaining, ORTHOGONAL residual (pre-existing, follow-up): a publish that
// errors AMBIGUOUSLY (a flush timeout after the broker already accepted the
// PUB) is treated as not-delivered and its number reused, which can still
// collide — see Emit. Closing that needs a stronger Publisher delivery
// contract.
//
// A tail record that cannot be read back as an emission record fails
// construction (the open-time damage doctrine extended to the seed). memlog
// provides no intent capability, so its recovery is exactly the tail-based
// behavior (in-memory, no restart). A nil logger defaults to slog.Default().
func NewEmitter(ctx context.Context, pub Publisher, codec contract.EnvelopeCodec, emission tlog.Log, logger *slog.Logger) (*Emitter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	intent, _ := emission.(intentLog)
	seq, err := recoverSequence(ctx, emission, intent)
	if err != nil {
		return nil, err
	}
	return &Emitter{pub: pub, codec: codec, emission: emission, intent: intent, logger: logger, seq: seq}, nil
}

// recoverSequence returns the next sequence number: max(committed tail,
// durable high-water) + 1, failing closed at the top of the space rather than
// wrapping to the invalid sequence 0. An empty log and a nil/zero high-water
// both contribute 0, so the first event of a fresh log is 1 — UNLESS a
// high-water survived from before (a first-event crash window), in which case
// it leads.
func recoverSequence(ctx context.Context, emission tlog.Log, intent intentLog) (uint64, error) {
	top, err := committedTailSequence(ctx, emission)
	if err != nil {
		return 0, err
	}
	if intent != nil {
		hw, err := intent.HighestIntent(ctx)
		if err != nil {
			return 0, fmt.Errorf("transport: emission log high-water: %w", err)
		}
		if hw > top {
			top = hw
		}
	}
	if top == math.MaxUint64 {
		// top+1 would wrap to 0 — an invalid sequence. An exhausted (or
		// absurdly damaged-but-parseable) source fails closed.
		return 0, fmt.Errorf("transport: emission sequence space exhausted (highest %d)", top)
	}
	return top + 1, nil
}

// committedTailSequence returns the sequence number of the last committed
// emission record, or 0 for an empty log.
func committedTailSequence(ctx context.Context, emission tlog.Log) (uint64, error) {
	size, err := emission.Size(ctx)
	if err != nil {
		return 0, fmt.Errorf("transport: emission log size: %w", err)
	}
	if size == 0 {
		return 0, nil
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
	return last, nil
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
// loss, never retried.
//
// Intent-before-publish: when the emission log provides the durable intent
// capability, Emit records the sequence number durably BEFORE publishing, so a
// crash in the publish→append window cannot let a restart re-issue it (see
// NewEmitter). It FAILS CLOSED — a RecordIntent error aborts the attempt
// before any publish, and the number is reused next time. Reuse-on-failure
// assumes a publish error means not-delivered; an AMBIGUOUS publish error (a
// broker that accepted the PUB before the flush timed out) can still make
// reuse collide — a pre-existing, orthogonal residual (see NewEmitter).
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

	// Durably record the intent to use this sequence BEFORE publishing. It
	// receives the live ctx (unlike the post-publish Append) because nothing
	// is delivered yet, so an implementation MAY honor cancellation here —
	// filelog performs the fast atomic write unconditionally, which is equally
	// fail-closed. No durable intent ⇒ no publish, number reused next time.
	if e.intent != nil {
		if err := e.intent.RecordIntent(ctx, next); err != nil {
			return fmt.Errorf("transport: record emission intent (sequenceNo %d): %w", next, err)
		}
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
