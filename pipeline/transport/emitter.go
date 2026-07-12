package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync/atomic"
	"time"

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
//
// Dual-emit (optional, see WithStrippedPublisher): a serving node additionally
// publishes a stripped (Payload: nil) form of every event under the same
// sequence number, to a second Publisher bound to the export seam's
// mode-scoped subject — this is how the cross-organization export seam
// applies an agreed by-reference delivery mode, since it cannot transform a
// message in flight. It rides the exact same publish→append ordering; a
// stripped-publish failure never perturbs it (see Emit).
type Emitter struct {
	pub      Publisher
	codec    contract.EnvelopeCodec
	emission tlog.Log
	// intent is the emission log's optional durable-sequence-intent capability
	// (nil when the log does not provide it, e.g. memlog). When present, Emit
	// records the sequence it is about to publish BEFORE publishing.
	intent   intentLog
	retainer PayloadRetainer
	// stripped is the optional cross-org export-seam dual-emit capability (see
	// WithStrippedPublisher). nil leaves Emit a single-publish (inline-only)
	// producer, byte-for-byte the pre-dual-emit behavior.
	stripped Publisher
	logger   *slog.Logger
	seq      uint64
	// strippedFailures / lastStrippedFailure back the read accessors
	// StrippedPublishFailures / LastStrippedPublishFailure. They are accessed
	// with atomics (not the single-goroutine Emit discipline the seq counter
	// relies on) because they are the intended wiring point for a health/
	// metrics surface polling from a DIFFERENT goroutine than the one calling
	// Emit.
	strippedFailures    atomic.Uint64
	lastStrippedFailure atomic.Int64 // UnixNano; 0 = never failed
	// strippedUnhealthy is the LAST stripped-publish outcome: true after a
	// failure, false after a success (zero value false = healthy, the optimistic
	// pre-first-emit default). It backs StrippedPublishHealthy — recovery is tied
	// to an actually-successful stripped publish, not a time window, so a broken
	// publisher that has simply gone quiet never looks healthy again on its own.
	strippedUnhealthy atomic.Bool
}

// PayloadRetainer is the optional publisher-side capability that retains a
// producing loop's payload bytes before they are published, so a by-reference
// subscriber can later dereference them from the publisher's serving boundary.
// Retain returns the content address the bytes were stored at, which Emit
// compares to the credential's declared outputHash — the emit-side binding gate.
//
// It is wired per producing loop (bound to that loop's owner pipeline DID at the
// composition root), so its method needs no owner argument. A loop with no
// retainer is an ordinary inline-only producer.
type PayloadRetainer interface {
	Retain(ctx context.Context, payload []byte) (contentHash string, err error)
}

// EmitterOption configures an Emitter at construction.
type EmitterOption func(*Emitter)

// WithPayloadRetainer attaches a PayloadRetainer so Emit durably retains each
// payload before publishing (see PayloadRetainer and Emit). Omitting it leaves
// the Emitter an ordinary inline producer.
func WithPayloadRetainer(r PayloadRetainer) EmitterOption {
	return func(e *Emitter) { e.retainer = r }
}

// WithStrippedPublisher attaches the dual-emit capability the cross-org
// export seam relies on to apply an agreed by-reference delivery mode
// (export-seam-mode spec D-1/D-5/D-6): the seam cannot transform a NATS
// message in flight (account export/import is a routing grant, not a
// transform), so a serving node's producing loop instead publishes TWICE —
// the primary (full) form on its existing subject, and a STRIPPED form
// (Payload: nil, same sequence number) on pub, which is bound at the
// composition root to the mode-scoped subject a by-reference subscriber's
// account imports (e.g. "byref.<outputSubject>"). Which subscribers can see
// which form is then entirely a matter of the export/import grant — not a
// runtime branch here. Omitting this option leaves the Emitter a
// single-publish (inline-only) producer, byte-for-byte the pre-dual-emit
// behavior; see Emit's partial-failure semantics doc and
// StrippedPublishFailures for what happens when the stripped publish itself
// fails.
func WithStrippedPublisher(pub Publisher) EmitterOption {
	return func(e *Emitter) { e.stripped = pub }
}

// StrippedPublishFailures returns the number of stripped-publish failures
// (marshal or publish) recorded since construction — monotonic, never reset.
// It is the wiring point for a future health/metrics surface (L3
// observability): the emission log is form-independent by design (§ its
// doc), so it cannot itself reveal a persistent, systematic stripped-form
// divergence (inline healthy, by-reference silently failing); a caller
// polling this counter (and LastStrippedPublishFailure) from a separate
// goroutine can. A zero value with no WithStrippedPublisher configured, or
// with one configured but never yet failing, are indistinguishable — callers
// that need to tell those apart hold the EmitterOption they passed.
func (e *Emitter) StrippedPublishFailures() uint64 { return e.strippedFailures.Load() }

// LastStrippedPublishFailure returns the time of the most recent
// stripped-publish failure and true, or the zero Time and false if none has
// occurred yet. Same wiring point as StrippedPublishFailures.
func (e *Emitter) LastStrippedPublishFailure() (time.Time, bool) {
	n := e.lastStrippedFailure.Load()
	if n == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}

// StrippedPublishHealthy reports whether the MOST RECENT stripped publish
// succeeded (true also before any attempt and for an inline-only emitter that
// never dual-emits). It is the control plane's by-reference degradation signal:
// unlike a time window, it stays false while the publisher is broken even if the
// loop goes quiet, and clears only on a genuinely successful stripped publish —
// so a node never re-advertises by-reference without evidence of recovery.
func (e *Emitter) StrippedPublishHealthy() bool { return !e.strippedUnhealthy.Load() }

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
// contract; tracked as https://github.com/provin-line/oss/issues/11.
//
// A tail record that cannot be read back as an emission record fails
// construction (the open-time damage doctrine extended to the seed). memlog
// provides no intent capability, so its recovery is exactly the tail-based
// behavior (in-memory, no restart). A nil logger defaults to slog.Default().
func NewEmitter(ctx context.Context, pub Publisher, codec contract.EnvelopeCodec, emission tlog.Log, logger *slog.Logger, opts ...EmitterOption) (*Emitter, error) {
	if logger == nil {
		logger = slog.Default()
	}
	intent, _ := emission.(intentLog)
	seq, err := recoverSequence(ctx, emission, intent)
	if err != nil {
		return nil, err
	}
	e := &Emitter{pub: pub, codec: codec, emission: emission, intent: intent, logger: logger, seq: seq}
	for _, opt := range opts {
		opt(e)
	}
	return e, nil
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
//
// Dual-emit partial failure (when WithStrippedPublisher is configured): the
// stripped publish runs AFTER the primary publish has already succeeded, so
// its own failure does NOT change any of the above — the sequence still
// advances and the emission log still appends exactly once, form-independent.
// See publishStripped for why failing Emit here would be strictly worse (it
// would duplicate the primary delivery on retry) and StrippedPublishFailures
// for how the loss is made observable instead.
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

	// Retain the payload BEFORE publishing (fail-closed) when a retainer is
	// wired. A by-reference subscriber dereferences these bytes from the serving
	// boundary by the credential's outputHash, so they must be durably servable
	// before the envelope goes out — and a payload not retained at emit time is
	// unrecoverable (the by-reference subscriber's chain would break permanently).
	// A retain error aborts the attempt before any publish; the sequence is not
	// advanced and the number is reused next time (an idempotent re-retain).
	if e.retainer != nil {
		subj, err := cred.Subject()
		if err != nil {
			return fmt.Errorf("transport: emit subject unreadable (sequenceNo %d): %w", next, err)
		}
		if subj.OutputHash == "" {
			return fmt.Errorf("transport: emit with payload retention but credential declares no outputHash (sequenceNo %d): binding undecidable, fail closed", next)
		}
		got, err := e.retainer.Retain(ctx, payload)
		if err != nil {
			return fmt.Errorf("transport: retain payload (sequenceNo %d): %w", next, err)
		}
		// Emit-side binding gate: the store keys the bytes by their own content
		// address, which MUST equal the outputHash a consumer will fetch by. A
		// mismatch is a producing-process bug — the payload does not match the
		// credential it is paired with — caught at the cheapest point, the mirror
		// of the consumer's binding gate.
		if got != subj.OutputHash {
			return fmt.Errorf("transport: retained payload hashes to %s but credential declares outputHash %s (sequenceNo %d): producing process paired mismatched bytes", got, subj.OutputHash, next)
		}
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

	// Dual-emit: best-effort stripped (Payload: nil) publish to the export
	// seam's mode-scoped subject, under the SAME sequence number as the
	// primary publish just above (see WithStrippedPublisher). A failure here
	// never fails Emit — see publishStripped's doc for why.
	if e.stripped != nil {
		e.publishStripped(cred, next)
	}

	// Append the pre-computed emission record under a detached context so that
	// ctx cancellation at shutdown cannot abort recording a delivered event.
	if _, err := e.emission.Append(context.WithoutCancel(ctx), rec); err != nil {
		e.logger.Error("transport: emission log append failed", "err", err, "sequenceNo", next)
		// Counter already advanced: the event was delivered. The gap is our
		// audit-defense loss. Log loudly; do not re-attempt (PoC posture).
	}
	return nil
}

// publishStripped marshals and publishes the stripped (Payload: nil) form of
// an already-delivered primary event. It NEVER returns an error to Emit:
// primary delivery already happened, so failing Emit here would force a
// seq-reuse retry that DUPLICATES the primary delivery on the next attempt —
// worse than the stripped form's own loss, which the existing at-most-once
// loss-accounting machinery (emission-log sequence-gap detection + TlogService
// reconciliation) already covers as POSSIBLE LOSS (the same class core NATS
// itself already admits for any subscriber). A failure instead increments the
// monotonic StrippedPublishFailures counter, records the failure time, and
// logs loudly with the counter attached — see StrippedPublishFailures.
func (e *Emitter) publishStripped(cred *vc.PipelinePassCredential, seq uint64) {
	wire, err := e.codec.MarshalEnvelope(&contract.Envelope{
		Credential: cred,
		Payload:    nil,
		SequenceNo: seq,
	})
	if err != nil {
		e.recordStrippedFailure()
		e.logger.Error("transport: marshal stripped envelope failed", "err", err, "sequenceNo", seq, "strippedPublishFailures", e.strippedFailures.Load())
		return
	}
	if err := e.stripped.Publish(wire); err != nil {
		e.recordStrippedFailure()
		e.logger.Error("transport: stripped publish failed", "err", err, "sequenceNo", seq, "strippedPublishFailures", e.strippedFailures.Load())
		return
	}
	// A successful stripped publish clears the health flag — recovery is proven,
	// not merely elapsed.
	e.strippedUnhealthy.Store(false)
}

// recordStrippedFailure advances the failure counter and last-failure time and
// marks the last outcome unhealthy (see StrippedPublishFailures /
// LastStrippedPublishFailure / StrippedPublishHealthy).
func (e *Emitter) recordStrippedFailure() {
	e.strippedFailures.Add(1)
	e.lastStrippedFailure.Store(time.Now().UnixNano())
	e.strippedUnhealthy.Store(true)
}
