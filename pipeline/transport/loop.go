package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/tlog"
)

// Typed sentinel errors for Loop construction validation.
var (
	// ErrMissingProcessor is returned when LoopConfig.Processor is nil.
	ErrMissingProcessor = errors.New("transport: Processor is required")
	// ErrMissingSubscriber is returned when LoopConfig.Subscriber is nil.
	ErrMissingSubscriber = errors.New("transport: Subscriber is required")
	// ErrUnknownBehavior is returned when LoopConfig.Behavior is ChainBehaviorUnknown.
	ErrUnknownBehavior = errors.New("transport: Behavior must be non-Unknown")
	// ErrUnknownStrategy is returned when LoopConfig.Strategy is VerificationUnknown.
	ErrUnknownStrategy = errors.New("transport: Strategy must be non-Unknown")
	// ErrMissingPublisher is returned when a producing behavior (Preserving/FirstDrop)
	// is configured without a Publisher.
	ErrMissingPublisher = errors.New("transport: Publisher is required for producing behaviors (Preserving/FirstDrop)")
	// ErrMissingCodec is returned when a producing behavior is configured without a Codec.
	ErrMissingCodec = errors.New("transport: Codec is required for producing behaviors (Preserving/FirstDrop)")
	// ErrMissingEmission is returned when a producing behavior is configured without an Emission log.
	ErrMissingEmission = errors.New("transport: Emission is required for producing behaviors (Preserving/FirstDrop)")
	// ErrSinkWithPublisher is returned when a ChainTerminating loop is wired with
	// a Publisher, Codec, or Emission — a sink publishes nothing; this is a misconfiguration.
	ErrSinkWithPublisher = errors.New("transport: ChainTerminating sink must not be wired with Publisher, Codec, or Emission — a sink publishes nothing; this is a misconfiguration")
)

// LoopConfig configures a runtime loop bound to one subscription.
type LoopConfig struct {
	// Behavior declares the output-side chain behaviour of the process this
	// loop drives. Must be a non-Unknown value.
	Behavior contract.ChainBehavior
	// Strategy declares the ingress verification strategy. Must be a non-Unknown value.
	Strategy contract.VerificationStrategy
	// Processor is the event processor invoked per message. Required.
	Processor contract.EventProcessor
	// Subscriber is the inbound subscription. Required.
	Subscriber Subscriber
	// Publisher is required for Preserving/FirstDrop; must be nil for ChainTerminating.
	Publisher Publisher
	// Codec is required for producing behaviors (Preserving/FirstDrop).
	Codec contract.EnvelopeCodec
	// Emission is the transparency log for recording each published event
	// (credential hash + sequence number). Required for producing behaviors.
	Emission tlog.Log
	// Logger is used for operational log output. Nil defaults to slog.Default().
	Logger *slog.Logger
}

// Loop is a transport runtime loop bound to one subscription. It implements
// contract.Process: it drives one EventProcessor over one Subscriber and
// publishes results (for producing behaviors) via one Publisher.
type Loop struct {
	cfg    LoopConfig
	logger *slog.Logger
}

// isProducing reports whether the behavior requires a Publisher, Codec, and
// Emission log.
func isProducing(b contract.ChainBehavior) bool {
	return b == contract.ChainPreserving || b == contract.ChainFirstDrop
}

// NewLoop constructs and validates a Loop. Returns a typed sentinel error for
// every misconfiguration class.
func NewLoop(cfg LoopConfig) (*Loop, error) {
	if cfg.Processor == nil {
		return nil, ErrMissingProcessor
	}
	if cfg.Subscriber == nil {
		return nil, ErrMissingSubscriber
	}
	switch cfg.Behavior {
	case contract.ChainPreserving, contract.ChainFirstDrop, contract.ChainTerminating:
		// valid
	default:
		return nil, ErrUnknownBehavior
	}
	if cfg.Strategy == contract.VerificationUnknown {
		return nil, ErrUnknownStrategy
	}
	if isProducing(cfg.Behavior) {
		if cfg.Publisher == nil {
			return nil, ErrMissingPublisher
		}
		if cfg.Codec == nil {
			return nil, ErrMissingCodec
		}
		if cfg.Emission == nil {
			return nil, ErrMissingEmission
		}
	}
	if cfg.Behavior == contract.ChainTerminating {
		if cfg.Publisher != nil || cfg.Codec != nil || cfg.Emission != nil {
			return nil, ErrSinkWithPublisher
		}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Loop{cfg: cfg, logger: logger}, nil
}

// ChainBehavior returns the configured chain behavior (constant for the Loop's lifetime).
// Implements contract.Process.
func (l *Loop) ChainBehavior() contract.ChainBehavior { return l.cfg.Behavior }

// VerificationStrategy returns the configured verification strategy (constant for
// the Loop's lifetime). Implements contract.Process.
func (l *Loop) VerificationStrategy() contract.VerificationStrategy { return l.cfg.Strategy }

// Run subscribes to the configured Subscriber, processes events until ctx is
// cancelled, drains the subscriber, and closes the publisher if present.
//
// Sequence-number discipline: the counter starts at 1 and is advanced only
// after a successful Publish call. A failed publish reuses the same sequence
// number on the next attempt — handlers are sequential per subscription
// (Subscriber contract), so this is race-free without a mutex. The counter
// is in-memory; restarts reset to 1 (PoC posture, same family as wireauth's
// in-memory nonce store — persistent sequence state is the follow-up).
//
// Drain posture: Process receives the cancellable ctx — a stuck processor
// must remain interruptible. Append receives a detached context so that
// ctx cancellation at shutdown cannot abort an emission record for an event
// that has already been successfully published.
//
// Implements contract.Process.
func (l *Loop) Run(ctx context.Context) error {
	// seq is the next sequence number to assign.
	// ONLY advanced after a successful Publish (see publishPassed).
	// Handlers are sequential per subscription (Subscriber contract),
	// so this pointer is race-free without a mutex.
	var seq uint64 = 1

	if err := l.cfg.Subscriber.Subscribe(func(data []byte) {
		l.handle(ctx, data, &seq)
	}); err != nil {
		return err
	}

	<-ctx.Done()

	var firstErr error

	if err := l.cfg.Subscriber.Drain(); err != nil {
		l.logger.Error("transport: drain failed", "err", err)
		firstErr = err
	}

	if l.cfg.Publisher != nil {
		if err := l.cfg.Publisher.Close(); err != nil {
			l.logger.Error("transport: publisher close failed", "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

// handle dispatches one inbound message through the EventProcessor and routes
// the result to the appropriate output path.
func (l *Loop) handle(ctx context.Context, data []byte, seq *uint64) {
	result, err := l.cfg.Processor.Process(ctx, data)
	if err != nil {
		// Go error = context cancellation or internal invariant violation.
		// The Subscriber API gives the handler no way to stop the loop;
		// ctx governs Run. Log loudly and drop.
		l.logger.Error("transport: processor error", "err", err)
		return
	}

	// Guard: nil result with nil error is a processor contract violation.
	if result == nil {
		l.logger.Error("transport: processor returned nil result with nil error — dropping")
		return
	}

	switch result.Status {
	case contract.StatusFiltered:
		l.logger.Info("transport: event filtered", "filteredAtStep", result.FilteredAtStep)
		return
	case contract.StatusErrored:
		l.logger.Error("transport: processing error", "error", result.Error)
		return
	case contract.StatusPassed:
		if !isProducing(l.cfg.Behavior) {
			// ChainTerminating: the process wrote externally. Publish nothing.
			return
		}
		l.publishPassed(ctx, result, seq)
	default:
		l.logger.Error("transport: processor returned invalid status — dropping", "status", result.Status)
	}
}

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

// publishPassed handles the StatusPassed path for producing behaviors
// (ChainPreserving, ChainFirstDrop).
//
// Contract: result must be non-nil with non-nil VC and non-nil Payload.
// Violations are rejected loudly; no publish, counter NOT advanced.
//
// Sequence-number discipline: the counter (*seq) is advanced ONLY after a
// successful Publish call. A failed pre-publish step (nil guard, hash,
// emission-record marshal, codec marshal) or a failed Publish reuses the same
// number on the next attempt — a gap in the subscriber's view is protocol
// evidence of foul play; the publisher must never create one by its own failure.
//
// Ordering: VC.Hash() and the emission record are computed BEFORE Publish so
// that a hash or marshal failure aborts the attempt without any delivery. Only
// Append remains after Publish.
//
// Emission append-after-publish: the emission record is appended to the tlog
// AFTER a successful Publish, using a detached context (context.WithoutCancel)
// so that ctx cancellation at shutdown cannot abort recording an event that
// was already delivered. If Append fails the event was delivered — the gap is
// our audit-defense loss and the counter still advances. A crash between
// Publish and Append creates an un-recorded delivery window (PoC posture —
// persistent WAL is the follow-up).
func (l *Loop) publishPassed(ctx context.Context, result *contract.Result, seq *uint64) {
	next := *seq

	// Finding 2: in-org processes always produce the full inline form
	// (contract.Envelope doc). Nil VC or nil Payload indicates a processor
	// contract violation — reject loudly before any publish attempt.
	if result.VC == nil {
		l.logger.Error("transport: StatusPassed result has nil VC — dropping", "sequenceNo", next)
		return
	}
	if result.Payload == nil {
		l.logger.Error("transport: StatusPassed result has nil Payload — dropping", "sequenceNo", next)
		return
	}

	// Finding 4: compute credential hash and marshal the emission record
	// BEFORE Publish so that a failure in either step aborts without delivery.
	hash, err := result.VC.Hash()
	if err != nil {
		l.logger.Error("transport: credential hash failed", "err", err, "sequenceNo", next)
		// Counter NOT advanced: event not published.
		return
	}

	rec, err := json.Marshal(emissionRecord{
		CredentialHash: hash,
		SequenceNo:     strconv.FormatUint(next, 10),
	})
	if err != nil {
		l.logger.Error("transport: marshal emission record failed", "err", err, "sequenceNo", next)
		// Counter NOT advanced: event not published.
		return
	}

	wire, err := l.cfg.Codec.MarshalEnvelope(&contract.Envelope{
		Credential: result.VC,
		Payload:    result.Payload,
		SequenceNo: next,
	})
	if err != nil {
		l.logger.Error("transport: marshal envelope failed", "err", err, "sequenceNo", next)
		// Counter NOT advanced: event not published; reuse on next attempt.
		return
	}

	if err := l.cfg.Publisher.Publish(wire); err != nil {
		l.logger.Error("transport: publish failed", "err", err, "sequenceNo", next)
		// Counter NOT advanced: event not delivered; reuse on next attempt.
		return
	}

	// Advance ONLY after successful publish.
	*seq = next + 1

	// Append the pre-computed emission record. Use a detached context so that
	// ctx cancellation at shutdown cannot abort recording a delivered event.
	if _, err := l.cfg.Emission.Append(context.WithoutCancel(ctx), rec); err != nil {
		l.logger.Error("transport: emission log append failed", "err", err, "sequenceNo", next)
		// Counter already advanced: event was delivered. The gap is our
		// audit-defense loss. Log loudly; do not re-attempt (PoC posture).
	}
}
