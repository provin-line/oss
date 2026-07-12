package transport

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

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
	// PayloadRetainer, when non-nil, durably retains each produced payload before
	// publishing so a by-reference subscriber can later dereference it (see
	// Emitter). Optional; nil leaves the loop an ordinary inline producer. Only
	// meaningful for producing behaviors.
	PayloadRetainer PayloadRetainer
	// StrippedPublisher, when non-nil, makes the loop's Emitter dual-emit: a
	// stripped (Payload: nil) form of every event additionally publishes to
	// it, under the same sequence number as the primary publish — the
	// cross-org export seam's mechanism for applying an agreed by-reference
	// delivery mode (see transport.WithStrippedPublisher). Optional; nil
	// leaves the loop single-publish, byte-for-byte the pre-dual-emit
	// behavior. Only meaningful for producing behaviors.
	StrippedPublisher Publisher
	// Logger is used for operational log output. Nil defaults to slog.Default().
	Logger *slog.Logger
}

// Loop is a transport runtime loop bound to one subscription. It implements
// contract.Process: it drives one EventProcessor over one Subscriber and
// publishes results (for producing behaviors) via one Publisher.
type Loop struct {
	cfg    LoopConfig
	logger *slog.Logger
	// emitter is published (atomically) by Run once it constructs the producing
	// emitter, so a health surface on ANOTHER goroutine can read the loop's
	// stripped-publish counters without racing Run. It stays nil for
	// non-producing (sink) loops and before Run — a nil read reports "no failure
	// observed", the availability-oriented default (the loop configured the
	// capability; there is no negative evidence yet). Run is not meant to execute
	// concurrently or repeatedly for one Loop.
	emitter atomic.Pointer[Emitter]
}

// StrippedPublishHealthy reports whether this loop's most recent stripped
// publish succeeded (true also before Run and for non-producing loops, which
// never dual-emit). It is the control plane's by-reference degradation signal:
// the node stops advertising by-reference while a producing loop's stripped
// emission is failing, and re-advertises only after a successful stripped
// publish proves recovery.
func (l *Loop) StrippedPublishHealthy() bool {
	if e := l.emitter.Load(); e != nil {
		return e.StrippedPublishHealthy()
	}
	return true
}

// StrippedPublishFailures reports this loop's monotonic stripped-publish failure
// count (0 before Run / for non-producing loops). Companion to
// StrippedPublishHealthy for metrics surfaces.
func (l *Loop) StrippedPublishFailures() uint64 {
	if e := l.emitter.Load(); e != nil {
		return e.StrippedPublishFailures()
	}
	return 0
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
	// emitter owns the sequence counter and the emission discipline. It is
	// created per Run (seq starts at 1) and used only for producing behaviors;
	// for ChainTerminating it stays nil (handle never reaches Emit). Handlers
	// are sequential per subscription (Subscriber contract), so the emitter's
	// counter is race-free without a mutex.
	var emitter *Emitter
	if isProducing(l.cfg.Behavior) {
		var err error
		var opts []EmitterOption
		if l.cfg.PayloadRetainer != nil {
			opts = append(opts, WithPayloadRetainer(l.cfg.PayloadRetainer))
		}
		if l.cfg.StrippedPublisher != nil {
			opts = append(opts, WithStrippedPublisher(l.cfg.StrippedPublisher))
		}
		emitter, err = NewEmitter(ctx, l.cfg.Publisher, l.cfg.Codec, l.cfg.Emission, l.logger, opts...)
		if err != nil {
			return err
		}
		// Publish the emitter for the health surface BEFORE Subscribe can deliver
		// any traffic, so a stripped-publish failure is observable the moment it
		// can occur.
		l.emitter.Store(emitter)
	}

	if err := l.cfg.Subscriber.Subscribe(func(data []byte) {
		l.handle(ctx, data, emitter)
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
func (l *Loop) handle(ctx context.Context, data []byte, emitter *Emitter) {
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
		// Emit via the shared emitter. A pre-publish/publish failure is logged
		// and dropped (the sequence is not advanced — reused next attempt); an
		// append-after-publish failure is logged inside Emit and returns nil.
		if err := emitter.Emit(ctx, result.VC, result.Payload); err != nil {
			l.logger.Error("transport: emit failed — dropping", "err", err)
		}
	default:
		l.logger.Error("transport: processor returned invalid status — dropping", "status", result.Status)
	}
}
