// Package tlogship is the background mirror shipper (tlog custody spec
// D-T6): it replicates checkpoint-aligned segments of ONE local tlog.Log to
// a registry's TlogService mirror surface (dplaax.tlog.v1
// MirrorLogSegment/GetMirrorState), asynchronously and on a timer, so that
// custody of the producing loop's durable log survives the pipeline
// process's own lifetime.
//
// Placement (AGENTS.md layer rule: network/ and pipeline/ never import each
// other): the production signing client that actually calls the wire RPCs
// lives at network/pkg/services/tlogservice/client, under network/. This
// package lives under pipeline/ (it consumes a pipeline-owned tlog.Log
// handle and is a pipeline-lifecycle concern — start with the loop, drain
// before the loop's log closer runs) and therefore must NOT import that
// client package directly. Instead it defines MirrorClient, a narrow local
// interface capturing exactly the two calls it needs;
// network/pkg/services/tlogservice/client.Client satisfies it structurally
// (Go's implicit interface satisfaction), and a composition root that is
// free to import both network/ and pipeline/ (e.g. a future cmd/pipeline)
// wires the concrete client in. This package itself imports only tlog/ (a
// pure domain library, AGENTS.md rule 1) and the standard library.
//
// Checkpoint-covering-batch constraint (D-T2 acceptance rule 1): every
// MirrorLogSegment call's checkpoint must cover EXACTLY that call's end
// (checkpoint.Size == fromIndex+len(payloads)). tlog.Log's only checkpoint
// operation is Checkpoint(ctx), which always signs the CURRENT head — there
// is no CheckpointAt(size) capability anywhere in the tlog contract or its
// implementations (verified: filelog.Log.Checkpoint signs
// len(l.records) at call time; memlog never signs at all; merklelog is out
// of v0's scope). A live log's size can only grow between the moment the
// shipper reads GetMirrorState and the moment it reads Checkpoint(), never
// shrink to an earlier boundary on demand — so the ONLY checkpoint a
// shipper can ever obtain that covers a prefix boundary strictly SMALLER
// than the log's current size does not exist. Consequently this shipper
// ships AT MOST ONE segment per flush attempt, spanning [acked, current
// head): the batch caps (MaxBatchRecords/MaxBatchBytes) are enforced as an
// ADMISSION GATE on that one segment (ship it only if it already fits;
// never split it, since no smaller covering checkpoint is obtainable to
// ship a split earlier piece under). A backlog that exceeds the configured
// caps in a single attempt is NOT shipped (ErrBacklogExceedsCaps, logged
// and retried next tick, exactly like any other transient failure) — this
// is an accepted, disclosed limitation of the current tlog.Log surface, not
// a bug in this package: see task-6-report.md's "checkpoint-covering-batch
// resolution" for the full analysis and the (not taken) alternative of
// amending tlog.Log with a CheckpointAt capability.
package tlogship

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/provin-line/oss/tlog"
)

// DefaultFlushInterval is the D-T6 default ticking cadence
// (tlog-mirror.flush-interval) when Config.FlushInterval is unset.
const DefaultFlushInterval = 5 * time.Second

// MirrorClient is the shipper's dependency on a mirror-registry client — see
// the package doc for why this interface is defined here rather than
// importing network/pkg/services/tlogservice/client directly.
// *client.Client (that package) satisfies this structurally.
type MirrorClient interface {
	// MirrorLogSegment ships payloads [fromIndex, fromIndex+len(payloads))
	// under cp (a checkpoint covering exactly that end) and returns the
	// registry's durable acked size after the call.
	MirrorLogSegment(ctx context.Context, logID string, fromIndex uint64, payloads [][]byte, cp *tlog.Checkpoint) (ackedSize uint64, err error)
	// GetMirrorState returns the registry's current durable acked size for
	// logID — the shipper's resume cursor.
	GetMirrorState(ctx context.Context, logID string) (ackedSize uint64, err error)
}

// Construction errors.
var (
	ErrMissingLog    = errors.New("tlogship: Log is required")
	ErrMissingLogID  = errors.New("tlogship: LogID is required")
	ErrMissingClient = errors.New("tlogship: Client is required")
	ErrBadConfig     = errors.New("tlogship: MaxBatchRecords and MaxBatchBytes must be positive")
)

// ErrBacklogExceedsCaps is tick's error when the pending backlog (the local
// log's current size minus the registry's acked size) exceeds the
// configured MaxBatchRecords or MaxBatchBytes: see the package doc's
// "checkpoint-covering-batch constraint". It is not a bug — the segment is
// never sent (the registry's own caps would reject it anyway) — but it IS a
// stuck condition this shipper cannot self-resolve by retrying alone: a
// growing local log only makes the backlog larger, never smaller, until an
// operator raises tlog-mirror.max-batch-records/max-batch-bytes (or a
// future tlog.Log capability allows genuine sub-head chunking). Run logs it
// like any other tick error and keeps ticking (never blocks emission).
var ErrBacklogExceedsCaps = errors.New("tlogship: pending backlog exceeds the configured batch caps; no smaller checkpoint-covering segment is obtainable from tlog.Log")

// Config configures a Shipper. MaxBatchRecords and MaxBatchBytes are
// required (positive); FlushInterval defaults to DefaultFlushInterval;
// Logger defaults to slog.Default().
type Config struct {
	// MaxBatchRecords / MaxBatchBytes bound the ONE segment shipped per
	// flush attempt (D-T2 rule 5; must match — or be no larger than — the
	// registry's own tlog-mirror.max-batch-records/max-batch-bytes, or the
	// registry rejects what this admission gate let through).
	MaxBatchRecords int
	MaxBatchBytes   int
	// FlushInterval is the ticking cadence (tlog-mirror.flush-interval). <=
	// 0 defaults to DefaultFlushInterval.
	FlushInterval time.Duration
	// Logger receives operational output (registry-down retries, the
	// backlog-exceeds-caps condition). Nil defaults to slog.Default().
	Logger *slog.Logger
}

// Shipper replicates ONE local tlog.Log to a registry's mirror surface.
// Construct with New; run its ticking loop with Run (typically `go
// shipper.Run(ctx)`, a separate goroutine — a flush attempt NEVER blocks or
// errors the emission path it shares the log handle with); flush the tail
// once more with Drain during graceful shutdown, BEFORE the log's own
// closer runs (D-T6 shutdown ordering: loops drain → shipper drains → log
// closers run).
type Shipper struct {
	log    tlog.Log
	logID  string
	client MirrorClient

	maxRecords int
	maxBytes   int
	interval   time.Duration
	logger     *slog.Logger
}

// New validates cfg and returns a ready Shipper over log (the LIVE tlog.Log
// handle shared with the emitting loop — this package never opens the log
// itself; the flock forbids a second opener) under logID, shipping through
// client.
func New(log tlog.Log, logID string, mc MirrorClient, cfg Config) (*Shipper, error) {
	if log == nil {
		return nil, ErrMissingLog
	}
	if logID == "" {
		return nil, ErrMissingLogID
	}
	if mc == nil {
		return nil, ErrMissingClient
	}
	if cfg.MaxBatchRecords <= 0 || cfg.MaxBatchBytes <= 0 {
		return nil, fmt.Errorf("%w: got MaxBatchRecords=%d MaxBatchBytes=%d", ErrBadConfig, cfg.MaxBatchRecords, cfg.MaxBatchBytes)
	}
	interval := cfg.FlushInterval
	if interval <= 0 {
		interval = DefaultFlushInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Shipper{
		log: log, logID: logID, client: mc,
		maxRecords: cfg.MaxBatchRecords, maxBytes: cfg.MaxBatchBytes,
		interval: interval, logger: logger,
	}, nil
}

// Run flushes on the configured interval until ctx is cancelled, returning
// nil on clean cancellation. A flush-tick error (registry unavailable, a
// backlog over caps, a local log error) is logged and the loop continues —
// Run NEVER returns early on a tick failure and never blocks the caller's
// emission path, which is why it is meant to run on its own goroutine.
func (s *Shipper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.tick(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				s.logger.Error("tlogship: flush tick failed", "log_id", s.logID, "err", err)
			}
		}
	}
}

// Drain performs flush attempts, spaced by the configured flush interval,
// until one succeeds (the log's current tail is fully mirrored) or ctx is
// done — the D-T6 graceful-shutdown flush: call it AFTER the producing
// loop has stopped appending and drained, BEFORE closing the log. Callers
// bound how long Drain may retry by ctx's deadline; on ctx expiry it
// returns ctx.Err() wrapping the last flush error observed.
func (s *Shipper) Drain(ctx context.Context) error {
	var lastErr error
	for {
		if err := s.tick(ctx); err != nil {
			lastErr = err
		} else {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("tlogship: drain: %w (last flush error: %v)", ctx.Err(), lastErr)
		case <-time.After(s.interval):
		}
	}
}

// tick performs ONE flush attempt: read the registry's resume cursor
// (GetMirrorState — the shipper's cursor is ALWAYS the registry's own
// acked size, never locally cached, so a shipper restart or a registry
// that fell behind/got ahead is always detected fresh), take the local
// log's current checkpoint (checkpoint-then-Get order: Checkpoint() fixes
// (size, head) atomically; every index below that size is already durably
// committed — see the package doc), and — if there is a nonzero,
// cap-admissible backlog — ship it as one segment.
func (s *Shipper) tick(ctx context.Context) error {
	acked, err := s.client.GetMirrorState(ctx, s.logID)
	if err != nil {
		return fmt.Errorf("tlogship: get mirror state: %w", err)
	}
	cp, err := s.log.Checkpoint(ctx)
	if err != nil {
		return fmt.Errorf("tlogship: local checkpoint: %w", err)
	}
	switch {
	case cp.Size == acked:
		return nil // caught up
	case cp.Size < acked:
		// The registry claims MORE durable records than this log currently
		// has. Under the log-identity model (D-T1/D-T3) this should never
		// happen — the registry only ever accepts segments THIS log's
		// signer shipped — so this is a serious inconsistency, not a
		// transient condition. Fail loudly rather than silently doing
		// nothing (fail-closed, AGENTS.md wire-integrity posture).
		return fmt.Errorf("tlogship: local log size %d is behind the registry's acked size %d for %q — refusing to ship", cp.Size, acked, s.logID)
	}

	pending := cp.Size - acked
	if pending > uint64(s.maxRecords) {
		s.logger.Warn("tlogship: backlog exceeds max-batch-records; cannot ship without an exactly-covering checkpoint at a smaller size",
			"log_id", s.logID, "pending_records", pending, "max_batch_records", s.maxRecords)
		return ErrBacklogExceedsCaps
	}

	payloads := make([][]byte, 0, pending)
	totalBytes := 0
	for i := acked; i < cp.Size; i++ {
		rec, err := s.log.Get(ctx, i)
		if err != nil {
			return fmt.Errorf("tlogship: get record %d: %w", i, err)
		}
		payloads = append(payloads, rec.Payload)
		totalBytes += len(rec.Payload)
	}
	if totalBytes > s.maxBytes {
		s.logger.Warn("tlogship: backlog exceeds max-batch-bytes; cannot ship without an exactly-covering checkpoint at a smaller size",
			"log_id", s.logID, "pending_bytes", totalBytes, "max_batch_bytes", s.maxBytes)
		return ErrBacklogExceedsCaps
	}

	if _, err := s.client.MirrorLogSegment(ctx, s.logID, acked, payloads, cp); err != nil {
		return fmt.Errorf("tlogship: mirror segment [%d,%d) for %q: %w", acked, cp.Size, s.logID, err)
	}
	return nil
}
