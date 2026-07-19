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
// Cap-bounded batching (D-T2 acceptance rule 1, task-6 controller decision):
// every MirrorLogSegment call's checkpoint must cover EXACTLY that call's
// end (checkpoint.Size == fromIndex+len(payloads)). tlog.Log's own
// Checkpoint(ctx) only ever signs the CURRENT head, which cannot bound a
// batch smaller than the whole outstanding backlog — so this package
// requires its log to ALSO provide the filelog-only CheckpointAt(ctx, size)
// capability (tlog/filelog), detected structurally via the unexported
// checkpointAtLog interface below (mirrors pipeline/transport's own
// intentLog precedent: a capability kept OUT of the tlog.Log contract
// itself, since memlog cannot sign at all and the tlog-custody spec's v0
// scope excludes merklelog). With CheckpointAt available, a backlog of any
// size drains in successive, exactly-covering, cap-sized segments — there
// is no "backlog exceeds the caps and can never be shipped" condition.
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

// checkpointAtLog is the optional filelog-only capability (see the package
// doc) a Shipper's log must provide: a signed checkpoint over an ARBITRARY
// earlier prefix, not just the current head. *filelog.Log satisfies it
// structurally; kept unexported (like transport's own intentLog) so
// tlog.Log's contract stays free of this shipper-specific coupling — the
// methods are still exported names because cross-package structural
// satisfaction requires it.
type checkpointAtLog interface {
	CheckpointAt(ctx context.Context, size uint64) (*tlog.Checkpoint, error)
}

// Construction errors.
var (
	ErrMissingLog    = errors.New("tlogship: Log is required")
	ErrMissingLogID  = errors.New("tlogship: LogID is required")
	ErrMissingClient = errors.New("tlogship: Client is required")
	ErrBadConfig     = errors.New("tlogship: MaxBatchRecords and MaxBatchBytes must be positive")
	// ErrLogLacksCheckpointAt is New's error when log does not provide the
	// CheckpointAt capability (see checkpointAtLog) — the tlog-custody
	// spec's v0 mirror scope is filelog-only, so a log that structurally
	// cannot produce an arbitrary-prefix checkpoint (memlog, merklelog)
	// cannot be mirrored by this shipper. Fails at construction, not on
	// the first tick.
	ErrLogLacksCheckpointAt = errors.New("tlogship: Log does not provide the CheckpointAt capability (tlog-custody v0 mirror scope is filelog-only)")
)

// ErrRecordExceedsMaxBatchBytes is tick's error when a SINGLE unmirrored
// record's payload alone is larger than the configured MaxBatchBytes: no
// batch containing it — even a batch of exactly one record — can ever fit
// under that cap, so retrying cannot resolve this on its own (unlike an
// ordinary registry-down failure). It stops the current tick's drain loop;
// Run logs it like any other tick error and keeps ticking. Resolving it
// requires raising MaxBatchBytes/tlog-mirror.max-batch-bytes.
var ErrRecordExceedsMaxBatchBytes = errors.New("tlogship: a single record's payload exceeds the configured max-batch-bytes; no batch containing it can ever be shipped")

// Config configures a Shipper. MaxBatchRecords and MaxBatchBytes are
// required (positive); FlushInterval defaults to DefaultFlushInterval;
// Logger defaults to slog.Default().
type Config struct {
	// MaxBatchRecords / MaxBatchBytes bound EACH segment shipped (D-T2 rule
	// 5; must match — or be no larger than — the registry's own
	// tlog-mirror.max-batch-records/max-batch-bytes, or the registry
	// rejects a batch this shipper thought was admissible).
	MaxBatchRecords int
	MaxBatchBytes   int
	// FlushInterval is the ticking cadence (tlog-mirror.flush-interval). <=
	// 0 defaults to DefaultFlushInterval.
	FlushInterval time.Duration
	// Logger receives operational output (registry-down retries, an
	// oversized single record). Nil defaults to slog.Default().
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
	log        tlog.Log
	checkpoint checkpointAtLog
	logID      string
	client     MirrorClient

	maxRecords int
	maxBytes   int
	interval   time.Duration
	logger     *slog.Logger
}

// New validates cfg and returns a ready Shipper over log (the LIVE tlog.Log
// handle shared with the emitting loop — this package never opens the log
// itself; the flock forbids a second opener) under logID, shipping through
// client. log must additionally provide the CheckpointAt capability (see
// checkpointAtLog); *filelog.Log does. A log that does not (e.g. memlog,
// merklelog) is rejected here, at construction, rather than failing on the
// first tick.
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
	capLog, ok := log.(checkpointAtLog)
	if !ok {
		return nil, fmt.Errorf("%w: got %T", ErrLogLacksCheckpointAt, log)
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
		log: log, checkpoint: capLog, logID: logID, client: mc,
		maxRecords: cfg.MaxBatchRecords, maxBytes: cfg.MaxBatchBytes,
		interval: interval, logger: logger,
	}, nil
}

// Run flushes on the configured interval until ctx is cancelled, returning
// nil on clean cancellation. A flush-tick error (registry unavailable, an
// oversized single record, a local log error) is logged and the loop
// continues — Run NEVER returns early on a tick failure and never blocks
// the caller's emission path, which is why it is meant to run on its own
// goroutine.
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
// returns ctx.Err() wrapping the last flush error observed. A single tick
// may itself ship several segments (see tick's doc) — a large backlog
// commonly drains fully within Drain's very first attempt.
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
// that fell behind/got ahead is always detected fresh), then drain the
// backlog [acked, head) in successive cap-sized segments — as many as it
// takes to reach the local log's CURRENT size as observed at the top of
// this tick (a fixed target for the duration of this one tick; new
// records appended DURING the drain are picked up by the NEXT tick, not
// chased within this one). Each segment's checkpoint is obtained via
// CheckpointAt(ctx, batchEnd) — exactly covering that segment's own end,
// never the log's current head — so every call satisfies D-T2 rule 1
// regardless of how large the outstanding backlog is.
//
// A registry-down (or any other) failure partway through a multi-segment
// drain stops THIS tick's loop immediately, having durably shipped
// whatever succeeded so far; it never retries within the same tick. The
// NEXT tick's fresh GetMirrorState call resumes exactly where the
// registry actually landed — never blocking or erroring the emission path
// this shipper shares a log handle with.
func (s *Shipper) tick(ctx context.Context) error {
	acked, err := s.client.GetMirrorState(ctx, s.logID)
	if err != nil {
		return fmt.Errorf("tlogship: get mirror state: %w", err)
	}
	head, err := s.log.Size(ctx)
	if err != nil {
		return fmt.Errorf("tlogship: local log size: %w", err)
	}
	if head < acked {
		// The registry claims MORE durable records than this log currently
		// has. Under the log-identity model (D-T1/D-T3) this should never
		// happen — the registry only ever accepts segments THIS log's
		// signer shipped — so this is a serious inconsistency, not a
		// transient condition. Fail loudly rather than silently doing
		// nothing (fail-closed, AGENTS.md wire-integrity posture).
		return fmt.Errorf("tlogship: local log size %d is behind the registry's acked size %d for %q — refusing to ship", head, acked, s.logID)
	}

	for acked < head {
		remaining := head - acked
		batchLen := remaining
		if batchLen > uint64(s.maxRecords) {
			batchLen = uint64(s.maxRecords)
		}

		payloads := make([][]byte, 0, batchLen)
		totalBytes := 0
		var n uint64
		for n = 0; n < batchLen; n++ {
			rec, err := s.log.Get(ctx, acked+n)
			if err != nil {
				return fmt.Errorf("tlogship: get record %d: %w", acked+n, err)
			}
			if totalBytes+len(rec.Payload) > s.maxBytes {
				if n == 0 {
					// Even a batch of exactly this ONE record exceeds the
					// byte cap — no smaller batch containing it can ever
					// fit either. Distinct from an ordinary transient
					// failure: retrying (this tick or the next) cannot
					// resolve it without a config change.
					s.logger.Error("tlogship: single record exceeds max-batch-bytes; cannot ship",
						"log_id", s.logID, "index", acked+n, "record_bytes", len(rec.Payload), "max_batch_bytes", s.maxBytes)
					return fmt.Errorf("%w: record %d is %d bytes, max-batch-bytes is %d", ErrRecordExceedsMaxBatchBytes, acked+n, len(rec.Payload), s.maxBytes)
				}
				break // ship what fits; the rest waits for the next batch
			}
			payloads = append(payloads, rec.Payload)
			totalBytes += len(rec.Payload)
		}
		batchLen = uint64(len(payloads))
		end := acked + batchLen

		cp, err := s.checkpoint.CheckpointAt(ctx, end)
		if err != nil {
			return fmt.Errorf("tlogship: checkpoint at %d: %w", end, err)
		}
		newAcked, err := s.client.MirrorLogSegment(ctx, s.logID, acked, payloads, cp)
		if err != nil {
			return fmt.Errorf("tlogship: mirror segment [%d,%d) for %q: %w", acked, end, s.logID, err)
		}
		acked = newAcked
	}
	return nil
}
