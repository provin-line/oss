// Package logobserver is a reference contract.ProcessObserver that emits each
// processed event as one structured slog record. It is the minimal,
// dependency-free observer — a template to copy for a real adapter (metrics, a
// store, a message bus) — and is fire-and-forget by construction: its
// OnProcessComplete always returns nil, so a logging observer can never affect a
// pipeline outcome.
//
// The interface (contract.ProcessObserver) permits an observer to return an
// error; the runtimes log and suppress it. This logger has nothing to fail on,
// so it returns nil rather than manufacture a failure — the honest model for a
// pure observation sink.
//
// Every event is one Info record ("pipeline event observed") carrying the
// outcome as the "status" attribute. Severity is deliberately uniform: the
// runtimes already log errored results at Error and filtered ones at Info, so
// the observer is a single event stream with status as data, not a second
// severity channel. A consumer that needs severity routing implements its own
// observer.
package logobserver

import (
	"context"
	"log/slog"
	"time"

	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/vc"
)

// Observer logs each ProcessEvent to a slog.Logger. Construct it with New.
type Observer struct {
	logger *slog.Logger
}

var _ contract.ProcessObserver = (*Observer)(nil)

// New returns an Observer logging to logger. A nil logger falls back to
// slog.Default() so a zero-config observer never panics.
func New(logger *slog.Logger) *Observer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Observer{logger: logger}
}

// OnProcessComplete emits one structured record for ev and always returns nil.
// Only populated fields are attached (an absent role reference, hash, or a zero
// Timestamp is omitted rather than logged empty); status is the one always-present
// anchor. The "timestamp" attribute is the EVENT time (ev.Timestamp); slog stamps
// the record's own emission time separately under its built-in time key — a copier
// should not conflate the two. It is nil-safe: a nil Result logs status "unknown"
// instead of panicking — observation must never crash the caller.
func (o *Observer) OnProcessComplete(ctx context.Context, ev contract.ProcessEvent) error {
	attrs := []slog.Attr{slog.String("status", statusName(ev.Result))}
	if !ev.Timestamp.IsZero() {
		attrs = append(attrs, slog.String("timestamp", ev.Timestamp.UTC().Format(time.RFC3339Nano)))
	}
	if ev.InputHash != "" {
		attrs = append(attrs, slog.String("inputHash", ev.InputHash))
	}
	if ev.OutputHash != "" {
		attrs = append(attrs, slog.String("outputHash", ev.OutputHash))
	}
	if ev.IssuedVCRef != "" {
		attrs = append(attrs, slog.String("issuedVCRef", ev.IssuedVCRef))
	}
	if ev.ConsumedVCRef != "" {
		attrs = append(attrs, slog.String("consumedVCRef", ev.ConsumedVCRef))
	}
	if r := ev.Result; r != nil {
		// Confidence when a verification ran: a passed sink can still carry a
		// failed/indeterminate verdict, and the record must not read as verified.
		if r.Confidence != nil {
			attrs = append(attrs, slog.String("confidence", confidenceName(*r.Confidence)))
		}
		// The rejecting filter index — keyed on status, since index 0 is valid.
		if r.Status == contract.StatusFiltered {
			attrs = append(attrs, slog.Int("filteredAtStep", r.FilteredAtStep))
		}
		if r.Error != "" {
			attrs = append(attrs, slog.String("error", r.Error))
		}
	}
	o.logger.LogAttrs(ctx, slog.LevelInfo, "pipeline event observed", attrs...)
	return nil
}

// statusName maps a Result's status to a stable lowercase token. A nil Result or
// an unrecognized status is "unknown".
func statusName(r *contract.Result) string {
	if r == nil {
		return "unknown"
	}
	switch r.Status {
	case contract.StatusPassed:
		return "passed"
	case contract.StatusFiltered:
		return "filtered"
	case contract.StatusErrored:
		return "errored"
	default:
		return "unknown"
	}
}

// confidenceName maps a confidence verdict to a stable lowercase token.
func confidenceName(c vc.ConfidenceState) string {
	switch c {
	case vc.ConfidenceVerified:
		return "verified"
	case vc.ConfidenceIndeterminate:
		return "indeterminate"
	case vc.ConfidenceFailed:
		return "failed"
	default:
		return "unknown"
	}
}
