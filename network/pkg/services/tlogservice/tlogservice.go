// Package tlogservice is the read service behind dplaax.tlog.v1.TlogService:
// a registry of the node's per-loop emission logs (keyed by log id = the
// producing loop's output subject), serving signed checkpoints and record
// ranges for transport-loss reconciliation. It owns the domain logic
// (registry lookup, range bounds); the logs are the tlog implementations
// and the handler is pure proto↔domain conversion.
package tlogservice

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/tlog"
)

// Sentinel errors the handler maps to Connect codes (errors.Is, never
// string matching).
var (
	// ErrNotFound is a log id no producing loop on this node owns.
	ErrNotFound = errors.New("tlogservice: no emission log with that id")
	// ErrInvalidArgument is a malformed range parameter.
	ErrInvalidArgument = errors.New("tlogservice: invalid argument")
)

// Service serves the node's emission logs.
type Service struct {
	logs map[string]tlog.Log
}

// New returns a Service over the node's log registry (log id → log). The
// map is captured as-is; the node builds it once at boot.
func New(logs map[string]tlog.Log) *Service {
	return &Service{logs: logs}
}

// Checkpoint returns the signed head commitment of the log with id logID,
// or a wrapped ErrNotFound. A log that cannot sign (armed without a
// checkpoint signer) surfaces its own error — a node misconfiguration, not
// absence.
func (s *Service) Checkpoint(ctx context.Context, logID string) (*tlog.Checkpoint, error) {
	l, ok := s.logs[logID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
	}
	cp, err := l.Checkpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlogservice: checkpoint %q: %w", logID, err)
	}
	// The signed Origin and the registry key must agree — a mismatch is a
	// node misconfiguration (a log armed with the wrong LogID) and serving
	// it would publish a checkpoint whose signed identity contradicts the
	// id it was requested under. Fail closed.
	if cp.Origin != logID {
		return nil, fmt.Errorf("tlogservice: checkpoint %q: signed origin %q does not match the registry key", logID, cp.Origin)
	}
	return cp, nil
}

// Records returns the records [start, start+count) of the log with id
// logID, index-ascending. A start at or past the current size is an empty
// slice (a caught-up reader is a normal state, not an error); a range that
// extends past the end returns what exists.
func (s *Service) Records(ctx context.Context, logID string, start uint64, count int) ([]*tlog.Record, error) {
	if count <= 0 {
		return nil, fmt.Errorf("%w: count %d is not positive", ErrInvalidArgument, count)
	}
	l, ok := s.logs[logID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, logID)
	}
	size, err := l.Size(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlogservice: size %q: %w", logID, err)
	}
	var out []*tlog.Record
	for i := start; i < size && len(out) < count; i++ {
		rec, err := l.Get(ctx, i)
		if err != nil {
			return nil, fmt.Errorf("tlogservice: record %q[%d]: %w", logID, i, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
