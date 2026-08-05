// Package console implements sink.Writer as an NDJSON emitter — the
// observation-only reference sink. It writes one newline-delimited JSON record
// per consumed event to an io.Writer (stdout in deployment), surfacing the
// verification verdict alongside the payload. It is development and inspection
// tooling, not a production delivery target.
//
// Output is plain inspection text, not a signed artifact, so it uses the
// standard library's JSON encoder (HTML-escaping and all) — the JCS canonical
// path that signing requires does not apply here. The payload rides as embedded
// JSON (json.RawMessage), so it must be valid JSON; the PoC wire profile
// guarantees that, and a malformed payload surfaces as a write error. The sink
// runtime's binding gate guarantees a non-nil payload before Write is reached;
// when this writer is called directly (extension repos, tests) a nil payload
// renders as JSON null.
package console

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/provin-line/oss/agentaccess"
	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/vc"
)

// Writer is an NDJSON Writer over an io.Writer. Safe for concurrent use:
// each record is marshalled fully, then written under a mutex so lines never
// interleave.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Writer emitting NDJSON to w.
func New(w io.Writer) *Writer {
	return &Writer{w: w}
}

// record is the NDJSON line shape.
type record struct {
	Credential   string                      `json:"credential"`
	Confidence   string                      `json:"confidence"`
	Payload      json.RawMessage             `json:"payload"`
	EvidenceView *appraisal.View             `json:"evidenceView,omitempty"`
	Delivery     *agentaccess.DeliveryRecord `json:"delivery,omitempty"`
}

// Write emits one NDJSON record. Implements sink.Writer.
func (c *Writer) Write(ctx context.Context, rec sink.Record) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	addr := ""
	if rec.Credential != nil {
		a, err := rec.Credential.Hash()
		if err != nil {
			return fmt.Errorf("console: hash credential: %w", err)
		}
		addr = a
	}

	conf := "unknown"
	if rec.Verdict != nil {
		conf = confidenceString(rec.Verdict.Overall)
	}

	line, err := json.Marshal(record{
		Credential:   addr,
		Confidence:   conf,
		Payload:      json.RawMessage(rec.Payload),
		EvidenceView: rec.EvidenceView,
		Delivery:     rec.Delivery,
	})
	if err != nil {
		return fmt.Errorf("console: marshal record: %w", err)
	}
	line = append(line, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(line); err != nil {
		return fmt.Errorf("console: write: %w", err)
	}
	return nil
}

// confidenceString renders a verdict for human inspection. ConfidenceState has
// no String method; this is the display mapping, local to the inspection sink.
func confidenceString(c vc.ConfidenceState) string {
	switch c {
	case vc.ConfidenceVerified:
		return "verified"
	case vc.ConfidenceFailed:
		return "failed"
	case vc.ConfidenceIndeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}
