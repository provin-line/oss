// Package file implements sink.Writer as a durable NDJSON append stream — the
// second reference sink surface. It exists so a consumer (operator tooling,
// e2e assertions, a tailer) can read delivered events from a file instead of
// scraping process stdout; the line shape is the console writer's, by
// construction (this IS a console writer over an append-mode file handle), so
// the two surfaces can never drift.
//
// Durability posture: the file is a delivery stream, not an evidence store —
// evidence lives in the VC/verdict stores (fsync'd, content-addressed). Lines
// are appended without a per-line fsync, matching the console writer's stance.
// sink.Writer has no lifecycle hook, so the handle lives for the process
// lifetime; O_APPEND means a restart resumes after the last complete line.
package file

import (
	"fmt"
	"os"

	"github.com/provin-line/oss/pipeline/sink/console"
)

// Writer appends NDJSON records to a file. Concurrent Writes never interleave
// (each line is written whole under the embedded writer's mutex). Two loops
// delivering to the same path must SHARE one Writer — construct once per
// cleaned path (cmd/standalone does this) so cross-loop lines cannot
// interleave either.
type Writer struct {
	*console.Writer
}

// New opens (creating if absent, 0600) path for append and returns the Writer.
// An unopenable path is a construction error: a sink that cannot deliver must
// not boot (fail-closed).
func New(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sink/file: open %s: %w", path, err)
	}
	return &Writer{Writer: console.New(f)}, nil
}
