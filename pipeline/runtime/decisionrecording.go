package runtime

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/provin-line/oss/decisionrecord"
	"github.com/provin-line/oss/pipeline/internal/pipeexcerpt"
)

// Where decision records are written. String-identical to
// network/pkg/pipelineconfig's DecisionRecordOutput* constants.
const (
	DecisionRecordOutputLog   = "log"
	DecisionRecordOutputJSONL = "jsonl"
)

// DecisionRecordConfig selects what is recorded of each purpose-first delivery
// decision and where. The zero value is refused: a level is in effect only
// when it is chosen.
type DecisionRecordConfig struct {
	Level decisionrecord.Level
	// Output is DecisionRecordOutputLog or DecisionRecordOutputJSONL. (The HOCON
	// key is provin.decision-record.sink; "sink" is the Sink Process here.)
	Output string
	// Path is the JSON-lines file; required when Output is DecisionRecordOutputJSONL.
	Path string
	// SummaryWindow is the flush interval at the summary level; positive there.
	SummaryWindow time.Duration
}

// decisionRecording is the node's delivery decision recorder: a Filter over
// the configured sink, the file the sink writes to, and the flusher the
// summary level needs.
type decisionRecording struct {
	filter *decisionrecord.Filter
	file   io.Closer
	level  decisionrecord.Level
	window time.Duration

	quit chan struct{}
	done chan struct{}
	once sync.Once
}

// newDecisionRecording builds the recorder. A JSON-lines file is opened
// append-only (O_CREATE with mode 0600, which does not change the mode of an
// existing file) and unbuffered, so a nil from Record means the line was
// handed to the OS — there is no fsync, the same posture as sink/file. If the
// file ends without a newline (a previous process died mid-line), a newline is
// written first so that fragment does not swallow the first new record. The
// file grows without bound: rotate it with copytruncate or a restart. Records
// written after a decision was accepted are best effort (see sink.Config): if
// one cannot be written, the accepted record stands, so the file may show an
// acceptance that was not delivered, never a delivery without its acceptance.
// At level none no sink is made and no file is opened.
func newDecisionRecording(cfg DecisionRecordConfig, logger *slog.Logger) (*decisionRecording, error) {
	if _, err := decisionrecord.ParseLevel(string(cfg.Level)); err != nil {
		return nil, fmt.Errorf("runtime: decision record: %w", err)
	}
	if cfg.Level == decisionrecord.LevelSummary && cfg.SummaryWindow <= 0 {
		return nil, fmt.Errorf("runtime: decision record: summary window must be positive, got %s", cfg.SummaryWindow)
	}
	d := &decisionRecording{level: cfg.Level, window: cfg.SummaryWindow}
	var sk decisionrecord.Sink
	if cfg.Level != decisionrecord.LevelNone {
		switch cfg.Output {
		case DecisionRecordOutputLog:
			sk = decisionrecord.NewLog(logger)
		case DecisionRecordOutputJSONL:
			if cfg.Path == "" {
				return nil, fmt.Errorf("runtime: decision record: output %q needs a path", cfg.Output)
			}
			f, err := openJSONLines(cfg.Path)
			if err != nil {
				return nil, fmt.Errorf("runtime: decision record: open %s: %w", cfg.Path, err)
			}
			d.file = f
			sk = decisionrecord.NewJSONLines(f)
		default:
			return nil, fmt.Errorf("runtime: decision record: unknown output %q", cfg.Output)
		}
	}
	f, err := decisionrecord.NewFilter(cfg.Level, sk, logger)
	if err != nil {
		_ = d.close()
		return nil, fmt.Errorf("runtime: decision record: %w", err)
	}
	d.filter = f
	return d, nil
}

func (d *decisionRecording) recorder() decisionrecord.Recorder { return d.filter }

// start begins flushing the summary level every window until stopAndFlush.
// Other levels have nothing to flush.
func (d *decisionRecording) start(ctx context.Context) {
	if d.level != decisionrecord.LevelSummary {
		return
	}
	d.quit = make(chan struct{})
	d.done = make(chan struct{})
	go func() {
		defer close(d.done)
		t := time.NewTicker(d.window)
		defer t.Stop()
		for {
			select {
			case <-d.quit:
				return
			case <-t.C:
				d.flush(ctx)
			}
		}
	}()
}

// stopAndFlush stops the flusher and writes the last window. Call it after
// every loop has drained, so no record follows the final flush.
func (d *decisionRecording) stopAndFlush(ctx context.Context) {
	if d.level != decisionrecord.LevelSummary || d.quit == nil {
		return
	}
	d.once.Do(func() {
		close(d.quit)
		<-d.done
		d.flush(ctx)
	})
}

func (d *decisionRecording) flush(ctx context.Context) {
	if err := d.filter.Flush(context.WithoutCancel(ctx), time.Now().UTC()); err != nil {
		slog.Warn("runtime: decision record summary not flushed", "err", pipeexcerpt.ErrorText(err))
	}
}

func (d *decisionRecording) close() error {
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}

// openJSONLines opens path for appending lines, first ending an unterminated
// last line.
func openJSONLines(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	end, err := endsMidLine(path)
	if err == nil && end {
		_, err = f.Write([]byte{'\n'})
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// endsMidLine reports whether the file is non-empty and its last byte is not '\n'.
func endsMidLine(path string) (bool, error) {
	r, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer r.Close()
	st, err := r.Stat()
	if err != nil || st.Size() == 0 {
		return false, err
	}
	var last [1]byte
	if _, err := r.ReadAt(last[:], st.Size()-1); err != nil {
		return false, err
	}
	return last[0] != '\n', nil
}
