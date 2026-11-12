package runtime

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

func testDecisionRecord() decisionrecord.Record {
	return decisionrecord.Record{
		DecisionID: "0123456789abcdef0123456789abcdef",
		Point:      "provin-agent-delivery@1",
		At:         time.Now().UTC(),
		Outcome:    decisionrecord.Refused,
		Check:      "appraisal",
	}
}

func TestNewDecisionRecording_ZeroConfigFailsClosed(t *testing.T) {
	if _, err := newDecisionRecording(DecisionRecordConfig{}, slog.Default()); err == nil {
		t.Fatal("zero DecisionRecordConfig: want an error (the zero level is refused)")
	}
}

func TestNewDecisionRecording_JSONLNeedsPath(t *testing.T) {
	_, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: "jsonl", SummaryWindow: time.Minute}, slog.Default())
	if err == nil {
		t.Fatal("jsonl without a path: want an error")
	}
}

func TestNewDecisionRecording_UnknownSink(t *testing.T) {
	_, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: "syslog", SummaryWindow: time.Minute}, slog.Default())
	if err == nil {
		t.Fatal("unknown sink: want an error")
	}
}

func TestDecisionRecording_LogSinkWritesToTheLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: "log", SummaryWindow: time.Minute}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "decision record") || !strings.Contains(buf.String(), "0123456789abcdef0123456789abcdef") {
		t.Fatalf("log output = %q", buf.String())
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionRecording_JSONLAppendsAndCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	cfg := DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: "jsonl", Path: path, SummaryWindow: time.Minute}
	for i := 0; i < 2; i++ {
		d, err := newDecisionRecording(cfg, slog.Default())
		if err != nil {
			t.Fatal(err)
		}
		if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
			t.Fatal(err)
		}
		if err := d.close(); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(b), "\n"); lines != 2 {
		t.Fatalf("lines = %d, want 2 (append-only across opens): %q", lines, b)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestDecisionRecording_NoneOpensNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelNone, Output: "jsonl", Path: path, SummaryWindow: time.Minute}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("level none created %s (err=%v)", path, err)
	}
}

func TestDecisionRecording_SummaryFlushesEachWindowAndAtShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelSummary, Output: "jsonl", Path: path, SummaryWindow: 20 * time.Millisecond}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	d.start(context.Background())
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), `"kind":"summary"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no summary written within the window: %q", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A record after the last tick is written by the flush at shutdown.
	second := testDecisionRecord()
	second.DecisionID = "ffffffffffffffffffffffffffffffff"
	second.Check = "write"
	if err := d.recorder().Record(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	d.stopAndFlush(context.Background())
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"check":"write"`) {
		t.Fatalf("the shutdown flush did not write the last window: %q", b)
	}
}

// stuckHandler holds every Handle until release is closed; started has a
// value for each Handle it holds, while it has room.
type stuckHandler struct{ release, started chan struct{} }

func (h stuckHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h stuckHandler) Handle(context.Context, slog.Record) error {
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-h.release
	return nil
}

func (h stuckHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h stuckHandler) WithGroup(string) slog.Handler      { return h }

// warnBuffer is a bytes.Buffer safe for concurrent use.
type warnBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *warnBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *warnBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newStuckRecording is a summary-level recorder whose log sink never ends a
// write, with a flush deadline of 50ms. The default logger, to which the
// runtime warns, writes to the returned buffer until t ends.
func newStuckRecording(t *testing.T, window time.Duration) (*decisionRecording, stuckHandler, *warnBuffer) {
	t.Helper()
	h := stuckHandler{release: make(chan struct{}), started: make(chan struct{}, 16)}
	t.Cleanup(func() { close(h.release) })
	warned := &warnBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(warned, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelSummary, Output: DecisionRecordOutputLog, SummaryWindow: window}, slog.New(h))
	if err != nil {
		t.Fatal(err)
	}
	d.flushTimeout = 50 * time.Millisecond
	return d, h, warned
}

// returnsWithin fails t unless call returns within bound.
func returnsWithin(t *testing.T, bound time.Duration, what string, call func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); call() }()
	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("%s did not return within %s", what, bound)
	}
}

// The last flush, behind a sink write that never ends, returns at its
// deadline and warns that the counts not written are lost.
func TestDecisionRecording_TheLastFlushReturnsByItsDeadlineBehindAStuckSink(t *testing.T) {
	d, _, warned := newStuckRecording(t, time.Hour)
	d.start(context.Background())
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	returnsWithin(t, 2*time.Second, "stopAndFlush", func() { d.stopAndFlush(context.Background()) })
	if w := warned.String(); !strings.Contains(w, "deadline") || !strings.Contains(w, "lost") {
		t.Errorf("warnings %q, want one saying the flush reached its deadline and counts were lost", w)
	}
}

// A periodic flush behind a sink write that never ends returns at its
// deadline too, so stopAndFlush, which waits for the flusher, returns.
func TestDecisionRecording_APeriodicFlushReturnsByItsDeadlineBehindAStuckSink(t *testing.T) {
	d, h, warned := newStuckRecording(t, 20*time.Millisecond)
	d.start(context.Background())
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("no periodic flush started its write")
	}
	returnsWithin(t, 2*time.Second, "stopAndFlush", func() { d.stopAndFlush(context.Background()) })
	if w := warned.String(); !strings.Contains(w, "deadline") || !strings.Contains(w, "lost") {
		t.Errorf("warnings %q, want one saying the flush reached its deadline and counts were lost", w)
	}
}

// A previous process may have died mid-line: the first new record must not be
// appended to that fragment.
func TestDecisionRecording_JSONLStartsOnANewLineAfterAnUnterminatedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(path, []byte("{\"v\":1,\"kind\":\"record\"}\n{\"v\":1,\"ki"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: DecisionRecordOutputJSONL, Path: path, SummaryWindow: time.Minute}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
		t.Fatal(err)
	}
	if err := d.close(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 3 || lines[1] != `{"v":1,"ki` || !strings.Contains(lines[2], "0123456789abcdef0123456789abcdef") || !strings.HasPrefix(lines[2], "{") {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDecisionRecording_JSONLTerminatedTailAddsNoBlankLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	if err := os.WriteFile(path, []byte("{\"v\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelAll, Output: DecisionRecordOutputJSONL, Path: path, SummaryWindow: time.Minute}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	_ = d.close()
	if b, _ := os.ReadFile(path); string(b) != "{\"v\":1}\n" {
		t.Fatalf("file = %q, want it unchanged", b)
	}
}
