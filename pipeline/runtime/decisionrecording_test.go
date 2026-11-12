package runtime

import (
	"bytes"
	"context"
	"log"
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

// waitForWarning fails t unless warned soon holds a warning with each of
// words: the runtime writes its warnings about a flush in a goroutine of
// their own.
func waitForWarning(t *testing.T, warned *warnBuffer, words ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		w := warned.String()
		has := true
		for _, word := range words {
			has = has && strings.Contains(w, word)
		}
		if has {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("warnings %q, want one with %q", w, words)
		}
		time.Sleep(5 * time.Millisecond)
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
	waitForWarning(t, warned, "deadline", "lost")
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
	waitForWarning(t, warned, "deadline", "lost")
}

// msgHandler holds every Handle until release is closed, after passing the
// record's message on msgs while it has room.
type msgHandler struct {
	release chan struct{}
	msgs    chan string
}

func (h msgHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h msgHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.msgs <- r.Message:
	default:
	}
	<-h.release
	return nil
}

func (h msgHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h msgHandler) WithGroup(string) slog.Handler      { return h }

// stuckDefaultLog makes a logger that never ends a write the default logger,
// and so the log package's output, until t ends or release is called. t's
// cleanup releases it first, then restores the default logger and the log
// package's output and flags, so no write held by it outlives t.
func stuckDefaultLog(t *testing.T) (h msgHandler, release func()) {
	t.Helper()
	h = msgHandler{release: make(chan struct{}), msgs: make(chan string, 64)}
	prev, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	var once sync.Once
	release = func() { once.Do(func() { close(h.release) }) }
	t.Cleanup(release)
	return h, release
}

// waitForMessage fails t unless a record whose message begins with prefix
// reaches h within 2 seconds; it passes the others by.
func waitForMessage(t *testing.T, h msgHandler, prefix string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case m := <-h.msgs:
			if strings.HasPrefix(m, prefix) {
				return
			}
		case <-deadline:
			t.Fatalf("no message beginning %q reached the log", prefix)
		}
	}
}

// With one logger that never ends a write as both the default logger and the
// decision sink's, as the node runs with slog.Default for both, shutdown
// still returns within two flush deadlines: the runtime's own warnings about
// a flush do not wait for the log either, whether the last flush or a
// periodic one met the stuck write. Each subtest waits for its warning to
// reach its own logger, which its cleanup then releases.
func TestDecisionRecording_ShutdownReturnsBehindAStuckDefaultLogger(t *testing.T) {
	for name, window := range map[string]time.Duration{"the last flush": time.Hour, "a periodic flush": 20 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			h, _ := stuckDefaultLog(t)
			d, err := newDecisionRecording(DecisionRecordConfig{Level: decisionrecord.LevelSummary, Output: DecisionRecordOutputLog, SummaryWindow: window}, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			d.flushTimeout = 50 * time.Millisecond
			d.start(context.Background())
			if err := d.recorder().Record(context.Background(), testDecisionRecord()); err != nil {
				t.Fatal(err)
			}
			returnsWithin(t, 2*time.Second, "stopAndFlush", func() { d.stopAndFlush(context.Background()) })
			waitForMessage(t, h, "runtime: decision record summary flush reached its deadline")
		})
	}
}

// The runtime's warnings about a flush are written one at a time: while one
// waits on a log that does not end a write, the next are dropped, so one of
// them at most waits on it; once it ends, the next warning is written.
func TestDecisionRecording_WarnsOneAtATime(t *testing.T) {
	h, release := stuckDefaultLog(t)
	d := &decisionRecording{warnTurn: make(chan struct{}, 1)}
	for range 3 {
		d.warnf("runtime: a warning")
	}
	waitForMessage(t, h, "runtime: a warning")
	quiet := time.After(100 * time.Millisecond)
	for waiting := true; waiting; {
		select {
		case m := <-h.msgs:
			if m == "runtime: a warning" {
				t.Fatal("a second warning reached the log while the first waited on it")
			}
		case <-quiet:
			waiting = false
		}
	}
	release()
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.warnf("runtime: a warning")
		select {
		case m := <-h.msgs:
			if m == "runtime: a warning" {
				return
			}
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("no warning reached the log after the first ended")
		}
	}
}

// panickingHandler panics in every Handle, after a value on handled.
type panickingHandler struct{ handled chan struct{} }

func (h panickingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h panickingHandler) Handle(context.Context, slog.Record) error {
	h.handled <- struct{}{}
	panic("handler down")
}
func (h panickingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h panickingHandler) WithGroup(string) slog.Handler      { return h }

// A log handler that panics as one of the runtime's warnings is written does
// not end the process: the panic is dropped, and the next warning can be
// written.
func TestDecisionRecording_AWarningsPanicIsDropped(t *testing.T) {
	h := panickingHandler{handled: make(chan struct{}, 4)}
	prev, prevOut, prevFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	d := &decisionRecording{warnTurn: make(chan struct{}, 1)}
	d.warnf("runtime: a warning")
	<-h.handled
	deadline := time.Now().Add(2 * time.Second)
	for len(d.warnTurn) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the turn did not come back after the handler panicked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	d.warnf("runtime: a warning")
	select {
	case <-h.handled:
	case <-time.After(2 * time.Second):
		t.Fatal("no warning reached the log after the panic")
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
