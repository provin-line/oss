package decisionrecord_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

// blockingWriter holds every Write until release is closed. The first Write
// after release fails with failFirst, if set.
type blockingWriter struct {
	release   chan struct{}
	started   chan struct{} // a value for each Write that starts
	mu        sync.Mutex
	buf       bytes.Buffer
	writes    int
	failFirst error
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{release: make(chan struct{}), started: make(chan struct{}, 16)}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	w.mu.Unlock()
	w.started <- struct{}{}
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.failFirst; err != nil {
		w.failFirst = nil
		return 0, err
	}
	return w.buf.Write(p)
}

func (w *blockingWriter) written() (string, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String(), w.writes
}

// blockingHandler holds Handle, and Enabled too if enabledBlocks, until
// release is closed; started has a value for each call it holds.
type blockingHandler struct {
	release       chan struct{}
	started       chan struct{}
	enabledBlocks bool
	mu            *sync.Mutex
	handled       *int
}

func newBlockingHandler(enabledBlocks bool) blockingHandler {
	return blockingHandler{release: make(chan struct{}), started: make(chan struct{}, 16), enabledBlocks: enabledBlocks, mu: &sync.Mutex{}, handled: new(int)}
}

func (h blockingHandler) Enabled(context.Context, slog.Level) bool {
	if h.enabledBlocks {
		h.started <- struct{}{}
		<-h.release
	}
	return true
}

func (h blockingHandler) Handle(context.Context, slog.Record) error {
	if !h.enabledBlocks {
		h.started <- struct{}{}
	}
	<-h.release
	h.mu.Lock()
	*h.handled++
	h.mu.Unlock()
	return nil
}

func (h blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h blockingHandler) WithGroup(string) slog.Handler      { return h }

func (h blockingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return *h.handled
}

// lockedBuffer is a bytes.Buffer safe for concurrent use.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// returnsBy runs call with a context that ends after a short while, and
// fails t unless call returns within a bound well past that end. It returns
// call's error.
func returnsBy(t *testing.T, call func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- call(ctx) }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("did not return when its context ended")
		return nil
	}
}

// stuckCall runs call with a context it ends once started has a value, that
// is once the write under call has begun and is held, and fails t unless
// call returns within a bound after that. It returns call's error.
func stuckCall(t *testing.T, started <-chan struct{}, call func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- call(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the write did not start")
	}
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("did not return when its context ended")
		return nil
	}
}

// eventually waits until cond holds, or fails t.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("%s: not within 2s", what)
}

// releaseOnCleanup closes release when t ends, if it is still open.
func releaseOnCleanup(t *testing.T, release chan struct{}) {
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
}

// A JSON lines sink returns when the context ends, without waiting for a
// Write that does not end, saying the write goes on; a call after it returns
// at its own context's end, saying its write did not start, and is never
// written; once the Write ends, the sink writes again.
func TestJSONLines_ReturnsWhenTheContextEnds(t *testing.T) {
	w := newBlockingWriter()
	releaseOnCleanup(t, w.release)
	s := decisionrecord.NewJSONLines(w)
	err := stuckCall(t, w.started, func(ctx context.Context) error {
		return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
	})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "JSON lines") || !strings.Contains(err.Error(), "may still be kept") {
		t.Errorf("Record on a stuck writer: %v, want the context's end, naming the JSON lines sink and a write that goes on", err)
	}
	err = returnsBy(t, func(ctx context.Context) error { return s.Record(ctx, rec("d2", "p", decisionrecord.Accepted, "")) })
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "before the write started") {
		t.Errorf("Record behind a stuck write: %v, want the context's end, before the write started", err)
	}
	if err := returnsBy(t, func(ctx context.Context) error { return s.Summary(ctx, goldenSummary()) }); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Summary behind a stuck write: %v, want the context's end", err)
	}
	close(w.release)
	if err := s.Record(context.Background(), rec("d3", "p", decisionrecord.Accepted, "")); err != nil {
		t.Fatalf("Record after the Write ended: %v", err)
	}
	out, writes := w.written()
	if writes != 2 || !strings.Contains(out, `"d1"`) || strings.Contains(out, `"d2"`) || !strings.Contains(out, `"d3"`) || strings.Contains(out, "summary") {
		t.Errorf("%d writes of %q, want d1 and d3 only", writes, out)
	}
}

// A record whose context ended before the call is not written: the record
// after it, which the sink writes once any write before it has ended, is the
// only line. The sink may take its turn before it sees the context ended, so
// this is tried many times.
func TestJSONLines_WritesNothingForAnEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 64; i++ {
		var b bytes.Buffer
		s := decisionrecord.NewJSONLines(&b)
		if err := s.Record(ctx, rec("d-ended", "p", decisionrecord.Accepted, "")); !errors.Is(err, context.Canceled) {
			t.Fatalf("try %d: Record with an ended context: %v, want context.Canceled", i, err)
		}
		if err := s.Record(context.Background(), rec("d-after", "p", decisionrecord.Accepted, "")); err != nil {
			t.Fatal(err)
		}
		if out := b.String(); strings.Contains(out, "d-ended") || strings.Count(out, "\n") != 1 {
			t.Fatalf("try %d: wrote %q, want only the record after", i, out)
		}
	}
}

// A nil context is context.Background().
func TestJSONLines_NilContext(t *testing.T) {
	var b bytes.Buffer
	//lint:ignore SA1012 a nil context is what this tests
	if err := decisionrecord.NewJSONLines(&b).Record(nil, rec("d", "p", decisionrecord.Accepted, "")); err != nil || b.Len() == 0 { //nolint:staticcheck
		t.Errorf("Record with a nil context: %v, wrote %q", err, b.String())
	}
}

// What a JSON lines sink writes is what the caller gave it: changing the
// record's slices and maps after the call returned changes nothing.
func TestJSONLines_WritesWhatTheCallerGave(t *testing.T) {
	w := newBlockingWriter()
	releaseOnCleanup(t, w.release)
	s := decisionrecord.NewJSONLines(w)
	r := rec("d", "p", decisionrecord.Refused, "c")
	r.Actors = []string{"actor-1"}
	r.Attributes = map[string]string{"k": "value-1"}
	if err := stuckCall(t, w.started, func(ctx context.Context) error { return s.Record(ctx, r) }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Record on a stuck writer: %v", err)
	}
	r.Actors[0], r.Attributes["k"] = "changed", "changed"
	close(w.release)
	eventually(t, "the Write ends", func() bool { out, _ := w.written(); return out != "" })
	if out, _ := w.written(); !strings.Contains(out, "actor-1") || !strings.Contains(out, "value-1") || strings.Contains(out, "changed") {
		t.Errorf("wrote %q, want the record as given", out)
	}
}

// A Write that fails after its call returned leaves the sink as any failed
// Write does: the next line starts on a line of its own.
func TestJSONLines_RecoversFromALateFailure(t *testing.T) {
	w := newBlockingWriter()
	releaseOnCleanup(t, w.release)
	w.failFirst = errors.New("disk full")
	s := decisionrecord.NewJSONLines(w)
	if err := stuckCall(t, w.started, func(ctx context.Context) error {
		return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Record on a stuck writer: %v", err)
	}
	close(w.release)
	if err := s.Record(context.Background(), rec("d2", "p", decisionrecord.Accepted, "")); err != nil {
		t.Fatalf("Record after the failed Write: %v", err)
	}
	if out, _ := w.written(); !strings.HasPrefix(out, "\n{") || !strings.Contains(out, `"d2"`) {
		t.Errorf("wrote %q, want d2's line on a line of its own", out)
	}
}

// A log sink returns when the context ends, whether its handler's Handle or
// its Enabled does not end, and names the log sink; a call behind it returns
// at its own context's end and is never handled. An entry whose context ended
// while Enabled was held is not handed to Handle.
func TestLog_ReturnsWhenTheContextEnds(t *testing.T) {
	for _, c := range []struct {
		enabledBlocks bool
		handled       int // when the last record is handled: the stuck one (if it reached Handle) and the last
	}{{false, 2}, {true, 1}} {
		h := newBlockingHandler(c.enabledBlocks)
		releaseOnCleanup(t, h.release)
		s := decisionrecord.NewLog(slog.New(h))
		err := stuckCall(t, h.started, func(ctx context.Context) error { return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, "")) })
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "log sink") {
			t.Errorf("Enabled blocks %v: %v, want the context's end, naming the log sink", c.enabledBlocks, err)
		}
		if err := returnsBy(t, func(ctx context.Context) error { return s.Record(ctx, rec("d2", "p", decisionrecord.Accepted, "")) }); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Enabled blocks %v, behind the stuck one: %v, want the context's end", c.enabledBlocks, err)
		}
		close(h.release)
		if err := s.Record(context.Background(), rec("d3", "p", decisionrecord.Accepted, "")); err != nil {
			t.Errorf("Enabled blocks %v: Record after the handler ended: %v", c.enabledBlocks, err)
		}
		if got := h.count(); got != c.handled {
			t.Errorf("Enabled blocks %v: %d entries handled, want %d", c.enabledBlocks, got, c.handled)
		}
	}
}

// Below LevelAll, a sink that fails because the context ended is warned
// about all the same, after the call returned.
func TestFilter_WarnsLateOfASinkThatMissedTheContext(t *testing.T) {
	h := newBlockingHandler(false)
	releaseOnCleanup(t, h.release)
	var warnings lockedBuffer
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, decisionrecord.NewLog(slog.New(h)), slog.New(slog.NewJSONHandler(&warnings, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := returnsBy(t, func(ctx context.Context) error { return f.Record(ctx, rec("d", "p", decisionrecord.Refused, "c")) }); err != nil {
		t.Fatalf("Record: %v, want nil (a sink's failure is a warning)", err)
	}
	eventually(t, "the warning is written", func() bool { return strings.Contains(warnings.String(), "decision record: not written") })
}

// Below LevelAll, a Filter warns that a sink failed; when the warning's
// logger is stuck, Record and Flush still return when the context ends, and
// so does a call behind the stuck warning.
func TestFilter_WarningsDoNotWaitPastTheContext(t *testing.T) {
	for _, level := range []decisionrecord.Level{decisionrecord.LevelRefusals, decisionrecord.LevelSummary} {
		h := newBlockingHandler(false)
		releaseOnCleanup(t, h.release)
		f, err := decisionrecord.NewFilter(level, &memSink{err: errors.New("sink down")}, slog.New(h))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := returnsBy(t, func(ctx context.Context) error { return f.Record(ctx, rec("d", "p", decisionrecord.Refused, "c")) }); err != nil {
				t.Errorf("%s, Record %d: %v, want nil", level, i, err)
			}
			if err := returnsBy(t, func(ctx context.Context) error { return f.Flush(ctx, t0.Add(time.Duration(i+1)*time.Minute)) }); err != nil {
				t.Errorf("%s, Flush %d: %v, want nil", level, i, err)
			}
		}
	}
}

// panicWriter panics in Write, after release is closed if it is set.
type panicWriter struct {
	release chan struct{}
	started chan struct{}
}

func (w panicWriter) Write([]byte) (int, error) {
	if w.release != nil {
		w.started <- struct{}{}
		<-w.release
	}
	panic("writer down")
}

// recovered runs call and returns what it panicked with, or nil.
func recovered(call func()) (p any) {
	defer func() { p = recover() }()
	call()
	return nil
}

// A Write that panics while its caller waits panics in the caller, with a
// context that cannot end as with one that can; the sink writes again after
// it, the next line on a line of its own.
func TestJSONLines_APanicReachesAWaitingCaller(t *testing.T) {
	cancellable, cancel := context.WithCancel(context.Background())
	defer cancel()
	for name, ctx := range map[string]context.Context{"Background": context.Background(), "cancellable": cancellable} {
		var b lockedBuffer
		w := &switchWriter{to: panicWriter{}}
		s := decisionrecord.NewJSONLines(w)
		if p := recovered(func() { _ = s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, "")) }); p != "writer down" {
			t.Errorf("%s: Record panicked with %v, want the writer's panic", name, p)
		}
		w.set(&b)
		if err := s.Record(ctx, rec("d2", "p", decisionrecord.Accepted, "")); err != nil {
			t.Fatalf("%s: Record after the panic: %v", name, err)
		}
		if out := b.String(); !strings.HasPrefix(out, "\n{") {
			t.Errorf("%s: wrote %q, want the line on a line of its own", name, out)
		}
	}
}

// A Write that panics after its caller returned is a failed write: the
// process goes on, and the next line starts on a line of its own.
func TestJSONLines_APanicAfterTheCallerReturnedIsAFailedWrite(t *testing.T) {
	pw := panicWriter{release: make(chan struct{}), started: make(chan struct{}, 1)}
	releaseOnCleanup(t, pw.release)
	w := &switchWriter{to: pw}
	s := decisionrecord.NewJSONLines(w)
	if err := stuckCall(t, pw.started, func(ctx context.Context) error {
		return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Record on a stuck writer: %v", err)
	}
	var b lockedBuffer
	w.set(&b)
	close(pw.release)
	if err := s.Record(context.Background(), rec("d2", "p", decisionrecord.Accepted, "")); err != nil {
		t.Fatalf("Record after the late panic: %v", err)
	}
	if out := b.String(); !strings.HasPrefix(out, "\n{") {
		t.Errorf("wrote %q, want the line on a line of its own", out)
	}
}

// switchWriter writes to one writer, then, once set, to another.
type switchWriter struct {
	mu sync.Mutex
	to interface{ Write([]byte) (int, error) }
}

func (w *switchWriter) set(to interface{ Write([]byte) (int, error) }) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.to = to
}

func (w *switchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	to := w.to
	w.mu.Unlock()
	return to.Write(p)
}

// panicHandler panics in Handle.
type panicHandler struct{}

func (panicHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (panicHandler) Handle(context.Context, slog.Record) error { panic("handler down") }
func (h panicHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h panicHandler) WithGroup(string) slog.Handler           { return h }

// A handler that panics while its caller waits panics in the caller; the log
// sink handles again after it.
func TestLog_APanicReachesAWaitingCaller(t *testing.T) {
	cancellable, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := decisionrecord.NewLog(slog.New(panicHandler{}))
	for name, ctx := range map[string]context.Context{"Background": context.Background(), "cancellable": cancellable} {
		for i := 0; i < 2; i++ {
			if p := recovered(func() { _ = s.Record(ctx, rec("d", "p", decisionrecord.Accepted, "")) }); p != "handler down" {
				t.Errorf("%s, call %d: Record panicked with %v, want the handler's panic", name, i, p)
			}
		}
	}
}

// Flush with a context that has ended returns its error and keeps the
// window: the next Flush writes its counts.
func TestFilter_FlushWithAnEndedContextKeepsTheWindow(t *testing.T) {
	sink := &memSink{}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Record(context.Background(), rec("d", "p", decisionrecord.Refused, "c")); err != nil {
		t.Fatal(err)
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.Flush(ended, t0.Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Errorf("Flush with an ended context: %v, want context.Canceled", err)
	}
	if err := f.Flush(context.Background(), t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sink.summaries) != 1 || len(sink.summaries[0].Counts) != 1 || sink.summaries[0].Counts[0].N != 1 || !sink.summaries[0].Until.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("summaries %v, want one of the kept window, its refusal counted", sink.summaries)
	}
}
