package decisionrecord_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

// goexitWriter calls runtime.Goexit in its first Write and writes to b in
// every later one.
type goexitWriter struct {
	mu    sync.Mutex
	calls int
	b     lockedBuffer
}

func (w *goexitWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.calls++
	first := w.calls == 1
	w.mu.Unlock()
	if first {
		runtime.Goexit()
	}
	return w.b.Write(p)
}

// within runs call and fails t unless it returns within bound.
func within[T any](t *testing.T, bound time.Duration, what string, call func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- call() }()
	select {
	case v := <-done:
		return v
	case <-time.After(bound):
		t.Fatalf("%s did not return within %s", what, bound)
		var zero T
		return zero
	}
}

// A Write that calls runtime.Goexit, in the goroutine a sink writes in, is a
// failed write: the waiting caller gets an error at once rather than at its
// context's end, and the sink writes again after it, with a context that can
// end and with one that cannot.
func TestJSONLines_AWriteThatCallsGoexitIsAFailedWrite(t *testing.T) {
	w := &goexitWriter{}
	s := decisionrecord.NewJSONLines(w)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := within(t, 2*time.Second, "Record whose Write calls Goexit", func() error {
		return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
	})
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Goexit") {
		t.Errorf("Record whose Write calls Goexit: %v, want an error naming Goexit", err)
	}
	if err := within(t, 2*time.Second, "Record after it, with a context that cannot end", func() error {
		return s.Record(context.Background(), rec("d2", "p", decisionrecord.Accepted, ""))
	}); err != nil {
		t.Errorf("Record after the Goexit: %v", err)
	}
	if err := within(t, 2*time.Second, "Record after it, with a context that can end", func() error {
		return s.Record(ctx, rec("d3", "p", decisionrecord.Accepted, ""))
	}); err != nil {
		t.Errorf("Record after the Goexit: %v", err)
	}
	if out := w.b.String(); !strings.Contains(out, `"d2"`) || !strings.Contains(out, `"d3"`) {
		t.Errorf("wrote %q, want d2 and d3", out)
	}
}

// Under GODEBUG panicnil=1, where recover returns nil during runtime.Goexit
// as for panic(nil), a Write that calls runtime.Goexit is still a failed
// write, not a panic.
func TestJSONLines_AWriteThatCallsGoexitIsAFailedWriteUnderPanicnil(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	s := decisionrecord.NewJSONLines(&goexitWriter{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	p := recovered(func() {
		err = within(t, 2*time.Second, "Record whose Write calls Goexit", func() error {
			return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
		})
	})
	if p != nil || err == nil || !strings.Contains(err.Error(), "Goexit") {
		t.Errorf("Record whose Write calls Goexit: %v, panic %v, want an error naming Goexit", err, p)
	}
}

// A Write that calls runtime.Goexit in the caller's own goroutine (a call
// whose context cannot end) ends that goroutine, as runtime.Goexit does
// anywhere: the call does not return. The sink gives its turn back and
// writes again after it.
func TestJSONLines_AWriteThatCallsGoexitInTheCallersGoroutineEndsIt(t *testing.T) {
	w := &goexitWriter{}
	s := decisionrecord.NewJSONLines(w)
	returned := make(chan bool, 1)
	go func() {
		ended := false
		defer func() { returned <- ended }()
		_ = s.Record(context.Background(), rec("d1", "p", decisionrecord.Accepted, ""))
		ended = true
	}()
	select {
	case r := <-returned:
		if r {
			t.Error("Record whose Write calls Goexit returned, want its goroutine ended")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the goroutine of a Record whose Write calls Goexit did not end within 2s")
	}
	if err := within(t, 2*time.Second, "Record after it", func() error {
		return s.Record(context.Background(), rec("d2", "p", decisionrecord.Accepted, ""))
	}); err != nil {
		t.Errorf("Record after the Goexit: %v", err)
	}
	if out := w.b.String(); !strings.Contains(out, `"d2"`) {
		t.Errorf("wrote %q, want d2", out)
	}
}

// goexitHandler calls runtime.Goexit in its first Handle and writes every
// later record's message to b.
type goexitHandler struct {
	mu    *sync.Mutex
	calls *int
	b     *lockedBuffer
}

func (goexitHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h goexitHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	*h.calls++
	first := *h.calls == 1
	h.mu.Unlock()
	if first {
		runtime.Goexit()
	}
	_, err := h.b.Write([]byte(r.Message + "\n"))
	return err
}
func (h goexitHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h goexitHandler) WithGroup(string) slog.Handler      { return h }

// A Filter's warning whose handler calls runtime.Goexit is lost, and the
// Filter warns again after it: the warning's turn comes back.
func TestFilter_AWarningThatCallsGoexitGivesTheTurnBack(t *testing.T) {
	var warnings lockedBuffer
	h := goexitHandler{mu: &sync.Mutex{}, calls: new(int), b: &warnings}
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, &memSink{err: errors.New("sink down")}, slog.New(h))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 2; i++ {
		if err := within(t, 2*time.Second, fmt.Sprintf("Record %d", i), func() error {
			return f.Record(ctx, rec(fmt.Sprintf("d%d", i), "p", decisionrecord.Refused, "c"))
		}); err != nil {
			t.Fatalf("Record %d: %v, want nil (a sink's failure is a warning)", i, err)
		}
	}
	eventually(t, "the second warning is written", func() bool { return strings.Contains(warnings.String(), "decision record: not written") })
}

// A handler that calls runtime.Goexit, in the goroutine the log sink writes
// in, is a failed write, and the log sink writes again after it.
func TestLog_AHandlerThatCallsGoexitIsAFailedWrite(t *testing.T) {
	var out lockedBuffer
	s := decisionrecord.NewLog(slog.New(goexitHandler{mu: &sync.Mutex{}, calls: new(int), b: &out}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := within(t, 2*time.Second, "Record whose handler calls Goexit", func() error {
		return s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, ""))
	})
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "Goexit") {
		t.Errorf("Record whose handler calls Goexit: %v, want an error naming Goexit", err)
	}
	if err := within(t, 2*time.Second, "Record after it", func() error {
		return s.Record(ctx, rec("d2", "p", decisionrecord.Accepted, ""))
	}); err != nil {
		t.Errorf("Record after the Goexit: %v", err)
	}
	if out.String() == "" {
		t.Error("the log sink wrote nothing after the Goexit")
	}
}
