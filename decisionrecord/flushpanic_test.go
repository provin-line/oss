package decisionrecord_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

// pointSink is a memSink whose Summary panics, with "summary of <point>", for
// the points in panics, with nil for those in nils, calls runtime.Goexit for
// those in exits, and fails for those in fails.
type pointSink struct {
	memSink
	panics, nils, exits, fails map[string]bool
}

func (s *pointSink) Summary(ctx context.Context, sum decisionrecord.Summary) error {
	if s.panics[sum.Point] {
		panic("summary of " + sum.Point)
	}
	if s.nils[sum.Point] {
		panic(nil)
	}
	if s.exits[sum.Point] {
		runtime.Goexit()
	}
	if s.fails[sum.Point] {
		return errors.New("summary of " + sum.Point + " failed")
	}
	return s.memSink.Summary(ctx, sum)
}

// summaryFilter is a Filter at LevelSummary over sink, warning to warn, with
// a decision recorded at each of gate-a, gate-b and gate-c.
func summaryFilter(t *testing.T, sink decisionrecord.Sink, warn *slog.Logger) *decisionrecord.Filter {
	t.Helper()
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, warn)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{"gate-a", "gate-b", "gate-c"} {
		if err := f.Record(context.Background(), rec(string(rune('1'+i)), p, decisionrecord.Accepted, "")); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func points(sums []decisionrecord.Summary) string {
	var ps []string
	for _, s := range sums {
		ps = append(ps, s.Point)
	}
	return strings.Join(ps, " ")
}

// A Summary that panics for one point does not lose the others: Flush writes
// every other point's summary, then panics with that panic, as it was.
func TestFilter_FlushWritesTheOtherPointsPastAPanic(t *testing.T) {
	sink := &pointSink{panics: map[string]bool{"gate-a": true}}
	warn, _ := quietLog()
	f := summaryFilter(t, sink, warn)
	if p := recovered(func() { _ = f.Flush(context.Background(), t0.Add(time.Minute)) }); p != "summary of gate-a" {
		t.Errorf("Flush panicked with %v, want the summary's panic", p)
	}
	if got := points(sink.summaries); got != "gate-b gate-c" {
		t.Errorf("summaries written: %q, want gate-b gate-c", got)
	}
}

// The panics after the first are warnings, each with its value and point;
// the first reaches the caller.
func TestFilter_FlushWarnsOfTheLaterPanics(t *testing.T) {
	sink := &pointSink{panics: map[string]bool{"gate-a": true, "gate-b": true}}
	warn, out := quietLog()
	f := summaryFilter(t, sink, warn)
	if p := recovered(func() { _ = f.Flush(context.Background(), t0.Add(time.Minute)) }); p != "summary of gate-a" {
		t.Errorf("Flush panicked with %v, want the first panic", p)
	}
	if got := points(sink.summaries); got != "gate-c" {
		t.Errorf("summaries written: %q, want gate-c", got)
	}
	if w := out.String(); !strings.Contains(w, "summary not written") || !strings.Contains(w, "summary of gate-b") || !strings.Contains(w, `"point":"gate-b"`) {
		t.Errorf("warnings %q, want gate-b's summary not written, with its panic", w)
	}
	if w := out.String(); strings.Contains(w, "summary of gate-a") {
		t.Errorf("warnings %q, want none of gate-a's panic, which reaches the caller", w)
	}
}

// A panic in the warning of a later panic is dropped: the first panic still
// reaches the caller, and the points after are written.
func TestFilter_FlushDropsAPanicInALaterPanicsWarning(t *testing.T) {
	sink := &pointSink{panics: map[string]bool{"gate-a": true, "gate-b": true}}
	f := summaryFilter(t, sink, slog.New(panicHandler{}))
	if p := recovered(func() { _ = f.Flush(context.Background(), t0.Add(time.Minute)) }); p != "summary of gate-a" {
		t.Errorf("Flush panicked with %v, want the first panic", p)
	}
	if got := points(sink.summaries); got != "gate-c" {
		t.Errorf("summaries written: %q, want gate-c", got)
	}
}

// The panic reaches the caller as it was raised: its stack, seen where the
// caller recovers it, still holds the frame that raised it.
func TestFilter_FlushPanicKeepsItsStack(t *testing.T) {
	sink := &pointSink{panics: map[string]bool{"gate-a": true}}
	warn, _ := quietLog()
	f := summaryFilter(t, sink, warn)
	var stack []byte
	func() {
		defer func() {
			if recover() != nil {
				stack = debug.Stack()
			}
		}()
		_ = f.Flush(context.Background(), t0.Add(time.Minute))
	}()
	if !bytes.Contains(stack, []byte("pointSink).Summary")) {
		t.Errorf("the stack where the panic is recovered lacks the sink's frame:\n%s", stack)
	}
}

// A panic(nil) is a panic under GODEBUG panicnil=1 too: Flush writes the
// other points and does not return.
func TestFilter_FlushWritesTheOtherPointsPastAPanicWithNil(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	sink := &pointSink{nils: map[string]bool{"gate-a": true}}
	warn, _ := quietLog()
	f := summaryFilter(t, sink, warn)
	returned := false
	func() {
		defer func() { _ = recover() }()
		_ = f.Flush(context.Background(), t0.Add(time.Minute))
		returned = true
	}()
	if returned {
		t.Error("Flush returned, want the panic(nil)")
	}
	if got := points(sink.summaries); got != "gate-b gate-c" {
		t.Errorf("summaries written: %q, want gate-b gate-c", got)
	}
}

// A Summary that calls runtime.Goexit in the caller's goroutine (a context
// that cannot end) ends it, as runtime.Goexit does anywhere, once Flush has
// written the other points.
func TestFilter_FlushWritesTheOtherPointsPastAGoexit(t *testing.T) {
	sink := &pointSink{exits: map[string]bool{"gate-a": true}}
	warn, _ := quietLog()
	f := summaryFilter(t, sink, warn)
	done := make(chan bool, 1)
	go func() {
		returned := false
		defer func() { done <- returned }()
		_ = f.Flush(context.Background(), t0.Add(time.Minute))
		returned = true
	}()
	if <-done {
		t.Error("Flush returned, want its goroutine ended")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := points(sink.summaries); got != "gate-b gate-c" {
		t.Errorf("summaries written: %q, want gate-b gate-c", got)
	}
}

// A warning handler that panics as Flush warns of a summary that failed is
// that point's panic: the other points are written, and it reaches the
// caller as a Filter's warning's panic does (a *WritePanic with a context
// that can end).
func TestFilter_FlushWritesTheOtherPointsPastAWarningsPanic(t *testing.T) {
	sink := &pointSink{fails: map[string]bool{"gate-a": true}}
	f := summaryFilter(t, sink, slog.New(panicHandler{}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = f.Flush(ctx, t0.Add(time.Minute)) })
	if wp, ok := p.(*decisionrecord.WritePanic); !ok || wp.Value != "handler down" {
		t.Errorf("Flush panicked with %T %.200v, want a *WritePanic of the handler's panic", p, p)
	}
	if got := points(sink.summaries); got != "gate-b gate-c" {
		t.Errorf("summaries written: %q, want gate-b gate-c", got)
	}
}

// pointWriter panics on a line that names gate-a and writes the others.
type pointWriter struct{ b *bytes.Buffer }

func (w pointWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"gate-a"`)) {
		panic("writer down")
	}
	return w.b.Write(p)
}

// With a sink made here and a context that can end, the panic Flush sends
// on is the sink's *WritePanic, as it was, and the other points are written.
func TestJSONLines_FlushWritesTheOtherPointsPastAWritePanic(t *testing.T) {
	var b bytes.Buffer
	warn, _ := quietLog()
	f := summaryFilter(t, decisionrecord.NewJSONLines(pointWriter{&b}), warn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = f.Flush(ctx, t0.Add(time.Minute)) })
	if wp, ok := p.(*decisionrecord.WritePanic); !ok || wp.Value != "writer down" || !strings.Contains(string(wp.Stack), "pointWriter.Write") {
		t.Errorf("Flush panicked with %T %.200v, want the sink's *WritePanic, with the writer's stack", p, p)
	}
	if out := b.String(); !strings.Contains(out, `"gate-b"`) || !strings.Contains(out, `"gate-c"`) {
		t.Errorf("wrote %q, want gate-b's and gate-c's summaries", out)
	}
}
