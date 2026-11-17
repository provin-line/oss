package decisionrecord_test

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/decisionrecord"
)

// traceSink is a memSink whose Summary first keeps, for each call, its
// point, the depth of the stack it is called on and how many goroutines are
// alive, and how many calls are under way at most at once; then runs act
// with the point, which may panic or call runtime.Goexit.
type traceSink struct {
	memSink
	act func(point string)

	traceMu     sync.Mutex
	calls       []traceCall
	inFlight    int
	maxInFlight int
}

type traceCall struct {
	point      string
	depth      int
	goroutines int
}

func (s *traceSink) Summary(ctx context.Context, sum decisionrecord.Summary) error {
	c := traceCall{point: sum.Point, depth: runtime.Callers(0, make([]uintptr, 1<<12)), goroutines: runtime.NumGoroutine()}
	s.traceMu.Lock()
	s.calls = append(s.calls, c)
	s.inFlight++
	s.maxInFlight = max(s.maxInFlight, s.inFlight)
	s.traceMu.Unlock()
	defer func() {
		s.traceMu.Lock()
		s.inFlight--
		s.traceMu.Unlock()
	}()
	s.act(sum.Point)
	return s.memSink.Summary(ctx, sum)
}

func (s *traceSink) trace() ([]traceCall, int) {
	s.traceMu.Lock()
	defer s.traceMu.Unlock()
	return append([]traceCall(nil), s.calls...), s.maxInFlight
}

// manyPoints is a Filter at LevelSummary over sink with a decision recorded
// at each of n points, p000000 to p(n-1), which Flush writes in that order.
func manyPoints(t *testing.T, sink decisionrecord.Sink, n int) *decisionrecord.Filter {
	t.Helper()
	warn, _ := quietLog()
	f, err := decisionrecord.NewFilter(decisionrecord.LevelSummary, sink, warn)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := f.Record(context.Background(), rec(fmt.Sprint(i), fmt.Sprintf("p%06d", i), decisionrecord.Accepted, "")); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// After a panic, every later point that calls runtime.Goexit is written on a
// stack of the same depth, so the stack does not grow with them, and the
// goroutines alive as they are written do not grow with them either: one
// writes at a time, beside those that have ended and that the runtime still
// counts. Once Flush is over, none of them is left. The panic reaches the
// caller.
func TestFilter_FlushGoexitsAfterAPanicDoNotGrowTheStack(t *testing.T) {
	const n = 200
	sink := &traceSink{act: func(p string) {
		if p == "p000000" {
			panic("summary of " + p)
		}
		runtime.Goexit()
	}}
	f := manyPoints(t, sink, n)
	before := runtime.NumGoroutine()
	if returned, p := flushExits(f); returned || p != "summary of p000000" {
		t.Errorf("Flush returned %v and panicked with %v, want the first point's panic", returned, p)
	}
	calls, _ := sink.trace()
	if len(calls) != n {
		t.Fatalf("%d calls to Summary, want %d", len(calls), n)
	}
	for _, c := range calls[2:] {
		if c.depth != calls[1].depth {
			t.Errorf("%s written on a stack %d deep, %s on one %d deep: want the same depth for every point after the first", c.point, c.depth, calls[1].point, calls[1].depth)
			break
		}
	}
	// The caller's and the one writing, with room for writers that have ended
	// and are still counted under load; one goroutine per point written so
	// far would pass it by the eleventh point.
	bound := before + 10
	for _, c := range calls[1:] {
		if c.goroutines > bound {
			t.Errorf("%d goroutines alive as %s is written, want at most %d", c.goroutines, c.point, bound)
			break
		}
	}
	eventually(t, "the goroutines Flush started end", func() bool { return runtime.NumGoroutine() <= before })
}

// actSink is a memSink whose Summary runs act with the point first, which
// may panic or call runtime.Goexit.
type actSink struct {
	memSink
	act func(point string)
}

func (s *actSink) Summary(ctx context.Context, sum decisionrecord.Summary) error {
	s.act(sum.Point)
	return s.memSink.Summary(ctx, sum)
}

// Writing the points after a panic takes a stack that does not grow with
// the runtime.Goexit calls among them: 20,000 points that call it after the
// first, which panics, are written within a stack of 4 MiB.
func TestFilter_FlushWritesManyGoexitsPastAPanicWithinAFixedStack(t *testing.T) {
	prev := debug.SetMaxStack(4 << 20)
	t.Cleanup(func() { debug.SetMaxStack(prev) })
	const n = 20000
	var called atomic.Int64
	sink := &actSink{act: func(p string) {
		called.Add(1)
		if p == "p000000" {
			panic("summary of " + p)
		}
		runtime.Goexit()
	}}
	f := manyPoints(t, sink, n)
	if returned, p := flushExits(f); returned || p != "summary of p000000" {
		t.Errorf("Flush returned %v and panicked with %v, want the first point's panic", returned, p)
	}
	if got := called.Load(); got != n {
		t.Errorf("%d calls to Summary, want %d", got, n)
	}
}

// Flush calls the sink for every point in the order of the points, one call
// at a time, and returns, or goes on with the first panic, only once every
// call has: panics and runtime.Goexit among them change neither.
func TestFilter_FlushWritesTheRestInOrderOneAtATime(t *testing.T) {
	act := map[string]string{
		"p000000": "panic", "p000001": "goexit", "p000003": "panic",
		"p000004": "goexit", "p000006": "goexit",
	}
	sink := &traceSink{act: func(p string) {
		time.Sleep(2 * time.Millisecond)
		switch act[p] {
		case "panic":
			panic("summary of " + p)
		case "goexit":
			runtime.Goexit()
		}
	}}
	const n = 8
	f := manyPoints(t, sink, n)
	if returned, p := flushExits(f); returned || p != "summary of p000000" {
		t.Errorf("Flush returned %v and panicked with %v, want the first point's panic", returned, p)
	}
	calls, most := sink.trace()
	var order []string
	for _, c := range calls {
		order = append(order, c.point)
	}
	if got, want := strings.Join(order, " "), "p000000 p000001 p000002 p000003 p000004 p000005 p000006 p000007"; got != want {
		t.Errorf("Summary called for %q, want %q", got, want)
	}
	if most != 1 {
		t.Errorf("%d calls to Summary under way at once, want 1", most)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := points(sink.summaries); got != "p000002 p000005 p000007" {
		t.Errorf("summaries written: %q, want p000002 p000005 p000007", got)
	}
}

// A runtime.Goexit as the first point is written ends the caller's
// goroutine, once the rest are written; a panic as a later point is written
// is a warning, and does not reach the caller.
func TestFilter_FlushAFirstGoexitReachesTheCallerPastALaterPanic(t *testing.T) {
	sink := &pointSink{exits: map[string]bool{"gate-a": true}, panics: map[string]bool{"gate-b": true}}
	warn, out := quietLog()
	f := summaryFilter(t, sink, warn)
	if returned, p := flushExits(f); returned || p != nil {
		t.Errorf("Flush returned %v, its goroutine recovered %v; want its goroutine ended", returned, p)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := points(sink.summaries); got != "gate-c" {
		t.Errorf("summaries written: %q, want gate-c", got)
	}
	if w := out.String(); !strings.Contains(w, "summary of gate-b") {
		t.Errorf("warnings %q, want gate-b's panic", w)
	}
}

// A panic(nil) as a later point is written, under GODEBUG panicnil=1, is a
// warning like any later panic: the points after it are written, and the
// first panic reaches the caller.
func TestFilter_FlushWarnsOfALaterPanicWithNil(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	sink := &pointSink{panics: map[string]bool{"gate-a": true}, nils: map[string]bool{"gate-b": true}}
	warn, out := quietLog()
	f := summaryFilter(t, sink, warn)
	if returned, p := flushExits(f); returned || p != "summary of gate-a" {
		t.Errorf("Flush returned %v and panicked with %v, want the first panic", returned, p)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := points(sink.summaries); got != "gate-c" {
		t.Errorf("summaries written: %q, want gate-c", got)
	}
	if w := out.String(); !strings.Contains(w, `"point":"gate-b"`) {
		t.Errorf("warnings %q, want gate-b's summary not written", w)
	}
}

// With a context that can end, a sink not made here that calls
// runtime.Goexit as a later point is written ends only the goroutine Flush
// writes it from: the points after it are written, and the first panic
// reaches the caller as it was raised.
func TestFilter_FlushWritesThePointsPastALaterGoexitWithAContextThatCanEnd(t *testing.T) {
	sink := &pointSink{panics: map[string]bool{"gate-a": true}, exits: map[string]bool{"gate-b": true}}
	warn, _ := quietLog()
	f := summaryFilter(t, sink, warn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		_ = f.Flush(ctx, t0.Add(time.Minute))
	}()
	if p := <-done; p != "summary of gate-a" {
		t.Errorf("Flush panicked with %v, want the first panic", p)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if got := points(sink.summaries); got != "gate-c" {
		t.Errorf("summaries written: %q, want gate-c", got)
	}
}
