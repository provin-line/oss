package decisionrecord_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/provin-line/oss/decisionrecord"
)

// stackPanicWriter panics from a function whose name the stack shows.
type stackPanicWriter struct{ value any }

func (w stackPanicWriter) Write([]byte) (int, error) { panicFromTheWriter(w.value); return 0, nil }

//go:noinline
func panicFromTheWriter(v any) { panic(v) }

// A Write that panics in the goroutine a sink writes in (a call whose
// context can end) reaches the waiting caller as a *WritePanic: the value
// the write panicked with and the writer's stack, both in its text.
func TestJSONLines_APanicInTheSinksGoroutineReachesTheCallerAsAWritePanic(t *testing.T) {
	s := decisionrecord.NewJSONLines(stackPanicWriter{value: "writer down"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, "")) })
	wp, ok := p.(*decisionrecord.WritePanic)
	if !ok {
		t.Fatalf("Record panicked with %T %.200v, want a *decisionrecord.WritePanic", p, p)
	}
	if wp.Value != "writer down" || !strings.Contains(string(wp.Stack), "panicFromTheWriter") {
		t.Errorf("WritePanic{Value: %v, Stack: %.200q}, want the writer's value and its stack", wp.Value, wp.Stack)
	}
	if text := wp.Error(); !strings.Contains(text, "writer down") || !strings.Contains(text, "panicFromTheWriter") {
		t.Errorf("WritePanic text %.300q, want the value and the stack", text)
	}
	if wp.Unwrap() != nil {
		t.Errorf("Unwrap() = %v, want nil for a value that is not an error", wp.Unwrap())
	}
}

// A WritePanic unwraps to the value the write panicked with when it is an
// error, so errors.Is and errors.As reach it.
func TestWritePanic_UnwrapsAnErrorValue(t *testing.T) {
	down := errors.New("disk gone")
	s := decisionrecord.NewJSONLines(stackPanicWriter{value: down})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, "")) })
	wp, ok := p.(*decisionrecord.WritePanic)
	if !ok || !errors.Is(wp, down) {
		t.Errorf("Record panicked with %T %.200v, want a *WritePanic that errors.Is finds %v in", p, p, down)
	}
}

// A Write that panics in the caller's own goroutine (a call whose context
// cannot end) panics in the caller as itself: its value, its stack.
func TestJSONLines_APanicInTheCallersGoroutineIsTheWritersOwn(t *testing.T) {
	s := decisionrecord.NewJSONLines(stackPanicWriter{value: "writer down"})
	if p := recovered(func() { _ = s.Record(context.Background(), rec("d1", "p", decisionrecord.Accepted, "")) }); p != "writer down" {
		t.Errorf("Record panicked with %T %v, want the writer's own value", p, p)
	}
}

// A handler that panics while a Filter's warning is written in a goroutine
// of its own reaches the waiting caller as a *WritePanic too.
func TestFilter_AWarningsPanicReachesTheCallerAsAWritePanic(t *testing.T) {
	f, err := decisionrecord.NewFilter(decisionrecord.LevelRefusals, &memSink{err: errors.New("sink down")}, slog.New(panicHandler{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = f.Record(ctx, rec("d1", "p", decisionrecord.Refused, "c")) })
	wp, ok := p.(*decisionrecord.WritePanic)
	if !ok || wp.Value != "handler down" {
		t.Fatalf("Record panicked with %T %.200v, want a *WritePanic of the handler's panic", p, p)
	}
	if text := wp.Error(); !strings.HasPrefix(text, "decisionrecord: a write panicked: handler down") {
		t.Errorf("WritePanic text %.200q, want it to say a write panicked, not a sink's", text)
	}
}

// A Summary whose Write panics in the sink's goroutine reaches the caller as
// a *WritePanic, as a Record does.
func TestJSONLines_ASummarysPanicReachesTheCallerAsAWritePanic(t *testing.T) {
	s := decisionrecord.NewJSONLines(stackPanicWriter{value: "writer down"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := recovered(func() { _ = s.Summary(ctx, goldenSummary()) })
	if wp, ok := p.(*decisionrecord.WritePanic); !ok || wp.Value != "writer down" {
		t.Errorf("Summary panicked with %T %.200v, want a *WritePanic of the writer's panic", p, p)
	}
}

// panicNilWriter panics with nil.
type panicNilWriter struct{}

func (panicNilWriter) Write([]byte) (int, error) { panic(nil) }

// A Write that panics with nil is a panic, not a written record, under
// GODEBUG panicnil=1 too, where recover returns nil for it: the waiting
// caller panics with a *WritePanic whose Value is nil.
func TestJSONLines_APanicWithNilIsAPanicUnderPanicnil(t *testing.T) {
	t.Setenv("GODEBUG", "panicnil=1")
	s := decisionrecord.NewJSONLines(panicNilWriter{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	p := recovered(func() { err = s.Record(ctx, rec("d1", "p", decisionrecord.Accepted, "")) })
	if wp, ok := p.(*decisionrecord.WritePanic); !ok || wp.Value != nil {
		t.Errorf("Record returned %v and panicked with %T %.200v, want a *WritePanic of nil", err, p, p)
	}
}
