package decisionrecord

import (
	"context"
	"errors"
	"testing"
)

// A write's result that is there when the context has ended is taken, every
// time: the wait does not choose between the two at random.
func TestAwaitResult_TakesAResultThatIsThereWhenTheContextHasEnded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("the write's error")
	for i := 0; i < 1000; i++ {
		done := make(chan writeResult, 1)
		done <- writeResult{err: want}
		r, ok := awaitResult(ctx, done)
		if !ok || r.err != want {
			t.Fatalf("try %d: awaitResult = (%v, %v), want (the write's error, true)", i, r.err, ok)
		}
	}
}

// With no result there, the wait ends at the context's end.
func TestAwaitResult_EndsAtTheContextsEndWithNoResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, ok := awaitResult(ctx, make(chan writeResult, 1)); ok {
		t.Fatalf("awaitResult = (%v, true) with no result there, want false", r.err)
	}
}
