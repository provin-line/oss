package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
)

// fakeRetryClock is a fully deterministic wireBackoff test double: Sleep
// advances a virtual clock by exactly the duration it was asked to wait
// (recording it for jitter assertions) instead of blocking on real
// wall-clock time, so no test in this file ever actually waits.
type fakeRetryClock struct {
	now   time.Time
	slept []time.Duration
}

func (c *fakeRetryClock) Now() time.Time { return c.now }

func (c *fakeRetryClock) Sleep(_ context.Context, d time.Duration) {
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
}

func unavailableErr(msg string) error {
	return connect.NewError(connect.CodeUnavailable, errors.New(msg))
}

// TestRetryOnUnavailable_RecoversWithinBudget is the plan's core recovery
// case: an attempt failing N times with CodeUnavailable then succeeding must
// be retried exactly N+1 times and return nil.
func TestRetryOnUnavailable_RecoversWithinBudget(t *testing.T) {
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	backoff := wireBackoff{
		Now:   clock.Now,
		Delay: func(attempt int) time.Duration { return 10 * time.Millisecond },
		Sleep: clock.Sleep,
	}

	calls := 0
	attempt := func(ctx context.Context) error {
		calls++
		if calls <= 2 {
			return unavailableErr(fmt.Sprintf("boot window, attempt %d", calls))
		}
		return nil
	}

	err := retryOnUnavailable(context.Background(), 10*time.Second, backoff, attempt)
	if err != nil {
		t.Fatalf("retryOnUnavailable: %v, want nil (recovered)", err)
	}
	if calls != 3 {
		t.Errorf("attempt() called %d times, want 3 (2 failures + 1 success)", calls)
	}
}

// TestRetryOnUnavailable_SucceedsFirstTry_NoBackoffInvoked proves the loop
// never sleeps/jitters when the very first attempt succeeds.
func TestRetryOnUnavailable_SucceedsFirstTry_NoBackoffInvoked(t *testing.T) {
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	backoff := wireBackoff{
		Now: clock.Now,
		Delay: func(attempt int) time.Duration {
			t.Fatal("Delay must not be called when the first attempt succeeds")
			return 0
		},
		Sleep: func(ctx context.Context, d time.Duration) {
			t.Fatal("Sleep must not be called when the first attempt succeeds")
		},
	}

	calls := 0
	attempt := func(ctx context.Context) error { calls++; return nil }

	if err := retryOnUnavailable(context.Background(), time.Second, backoff, attempt); err != nil {
		t.Fatalf("retryOnUnavailable: %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("attempt() called %d times, want 1", calls)
	}
}

// TestRetryOnUnavailable_NonUnavailable_NoRetry proves a persistent
// CodeUnauthenticated (a genuine identity rejection, never recoverable by
// re-signing) returns IMMEDIATELY with exactly one attempt — the contract's
// central safety property (never blind-retry a non-Unavailable failure).
func TestRetryOnUnavailable_NonUnavailable_NoRetry(t *testing.T) {
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	backoff := wireBackoff{
		Now: clock.Now,
		Delay: func(attempt int) time.Duration {
			t.Fatal("Delay must not be called for a non-Unavailable error")
			return 0
		},
		Sleep: func(ctx context.Context, d time.Duration) {
			t.Fatal("Sleep must not be called for a non-Unavailable error")
		},
	}

	calls := 0
	wantErr := connect.NewError(connect.CodeUnauthenticated, errors.New("identity rejected"))
	attempt := func(ctx context.Context) error { calls++; return wantErr }

	err := retryOnUnavailable(context.Background(), time.Second, backoff, attempt)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v unchanged", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("attempt() called %d times, want exactly 1 (no retry)", calls)
	}
}

// TestRetryOnUnavailable_AlwaysUnavailable_StopsAtBudget proves best-effort
// exhaustion: budget=300ms with a fixed 100ms backoff bounds the loop to
// exactly 4 attempts (elapsed checked before each sleep: 0,100,200,300ms —
// the 4th attempt's elapsed==budget stops the loop), returning the LAST
// Unavailable error unchanged (surfaced for the caller's existing drop
// behavior, per the spec's accepted best-effort exhaustion posture).
func TestRetryOnUnavailable_AlwaysUnavailable_StopsAtBudget(t *testing.T) {
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	backoff := wireBackoff{
		Now:   clock.Now,
		Delay: func(attempt int) time.Duration { return 100 * time.Millisecond },
		Sleep: clock.Sleep,
	}

	calls := 0
	attempt := func(ctx context.Context) error {
		calls++
		return unavailableErr(fmt.Sprintf("boot window, attempt %d", calls))
	}

	err := retryOnUnavailable(context.Background(), 300*time.Millisecond, backoff, attempt)
	if err == nil {
		t.Fatal("want the last Unavailable error on exhaustion, got nil")
	}
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("code = %v, want CodeUnavailable", connect.CodeOf(err))
	}
	if calls != 4 {
		t.Fatalf("attempt() called %d times, want exactly 4", calls)
	}
	wantMsg := fmt.Sprintf("boot window, attempt %d", calls)
	if got := err.Error(); !strings.Contains(got, wantMsg) {
		t.Errorf("returned error = %q, want it to be the LAST attempt's error (contain %q)", got, wantMsg)
	}
}

// TestRetryOnUnavailable_UsesInjectedBackoffSeam asserts the loop actually
// drives its wait through the injected Delay/Sleep seam (never a real
// wall-clock time.Sleep): Delay is called once per failed attempt with the
// 0-indexed attempt number, and Sleep is called with EXACTLY the duration
// Delay computed — the hook a production jitter implementation uses, and the
// hook these tests use to stay fully deterministic.
func TestRetryOnUnavailable_UsesInjectedBackoffSeam(t *testing.T) {
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	var delayAttempts []int
	backoff := wireBackoff{
		Now: clock.Now,
		Delay: func(attempt int) time.Duration {
			delayAttempts = append(delayAttempts, attempt)
			return time.Duration(attempt+1) * 10 * time.Millisecond
		},
		Sleep: clock.Sleep,
	}

	calls := 0
	attempt := func(ctx context.Context) error {
		calls++
		if calls <= 2 {
			return unavailableErr("boot window")
		}
		return nil
	}

	if err := retryOnUnavailable(context.Background(), 10*time.Second, backoff, attempt); err != nil {
		t.Fatalf("retryOnUnavailable: %v", err)
	}

	if len(delayAttempts) != 2 || delayAttempts[0] != 0 || delayAttempts[1] != 1 {
		t.Fatalf("Delay called with attempt numbers %v, want [0 1]", delayAttempts)
	}
	if len(clock.slept) != 2 || clock.slept[0] != 10*time.Millisecond || clock.slept[1] != 20*time.Millisecond {
		t.Fatalf("Sleep durations = %v, want [10ms 20ms] (exactly what Delay computed — proves jitter flows through the seam)", clock.slept)
	}
}

// TestRetryOnUnavailable_CtxCanceled_StopsRetrying proves the loop honors
// caller cancellation rather than continuing to retry (and burn backoff
// budget) once the caller has given up — checked before each attempt.
func TestRetryOnUnavailable_CtxCanceled_StopsRetrying(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &fakeRetryClock{now: time.Unix(0, 0)}
	backoff := wireBackoff{
		Now:   clock.Now,
		Delay: func(attempt int) time.Duration { return time.Millisecond },
		Sleep: func(ctx context.Context, d time.Duration) {
			// First backoff: cancel here to simulate the caller giving up
			// mid-retry.
			cancel()
		},
	}

	calls := 0
	attempt := func(ctx context.Context) error {
		calls++
		return unavailableErr("boot window")
	}

	err := retryOnUnavailable(ctx, 10*time.Second, backoff, attempt)
	if err == nil {
		t.Fatal("want a non-nil error once ctx is canceled, got nil")
	}
	if calls != 1 {
		t.Errorf("attempt() called %d times after cancellation, want exactly 1 (no attempt after cancel)", calls)
	}
}

// TestRetryOnUnavailable_DeadlineBoundsHangingAttempt is FIX 1's core proof:
// budget must bound a HANGING attempt() call in real wall-clock time, not
// merely the retry DECISION between attempts. Before this fix, budget was
// checked only via the injected clock between calls — an attempt() that
// itself never returns (a stalled RPC; the guarded HTTP client only bounds
// dialing, never the full round trip) could block retryOnUnavailable
// forever. attempt here blocks on <-ctx.Done() and returns ctx.Err(), so the
// ONLY thing that can make it return is the dctx deadline
// (context.WithTimeout(ctx, budget)) firing.
//
// Deterministic despite using a real timer: budget is a tiny fixed duration
// (20ms) and the assertion is a generous upper bound (10x budget), not an
// exact time — this can never flake slow (a hang would time out the whole
// test binary) and has ample margin against scheduler jitter.
func TestRetryOnUnavailable_DeadlineBoundsHangingAttempt(t *testing.T) {
	const budget = 20 * time.Millisecond
	backoff := wireBackoff{
		Now: time.Now,
		Delay: func(attempt int) time.Duration {
			t.Fatal("Delay must not be called — attempt() never fails with CodeUnavailable")
			return 0
		},
		Sleep: func(ctx context.Context, d time.Duration) {
			t.Fatal("Sleep must not be called — attempt() never fails with CodeUnavailable")
		},
	}

	var gotDeadline time.Time
	var gotOK bool
	calls := 0
	attempt := func(ctx context.Context) error {
		calls++
		gotDeadline, gotOK = ctx.Deadline()
		<-ctx.Done()
		return ctx.Err()
	}

	start := time.Now()
	err := retryOnUnavailable(context.Background(), budget, backoff, attempt)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want a non-nil error once the hanging attempt's ctx deadline fires, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded (dctx's own deadline expiring, surfaced as attempt()'s return value; not a connect error, so returned immediately with no retry)", err)
	}
	if calls != 1 {
		t.Errorf("attempt() called %d times, want exactly 1 (a non-Unavailable error — CodeUnknown for a plain context.DeadlineExceeded — never retries)", calls)
	}
	if elapsed > budget*10 {
		t.Errorf("retryOnUnavailable took %v to return, want well under %v (budget*10) — dctx must bound the hanging attempt() call itself, per FIX 1", elapsed, budget*10)
	}
	if !gotOK {
		t.Fatal("attempt()'s ctx has no deadline (Deadline() ok=false) — want the dctx from context.WithTimeout(ctx, budget), which always sets one")
	}
	if gotDeadline.After(start.Add(budget + time.Second)) {
		t.Errorf("attempt()'s ctx deadline = %v, want <= start+budget (plus a generous scheduling margin) — the dctx passed to attempt must actually be budget-bounded, not the caller's unbounded ctx", gotDeadline)
	}
}
