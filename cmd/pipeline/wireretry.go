package main

import (
	"context"
	"math/rand/v2"
	"time"

	"connectrpc.com/connect"
)

// ─────────────────────────────────────────────────────────────────────────
// Client boot-window recovery — the client half of the restart-epoch
// contract documented in docs/protocol/auth.md ("replay defense").
// During cmd/network's boot window, its restart-epoch
// barrier now returns connect.CodeUnavailable for a wireauth-signed call
// whose proof was signed before the barrier's epoch (wireautherr.Code maps
// wireauth.ErrBeforeEpoch there — see network/pkg/wireautherr) instead of
// the PERMANENT connect.CodeUnauthenticated it used to return. An honest,
// roughly clock-synced caller recovers by simply RE-SIGNING with its current
// clock and re-calling: retryOnUnavailable below is a bounded,
// caller-agnostic retry loop over exactly that recovery — it never
// resends a cached proof (that would never clear the epoch); it re-invokes
// the caller-supplied attempt func, which must build a FRESH signed request
// internally on every call (every production client this binary wraps
// already does — see e.g. payloadresolver/client.Resolver.proof and
// auditor/client.Client.proof, both of which sign with time.Now() + a fresh
// nonce on each invocation).
//
// Kept UNEXPORTED (package main, cmd/pipeline): this is wiring glue for this
// binary's own loss-sensitive call sites (wiring.go), not a public seam any
// other package or binary is meant to import.
// ─────────────────────────────────────────────────────────────────────────

// defaultWireRetryBudget bounds the total wall-clock time (backoff sleeps
// included) a loss-sensitive wireauth-signed call may spend retrying a
// connect.CodeUnavailable failure. Sized to cmd/network's boot-window
// barrier (restart-epoch = ceilToSecond(boot + MaxFuture); MaxFuture
// defaults to a few seconds, per network/pkg/services/chainmanager/wireauth's
// VerifierConfig) plus a margin generous enough that a caller racing the
// barrier is still retrying once the verifier is past its own boot — the
// spec's "~MaxFuture+ceil ≈ 6s default, plus margin" budget.
const defaultWireRetryBudget = 8 * time.Second

// defaultWireRetryBaseDelay is the un-jittered backoff floor between retry
// attempts. Kept short relative to defaultWireRetryBudget so a handful of
// attempts fit comfortably inside the boot window.
const defaultWireRetryBaseDelay = 250 * time.Millisecond

// wireBackoff is retryOnUnavailable's injected timing seam. Now reports the
// current time (for budget accounting); Delay computes the — already
// jittered — wait before the NEXT attempt given how many attempts have
// already failed (0-indexed: attempt 0 is the delay before the 2nd call);
// Sleep performs that wait, honoring ctx cancellation.
//
// defaultWireBackoff wires the real thing: wall-clock time, backoff.Delay
// jittered via math/rand/v2 so a synchronized fleet racing the SAME boot
// window does not retry in lockstep (the spec's thundering-herd
// requirement), and a context-aware timer for Sleep. wireretry_test.go
// injects a fully deterministic fake for both Now and Sleep so no retry
// test in this package ever depends on, or blocks on, real wall-clock time.
type wireBackoff struct {
	Now   func() time.Time
	Delay func(attempt int) time.Duration
	Sleep func(ctx context.Context, d time.Duration)
}

// defaultWireBackoff returns the production wireBackoff: Delay(n) =
// defaultWireRetryBaseDelay*(n+1), jittered by a uniform random factor in
// [0.5, 1.5), and Sleep blocks on a context-aware timer (never a bare
// time.Sleep, so caller cancellation interrupts the wait immediately rather
// than after the full delay).
func defaultWireBackoff() wireBackoff {
	return wireBackoff{
		Now: time.Now,
		Delay: func(attempt int) time.Duration {
			base := defaultWireRetryBaseDelay * time.Duration(attempt+1)
			jitter := 0.5 + rand.Float64() // [0.5, 1.5)
			return time.Duration(float64(base) * jitter)
		},
		Sleep: func(ctx context.Context, d time.Duration) {
			if d <= 0 {
				return
			}
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		},
	}
}

// retryOnUnavailable retries attempt() while it fails with
// connect.CodeUnavailable — the code cmd/network's boot-window barrier now
// returns for a wireauth-signed call racing its restart-epoch — within
// budget's total wall-clock allowance (per backoff.Now), backing off via
// backoff.Delay/backoff.Sleep between attempts. It returns:
//
//   - nil, as soon as attempt() succeeds;
//   - the first non-Unavailable error IMMEDIATELY, with NO retry — this is
//     how a genuine identity rejection (connect.CodeUnauthenticated) or any
//     other failure is distinguished from the boot-window race, which is the
//     ONLY condition this loop treats as recoverable;
//   - the LAST Unavailable error once budget is exhausted or ctx is done —
//     best-effort exhaustion: the caller's existing log-and-drop handling is
//     unchanged; this residual boot-window loss is the accepted PoC posture
//     documented in docs/protocol/auth.md ("replay defense", retry-budget
//     exhaustion).
//
// attempt is called FRESH on every retry (with the budget-bounded ctx below,
// NEVER the caller's original ctx) and MUST re-sign internally — a wireauth
// proof's issued-at/nonce are fixed at signing time, so resending a cached
// proof can never clear the epoch. retryOnUnavailable itself is a pure
// Connect-code-driven retry loop; it knows nothing about wireauth or proofs.
//
// budget is enforced TWICE, deliberately, and both mechanisms are load-
// bearing:
//
//  1. A real context.WithTimeout(ctx, budget) (dctx below) bounds attempt()
//     and backoff.Sleep in WALL-CLOCK time. Without this, budget was only
//     ever checked BETWEEN attempts (per backoff.Now), so a single hanging
//     RPC — the guarded HTTP client only bounds dialing, not the full
//     round trip — could stall far past budget with no enforcement at all.
//     dctx is what actually bounds an in-flight call in production.
//  2. The injected-clock loop check (backoff.Now().Sub(start) >= budget)
//     still decides when to STOP RETRYING. It stays because it is what
//     makes the exhaustion tests in wireretry_test.go deterministic: dctx's
//     deadline is a REAL 8s (defaultWireRetryBudget) and stays inert inside
//     a fast fake-clock test (the test never runs long enough for real time
//     to elapse), while the fake backoff.Now() advances instantly and drives
//     the loop to its budget-exhaustion return. In production the two
//     mechanisms agree (both are keyed off the same budget); dctx is the
//     one that matters for a hung RPC, the fake clock is the one that
//     matters for deterministic tests.
func retryOnUnavailable(ctx context.Context, budget time.Duration, backoff wireBackoff, attempt func(context.Context) error) error {
	dctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	start := backoff.Now()
	var lastErr error
	for n := 0; ; n++ {
		if err := dctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		err := attempt(dctx)
		if err == nil || connect.CodeOf(err) != connect.CodeUnavailable {
			return err
		}
		lastErr = err

		if backoff.Now().Sub(start) >= budget {
			return lastErr
		}
		backoff.Sleep(dctx, backoff.Delay(n))
	}
}
