package main

// TDD for PR3b Task 7 (D8 ordered shutdown): proves run's shutdown sequence
// actually happens in the documented order — HTTP drains, THEN loops drain,
// THEN shippers stop ticking, THEN each shipper gets ONE final flush on a
// FRESH (non-cancelled) context, THEN the data plane closes — and that a
// final flush which cannot complete within its budget still exits zero.

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
)

const lifecycleSignerDID = "did:dplaax:reg:org:acme:pipeline:p:process:iss"

// newLoopbackServer binds an ephemeral loopback listener and returns an
// *http.Server + listen func in run's own (srv, listen) shape
// (httpserve.BuildServer's return shape), so tests can drive run exactly
// like main does, and the request URL to reach handler.
func newLoopbackServer(t *testing.T, handler http.Handler) (srv *http.Server, listen func() error, url string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv = &http.Server{Handler: handler}
	return srv, func() error { return srv.Serve(ln) }, "http://" + ln.Addr().String()
}

// TestRun_OrderedShutdown_FinalDrainGetsFreshContext is the D8 capstone: a
// SIGTERM-style ctx cancellation must (1) let an in-flight HTTP request
// finish before anything else proceeds, (2) drain the data-plane loops only
// after that, (3) stop the shipper's periodic ticking only after THAT, then
// (4) flush the shipper's local tail on a context that is NOT the (by then
// long-cancelled) signal context — every recorded mirror-client call, right
// through to this final flush, must observe a live context — and only then
// (5) close the data plane. FlushInterval is set to an hour so the ONLY
// MirrorLogSegment call in this test comes from the final drain, not from
// the shipper's own periodic ticking racing the assertions.
func TestRun_OrderedShutdown_FinalDrainGetsFreshContext(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	genEd25519Key(t, ks, lifecycleSignerDID, keystore.KeyIDSigning)
	tlogHandle := newTestFilelog(t, ks, lifecycleSignerDID, "test-log")
	if _, err := tlogHandle.Append(context.Background(), []byte("r0")); err != nil {
		t.Fatalf("append: %v", err)
	}

	spy := &spyMirrorClient{}
	sh, err := tlogship.New(tlogHandle, "test-log", spy, tlogship.Config{
		MaxBatchRecords: 10, MaxBatchBytes: 1 << 20, FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("tlogship.New: %v", err)
	}

	events := &eventLog{}
	releaseHTTP := make(chan struct{})
	srv, listen, url := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-releaseHTTP
		events.add("http-in-flight-done")
		w.WriteHeader(http.StatusOK)
	}))

	dp := &fakeDataPlane{
		runFn: func(ctx context.Context) error {
			<-ctx.Done()
			events.add("loops-drained")
			return nil
		},
		closeFn: func() error {
			events.add("closed")
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- run(ctx, srv, listen, dp, []*tlogship.Shipper{sh}, nil, 5*time.Second) }()

	// Fire an in-flight request and let it reach the (blocking) handler
	// before signalling shutdown, proving step 1's drain is real (the
	// handler only finishes once explicitly released, below).
	reqDone := make(chan struct{})
	go func() {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
		}
		close(reqDone)
	}()
	time.Sleep(50 * time.Millisecond) // let the request reach the handler and block
	cancel()                          // simulate SIGTERM
	time.Sleep(50 * time.Millisecond) // let ServeHTTP's Shutdown start waiting on the in-flight request
	close(releaseHTTP)                // let the in-flight handler finish, unblocking ServeHTTP's drain
	<-reqDone

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}

	if got, want := events.snapshot(), []string{"http-in-flight-done", "loops-drained", "closed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event order = %v, want %v", got, want)
	}

	// The core D8 property: no recorded mirror-client call — including the
	// final Drain-time call, made well after ctx/loopCtx/shipCtx were all
	// already cancelled — ever observed an already-cancelled context.
	if spy.anyCallSawCanceledCtx() {
		t.Fatal("a mirror client call observed an already-cancelled context — the final flush must get a FRESH context")
	}
	acked, calls := spy.snapshot()
	if acked != 1 {
		t.Fatalf("final acked size = %d, want 1 (the final drain must have shipped the record no earlier tick had a chance to)", acked)
	}
	var shipped bool
	for _, c := range calls {
		if c.op == "MirrorLogSegment" {
			shipped = true
		}
	}
	if !shipped {
		t.Fatal("no MirrorLogSegment call was recorded — the final drain never shipped anything")
	}
}

// TestRun_TimedOutFinalDrain_LogsAndExitsZero proves the D8 timeout posture:
// a shipper whose registry never accepts a segment cannot finish its final
// flush within budget — this is NOT a shutdown failure. run must still
// return nil (exit zero), having logged the documented message (the local
// durable tail is safe; the next boot's shipper resumes it from the
// registry's own acked cursor).
func TestRun_TimedOutFinalDrain_LogsAndExitsZero(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	genEd25519Key(t, ks, lifecycleSignerDID, keystore.KeyIDSigning)
	tlogHandle := newTestFilelog(t, ks, lifecycleSignerDID, "test-log")
	if _, err := tlogHandle.Append(context.Background(), []byte("r0")); err != nil {
		t.Fatalf("append: %v", err)
	}

	spy := &spyMirrorClient{failAlways: true}
	sh, err := tlogship.New(tlogHandle, "test-log", spy, tlogship.Config{
		MaxBatchRecords: 10, MaxBatchBytes: 1 << 20, FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("tlogship.New: %v", err)
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	srv, listen, _ := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	dp := &fakeDataPlane{
		runFn:   func(ctx context.Context) error { <-ctx.Done(); return nil },
		closeFn: func() error { return nil },
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shut down immediately; nothing in this test needs an in-flight window

	// A short drain budget keeps this test fast: failAlways guarantees the
	// budget is what ends the drain, not an eventual success.
	err = run(ctx, srv, listen, dp, []*tlogship.Shipper{sh}, nil, 60*time.Millisecond)
	if err != nil {
		t.Fatalf("run returned %v, want nil (a timed-out final drain must still exit zero)", err)
	}

	const wantMsg = "local durable tail remains unmirrored (resume re-ships it)"
	if got := logBuf.String(); !strings.Contains(got, wantMsg) {
		t.Fatalf("log output = %q, does not contain the D8 timeout message %q", got, wantMsg)
	}
}

// TestRun_UnpromptedDataPlaneFailure_CancelsHTTPAndReturnsError proves an
// early, unprompted dp.Run failure (a boot-time error before any external
// signal) brings the HTTP surface down too and surfaces as run's error —
// mirroring the old single-context run()'s "first error cancels everyone"
// posture, now re-anchored at the front of the ordered sequence.
func TestRun_UnpromptedDataPlaneFailure_CancelsHTTPAndReturnsError(t *testing.T) {
	srv, listen, _ := newLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	wantErr := context.Canceled // any distinguishable sentinel error stands in for a boot failure
	dp := &fakeDataPlane{
		runFn:   func(ctx context.Context) error { return wantErr },
		closeFn: func() error { return nil },
	}

	// ctx is NEVER cancelled externally — run must still return promptly,
	// proving the failure itself (not an external signal) drove the
	// teardown.
	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, srv, listen, dp, nil, nil, time.Second) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("run returned nil, want the data-plane error to surface")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after an unprompted data-plane failure — HTTP was never cancelled")
	}
}
