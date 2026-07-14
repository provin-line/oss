package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/provin-line/oss/pipeline/transport"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// TestRunServices_DataPlaneErrorPropagates is the regression guard for the silent
// exit-0 on failure: a data plane whose loop fails at boot must make runServices
// return a non-nil error (so main exits non-zero), even though the HTTP server is
// healthy and shuts down cleanly when the failed loop cancels the shared context.
// Before the fix the failing goroutine only logged and main exited 0.
func TestRunServices_DataPlaneErrorPropagates(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	conn, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	builder := vc.NewBuilder(dpKeyStore(t))
	badLC := dpPipelineCfg().Loops[0]
	badLC.IngressSubject = "bad subject" // embedded space => nats ErrBadSubject at Subscribe
	bad, err := buildSourceLoop(conn.Subscriber(badLC.IngressSubject), conn, builder, nil, memlog.New(), vc.SchemaRef{}, payloadWiring{}, badLC)
	if err != nil {
		t.Fatalf("build bad loop: %v", err)
	}
	dp := &dataPlane{conn: conn, loops: []*transport.Loop{bad}}

	// A healthy server on an ephemeral port; the failed loop cancels runCtx, which
	// shuts the server down gracefully (no error from its side).
	srv := &http.Server{Addr: "127.0.0.1:0"}

	done := make(chan error, 1)
	go func() { done <- runServices(context.Background(), srv, dp, nil, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runServices returned nil; want the data-plane failure to propagate")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServices did not return after the data-plane loop failed")
	}
}

// The HTTP/2 (h2c) server the connection is hijacked into must carry its own
// stall defenses: http.Server's timeouts do not reach HTTP/2 streams, so a
// regression to zero here would reopen the slow-stream DoS (adversarial-review
// F7 / Codex Issue 7).
func TestH2CServer_HasStallTimeouts(t *testing.T) {
	s := h2cServer()
	if s.IdleTimeout <= 0 {
		t.Error("IdleTimeout unset — idle HTTP/2 connections would never be reaped")
	}
	if s.ReadIdleTimeout <= 0 || s.PingTimeout <= 0 {
		t.Errorf("ReadIdleTimeout=%v PingTimeout=%v — a silent peer is never probed/dropped", s.ReadIdleTimeout, s.PingTimeout)
	}
	if s.WriteByteTimeout <= 0 {
		t.Error("WriteByteTimeout unset — a per-write stall is unbounded")
	}
}

// The outer raw-body cap is the largest legitimate request plus headroom — big
// enough for the biggest real request (credential or push body), never smaller
// (which would reject legitimate traffic).
func TestOuterRequestCapBytes_SizedToLargestLegit(t *testing.T) {
	const cred, push = 1 << 20, 4 << 20
	got := outerRequestCapBytes(cred, push)
	if got <= push {
		t.Errorf("cap %d not above the largest legit request %d", got, push)
	}
	if outerRequestCapBytes(push, cred) != got {
		t.Error("cap must not depend on argument order (it takes the max)")
	}
	// Even with credential/push configured BELOW the document-class per-RPC cap,
	// the outer bound must still exceed a document-class request plus its JSON
	// base64 inflation — otherwise a legit doc request is rejected pre-auth.
	small := outerRequestCapBytes(4<<10, 4<<10)
	if small <= maxDocumentRequestBytes {
		t.Errorf("outer cap %d does not cover the document class %d when cred/push are tiny", small, maxDocumentRequestBytes)
	}
	if small <= maxDocumentRequestBytes*4/3 {
		t.Errorf("outer cap %d does not cover base64-inflated document request (~4/3 of %d)", small, maxDocumentRequestBytes)
	}
}
