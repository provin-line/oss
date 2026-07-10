package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
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
	builder := vc.NewBuilder(ed25519.NewSigner(dpKeyStore(t)))
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
