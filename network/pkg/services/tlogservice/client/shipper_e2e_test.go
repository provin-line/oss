package client_test

// TestShipper_EndToEnd is task-6's "ideally one integration test against
// the real client+handler" (brief): a real tlogship.Shipper (pipeline/,
// under test here from the network SIDE — see
// network/pkg/services/payloadresolver/handler/byref_dataplane_e2e_test.go
// for the established precedent of an external `_test` package crossing
// the network/pipeline boundary for exactly this kind of wire e2e, without
// either PRODUCTION package importing the other) driving a real filelog.Log
// through the real client.Client, the real handler.Handler, the real
// wireauth.Verifier, and the real mirrorstore.Store — over httptest.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/services/tlogservice/client"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
)

var e2eDiscardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// noopSigner is a throwaway crypto.Signer for TestShipper_RegistryDown_RunDoesNotBlock:
// the client it backs is pointed at an address nothing listens on, so every
// call fails at the transport (connection refused) before a signature is
// ever verified — the signed bytes' actual validity is irrelevant to that
// test.
type noopSigner struct{}

func (noopSigner) Sign(string, string, []byte) ([]byte, error) { return []byte("sig"), nil }

// newDownClient returns a client.Client configured exactly like h.client
// (same signer identity) but pointed at a port nothing listens on, for
// proving a shipper never blocks when the registry is unreachable.
func newDownClient(_ *testing.T, _ *harness) *client.Client {
	return client.New(client.Config{
		Signer: noopSigner{}, SignerDID: clientProcessA1,
		BaseURL: "http://127.0.0.1:1", HTTPClient: http.DefaultClient,
	})
}

// TestShipper_EndToEnd exercises, against the real production stack: an
// initial catch-up ship, resume-after-restart (a fresh Shipper instance
// reading the same registry state), cap-honoring incremental batching as
// new records keep arriving, and Drain flushing the final tail.
func TestShipper_EndToEnd(t *testing.T) {
	h := newHarness(t, 2, 4<<20) // max-batch-records = 2: small enough to force multiple ticks
	ctx := context.Background()

	// Seed 2 records and let a shipper catch the registry up.
	if _, err := h.log.Append(ctx, []byte("r0")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := h.log.Append(ctx, []byte("r1")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	cfg := tlogship.Config{MaxBatchRecords: 2, MaxBatchBytes: 4 << 20, FlushInterval: 20 * time.Millisecond, Logger: e2eDiscardLogger}
	sh1, err := tlogship.New(h.log, clientPipeline, h.client, cfg)
	if err != nil {
		t.Fatalf("tlogship.New: %v", err)
	}
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sh1.Drain(drainCtx); err != nil {
		t.Fatalf("Drain (initial catch-up): %v", err)
	}
	if state, err := h.client.GetMirrorState(ctx, clientPipeline); err != nil || state != 2 {
		t.Fatalf("GetMirrorState after initial catch-up = (%d, %v), want (2, nil)", state, err)
	}

	// Resume-after-restart: a FRESH Shipper instance over the SAME log and
	// registry state must discover acked=2 on its own (GetMirrorState is
	// never locally cached) and ship only the tail below.
	if _, err := h.log.Append(ctx, []byte("r2")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	sh2, err := tlogship.New(h.log, clientPipeline, h.client, cfg)
	if err != nil {
		t.Fatalf("tlogship.New (post-restart): %v", err)
	}
	if err := sh2.Drain(drainCtx); err != nil {
		t.Fatalf("Drain (resume after restart): %v", err)
	}
	if state, err := h.client.GetMirrorState(ctx, clientPipeline); err != nil || state != 3 {
		t.Fatalf("GetMirrorState after resume = (%d, %v), want (3, nil)", state, err)
	}

	// Cap-honoring incremental batching: Run ticks every 20ms while more
	// records keep arriving one at a time (each tick's backlog is at most
	// 1, comfortably within the 2-record cap) — over enough ticks, every
	// new record lands in the real mirror store without ever exceeding the
	// registry's own configured cap (which would reject an oversized call
	// with ResourceExhausted).
	runCtx, cancelRun := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- sh2.Run(runCtx) }()
	for i := 0; i < 5; i++ {
		time.Sleep(15 * time.Millisecond)
		if _, err := h.log.Append(ctx, []byte("more")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// Give Run a few more ticks to catch the tail up, then stop it and
	// drain the remainder deterministically.
	time.Sleep(100 * time.Millisecond)
	cancelRun()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	finalDrain, cancelFinal := context.WithTimeout(ctx, 5*time.Second)
	defer cancelFinal()
	if err := sh2.Drain(finalDrain); err != nil {
		t.Fatalf("Drain (final tail): %v", err)
	}
	wantSize, err := h.log.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	state, err := h.client.GetMirrorState(ctx, clientPipeline)
	if err != nil {
		t.Fatalf("GetMirrorState (final): %v", err)
	}
	if state != wantSize {
		t.Fatalf("GetMirrorState (final) = %d, want the full local size %d", state, wantSize)
	}
}

// TestShipper_RegistryDown_RunDoesNotBlock proves that at the real-wire
// level (not just against a fake), a Shipper pointed at an unreachable
// registry keeps ticking and Run still returns promptly on ctx
// cancellation — the emission path this shipper shares a log handle with
// is never blocked by a dead registry.
func TestShipper_RegistryDown_RunDoesNotBlock(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	ctx := context.Background()
	if _, err := h.log.Append(ctx, []byte("r0")); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// h.client points at a live server; build a SECOND client identical in
	// every way except BaseURL, aimed at a port nothing listens on.
	downClient := newDownClient(t, h)

	cfg := tlogship.Config{MaxBatchRecords: 256, MaxBatchBytes: 4 << 20, FlushInterval: 10 * time.Millisecond, Logger: e2eDiscardLogger}
	sh, err := tlogship.New(h.log, clientPipeline, downClient, cfg)
	if err != nil {
		t.Fatalf("tlogship.New: %v", err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sh.Run(runCtx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return — a down registry must never block shutdown")
	}
}
