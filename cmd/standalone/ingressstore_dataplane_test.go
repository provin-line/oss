package main

import (
	"context"
	"io"
	"testing"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/sink/console"
)

// newTestVCSvc returns a fresh *vcresolver.Service backed by in-memory stores.
func newTestVCSvc() *vcresolver.Service {
	return vcresolver.New(memstore.NewStore(), memstore.NewPool())
}

// TestBuildDataPlane_SinkRequiresVCStore asserts that a sink loop without a VCStore
// is a build error (fail closed, D-17f-7) — mirroring TestBuildDataPlane_SinkRequiresDeps.
func TestBuildDataPlane_SinkRequiresVCStore(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	// Resolver and SinkWriter are provided, but VCStore is nil — must fail.
	if _, err := buildDataPlane(context.Background(), chainCfg, dpSinkCfg(), dpKeyStore(t), dataPlaneDeps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    nil,
	}); err == nil {
		t.Fatal("sink loop without VCStore: want build error, got nil")
	}
}

// TestBuildDataPlane_ChainedRequiresVCStore asserts that a chained loop without a
// VCStore is a build error (D-17f-7).
func TestBuildDataPlane_ChainedRequiresVCStore(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(context.Background(), chainCfg, dpChainedCfg(""), dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  nil,
	}); err == nil {
		t.Fatal("chained loop without VCStore: want build error, got nil")
	}
}

// TestBuildDataPlane_SinkWithVCStoreAssembles asserts a sink loop assembles when a
// real vcresolver.Service is passed as VCStore.
func TestBuildDataPlane_SinkWithVCStoreAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpSinkCfg(), dpKeyStore(t), dataPlaneDeps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    newTestVCSvc(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (sink + VCStore): %v", err)
	}
	if len(dp.loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(dp.loops))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("sink Run drain: %v", err)
	}
}

// TestBuildDataPlane_ChainedWithVCStoreAssembles asserts a chained loop assembles
// when a real vcresolver.Service is passed as VCStore.
func TestBuildDataPlane_ChainedWithVCStoreAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpChainedCfg("{ 'relayed': true }"), dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  newTestVCSvc(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (chained + VCStore): %v", err)
	}
	if len(dp.loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(dp.loops))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("chained Run drain: %v", err)
	}
}
