package main

import (
	"context"
	"io"
	"testing"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/sink/console"
)

func dpFullSinkCfg(endpoint string) *pipelineconfig.Config {
	bearer := ""
	if endpoint != "" {
		bearer = "dummy"
	}
	return &pipelineconfig.Config{
		VCStoreEndpoint: endpoint,
		VCStoreBearer:   bearer,
		Loops: []pipelineconfig.LoopConfig{{
			Name:           "archive",
			Role:           pipelineconfig.RoleSink,
			IngressSubject: dpPipelineDID,
			Sink: pipelineconfig.SinkConfig{
				Kind:                 pipelineconfig.SinkObservationOnly,
				VerificationStrategy: pipelineconfig.StrategyFull,
				UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
			},
		}},
	}
}

// 17e: a "full" sink assembles when a vc-store-endpoint is configured (the chainwalk
// ChainVerifier is wired from the network resolver + the shared vc.Verifier core). The
// endpoint is not dialed at build time, so a bogus URL still builds.
func TestBuildDataPlane_FullSinkAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(chainCfg, dpFullSinkCfg("http://127.0.0.1:1/"), dpKeyStore(t), dataPlaneDeps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (full sink): %v", err)
	}
	if len(dp.loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(dp.loops))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("full sink Run drain: %v", err)
	}
}

// Defense in depth: a "full" sink with no vc-store-endpoint (so no network resolver)
// fails closed at assembly — sink.New rejects a nil ChainVerifier. (LoadPipelineConfig
// also rejects this earlier; this guards the assembly seam directly.)
func TestBuildDataPlane_FullSinkWithoutEndpoint_FailsClosed(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(chainCfg, dpFullSinkCfg(""), dpKeyStore(t), dataPlaneDeps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
	}); err == nil {
		t.Fatal("full sink without vc-store-endpoint: want assembly error, got nil")
	}
}
