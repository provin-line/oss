package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// TestBuildSourceLoop_AggregateClaimRejected guards the slice-17k boot error
// (D-17k-5 / spec-review rec): an ingest source loop signs via SignFirstDrop (N=0),
// so the aggregate transformation-claim is not valid on it — the aggregate Source
// Process runtime is a separate slice. The guard returns before touching the (nil)
// conn/builder, so a legible boot error is produced rather than the raw vcdid
// "aggregate requires SourceRootCanonical" construction error.
func TestBuildSourceLoop_AggregateClaimRejected(t *testing.T) {
	lc := pipelineconfig.LoopConfig{
		Name: "agg", Role: pipelineconfig.RoleSource, IngressSubject: "in",
		Source: pipelineconfig.SourceConfig{
			OutputSubject: "out",
			Issuer: pipelineconfig.IssuerConfig{
				DID: "did:x", KeyID: "signing", VerificationMethod: "did:x#signing",
			},
			PipelineID: "p", ProcessID: "s", TransformationClaim: vc.ClaimAggregate,
		},
	}
	_, err := buildSourceLoop(nil, nil, nil, nil, memlog.New(), lc)
	if err == nil {
		t.Fatal("aggregate claim on ingest source loop: want boot error, got nil")
	}
	if !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("boot error %q should name the aggregate claim", err)
	}
}

const (
	dpAggDID  = "did:dplaax:reg:org:acme:pipeline:agg"
	dpAggIssr = "did:dplaax:reg:org:acme:pipeline:agg:process:a1"
)

// dpAggregateCfg is one aggregate loop consuming the shared pipeline DID as its single
// ingress (a valid N=1 aggregate) and emitting on its own output subject.
func dpAggregateCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name: "agg",
		Role: pipelineconfig.RoleAggregate,
		Aggregate: pipelineconfig.AggregateConfig{
			OutputSubject: dpAggDID,
			Issuer: pipelineconfig.IssuerConfig{
				DID: dpAggIssr, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpAggIssr + "#signing",
			},
			PipelineID:           "agg",
			ProcessID:            "a1",
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
			Window:               time.Second,
			Ingresses: []pipelineconfig.AggregateIngress{
				{Subject: dpPipelineDID, UpstreamEndpoint: "https://acme.example/pipelines/pipe"},
			},
		},
	}}}
}

// TestBuildDataPlane_AggregateProcessAssembles asserts the role dispatch builds an
// aggregate contract.Process (tracked in dp.aggregates, not dp.loops) given a resolver +
// VC store, and that dp.Run drains it cleanly.
func TestBuildDataPlane_AggregateProcessAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpAggregateCfg(), dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (aggregate): %v", err)
	}
	if len(dp.aggregates) != 1 {
		t.Fatalf("aggregates: got %d want 1", len(dp.aggregates))
	}
	if len(dp.loops) != 0 {
		t.Fatalf("loops: got %d want 0 (aggregate is not a loop)", len(dp.loops))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("aggregate Run drain: %v", err)
	}
}

// TestBuildDataPlane_AggregateRequiresConsumerDeps asserts an aggregate loop without a
// resolver/VC store is a build error (it verifies+stores ingress, like sink/chained).
func TestBuildDataPlane_AggregateRequiresConsumerDeps(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(context.Background(), chainCfg, dpAggregateCfg(), dpKeyStore(t), dataPlaneDeps{}); err == nil {
		t.Fatal("aggregate without resolver/VC store: want error, got nil")
	}
}
