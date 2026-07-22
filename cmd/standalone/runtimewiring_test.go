package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/vc"
)

// fullChainConfig is a fully-populated chainconfig.Config (NATS transport,
// every NATS field set) — the golden mapping test's chain-side input.
func fullChainConfig() *chainconfig.Config {
	return &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS: chainconfig.NATSConfig{
			URL:         "nats://broker.example:4222",
			AccountSeed: "SAAAACCOUNTSEED",
			ConnectWait: 7 * time.Second,
			// TrustRootSeed/ResolverDir/NodeDID/ResolverBaseURL/RegistryBaseURLs/
			// SysUserJWT/SysUserSeed are chain-manager-side fields
			// runtimeConfigFrom never reads (pipeline/runtime.NATSConfig has no
			// field for them) — deliberately left zero so this fixture pins
			// exactly the read set.
		},
	}
}

// fullPipelineConfig is a fully-populated pipelineconfig.Config carrying one
// loop of EVERY role, each with every field the moved builders read (see
// pipeline/runtime/dataplane.go's buildSourceLoop/buildSinkLoop/
// buildChainedLoop/buildAggregateProcess) populated to a distinct,
// recognizable value — the golden mapping test's pipeline-side input.
func fullPipelineConfig() *pipelineconfig.Config {
	return &pipelineconfig.Config{
		Loops: []pipelineconfig.LoopConfig{
			{
				Name:           "src",
				Role:           pipelineconfig.RoleSource,
				IngressSubject: "ingest.src",
				Source: pipelineconfig.SourceConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:src",
					Issuer: pipelineconfig.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:src:process:s1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:src:process:s1#signing",
					},
					PipelineID:          "src",
					ProcessID:           "s1",
					TransformationClaim: vc.ClaimConvert,
					SchemaRef:           "reading@1",
					PushIngress:         true,
				},
			},
			{
				Name:           "sink",
				Role:           pipelineconfig.RoleSink,
				IngressSubject: "did:dplaax:reg:org:acme:pipeline:src",
				Sink: pipelineconfig.SinkConfig{
					Kind:                 pipelineconfig.SinkArchival,
					VerificationStrategy: pipelineconfig.StrategyAdjacent,
					UpstreamEndpoint:     "https://acme.example/pipelines/src",
					PayloadDelivery:      "by-reference",
					AllowIssuers:         []string{"did:dplaax:reg:org:acme:*"},
					Receipt: pipelineconfig.SinkReceiptConfig{
						Issue: true,
						Issuer: pipelineconfig.IssuerConfig{
							DID:                "did:dplaax:reg:org:acme:pipeline:sink:process:a1",
							KeyID:              "signing",
							VerificationMethod: "did:dplaax:reg:org:acme:pipeline:sink:process:a1#signing",
						},
						PipelineID: "sink",
						ProcessID:  "a1",
					},
					Output: pipelineconfig.SinkOutputConfig{Type: pipelineconfig.SinkOutputFile, Path: "/data/out.ndjson"},
				},
			},
			{
				Name:           "relay",
				Role:           pipelineconfig.RoleChained,
				IngressSubject: "did:dplaax:reg:org:acme:pipeline:src",
				Chained: pipelineconfig.ChainedConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:relay",
					Issuer: pipelineconfig.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:relay:process:r1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:relay:process:r1#signing",
					},
					PipelineID:           "relay",
					ProcessID:            "r1",
					TransformationClaim:  vc.ClaimFilterConvert,
					SchemaRef:            "relayed@2",
					VerificationStrategy: pipelineconfig.StrategyAdjacent,
					UpstreamEndpoint:     "https://acme.example/pipelines/src",
					PayloadDelivery:      "inline",
					Converter:            "{ 'relayed': true }",
					Filters:              []string{"reading > 0"},
				},
			},
			{
				Name: "agg",
				Role: pipelineconfig.RoleAggregate,
				Aggregate: pipelineconfig.AggregateConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg",
					Issuer: pipelineconfig.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:agg:process:g1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:agg:process:g1#signing",
					},
					PipelineID:           "agg",
					ProcessID:            "g1",
					SchemaRef:            "folded@1",
					VerificationStrategy: pipelineconfig.StrategyAdjacent, // never read by buildAggregateProcess; must not be mapped
					Window:               250 * time.Millisecond,
					Ingresses: []pipelineconfig.AggregateIngress{
						{Subject: "did:dplaax:reg:org:acme:pipeline:src", UpstreamEndpoint: "https://acme.example/pipelines/src", PayloadDelivery: "inline"},
						{Subject: "did:dplaax:reg:org:acme:pipeline:relay", UpstreamEndpoint: "https://acme.example/pipelines/relay", PayloadDelivery: "by-reference"},
					},
				},
			},
		},
		// VCStoreEndpoint/VCStoreBearer/MaxCredentialSize/... are read by
		// credentialPublisherFrom, not runtimeConfigFrom (severance #3 moved VC-
		// client construction out of Build entirely) — deliberately left zero so
		// this fixture pins exactly runtimeConfigFrom's own read set.
	}
}

// wantRuntimeConfig is the exact pipelineruntime.Config fullChainConfig() +
// fullPipelineConfig() must map to, field for field — the drift guard
// between the two config trees.
func wantRuntimeConfig(dataDir string) pipelineruntime.Config {
	cfg := pipelineruntime.Config{
		NATS: pipelineruntime.NATSConfig{
			URL:         "nats://broker.example:4222",
			AccountSeed: "SAAAACCOUNTSEED",
			ConnectWait: 7 * time.Second,
		},
		Loops: []pipelineruntime.LoopConfig{
			{
				Name:           "src",
				Role:           pipelineruntime.RoleSource,
				IngressSubject: "ingest.src",
				Source: pipelineruntime.SourceConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:src",
					Issuer: pipelineruntime.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:src:process:s1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:src:process:s1#signing",
					},
					PipelineID:          "src",
					ProcessID:           "s1",
					TransformationClaim: vc.ClaimConvert,
					SchemaRef:           "reading@1",
					PushIngress:         true,
				},
			},
			{
				Name:           "sink",
				Role:           pipelineruntime.RoleSink,
				IngressSubject: "did:dplaax:reg:org:acme:pipeline:src",
				Sink: pipelineruntime.SinkConfig{
					Kind:                 pipelineruntime.SinkArchival,
					VerificationStrategy: pipelineruntime.StrategyAdjacent,
					UpstreamEndpoint:     "https://acme.example/pipelines/src",
					PayloadDelivery:      "by-reference",
					AllowIssuers:         []string{"did:dplaax:reg:org:acme:*"},
					Receipt: pipelineruntime.SinkReceiptConfig{
						Issue: true,
						Issuer: pipelineruntime.IssuerConfig{
							DID:                "did:dplaax:reg:org:acme:pipeline:sink:process:a1",
							KeyID:              "signing",
							VerificationMethod: "did:dplaax:reg:org:acme:pipeline:sink:process:a1#signing",
						},
						PipelineID: "sink",
						ProcessID:  "a1",
					},
					Output: pipelineruntime.SinkOutputConfig{Type: pipelineruntime.SinkOutputFile, Path: "/data/out.ndjson"},
				},
			},
			{
				Name:           "relay",
				Role:           pipelineruntime.RoleChained,
				IngressSubject: "did:dplaax:reg:org:acme:pipeline:src",
				Chained: pipelineruntime.ChainedConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:relay",
					Issuer: pipelineruntime.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:relay:process:r1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:relay:process:r1#signing",
					},
					PipelineID:           "relay",
					ProcessID:            "r1",
					TransformationClaim:  vc.ClaimFilterConvert,
					SchemaRef:            "relayed@2",
					VerificationStrategy: pipelineruntime.StrategyAdjacent,
					UpstreamEndpoint:     "https://acme.example/pipelines/src",
					PayloadDelivery:      "inline",
					Converter:            "{ 'relayed': true }",
					Filters:              []string{"reading > 0"},
				},
			},
			{
				Name: "agg",
				Role: pipelineruntime.RoleAggregate,
				Aggregate: pipelineruntime.AggregateConfig{
					OutputSubject: "did:dplaax:reg:org:acme:pipeline:agg",
					Issuer: pipelineruntime.IssuerConfig{
						DID:                "did:dplaax:reg:org:acme:pipeline:agg:process:g1",
						KeyID:              "signing",
						VerificationMethod: "did:dplaax:reg:org:acme:pipeline:agg:process:g1#signing",
					},
					PipelineID: "agg",
					ProcessID:  "g1",
					SchemaRef:  "folded@1",
					// VerificationStrategy is deliberately absent: runtime.AggregateConfig
					// has no field for it (buildAggregateProcess never reads it).
					Window: 250 * time.Millisecond,
					Ingresses: []pipelineruntime.AggregateIngress{
						{Subject: "did:dplaax:reg:org:acme:pipeline:src", UpstreamEndpoint: "https://acme.example/pipelines/src", PayloadDelivery: "inline"},
						{Subject: "did:dplaax:reg:org:acme:pipeline:relay", UpstreamEndpoint: "https://acme.example/pipelines/relay", PayloadDelivery: "by-reference"},
					},
				},
			},
		},
	}
	if dataDir != "" {
		cfg.TlogDir = dataDir + "/tlog"
		cfg.RejectLogDir = dataDir + "/evidence/sink-rejects"
	}
	return cfg
}

// TestRuntimeConfigFrom_GoldenMapping is the drift guard between
// network/pkg/chainconfig.Config + network/pkg/pipelineconfig.Config and
// pipeline/runtime.Config: a fully-populated pair of network config trees
// must map to the EXACT expected runtime.Config, field for field. A field
// added to either config-side type without a corresponding update to
// runtimeConfigFrom (and this fixture) fails this test rather than silently
// dropping data at the network/pipeline boundary.
func TestRuntimeConfigFrom_GoldenMapping(t *testing.T) {
	got, err := runtimeConfigFrom(fullChainConfig(), fullPipelineConfig(), "/data")
	if err != nil {
		t.Fatalf("runtimeConfigFrom: %v", err)
	}
	want := wantRuntimeConfig("/data")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtimeConfigFrom mismatch:\n got  = %#v\n want = %#v", got, want)
	}
}

// TestRuntimeConfigFrom_EmptyDataDirLeavesLogDirsUnset asserts the unit-test
// seam: an empty dataDir leaves TlogDir/RejectLogDir unset (Build's in-memory
// fallback), rather than resolving to a bogus relative "tlog" path in the
// caller's working directory.
func TestRuntimeConfigFrom_EmptyDataDirLeavesLogDirsUnset(t *testing.T) {
	got, err := runtimeConfigFrom(fullChainConfig(), &pipelineconfig.Config{}, "")
	if err != nil {
		t.Fatalf("runtimeConfigFrom: %v", err)
	}
	if got.TlogDir != "" || got.RejectLogDir != "" {
		t.Errorf("TlogDir=%q RejectLogDir=%q, want both empty for an empty dataDir", got.TlogDir, got.RejectLogDir)
	}
}

// TestRuntimeConfigFrom_NonNATSTransportWithLoopsFails is the fail-closed
// regression guard (review finding on this task's first pass): a non-NATS
// transport (the dev-only noop transport) with configured loops must be a
// BOOT ERROR naming the offending transport — the faithful relocation of
// pipeline/runtime's pre-severance in-Build "data-plane loops require the
// nats transport" guard. Silently mapping zero loops instead (the first-pass
// behavior this replaces) would fail OPEN: an operator who mistakenly wires
// a data-plane config under a noop transport would see the node boot
// successfully and simply never run the loops they configured, instead of
// the boot dying with a legible reason.
func TestRuntimeConfigFrom_NonNATSTransportWithLoopsFails(t *testing.T) {
	chainCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	_, err := runtimeConfigFrom(chainCfg, fullPipelineConfig(), "")
	if err == nil {
		t.Fatal("non-NATS transport with configured loops: want a boot error, got nil")
	}
	if !strings.Contains(err.Error(), chainconfig.TransportNoop) {
		t.Errorf("error %q does not name the offending transport %q", err, chainconfig.TransportNoop)
	}
}

// TestRuntimeConfigFrom_NonNATSTransportNoLoopsOK asserts the benign case:
// a non-NATS transport with NO configured loops maps cleanly (there is
// nothing for the guard above to protect — an HTTP-only node with a noop
// transport and an empty pipeline config is a legitimate deployment shape).
func TestRuntimeConfigFrom_NonNATSTransportNoLoopsOK(t *testing.T) {
	chainCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	got, err := runtimeConfigFrom(chainCfg, &pipelineconfig.Config{}, "")
	if err != nil {
		t.Fatalf("non-NATS transport with zero loops: want no error, got %v", err)
	}
	if len(got.Loops) != 0 {
		t.Errorf("Loops = %d, want 0", len(got.Loops))
	}
}
