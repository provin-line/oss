package main

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/pipelineconfig"
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
	_, err := buildSourceLoop(nil, nil, nil, lc)
	if err == nil {
		t.Fatal("aggregate claim on ingest source loop: want boot error, got nil")
	}
	if !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("boot error %q should name the aggregate claim", err)
	}
}
