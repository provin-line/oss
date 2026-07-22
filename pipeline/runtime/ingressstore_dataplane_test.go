package runtime

import (
	"context"
	"testing"
)

// TestBuildDataPlane_SinkRequiresVCStore asserts that a sink loop without a VCStore
// is a build error (fail closed, D-17f-7) — mirroring TestBuildDataPlane_SinkRequiresDeps.
//
// The companion "assembles when a real vcresolver.Service is passed as
// VCStore" coverage this file used to carry moved out with the boundary
// severance: IngressStorer's shape (a bare body-address string, not
// vcresolver.StoreVCResult) means this package can no longer accept a real
// *vcresolver.Service directly (network/ and pipeline/ never import each
// other, AGENTS.md rule 2) — cmd/standalone adapts it for production and its
// own e2e tests. The "assembles with a non-nil VCStore" case is already
// covered here (and in dataplane_test.go) via the package's fakeVCStore.
func TestBuildDataPlane_SinkRequiresVCStore(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	// Resolver and SinkWriter are provided, but VCStore is nil — must fail.
	if _, err := Build(context.Background(), withNATS(url, accSeed, dpSinkCfg()), dpKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: nil,
		VCStore:    nil,
	}); err == nil {
		t.Fatal("sink loop without VCStore: want build error, got nil")
	}
}

// TestBuildDataPlane_ChainedRequiresVCStore asserts that a chained loop without a
// VCStore is a build error (D-17f-7).
func TestBuildDataPlane_ChainedRequiresVCStore(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	if _, err := Build(context.Background(), withNATS(url, accSeed, dpChainedCfg("")), dpKeyStore(t), Deps{
		Resolver: stubResolver{},
		VCStore:  nil,
	}); err == nil {
		t.Fatal("chained loop without VCStore: want build error, got nil")
	}
}
