package vc_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

// How many DID documents VerifyChain resolves is a load-bearing number outside
// this package. The production resolver (network/pkg/didresolver) has no cache
// and fails fast at maxConcurrentResolutions, so each resolution is a network
// round trip and the count sets both a delivery's latency and a deployment's
// sustainable throughput. provin.bench models delivery cost from it.
//
// The count is not a constant of the code: it is
//
//	per credential: 1 (signer authenticity) + one per controller-chain hop
//
// so a deployment's DID hierarchy depth changes it. What must not change
// silently is the SHAPE — one resolution per credential plus one per hop, with
// no caching and no deduplication of repeated documents.
//
// This test pins that shape. It lives here, next to the verifier that owns the
// behaviour, rather than beside the benchmark that consumes it: a guard in the
// benchmark repository would only fail when someone bumped its pin, long after
// the change that broke it.

// countingResolver counts resolutions and records repeats, since the absence of
// caching is part of what is being pinned.
type countingResolver struct {
	next  resolver.Resolver
	calls atomic.Int64
	seen  map[string]int
}

func (c *countingResolver) Resolve(ctx context.Context, didString string) (*did.DIDDocument, error) {
	c.calls.Add(1)
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[didString]++
	return c.next.Resolve(ctx, didString)
}

func TestVerifyChain_DIDResolutionBudget(t *testing.T) {
	origin, child, base := buildChainFixture(t, procAOrigin, procBSameOrg)
	counter := &countingResolver{next: base}
	v := vc.NewVerifier(counter, ed25519Verifier())

	chain := []*vc.PipelinePassCredential{origin, child}
	res, err := v.VerifyChain(context.Background(), chain)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Fatalf("Overall=%v, want Verified — the budget below is only meaningful for a fully walked chain", res.Overall)
	}

	// This fixture's controller chain is Process -> Owner (two hops: the process
	// document, then the self-controlled owner), so each credential costs
	// 1 + 2 = 3 resolutions.
	const perCredential = 3
	want := int64(len(chain) * perCredential)
	if got := counter.calls.Load(); got != want {
		t.Errorf("DID resolutions = %d, want %d (%d credentials x %d: 1 signer authenticity + 2 controller-chain hops).\n"+
			"A change here changes every provin.bench latency figure and the deployment's "+
			"sustainable throughput against didresolver's concurrency bound. If the new count is "+
			"intended, update this test AND re-run the gate benchmarks.",
			got, want, len(chain), perCredential)
	}

	// The owner document is resolved once per credential, not once per chain:
	// there is no cache on this path, and provin.bench's cost model depends on
	// that. If a cache is introduced, this expectation should fall — and the
	// benchmark's round-trip model must be revisited in the same change.
	owner := ownerOf(t, procAOrigin)
	if got := counter.seen[owner]; got != len(chain) {
		t.Errorf("owner document %s resolved %d times, want %d (once per credential; the path is uncached)",
			owner, got, len(chain))
	}
}

// TestVerifyChain_DIDResolutionScalesWithDepth pins the other half of the shape:
// the budget is linear in chain length, with no amortization across credentials.
// A sub-linear result would mean caching appeared, which changes the cost model
// provin.bench publishes.
func TestVerifyChain_DIDResolutionScalesWithDepth(t *testing.T) {
	oneHop, twoHop, base := buildChainFixture(t, procAOrigin, procBSameOrg)

	single := &countingResolver{next: base}
	if _, err := vc.NewVerifier(single, ed25519Verifier()).
		VerifyChain(context.Background(), []*vc.PipelinePassCredential{oneHop}); err != nil {
		t.Fatalf("VerifyChain(origin): %v", err)
	}

	pair := &countingResolver{next: base}
	if _, err := vc.NewVerifier(pair, ed25519Verifier()).
		VerifyChain(context.Background(), []*vc.PipelinePassCredential{oneHop, twoHop}); err != nil {
		t.Fatalf("VerifyChain(origin, child): %v", err)
	}

	if got, want := pair.calls.Load(), 2*single.calls.Load(); got != want {
		t.Errorf("two-credential chain resolved %d documents, want %d (exactly twice the one-credential chain).\n"+
			"Sub-linear means resolution became cached or deduplicated; super-linear means a per-chain "+
			"resolution was added. Either changes provin.bench's cost model.", got, want)
	}
}
