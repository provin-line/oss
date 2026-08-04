package vc_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/cache"
	"github.com/provin-line/oss/vc"
)

// How many DID documents VerifyChain resolves is a load-bearing number outside
// this package. The production resolver (network/pkg/didresolver) performs a
// network round trip per resolution and fails fast at
// maxConcurrentResolutions, so the count sets both a delivery's latency and a
// deployment's sustainable throughput. provin.bench models delivery cost from
// it.
//
// Since resolver/cache exists, the product offers TWO composition modes, and
// each has its own shape:
//
//   - UNCACHED (the verifier over a bare resolver — the default composition):
//     per credential, 1 resolution for signer authenticity plus one per
//     controller-chain hop; linear in chain length; repeated documents are
//     re-resolved, never deduplicated.
//   - CACHED (the verifier over resolver/cache): each DISTINCT document is
//     resolved once on first touch per TTL window; every later use within the
//     window is a local read, so the underlying count is set by the number of
//     distinct documents, not by chain length.
//
// The tests below pin both shapes. They live here, next to the verifier that
// owns the behaviour, rather than beside the benchmark that consumes it: a
// guard in the benchmark repository would only fail when someone bumped its
// pin, long after the change that broke it.

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
	// the UNCACHED composition performs no deduplication, and provin.bench's
	// uncached cost model depends on that. The cached composition's first-touch
	// shape is pinned separately below.
	owner := ownerOf(t, procAOrigin)
	if got := counter.seen[owner]; got != len(chain) {
		t.Errorf("owner document %s resolved %d times, want %d (once per credential; the uncached path deduplicates nothing)",
			owner, got, len(chain))
	}
}

// TestVerifyChain_DIDResolutionScalesWithDepth pins the other half of the
// UNCACHED shape: the budget is linear in chain length, with no amortization
// across credentials. Caching exists — it is the explicit resolver/cache
// composition, pinned by TestVerifyChain_DIDResolutionBudget_Cached — so a
// sub-linear result HERE would mean the bare verifier composition gained an
// implicit cache, which must never happen: the uncached mode is what
// freshness-critical deployments rely on and what provin.bench's uncached
// cost model publishes.
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
			"Sub-linear means the bare composition became cached or deduplicating; super-linear means a "+
			"per-chain resolution was added. Either changes provin.bench's uncached cost model.", got, want)
	}
}

// TestVerifyChain_DIDResolutionBudget_Cached pins the CACHED composition's
// shape: with resolver/cache between the verifier and the resolver, the
// underlying count is the number of DISTINCT documents the chain touches
// (first-touch fills), not linear in chain length — and a repeated walk within
// the TTL reaches the resolver zero times. provin.bench's cached cost model
// derives from exactly this: after warmup, DID resolution leaves the
// synchronous path entirely.
func TestVerifyChain_DIDResolutionBudget_Cached(t *testing.T) {
	origin, child, base := buildChainFixture(t, procAOrigin, procBSameOrg)
	counter := &countingResolver{next: base}
	cached, err := cache.New(counter, cache.Config{})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	v := vc.NewVerifier(cached, ed25519Verifier())

	chain := []*vc.PipelinePassCredential{origin, child}
	res, err := v.VerifyChain(context.Background(), chain)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Fatalf("Overall=%v, want Verified — the budget below is only meaningful for a fully walked chain", res.Overall)
	}

	// The chain touches three distinct documents — procA's, procB's, and their
	// shared owner — where the uncached walk pays 2 credentials × 3 = 6.
	if got := counter.calls.Load(); got != 3 {
		t.Errorf("underlying resolutions = %d, want 3 (one per DISTINCT document; the cache deduplicates repeats)", got)
	}
	for docID, n := range counter.seen {
		if n != 1 {
			t.Errorf("document %s reached the resolver %d times, want 1 (first touch only)", docID, n)
		}
	}

	// A second walk within the TTL is entirely local.
	if _, err := v.VerifyChain(context.Background(), chain); err != nil {
		t.Fatalf("second VerifyChain: %v", err)
	}
	if got := counter.calls.Load(); got != 3 {
		t.Errorf("underlying resolutions after a second walk = %d, want 3 (every use within the TTL is a hit)", got)
	}
}
