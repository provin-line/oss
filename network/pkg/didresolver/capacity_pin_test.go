package didresolver

import "testing"

// The resolution admission bound is a load-bearing number outside this package.
// provin.bench's BenchmarkGateBoundedResolver saturates a model of this
// semaphore, and gate-scaling-results.md §5 publishes the resulting capacity
// ceiling as 64 / (per-delivery slot-hold time). The fail-fast semantics are
// pinned by TestResolve_ConcurrencyBounded_FailFast; what is NOT otherwise
// pinned is the capacity itself.
//
// This test pins it next to the constant that owns it, rather than beside the
// benchmark that consumes it: a guard in the benchmark repository would only
// fail when someone bumped its pin, long after the change that broke it.
func TestDefaultResolutionBoundIsThePublishedCapacityModel(t *testing.T) {
	r := New(nil)
	if got := cap(r.sem); got != 64 {
		t.Errorf("default resolution semaphore capacity = %d, want 64.\n"+
			"This bound sets the published capacity ceiling (gate-scaling-results.md §5, "+
			"provin.bench gateResolverSlots). If the new capacity is intended, update the "+
			"benchmark constant AND re-run BenchmarkGateBoundedResolver, recording the new "+
			"numbers in the same change.", got)
	}
}
