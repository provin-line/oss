package cache_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/resolver/cache"
)

// Over a resolver that keeps the resolver.Resolver contract, Resolve answers
// with a document or an error, on a miss, on a hit, and when next fails.
func TestResolve_ReturnsADocumentOrAnError(t *testing.T) {
	const present = "did:dplaax:poc.dplaax.dev:org:acme"
	next := newCountingResolver()
	r, err := cache.New(next, cache.Config{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(d string) {
		t.Helper()
		if doc, err := r.Resolve(context.Background(), d); doc == nil && err == nil {
			t.Errorf("Resolve(%q): neither a document nor an error", d)
		}
	}
	check(present) // a miss
	check(present) // a hit
	if n := next.count(present); n != 1 {
		t.Fatalf("next resolved %s %d times, want 1: the second call was not a hit", present, n)
	}
	next.fail = errors.New("registry unavailable")
	for _, d := range []string{"did:dplaax:poc.dplaax.dev:org:absent", ""} {
		check(d)
	}
}
