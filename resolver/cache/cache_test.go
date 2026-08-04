package cache_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/cache"
)

// countingResolver serves programmatically built documents and counts every
// call that reaches it — the observable that separates a hit (count unchanged)
// from a miss (count grown).
type countingResolver struct {
	mu    sync.Mutex
	calls map[string]int
	total atomic.Int64
	fail  error // when set, every Resolve returns this error
}

func newCountingResolver() *countingResolver {
	return &countingResolver{calls: map[string]int{}}
}

func (c *countingResolver) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	c.total.Add(1)
	c.mu.Lock()
	c.calls[didStr]++
	c.mu.Unlock()
	if c.fail != nil {
		return nil, c.fail
	}
	return testDoc(didStr), nil
}

func (c *countingResolver) count(didStr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[didStr]
}

func testDoc(id string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		Context:    did.IssuedDocumentContexts(),
		ID:         id,
		Controller: id,
	})
}

// fakeClock is a settable clock for TTL boundaries; the zero value starts at a
// fixed instant so tests are deterministic.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newCached(t *testing.T, next resolver.Resolver, cfg cache.Config) (*cache.Resolver, *fakeClock) {
	t.Helper()
	r, err := cache.New(next, cfg)
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	clock := newFakeClock()
	cache.SetNowForTest(r, clock.now)
	return r, clock
}

func TestResolveCachesWithinTTLAndIsolatesCallers(t *testing.T) {
	ctx := context.Background()
	next := newCountingResolver()
	r, clock := newCached(t, next, cache.Config{})

	const id = "did:dplaax:reg:org:a"
	first, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	clock.advance(30 * time.Second) // within the 60s default
	second, err := r.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := next.count(id); got != 1 {
		t.Errorf("underlying resolutions = %d, want 1 (second call must be a hit)", got)
	}
	if second.ID() != first.ID() {
		t.Errorf("hit returned a different identity: %s vs %s", second.ID(), first.ID())
	}
	if first == second {
		t.Error("hit returned the same *did.DIDDocument as the miss: cached objects must not be shared between callers")
	}
}

func TestTTLIsAbsoluteFromFillAndHitsDoNotRefresh(t *testing.T) {
	next := newCountingResolver()
	r, clock := newCached(t, next, cache.Config{TTL: 60 * time.Second})

	const id = "did:dplaax:reg:org:a"
	mustResolve(t, r, id) // fill at t=0
	clock.advance(30 * time.Second)
	mustResolve(t, r, id) // hit at t=30 — must NOT extend the entry's life
	clock.advance(31 * time.Second)
	mustResolve(t, r, id) // t=61 > 60: expired even though a hit occurred at t=30
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (expiry is absolute from fill; hits must not refresh)", got)
	}
}

func TestExpiredEntryIsNeverServed(t *testing.T) {
	next := newCountingResolver()
	r, clock := newCached(t, next, cache.Config{TTL: 10 * time.Second})

	const id = "did:dplaax:reg:org:a"
	mustResolve(t, r, id)
	clock.advance(10 * time.Second) // exactly TTL: expired, not "still fresh"
	mustResolve(t, r, id)
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (an entry at exactly TTL must not be served)", got)
	}
}

func TestErrorsAreNotCached(t *testing.T) {
	ctx := context.Background()
	next := newCountingResolver()
	r, _ := newCached(t, next, cache.Config{})

	const id = "did:dplaax:reg:org:a"
	next.fail = errors.New("registry unreachable")
	if _, err := r.Resolve(ctx, id); err == nil {
		t.Fatal("resolve during outage: want error")
	}
	next.fail = nil
	if _, err := r.Resolve(ctx, id); err != nil {
		t.Fatalf("resolve after recovery: %v", err)
	}
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (a failure must not be cached)", got)
	}
	// The recovery fill must now serve hits.
	mustResolve(t, r, id)
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d after recovery hit, want 2", got)
	}
}

func TestNotFoundKeepsItsIdentityAndIsNotCached(t *testing.T) {
	ctx := context.Background()
	next := newCountingResolver()
	r, _ := newCached(t, next, cache.Config{})

	const id = "did:dplaax:reg:org:missing"
	next.fail = fmt.Errorf("no doc: %w", resolver.ErrNotFound)
	_, err := r.Resolve(ctx, id)
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Fatalf("error lost its ErrNotFound identity through the cache: %v", err)
	}
	if _, err := r.Resolve(ctx, id); !errors.Is(err, resolver.ErrNotFound) {
		t.Fatalf("second miss: %v", err)
	}
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (definitive absence must not be cached: absence can become presence at registration)", got)
	}
}

func TestOversizedDocumentIsServedButNotCached(t *testing.T) {
	ctx := context.Background()
	next := newCountingResolver()
	// Any real document marshals larger than 8 bytes, so nothing is cacheable.
	r, _ := newCached(t, next, cache.Config{MaxBytes: 8})

	const id = "did:dplaax:reg:org:a"
	doc, err := r.Resolve(ctx, id)
	if err != nil || doc == nil {
		t.Fatalf("over-budget document must still be served: doc=%v err=%v", doc, err)
	}
	mustResolve(t, r, id)
	if got := next.count(id); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (an over-budget document is non-cacheable, never an error)", got)
	}
}

func TestEvictionByEntryCountIsLRU(t *testing.T) {
	next := newCountingResolver()
	r, _ := newCached(t, next, cache.Config{MaxEntries: 2})

	a, b, c := "did:dplaax:reg:org:a", "did:dplaax:reg:org:b", "did:dplaax:reg:org:c"
	mustResolve(t, r, a)
	mustResolve(t, r, b)
	mustResolve(t, r, a) // a is now more recent than b
	mustResolve(t, r, c) // evicts b, the least recently used
	mustResolve(t, r, a)
	mustResolve(t, r, b)
	if got := next.count(a); got != 1 {
		t.Errorf("a resolved %d times, want 1 (recently used; must survive)", got)
	}
	if got := next.count(b); got != 2 {
		t.Errorf("b resolved %d times, want 2 (least recently used; must be evicted)", got)
	}
}

func TestEvictionByByteBudget(t *testing.T) {
	next := newCountingResolver()
	one, err := testDoc("did:dplaax:reg:org:a").MarshalJSON()
	if err != nil {
		t.Fatalf("marshal probe: %v", err)
	}
	// Budget for one document but not two (ids differ by one byte, not enough
	// to change the arithmetic).
	r, _ := newCached(t, next, cache.Config{MaxBytes: int64(len(one)) + 10})

	a, b := "did:dplaax:reg:org:a", "did:dplaax:reg:org:b"
	mustResolve(t, r, a)
	mustResolve(t, r, b) // admitting b must evict a to fit the budget
	mustResolve(t, r, a)
	if got := next.count(a); got != 2 {
		t.Errorf("a resolved %d times, want 2 (evicted by the byte budget)", got)
	}
}

func TestConfigValidation(t *testing.T) {
	next := newCountingResolver()
	if _, err := cache.New(nil, cache.Config{}); !errors.Is(err, cache.ErrMissingResolver) {
		t.Errorf("nil next: err = %v, want ErrMissingResolver", err)
	}
	for name, cfg := range map[string]cache.Config{
		"negative TTL":     {TTL: -time.Second},
		"negative entries": {MaxEntries: -1},
		"negative bytes":   {MaxBytes: -1},
	} {
		if _, err := cache.New(next, cfg); !errors.Is(err, cache.ErrInvalidConfig) {
			t.Errorf("%s: err = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := cache.New(next, cache.Config{}); err != nil {
		t.Errorf("zero config must apply defaults, got %v", err)
	}
}

func TestConcurrentResolveIsRaceFreeAndCoalescesToHits(t *testing.T) {
	ctx := context.Background()
	next := newCountingResolver()
	r, _ := newCached(t, next, cache.Config{})

	const workers = 16
	const perWorker = 50
	ids := []string{"did:dplaax:reg:org:a", "did:dplaax:reg:org:b", "did:dplaax:reg:org:c"}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := ids[(w+i)%len(ids)]
				doc, err := r.Resolve(ctx, id)
				if err != nil || doc == nil || doc.ID() != id {
					t.Errorf("concurrent resolve %s: doc=%v err=%v", id, doc, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	// No singleflight: concurrent cold misses may each reach the resolver, so
	// the bound is workers-per-id on the first wave, not 1. What must hold is
	// that the steady state is hits: far fewer underlying calls than resolves.
	if got, limit := next.total.Load(), int64(workers*len(ids)); got > limit {
		t.Errorf("underlying resolutions = %d, want <= %d (cold-wave bound)", got, limit)
	}
}

func mustResolve(t *testing.T, r *cache.Resolver, id string) *did.DIDDocument {
	t.Helper()
	doc, err := r.Resolve(context.Background(), id)
	if err != nil {
		t.Fatalf("resolve %s: %v", id, err)
	}
	if doc == nil || doc.ID() != id {
		t.Fatalf("resolve %s returned wrong document: %+v", id, doc)
	}
	return doc
}

// TestUnsafeIntegerDocumentIsServedButNotCached pins the canonicalization-
// fidelity admission gate: a document carrying an integer outside ±(2^53−1)
// cannot round-trip through RFC 8785 (binary64 rounds it), so a hit would
// return a numerically different body than the miss did. Such documents are
// served uncached.
func TestUnsafeIntegerDocumentIsServedButNotCached(t *testing.T) {
	ctx := context.Background()
	const id = "did:dplaax:reg:org:unsafe"
	raw, err := testDoc(id).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal probe: %v", err)
	}
	// Splice an unsafe integer literal into otherwise-valid document bytes;
	// building it through encoding/json would round at the test level.
	unsafeRaw := []byte(strings.Replace(string(raw), `"id":`, `"unsafe":9007199254740993,"id":`, 1))
	unsafeDoc := &did.DIDDocument{}
	if err := unsafeDoc.UnmarshalJSON(unsafeRaw); err != nil {
		t.Fatalf("unmarshal unsafe doc: %v", err)
	}

	next := &fixedResolver{doc: unsafeDoc}
	r, _ := newCached(t, next, cache.Config{})
	first, err := r.Resolve(ctx, id)
	if err != nil || first == nil {
		t.Fatalf("unsafe-number document must still be served: doc=%v err=%v", first, err)
	}
	if _, err := r.Resolve(ctx, id); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := next.calls.Load(); got != 2 {
		t.Errorf("underlying resolutions = %d, want 2 (a document that cannot round-trip canonicalization must not be cached)", got)
	}
}

// fixedResolver serves one pre-built document and counts calls.
type fixedResolver struct {
	doc   *did.DIDDocument
	calls atomic.Int64
}

func (f *fixedResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	f.calls.Add(1)
	return f.doc, nil
}

// TestHitParseBoundMatchesResolverAdmission pins the hit-path parse bound: the
// bare resolver holds its 64-slot admission semaphore through fetch AND parse,
// so enabling the cache must not raise the pre-authentication parse
// concurrency above what the bare path allowed.
func TestHitParseBoundMatchesResolverAdmission(t *testing.T) {
	next := newCountingResolver()
	r, _ := newCached(t, next, cache.Config{})
	if got := cache.HitParseSlotsForTest(r); got != 64 {
		t.Errorf("hit-parse slots = %d, want 64 (the production resolver's admission bound)", got)
	}
}
