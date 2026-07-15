package batchresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

const issuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

// credOf builds a VC, optionally linking previousCredential by content address.
func credOf(t *testing.T, prev string) *vc.PipelinePassCredential {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != "" {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func hashOf(t *testing.T, c *vc.PipelinePassCredential) string {
	t.Helper()
	h, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustJSON(t *testing.T, c *vc.PipelinePassCredential) []byte {
	t.Helper()
	b, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fakeFetcher struct {
	fn    func(ctx context.Context, endpoint, addr string) (*vc.PipelinePassCredential, error)
	calls []string // endpoints called
}

func (f *fakeFetcher) Fetch(ctx context.Context, ep, addr string) (*vc.PipelinePassCredential, error) {
	f.calls = append(f.calls, ep)
	return f.fn(ctx, ep, addr)
}

type fakeDID struct {
	doc *did.DIDDocument
	err error
}

func (f fakeDID) Resolve(_ context.Context, _ string) (*did.DIDDocument, error) { return f.doc, f.err }

type fakeGuard struct{ deny map[string]bool }

func (g fakeGuard) CheckURL(_ context.Context, raw string) error {
	if g.deny[raw] {
		return errors.New("ssrf: blocked")
	}
	return nil
}

func okConfig() Config {
	return Config{Interval: time.Second, BatchSize: 16, MaxRetries: 3, MaxDepth: 10}
}

func notFound() error { return connect.NewError(connect.CodeNotFound, errors.New("absent")) }

// newWiring returns a real pool + service (the Submitter) over memstore.
func newWiring() (*memstore.Pool, *vcresolver.Service) {
	pool := memstore.NewPool()
	return pool, vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
}

func TestNew_RejectsNilDepsAndBadConfig(t *testing.T) {
	pool, svc := newWiring()
	f := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) { return nil, notFound() }}
	d := fakeDID{}
	g := fakeGuard{}
	good := okConfig()

	nilCases := []struct {
		name  string
		pool  Pool
		sub   Submitter
		fetch Fetcher
		didr  DIDResolver
		guard Guard
	}{
		{"pool", nil, svc, f, d, g},
		{"sub", pool, nil, f, d, g},
		{"fetch", pool, svc, nil, d, g},
		{"did", pool, svc, f, nil, g},
		{"guard", pool, svc, f, d, nil},
	}
	for _, tc := range nilCases {
		if _, err := New(tc.pool, tc.sub, tc.fetch, tc.didr, tc.guard, good); err == nil {
			t.Errorf("nil %s: want error, got nil", tc.name)
		}
	}

	badCfg := map[string]Config{
		"interval":   {Interval: 0, BatchSize: 1, MaxRetries: 1, MaxDepth: 1},
		"batchSize":  {Interval: time.Second, BatchSize: 0, MaxRetries: 1, MaxDepth: 1},
		"maxRetries": {Interval: time.Second, BatchSize: 1, MaxRetries: 0, MaxDepth: 1},
		"maxDepth":   {Interval: time.Second, BatchSize: 1, MaxRetries: 1, MaxDepth: 0},
	}
	for name, c := range badCfg {
		if _, err := New(pool, svc, f, d, g, c); err == nil {
			t.Errorf("bad config %s: want error, got nil", name)
		}
	}

	if _, err := New(pool, svc, f, d, g, good); err != nil {
		t.Errorf("valid construction: unexpected error %v", err)
	}
}

// Happy path: a queued hole whose predecessor the peer holds is fetched, content-address
// verified, stored, and removed from the pool — the predecessor becomes resolvable locally.
func TestDrainOnce_FetchesHeldPredecessor(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	p := credOf(t, "") // origin the peer holds
	pAddr := hashOf(t, p)
	h := credOf(t, pAddr) // consumed head linking P
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://peer.example/vc", 0); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 1 {
		t.Fatalf("precondition: pool len = %d, want 1", pool.Len())
	}

	fetch := &fakeFetcher{fn: func(_ context.Context, _, addr string) (*vc.PipelinePassCredential, error) {
		if addr == pAddr {
			return p, nil
		}
		return nil, notFound()
	}}
	r, err := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, okConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.drainOnce(ctx); err != nil {
		t.Fatalf("drainOnce: %v", err)
	}

	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (hole filled)", pool.Len())
	}
	if _, err := svc.ResolveVC(ctx, pAddr); err != nil {
		t.Errorf("predecessor not resolvable after drain: %v", err)
	}
	if len(fetch.calls) != 1 || fetch.calls[0] != "https://peer.example/vc" {
		t.Errorf("fetch calls = %v, want one to the hint endpoint", fetch.calls)
	}
}

// A two-deep chain (head → parent → origin) resolves to origin across two ticks: tick 1
// fills the parent hole and enqueues the grandparent at depth+1; tick 2 fills it.
func TestDrainOnce_TwoDeepChain_ResolvesAcrossTwoTicks(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	g := credOf(t, "") // origin
	gAddr := hashOf(t, g)
	pp := credOf(t, gAddr) // parent
	ppAddr := hashOf(t, pp)
	h := credOf(t, ppAddr) // consumed head
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://peer.example/vc", 0); err != nil {
		t.Fatal(err)
	}

	held := map[string]*vc.PipelinePassCredential{ppAddr: pp, gAddr: g}
	fetch := &fakeFetcher{fn: func(_ context.Context, _, addr string) (*vc.PipelinePassCredential, error) {
		if c, ok := held[addr]; ok {
			return c, nil
		}
		return nil, notFound()
	}}
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, okConfig())

	// Tick 1: parent filled, grandparent enqueued at depth 2.
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveVC(ctx, ppAddr); err != nil {
		t.Errorf("parent not resolvable after tick 1: %v", err)
	}
	rem, _ := pool.ListNewest(10)
	if len(rem) != 1 || rem[0].Hash != gAddr || rem[0].AssemblyDepth != 2 {
		t.Fatalf("after tick 1, pool = %+v, want [grandparent @ depth 2]", rem)
	}

	// Tick 2: grandparent filled, pool empty.
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 0 {
		t.Errorf("after tick 2: pool len = %d, want 0", pool.Len())
	}
	if _, err := svc.ResolveVC(ctx, gAddr); err != nil {
		t.Errorf("grandparent not resolvable after tick 2: %v", err)
	}
}

// Within one drain tick, an earlier entry can lower this hole's depth (keep-min) before it
// is processed; the depth bound must use the LIVE depth, not the stale snapshot, or a
// now-shallow hole is wrongly max-depth-dropped (multi-path truncation). Codex P2.
func TestDrainOnce_LiveDepth_NotStaleSnapshot(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	x := credOf(t, "") // the shared predecessor, fetchable from the peer
	xAddr := hashOf(t, x)
	a := credOf(t, xAddr) // A links X; storing A enqueues X at A.depth+1
	aAddr := hashOf(t, a)

	// X is queued deep (>= max-depth); A is queued shallow and NEWER (processed first).
	if err := pool.Add(vcresolver.UnresolvedEntry{Hash: xAddr, AssemblyDepth: 5}); err != nil {
		t.Fatal(err)
	}
	if err := pool.Add(vcresolver.UnresolvedEntry{Hash: aAddr, AssemblyDepth: 1, UpstreamEndpoint: "https://peer.example/vc"}); err != nil {
		t.Fatal(err)
	}

	held := map[string]*vc.PipelinePassCredential{aAddr: a, xAddr: x}
	fetch := &fakeFetcher{fn: func(_ context.Context, _, addr string) (*vc.PipelinePassCredential, error) {
		if c, ok := held[addr]; ok {
			return c, nil
		}
		return nil, notFound()
	}}
	cfg := okConfig()
	cfg.MaxDepth = 5 // X's snapshot depth (5) is at the bound; its live depth becomes 2
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, cfg)

	// Processing A (depth 1) stores it and enqueues X at depth 2 (keep-min 5→2). X must
	// then be fetched on its live depth (2 < 5), not dropped on the stale snapshot depth (5).
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveVC(ctx, xAddr); err != nil {
		t.Errorf("X wrongly dropped on stale snapshot depth (not resolvable): %v", err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (both A and X resolved)", pool.Len())
	}
}

// A hole at or beyond max-depth is dropped WITHOUT fetching, and the truncation is logged
// — the bound that stops an adversarial unbounded chain (D-17g-12).
func TestDrainOnce_MaxDepth_DropsWithoutFetching(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	h := credOf(t, "sha256:"+strings.Repeat("a", 64))
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://peer.example/vc", 0); err != nil {
		t.Fatal(err)
	} // predecessor queued at depth 1

	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		return nil, notFound()
	}}
	var buf bytes.Buffer
	cfg := okConfig()
	cfg.MaxDepth = 1 // depth-1 hole is at the bound → dropped
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, cfg, WithLogger(log.New(&buf, "", 0)))

	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fetch.calls) != 0 {
		t.Errorf("fetched despite max-depth: calls = %v", fetch.calls)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (dropped)", pool.Len())
	}
	if !strings.Contains(buf.String(), "max-depth") {
		t.Errorf("truncation not logged: %q", buf.String())
	}
}

// A peer returning a body that hashes to a different address is rejected — never stored,
// terminal drop (D-17g-11: never trust the peer).
func TestDrainOnce_ContentAddressMismatch_NotStored(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	wantAddr := "sha256:" + strings.Repeat("a", 64)
	h := credOf(t, wantAddr)
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://peer.example/vc", 0); err != nil {
		t.Fatal(err)
	}

	substitute := credOf(t, "") // hashes to something other than wantAddr
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		return substitute, nil
	}}
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveVC(ctx, hashOf(t, substitute)); err == nil {
		t.Error("substituted body was stored")
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (mismatch terminal drop)", pool.Len())
	}
}

// A guard-rejected endpoint is never dialed and the entry is dropped (D-17g-8).
func TestDrainOnce_SSRFRejected_NotDialed(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	h := credOf(t, "sha256:"+strings.Repeat("a", 64))
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://evil.internal/vc", 0); err != nil {
		t.Fatal(err)
	}
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		t.Error("fetch called despite SSRF rejection")
		return nil, notFound()
	}}
	guard := fakeGuard{deny: map[string]bool{"https://evil.internal/vc": true}}
	r, _ := New(pool, svc, fetch, fakeDID{}, guard, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (SSRF terminal drop)", pool.Len())
	}
}

// docWith builds a DID document carrying a single #vc-resolver VCResolver service.
func docWith(ep string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: issuer,
		Service: []did.ServiceEndpoint{{
			ID:              issuer + "#vc-resolver",
			Type:            "VCResolver",
			ServiceEndpoint: ep,
		}},
	})
}

// An entry with no UpstreamEndpoint hint resolves via the ReferrerIssuer's #vc-resolver
// service endpoint (D-17g-2).
func TestDrainOnce_IssuerDerivedEndpoint(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	p := credOf(t, "")
	pAddr := hashOf(t, p)
	h := credOf(t, pAddr)
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "", 0); err != nil { // empty hint
		t.Fatal(err)
	}

	const derived = "https://issuer.example/vc"
	fetch := &fakeFetcher{fn: func(_ context.Context, ep, addr string) (*vc.PipelinePassCredential, error) {
		if ep == derived && addr == pAddr {
			return p, nil
		}
		return nil, notFound()
	}}
	r, _ := New(pool, svc, fetch, fakeDID{doc: docWith(derived)}, fakeGuard{}, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (resolved via issuer endpoint)", pool.Len())
	}
	if len(fetch.calls) != 1 || fetch.calls[0] != derived {
		t.Errorf("fetch calls = %v, want one to %q", fetch.calls, derived)
	}
}

// A connection error on the hint falls back to the issuer-derived endpoint (D-17g-6).
func TestDrainOnce_ConnectionError_FallsBackToIssuer(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	p := credOf(t, "")
	pAddr := hashOf(t, p)
	h := credOf(t, pAddr)
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://hint.example/vc", 0); err != nil {
		t.Fatal(err)
	}

	const derived = "https://issuer.example/vc"
	fetch := &fakeFetcher{fn: func(_ context.Context, ep, addr string) (*vc.PipelinePassCredential, error) {
		if ep == "https://hint.example/vc" {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("dial fail"))
		}
		if ep == derived && addr == pAddr {
			return p, nil
		}
		return nil, notFound()
	}}
	r, _ := New(pool, svc, fetch, fakeDID{doc: docWith(derived)}, fakeGuard{}, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (fell back to issuer)", pool.Len())
	}
	if len(fetch.calls) != 2 {
		t.Errorf("fetch calls = %v, want hint then issuer (2)", fetch.calls)
	}
}

// A NotFound is a definitive miss: the entry is retried, NOT failed over to another
// endpoint (D-17g-6).
func TestDrainOnce_NotFound_IsMissNoFallback(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	h := credOf(t, "sha256:"+strings.Repeat("a", 64))
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://hint.example/vc", 0); err != nil {
		t.Fatal(err)
	}
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		return nil, notFound()
	}}
	r, _ := New(pool, svc, fetch, fakeDID{doc: docWith("https://issuer.example/vc")}, fakeGuard{}, okConfig())
	if err := r.drainOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fetch.calls) != 1 || fetch.calls[0] != "https://hint.example/vc" {
		t.Errorf("fetch calls = %v, want only the hint (NotFound is no fallback)", fetch.calls)
	}
	rem, _ := pool.ListNewest(10)
	if len(rem) != 1 || rem[0].RetryCount != 1 {
		t.Errorf("entry = %+v, want retained with RetryCount 1", rem)
	}
}

// A hole is retried up to MaxRetries, then dropped (D-17g-6).
func TestDrainOnce_BoundedRetry_DropsAfterMaxRetries(t *testing.T) {
	pool, svc := newWiring()
	ctx := context.Background()

	h := credOf(t, "sha256:"+strings.Repeat("a", 64))
	if _, err := svc.StoreVC(ctx, mustJSON(t, h), "https://hint.example/vc", 0); err != nil {
		t.Fatal(err)
	}
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}}
	cfg := okConfig()
	cfg.MaxRetries = 2
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, cfg)

	// RetryCount 0→1, 1→2, then 2 >= MaxRetries → drop.
	for i := 0; i < 3; i++ {
		if err := r.drainOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if pool.Len() != 0 {
		t.Errorf("pool len = %d, want 0 (dropped after max retries)", pool.Len())
	}
}

// Run returns promptly (nil) when its context is cancelled.
func TestRun_StopsOnContextCancel(t *testing.T) {
	pool, svc := newWiring()
	fetch := &fakeFetcher{fn: func(context.Context, string, string) (*vc.PipelinePassCredential, error) {
		return nil, notFound()
	}}
	cfg := okConfig()
	cfg.Interval = 10 * time.Millisecond
	r, _ := New(pool, svc, fetch, fakeDID{}, fakeGuard{}, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// A service whose ID is another URI merely ENDING in "#vc-resolver" is not
// this issuer's advertisement: it must be ignored — neither captured as the
// endpoint nor counted into a false ambiguity (the exact-id rule the bundle
// exporter applies; P1-3 alignment).
func TestDeriveIssuerEndpoint_ForeignSuffixIgnored(t *testing.T) {
	pool, svc := newWiring()
	const legit = "https://issuer.example/vc"
	doc := did.New(did.DocumentFields{
		ID: issuer,
		Service: []did.ServiceEndpoint{
			{ID: "did:dplaax:reg:org:mallory#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://mallory.example/vc"},
			{ID: issuer + "#vc-resolver", Type: "VCResolver", ServiceEndpoint: legit},
		},
	})
	r, err := New(pool, svc, &fakeFetcher{}, fakeDID{doc: doc}, fakeGuard{}, okConfig())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.deriveIssuerEndpoint(context.Background(), issuer)
	if err != nil {
		t.Fatalf("deriveIssuerEndpoint: %v (foreign-suffix id must not create ambiguity)", err)
	}
	if got != legit {
		t.Errorf("endpoint = %q, want %q", got, legit)
	}
}

// A document carrying ONLY a foreign-suffix id has no advertisement for this
// issuer: zero matches, fail-closed error (never route to the foreign URI).
func TestDeriveIssuerEndpoint_ForeignOnlyIsZeroMatches(t *testing.T) {
	pool, svc := newWiring()
	doc := did.New(did.DocumentFields{
		ID: issuer,
		Service: []did.ServiceEndpoint{
			{ID: "did:dplaax:reg:org:mallory#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://mallory.example/vc"},
		},
	})
	r, err := New(pool, svc, &fakeFetcher{}, fakeDID{doc: doc}, fakeGuard{}, okConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.deriveIssuerEndpoint(context.Background(), issuer); err == nil {
		t.Fatal("want zero-matches error, got nil (foreign endpoint captured)")
	}
}

// The bare "#fragment" advertisement form (as issued before fragment
// re-anchoring) matches too — the same two accepted forms as the exporter.
func TestDeriveIssuerEndpoint_BareFragmentAccepted(t *testing.T) {
	pool, svc := newWiring()
	const legit = "https://issuer.example/vc"
	doc := did.New(did.DocumentFields{
		ID: issuer,
		Service: []did.ServiceEndpoint{
			{ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: legit},
		},
	})
	r, err := New(pool, svc, &fakeFetcher{}, fakeDID{doc: doc}, fakeGuard{}, okConfig())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.deriveIssuerEndpoint(context.Background(), issuer)
	if err != nil {
		t.Fatalf("deriveIssuerEndpoint: %v", err)
	}
	if got != legit {
		t.Errorf("endpoint = %q, want %q", got, legit)
	}
}

// Both accepted id forms present at once is an ambiguity: fail closed, never
// pick one (the "two or more matches: error" arm of the shared rule).
func TestDeriveIssuerEndpoint_BothFormsIsAmbiguous(t *testing.T) {
	pool, svc := newWiring()
	doc := did.New(did.DocumentFields{
		ID: issuer,
		Service: []did.ServiceEndpoint{
			{ID: "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://a.example/vc"},
			{ID: issuer + "#vc-resolver", Type: "VCResolver", ServiceEndpoint: "https://b.example/vc"},
		},
	})
	r, err := New(pool, svc, &fakeFetcher{}, fakeDID{doc: doc}, fakeGuard{}, okConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.deriveIssuerEndpoint(context.Background(), issuer); err == nil {
		t.Fatal("want ambiguity error for two matching advertisements, got nil")
	}
}
