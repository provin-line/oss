package netcompose

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

func brCred(t *testing.T, prev, fatField string) *vc.PipelinePassCredential {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != "" {
		subject["previousCredential"] = prev
	}
	if fatField != "" {
		subject["blob"] = fatField
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            pipelineDID + ":process:proc1",
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

func brHash(t *testing.T, c *vc.PipelinePassCredential) string {
	t.Helper()
	h, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func brMarshal(t *testing.T, c *vc.PipelinePassCredential) []byte {
	t.Helper()
	b, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func brConfig(loops []pipelineconfig.LoopConfig, interval time.Duration, maxBytes int) *pipelineconfig.Config {
	return &pipelineconfig.Config{
		Loops:             loops,
		MaxCredentialSize: maxBytes,
		BatchResolver: pipelineconfig.BatchResolverConfig{
			Interval:   interval,
			BatchSize:  16,
			MaxRetries: 3,
			MaxDepth:   1024,
		},
	}
}

// BuildBatchResolver builds unconditionally from its args now (Task 9): the "does this
// node have a consuming loop" gate moved to the composition roots (cmd/network always
// builds, since it never has a local loop to gate on).
// A source-only or zero-loop config therefore returns a non-nil runner just like a
// sink/chained config — the builder itself no longer inspects pipeCfg.HasConsumingLoop().
func TestBuildBatchResolver_BuildsUnconditionally(t *testing.T) {
	guard := core.NewURLGuard()
	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	resolver := didresolver.New(guard)

	for _, tc := range []struct {
		name  string
		loops []pipelineconfig.LoopConfig
	}{
		{"source-only", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSource}}},
		{"sink", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}},
		{"chained", []pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleChained}}},
		{"no-loops", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := brConfig(tc.loops, time.Second, 1<<20)
			r, err := BuildBatchResolver(pool, svc, guard, resolver, cfg)
			if err != nil {
				t.Fatalf("BuildBatchResolver: %v", err)
			}
			if r == nil {
				t.Error("runner is nil, want non-nil (the builder builds unconditionally now)")
			}
		})
	}
}

// peerVCResolver stands up a real VCResolverService over httptest, optionally size-capped,
// and returns the server plus its service so a test can seed credentials.
func peerVCResolver(t *testing.T, maxBytes int) (*httptest.Server, *vcresolver.Service) {
	t.Helper()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
	var opts []connect.HandlerOption
	if maxBytes > 0 {
		opts = append(opts, connect.WithReadMaxBytes(maxBytes))
	}
	_, h := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(svc), opts...)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, svc
}

func waitPoolEmpty(t *testing.T, pool *memstore.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pool.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pool not drained within deadline (len=%d)", pool.Len())
}

// End-to-end through the production peerFetcher + Runner: a consumed head's missing
// predecessor, held by a real peer VCResolverService, is fetched over the wire,
// content-address verified, and stored locally — the hole drains.
func TestBatchResolver_Integration_DrainsFromPeer(t *testing.T) {
	ctx := context.Background()

	peer, peerSvc := peerVCResolver(t, 0)
	p := brCred(t, "", "")
	pAddr := brHash(t, p)
	if _, err := peerSvc.StoreVC(ctx, brMarshal(t, p), "", 0); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	h := brCred(t, pAddr, "")
	if _, err := svc.StoreVC(ctx, brMarshal(t, h), peer.URL, 0); err != nil { // hint = peer
		t.Fatalf("seed local: %v", err)
	}
	if pool.Len() != 1 {
		t.Fatalf("precondition: pool len = %d, want 1", pool.Len())
	}

	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	resolver := didresolver.New(guard)
	cfg := brConfig([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}, 5*time.Millisecond, 1<<20)
	r, err := BuildBatchResolver(pool, svc, guard, resolver, cfg)
	if err != nil || r == nil {
		t.Fatalf("BuildBatchResolver: r=%v err=%v", r, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = r.Run(runCtx) }()

	waitPoolEmpty(t, pool)
	if _, err := svc.ResolveVC(ctx, pAddr); err != nil {
		t.Errorf("predecessor not resolvable locally after drain: %v", err)
	}
}

// An over-cap predecessor on the peer is rejected by the size-bounded fetch client and
// never stored locally (D-17g-13).
func TestBatchResolver_Integration_OverCapFetchRejected(t *testing.T) {
	ctx := context.Background()
	const cap = 512

	peer, peerSvc := peerVCResolver(t, 0) // peer uncapped: it holds a big VC
	big := brCred(t, "", strings.Repeat("x", cap*4))
	bigAddr := brHash(t, big)
	if _, err := peerSvc.StoreVC(ctx, brMarshal(t, big), "", 0); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	h := brCred(t, bigAddr, "")
	if _, err := svc.StoreVC(ctx, brMarshal(t, h), peer.URL, 0); err != nil {
		t.Fatalf("seed local: %v", err)
	}

	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	resolver := didresolver.New(guard)
	cfg := brConfig([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}, 5*time.Millisecond, cap)
	r, _ := BuildBatchResolver(pool, svc, guard, resolver, cfg)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = r.Run(runCtx) }()

	// The hole drains (terminal-dropped on the size error), but the big VC is NOT stored.
	waitPoolEmpty(t, pool)
	if _, err := svc.ResolveVC(ctx, bigAddr); err == nil {
		t.Error("over-cap predecessor was stored locally")
	}
}

// requireBearer is a peer-side interceptor that rejects any RPC lacking the exact bearer,
// modelling a real node's L1-protected VCResolverService.
func requireBearer(token string) connect.HandlerOption {
	return connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if req.Header().Get("Authorization") != "Bearer "+token {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing/bad bearer"))
			}
			return next(ctx, req)
		}
	}))
}

// The audit fetch must present the node's configured bearer: a real peer mounts
// VCResolverService behind L1 auth, so an unauthenticated fetch would never assemble
// (D-17g-10 revised — reuse the node's VCStoreBearer). Codex P1.
func TestBatchResolver_Integration_AuthenticatedPeer(t *testing.T) {
	ctx := context.Background()
	const token = "audit-token"

	peerSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
	_, ph := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(peerSvc), requireBearer(token))
	peer := httptest.NewServer(ph)
	t.Cleanup(peer.Close)
	p := brCred(t, "", "")
	pAddr := brHash(t, p)
	if _, err := peerSvc.StoreVC(ctx, brMarshal(t, p), "", 0); err != nil { // in-process seed (no interceptor)
		t.Fatalf("seed peer: %v", err)
	}

	pool := memstore.NewPool()
	svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
	h := brCred(t, pAddr, "")
	if _, err := svc.StoreVC(ctx, brMarshal(t, h), peer.URL, 0); err != nil {
		t.Fatalf("seed local: %v", err)
	}

	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	resolver := didresolver.New(guard)
	cfg := brConfig([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}, 5*time.Millisecond, 1<<20)
	cfg.VCStoreBearer = token
	cfg.CredentialOrigins = []string{peer.URL} // httptest's URL is an origin as the loader spells it
	r, err := BuildBatchResolver(pool, svc, guard, resolver, cfg)
	if err != nil || r == nil {
		t.Fatalf("BuildBatchResolver: r=%v err=%v", r, err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = r.Run(runCtx) }()

	waitPoolEmpty(t, pool)
	if _, err := svc.ResolveVC(ctx, pAddr); err != nil {
		t.Errorf("predecessor not assembled from authenticated peer (bearer not presented?): %v", err)
	}
}

// The node's bearer goes only to an origin the operator listed: a peer named
// by a StoreVC caller's hint, or by an issuer's DID document, is fetched
// from without it.
func TestBatchResolver_Integration_BearerOnlyToListedOrigins(t *testing.T) {
	for _, listed := range []bool{false, true} {
		ctx := context.Background()
		const token = "audit-token"

		var seen []string
		var mu sync.Mutex
		record := connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				mu.Lock()
				seen = append(seen, req.Header().Get("Authorization"))
				mu.Unlock()
				return next(ctx, req)
			}
		}))
		peerSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
		_, ph := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(peerSvc), record)
		peer := httptest.NewServer(ph)
		t.Cleanup(peer.Close)
		p := brCred(t, "", "")
		pAddr := brHash(t, p)
		if _, err := peerSvc.StoreVC(ctx, brMarshal(t, p), "", 0); err != nil {
			t.Fatalf("seed peer: %v", err)
		}

		pool := memstore.NewPool()
		svc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), pool)
		if _, err := svc.StoreVC(ctx, brMarshal(t, brCred(t, pAddr, "")), peer.URL, 0); err != nil {
			t.Fatalf("seed local: %v", err)
		}

		guard := core.NewURLGuard(core.WithAllowLoopback(true))
		cfg := brConfig([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleSink}}, 5*time.Millisecond, 1<<20)
		cfg.VCStoreBearer = token
		cfg.VCStoreEndpoint = "https://store.example"
		if listed {
			cfg.CredentialOrigins = []string{peer.URL}
		}
		r, err := BuildBatchResolver(pool, svc, guard, didresolver.New(guard), cfg)
		if err != nil {
			t.Fatalf("BuildBatchResolver: %v", err)
		}
		runCtx, cancel := context.WithCancel(ctx)
		go func() { _ = r.Run(runCtx) }()
		waitPoolEmpty(t, pool)
		cancel()

		want := ""
		if listed {
			want = "Bearer " + token
		}
		mu.Lock()
		got := append([]string(nil), seen...)
		mu.Unlock()
		if len(got) == 0 {
			t.Fatalf("listed=%v: the peer was not asked", listed)
		}
		for _, h := range got {
			if h != want {
				t.Errorf("listed=%v: peer saw Authorization %q, want %q", listed, h, want)
			}
		}
	}
}

// The server handler bounds an inbound StoreVC: an over-cap credential is rejected through
// the real authenticated stack (D-17g-13).
func TestBoot_StoreVC_RejectsOverCap(t *testing.T) {
	const cap = 512
	ctx := context.Background()
	srv, _, _ := assembledWith(t, cap)
	vcClient := vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL)

	big, _ := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            pipelineDID,
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "proc1", "blob": strings.Repeat("x", cap*4)},
	})
	_, err := vcClient.StoreVC(ctx, bearer(connect.NewRequest(&vcpb.StoreVCRequest{Credential: big})))
	if err == nil {
		t.Fatal("over-cap StoreVC: want error, got nil")
	}
}

// silentVCResolver never answers, and ignores the deadline the client sends:
// each call waits until the test ends.
type silentVCResolver struct {
	vcpbconnect.UnimplementedVCResolverServiceHandler
	release chan struct{}
}

func (s silentVCResolver) ResolveVC(context.Context, *connect.Request[vcpb.ResolveVCRequest]) (*connect.Response[vcpb.ResolveVCResponse], error) {
	<-s.release
	return nil, errors.New("released")
}

// A peer is another organization's server: a fetch from it ends within the
// fetcher's timeout although the runner's context lives as long as the process.
func TestPeerFetcher_FetchEndsWithinTheTimeout(t *testing.T) {
	release := make(chan struct{})
	_, h := vcpbconnect.NewVCResolverServiceHandler(silentVCResolver{release: release})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	f := &peerFetcher{httpClient: srv.Client(), maxBytes: 1 << 20, timeout: 50 * time.Millisecond}
	done := make(chan error, 1)
	go func() {
		_, err := f.Fetch(context.WithoutCancel(context.Background()), srv.URL, "sha256:"+strings.Repeat("a", 64))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("silent peer: want error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("silent peer: still waiting after 5s")
	}
}

// A fetcher without a timeout of its own, as BuildBatchResolver builds it,
// bounds every fetch with peerFetchTimeout.
func TestPeerFetcher_DefaultsToPeerFetchTimeout(t *testing.T) {
	if got := (&peerFetcher{}).fetchTimeout(); got != peerFetchTimeout || got <= 0 {
		t.Fatalf("fetchTimeout = %s, want peerFetchTimeout (%s)", got, peerFetchTimeout)
	}
}

// A named peer that redirects does not pass the bearer on: the fetch that
// shows the credential follows no redirect.
func TestPeerFetcher_ShowsTheBearerToNoServerANamedPeerRedirectsTo(t *testing.T) {
	var sawBearer atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawBearer.Store(true)
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	t.Cleanup(other.Close)
	named := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(named.Close)
	f := &peerFetcher{
		httpClient:           named.Client(),
		bearer:               "node-token",
		presentsCredentialTo: func(endpoint string) bool { return strings.HasPrefix(endpoint, named.URL) },
		maxBytes:             1 << 20,
	}
	if _, err := f.Fetch(context.Background(), named.URL, "sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Error("a redirected fetch succeeded")
	}
	if sawBearer.Load() {
		t.Error("the server the named peer redirected to saw the bearer")
	}
}
