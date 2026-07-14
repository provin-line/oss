package didresolver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/resolver"
)

// One HTTP resolver satisfies both consumer interfaces (D-r1): the publisher-side
// verifier (wireauth.DIDResolver) and the subscriber-side domain
// (chainmanager.DIDResolver).
var (
	_ wireauth.DIDResolver     = (*didresolver.Resolver)(nil)
	_ chainmanager.DIDResolver = (*didresolver.Resolver)(nil)
)

const testDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"

// stub serves the canned doc for the expected resolution path and records the
// path it was hit on; it can be told to 404, to fail with a 500, to return a
// mismatched id, or to return an oversized body.
type stub struct {
	gotPath     string
	docID       string // id to put in the returned document (default testDID)
	notFound    bool
	serverError bool
	oversized   bool
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.gotPath = r.URL.Path
	if s.notFound {
		http.NotFound(w, r)
		return
	}
	if s.serverError {
		http.Error(w, "registry unavailable", http.StatusInternalServerError)
		return
	}
	if s.oversized {
		w.Header().Set("Content-Type", "application/did+json")
		w.Write([]byte(`{"id":"` + testDID + `","padding":"`))
		w.Write([]byte(strings.Repeat("x", 4<<20))) // 4MB, exceeds the cap
		w.Write([]byte(`"}`))
		return
	}
	id := s.docID
	if id == "" {
		id = testDID
	}
	body, _ := did.New(did.DocumentFields{ID: id}).MarshalJSON()
	w.Header().Set("Content-Type", "application/did+json")
	w.Write(body)
}

func newResolver(t *testing.T, s *stub, g *core.URLGuard) *didresolver.Resolver {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return didresolver.New(g, didresolver.WithRegistryBaseURL(func(string) (string, error) {
		return srv.URL, nil
	}))
}

func loopbackGuard() *core.URLGuard { return core.NewURLGuard(core.WithAllowLoopback(true)) }

func TestResolve_Success_AndURLDerivation(t *testing.T) {
	s := &stub{}
	r := newResolver(t, s, loopbackGuard())
	doc, err := r.Resolve(context.Background(), testDID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if doc.ID() != testDID {
		t.Errorf("doc.ID = %q", doc.ID())
	}
	if s.gotPath != "/did/org/acme/pipeline/p1/did.json" {
		t.Errorf("resolution path = %q, want /did/org/acme/pipeline/p1/did.json", s.gotPath)
	}
}

// URL derivation must be the inverse of the resolution handler for every DID
// shape (owner / pipeline / process) and must tolerate a trailing-slash base.
func TestResolve_URLDerivation_AllShapes(t *testing.T) {
	cases := []struct {
		did      string
		wantPath string
	}{
		{"did:dplaax:poc.dplaax.dev:org:acme", "/did/org/acme/did.json"},                                               // owner
		{"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1", "/did/org/acme/pipeline/p1/did.json"},                       // pipeline
		{"did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1", "/did/org/acme/pipeline/p1/process/s1/did.json"}, // process
	}
	for _, tc := range cases {
		t.Run(tc.wantPath, func(t *testing.T) {
			s := &stub{docID: tc.did}
			srv := httptest.NewServer(s)
			t.Cleanup(srv.Close)
			// a trailing-slash base exercises TrimRight in resolutionURL
			r := didresolver.New(loopbackGuard(), didresolver.WithRegistryBaseURL(func(string) (string, error) {
				return srv.URL + "/", nil
			}))
			if _, err := r.Resolve(context.Background(), tc.did); err != nil {
				t.Fatalf("Resolve(%s): %v", tc.did, err)
			}
			if s.gotPath != tc.wantPath {
				t.Errorf("path = %q, want %q", s.gotPath, tc.wantPath)
			}
		})
	}
}

func TestResolve_NotFound(t *testing.T) {
	r := newResolver(t, &stub{notFound: true}, loopbackGuard())
	_, err := r.Resolve(context.Background(), testDID)
	if !errors.Is(err, didresolver.ErrDIDNotFound) {
		t.Errorf("err = %v, want ErrDIDNotFound", err)
	}
	// A registry 404 is a definitive absence: it must ALSO carry the
	// resolver.ErrNotFound classification the confidence axes key on.
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is(err, resolver.ErrNotFound)", err)
	}
}

// A non-404 upstream failure is transient, not a definitive absence: the error
// must NOT classify as resolver.ErrNotFound (the verifier treats it as
// indeterminate, retryable).
func TestResolve_ServerError_NotClassifiedNotFound(t *testing.T) {
	r := newResolver(t, &stub{serverError: true}, loopbackGuard())
	_, err := r.Resolve(context.Background(), testDID)
	if err == nil {
		t.Fatal("HTTP 500: want error")
	}
	if errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("HTTP 500 classified as definitive not-found: %v", err)
	}
}

func TestResolve_IdentityMismatch(t *testing.T) {
	r := newResolver(t, &stub{docID: "did:dplaax:poc.dplaax.dev:org:other"}, loopbackGuard())
	_, err := r.Resolve(context.Background(), testDID)
	if !errors.Is(err, didresolver.ErrDIDIdentityMismatch) {
		t.Errorf("err = %v, want ErrDIDIdentityMismatch", err)
	}
	// A substituted identity is misconfiguration-or-attack, not a definitive
	// absence — it must stay in the indeterminate (retryable) error class.
	if errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("identity mismatch classified as definitive not-found: %v", err)
	}
}

func TestResolve_OversizedBody(t *testing.T) {
	r := newResolver(t, &stub{oversized: true}, loopbackGuard())
	if _, err := r.Resolve(context.Background(), testDID); err == nil {
		t.Error("oversized body accepted, want error")
	}
}

func TestResolve_InvalidDID(t *testing.T) {
	r := newResolver(t, &stub{}, loopbackGuard())
	if _, err := r.Resolve(context.Background(), "not-a-did"); err == nil {
		t.Error("invalid DID accepted, want error")
	}
}

// A strict guard (no loopback) must block the 127.0.0.1 httptest target before
// any document is returned.
func TestResolve_SSRFBlocked(t *testing.T) {
	s := &stub{}
	r := newResolver(t, s, core.NewURLGuard()) // strict: loopback denied
	if _, err := r.Resolve(context.Background(), testDID); err == nil {
		t.Error("strict guard did not block loopback target")
	}
	if s.gotPath != "" {
		t.Error("request reached the server despite SSRF block")
	}
}

// A guard whose resolver maps the host to a private IP also blocks (DNS-level).
func TestResolve_SSRFBlocked_PrivateDNS(t *testing.T) {
	g := core.NewURLGuard(core.WithResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}))
	r := didresolver.New(g, didresolver.WithRegistryBaseURL(func(string) (string, error) {
		return "https://evil.example", nil
	}))
	if _, err := r.Resolve(context.Background(), testDID); err == nil {
		t.Error("private-resolving host not blocked")
	}
}

// ResolveDocument returns the parsed document AND the raw bytes actually
// fetched (post size-cap, post identity check) — what an archiver stores.
// The bytes must be the wire bytes verbatim, never a re-marshal.
func TestResolveDocument_RawBytesVerbatim(t *testing.T) {
	s := &stub{}
	r := newResolver(t, s, loopbackGuard())
	doc, raw, err := r.ResolveDocument(context.Background(), testDID)
	if err != nil {
		t.Fatalf("ResolveDocument: %v", err)
	}
	if doc.ID() != testDID {
		t.Errorf("doc.ID = %q", doc.ID())
	}
	want, _ := did.New(did.DocumentFields{ID: testDID}).MarshalJSON()
	if string(raw) != string(want) {
		t.Errorf("raw bytes differ from what the stub served:\n got %s\nwant %s", raw, want)
	}
}

// The raw-bytes path applies the same defenses as Resolve: an identity
// mismatch is never honoured, bytes or not.
func TestResolveDocument_IdentityMismatch(t *testing.T) {
	s := &stub{docID: "did:dplaax:poc.dplaax.dev:org:evil"}
	r := newResolver(t, s, loopbackGuard())
	if _, _, err := r.ResolveDocument(context.Background(), testDID); !errors.Is(err, didresolver.ErrDIDIdentityMismatch) {
		t.Fatalf("err = %v, want ErrDIDIdentityMismatch", err)
	}
}

// The resolver bounds how many outbound fetches run at once: an
// unauthenticated caller presenting attacker DIDs (wireauth resolves the
// signer BEFORE checking the signature) cannot pin an unbounded number of
// goroutines/connections. When the semaphore is full, a new resolution
// fails fast with ErrResolverBusy rather than queueing.
func TestResolve_ConcurrencyBounded_FailFast(t *testing.T) {
	release := make(chan struct{})
	blocked := make(chan struct{}, 1)
	s := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blocked <- struct{}{}
		// Hold the sole slot until released — but also unblock if the client
		// cancels, so the test server can close without hanging.
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		body, _ := did.New(did.DocumentFields{ID: testDID}).MarshalJSON()
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(body)
	})
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	srv := httptest.NewServer(s)
	t.Cleanup(func() { closeRelease(); srv.Close() })
	r := didresolver.New(loopbackGuard(), didresolver.WithRegistryBaseURL(func(string) (string, error) {
		return srv.URL, nil
	}))
	didresolver.SetResolutionConcurrencyForTest(r, 1)

	done := make(chan error, 1)
	go func() { _, err := r.Resolve(context.Background(), testDID); done <- err }()
	<-blocked // the first resolution now holds the only slot

	if _, err := r.Resolve(context.Background(), testDID); !errors.Is(err, didresolver.ErrResolverBusy) {
		t.Fatalf("second concurrent resolve: want ErrResolverBusy, got %v", err)
	}
	closeRelease()
	if err := <-done; err != nil {
		t.Fatalf("first resolve: %v", err)
	}
}

// A registry that accepts the connection but never responds must not pin the
// caller forever: the per-resolve deadline bounds the whole fetch even when the
// caller's context has no deadline of its own.
func TestResolve_PerResolveTimeout(t *testing.T) {
	s := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never respond; unblock when the client cancels
	})
	srv := httptest.NewServer(s)
	defer srv.Close()
	r := didresolver.New(loopbackGuard(), didresolver.WithRegistryBaseURL(func(string) (string, error) {
		return srv.URL, nil
	}))
	didresolver.SetResolutionTimeoutForTest(r, 100*time.Millisecond)

	start := time.Now()
	_, err := r.Resolve(context.Background(), testDID) // background ctx: no caller deadline
	if err == nil {
		t.Fatal("stalling registry: want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("resolve took %v — the per-resolve deadline did not bound it", elapsed)
	}
}

// A DNS lookup that runs into the per-resolve deadline must surface a
// context-timeout identity (not an SSRF-rejection string), so wireauth
// classifies it as transient/retryable rather than an identity failure.
func TestResolve_PreflightTimeout_PreservesContextError(t *testing.T) {
	slow := core.NewURLGuard(core.WithResolver(func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	r := didresolver.New(slow, didresolver.WithRegistryBaseURL(func(string) (string, error) {
		return "https://registry.example", nil
	}))
	didresolver.SetResolutionTimeoutForTest(r, 100*time.Millisecond)

	_, err := r.Resolve(context.Background(), testDID)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("preflight-timeout err = %v, want errors.Is(context.DeadlineExceeded)", err)
	}
}
