package didresolver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
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
// path it was hit on; it can be told to 404, to return a mismatched id, or to
// return an oversized body.
type stub struct {
	gotPath   string
	docID     string // id to put in the returned document (default testDID)
	notFound  bool
	oversized bool
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.gotPath = r.URL.Path
	if s.notFound {
		http.NotFound(w, r)
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
}

func TestResolve_IdentityMismatch(t *testing.T) {
	r := newResolver(t, &stub{docID: "did:dplaax:poc.dplaax.dev:org:other"}, loopbackGuard())
	_, err := r.Resolve(context.Background(), testDID)
	if !errors.Is(err, didresolver.ErrDIDIdentityMismatch) {
		t.Errorf("err = %v, want ErrDIDIdentityMismatch", err)
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
