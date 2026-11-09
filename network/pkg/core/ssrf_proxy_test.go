package core_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

// HTTPClient must disable proxying: an SSRF guard pins the dialed target IP, but a
// proxy makes Go dial the proxy instead, so DialContext would validate the proxy,
// not the attacker-controlled target — silently bypassing the guarantee. The
// guarded client therefore sets Transport.Proxy = nil.
func TestURLGuard_HTTPClient_DisablesProxy(t *testing.T) {
	c := core.NewURLGuard().HTTPClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("guarded HTTPClient must have Transport.Proxy == nil (proxy bypasses IP pinning)")
	}
}

// The guarded client reaches other parties' servers, so it takes at most
// maxResponseHeaderBytes of response headers (net/http's default is 10 MiB).
func TestURLGuard_HTTPClient_BoundsResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("x", 128<<10))
	}))
	t.Cleanup(srv.Close)
	c := core.NewURLGuard(core.WithAllowLoopback(true)).HTTPClient()
	resp, err := c.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("128 KiB of response headers: want error")
	}

	small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Ok", strings.Repeat("x", 32<<10))
	}))
	t.Cleanup(small.Close)
	resp, err = c.Get(small.URL)
	if err != nil {
		t.Fatalf("32 KiB of response headers: %v", err)
	}
	resp.Body.Close()
}
