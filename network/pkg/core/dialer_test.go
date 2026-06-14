package core_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
)

// DialContext must reject a blocked address BEFORE dialing — the resolution that
// feeds validation is the same one that feeds the dial, so a rebinding attacker
// cannot return a public addr to the check and a blocked addr to the dial.
func TestDialContext_RejectsBlockedResolvedAddr(t *testing.T) {
	g := core.NewURLGuard(core.WithResolver(staticResolver(mustAddrs("169.254.169.254"), nil)))
	if _, err := g.DialContext(context.Background(), "tcp", "rebind.example:80"); !errors.Is(err, core.ErrURLBlocked) {
		t.Errorf("DialContext to a host resolving to metadata: want ErrURLBlocked, got %v", err)
	}
}

func TestDialContext_RejectsBlockedLiteral(t *testing.T) {
	g := core.NewURLGuard()
	if _, err := g.DialContext(context.Background(), "tcp", "127.0.0.1:80"); !errors.Is(err, core.ErrURLBlocked) {
		t.Errorf("DialContext to loopback literal: want ErrURLBlocked, got %v", err)
	}
}

// DialContext connects to the validated RESOLVED IP (pinned), not by re-resolving
// the hostname. A real loopback listener proves the connection lands on the IP
// the resolver returned.
func TestDialContext_DialsValidatedResolvedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	g := core.NewURLGuard(
		core.WithAllowLoopback(true),
		core.WithResolver(staticResolver(mustAddrs("127.0.0.1"), nil)),
	)
	conn, err := g.DialContext(context.Background(), "tcp", "pinned.example:"+port)
	if err != nil {
		t.Fatalf("DialContext to a host that resolves to the listener: %v", err)
	}
	conn.Close()
}

func TestHTTPClient_GuardsDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer srv.Close() // srv.URL is http://127.0.0.1:PORT

	// Default guard blocks loopback at dial.
	if _, err := core.NewURLGuard().HTTPClient().Get(srv.URL); !errors.Is(err, core.ErrURLBlocked) {
		t.Errorf("default guard: Get(loopback) should be blocked at dial, got %v", err)
	}

	// Loopback opt-in lets the same request through.
	resp, err := core.NewURLGuard(core.WithAllowLoopback(true)).HTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatalf("loopback opt-in: Get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
