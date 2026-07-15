package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
)

// P0-6 closure #4: the production route surface served over native TLS — not a
// bare teapot handler. One boot, every ledger item: HTTP/2 via ALPN, plain-HTTP
// rejection on the TLS port, /did resolution, /healthz, /readyz, an enabled
// /metrics, and the SAN positive/negative pair against the private CA.
func TestNativeTLS_RouteIntegration(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	// The full mux, as production composes it: BuildHandler wrapped by the
	// metrics gate (enabled here — the ledger names an enabled /metrics).
	inner, ownerSigner, ownerPub := assembledHandler(t)
	handler, err := maybeMountMetrics(true, inner, nil, nil)
	if err != nil {
		t.Fatalf("maybeMountMetrics: %v", err)
	}

	coreCfg := &core.CoreConfig{
		ListenAddr: "127.0.0.1:0",
		TLS:        core.TLSConfig{CertFile: certFile, KeyFile: keyFile},
	}
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	srv, _, mode, err := buildServer(coreCfg, tlsConf, handler, 1<<20)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	if mode != "direct-tls" {
		t.Fatalf("mode = %q, want direct-tls", mode)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }() // empty paths: the preflighted pair serves
	t.Cleanup(func() { _ = srv.Close() })
	base := "https://" + ln.Addr().String()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(pemBytes)

	t.Run("ALPN negotiates HTTP/2", func(t *testing.T) {
		client := &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
		resp, err := client.Get(base + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz over h2: %v", err)
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("proto = %s, want HTTP/2 via ALPN", resp.Proto)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/healthz = %d", resp.StatusCode)
		}
	})

	t.Run("plain HTTP on the TLS port is refused", func(t *testing.T) {
		// A cleartext request must not reach any handler: the TLS record layer
		// rejects it below HTTP. Timeouts bound the failure.
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + ln.Addr().String() + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatal("a cleartext request reached the handler through the TLS port")
			}
		}
	})

	// One HTTP/1.1-capable client over the trusted pool for the route sweep.
	h1 := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}

	t.Run("readiness and metrics respond", func(t *testing.T) {
		for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
			resp, err := h1.Get(base + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s = %d (%s)", path, resp.StatusCode, strings.TrimSpace(string(body)))
			}
		}
	})

	t.Run("DID resolution route serves over TLS", func(t *testing.T) {
		// Register an owner through the authenticated Connect surface, then
		// resolve it through the public /did route — both over native TLS.
		didClient := didpbconnect.NewDIDServiceClient(h1, base)
		req := connect.NewRequest(&didpb.RegisterOwnerRequest{
			DidDocument: signedOwnerDocBytes(t, ownerSigner, ownerPub),
		})
		req.Header().Set("Authorization", "Bearer dummy")
		if _, err := didClient.RegisterOwner(t.Context(), req); err != nil {
			t.Fatalf("RegisterOwner over TLS: %v", err)
		}
		resp, err := h1.Get(base + "/did/org/acme/did.json")
		if err != nil {
			t.Fatalf("GET /did: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/did resolution = %d", resp.StatusCode)
		}
	})

	t.Run("SAN mismatch is refused, matching SAN is accepted", func(t *testing.T) {
		// The certificate's SAN is 127.0.0.1. A client connecting to the same
		// socket under a different name must refuse the chain; the matching
		// name (exercised by every subtest above) is the positive half.
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			RootCAs:    pool,
			ServerName: "not-the-san.example",
		})
		if err == nil {
			conn.Close()
			t.Errorf("a SAN-mismatched name verified against the private CA (port %s)", port)
		}
		var certErr *tls.CertificateVerificationError
		if err != nil && !errors.As(err, &certErr) {
			t.Errorf("mismatch failed with %T (%v), want a certificate verification error", err, err)
		}
	})
}
