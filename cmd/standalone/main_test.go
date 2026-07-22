package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	"golang.org/x/net/http2"

	"math/big"
	"net"
	"os"
	"path/filepath"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// TestRunServices_DataPlaneErrorPropagates is the regression guard for the silent
// exit-0 on failure: a data plane whose loop fails at boot must make runServices
// return a non-nil error (so main exits non-zero), even though the HTTP server is
// healthy and shuts down cleanly when the failed loop cancels the shared context.
// Before the fix the failing goroutine only logged and main exited 0.
func TestRunServices_DataPlaneErrorPropagates(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	// A source loop's IngressSubject is not validated at build time (that is the
	// config layer's job — see pipeline/runtime's buildSourceLoop doc): it builds
	// fine and only fails at Subscribe, inside Run. That is exactly the shape this
	// test needs — a runtime that assembles successfully but fails during Run.
	badCfg := dpPipelineCfg()
	badCfg.Loops[0].IngressSubject = "bad subject" // embedded space => nats ErrBadSubject at Subscribe
	dp, err := pipelineruntime.Build(context.Background(), chainCfg, badCfg, dpKeyStore(t), pipelineruntime.Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A healthy server on an ephemeral port; the failed loop cancels runCtx, which
	// shuts the server down gracefully (no error from its side).
	srv := &http.Server{Addr: "127.0.0.1:0"}

	done := make(chan error, 1)
	go func() { done <- runServices(context.Background(), srv, srv.ListenAndServe, dp, nil, nil) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runServices returned nil; want the data-plane failure to propagate")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServices did not return after the data-plane loop failed")
	}
}

// The HTTP/2 (h2c) server the connection is hijacked into must carry its own
// stall defenses: http.Server's timeouts do not reach HTTP/2 streams, so a
// regression to zero here would reopen the slow-stream DoS (adversarial-review
// F7 / Codex Issue 7).
func TestH2CServer_HasStallTimeouts(t *testing.T) {
	s := http2Server()
	if s.IdleTimeout <= 0 {
		t.Error("IdleTimeout unset — idle HTTP/2 connections would never be reaped")
	}
	if s.ReadIdleTimeout <= 0 || s.PingTimeout <= 0 {
		t.Errorf("ReadIdleTimeout=%v PingTimeout=%v — a silent peer is never probed/dropped", s.ReadIdleTimeout, s.PingTimeout)
	}
	if s.WriteByteTimeout <= 0 {
		t.Error("WriteByteTimeout unset — a per-write stall is unbounded")
	}
}

// The outer raw-body cap is the largest legitimate request plus headroom — big
// enough for the biggest real request (credential or push body), never smaller
// (which would reject legitimate traffic).
func TestOuterRequestCapBytes_SizedToLargestLegit(t *testing.T) {
	// maxDocumentRequestBytes mirrors internal/netcompose/server.go's private
	// constant of the same name/value: it stays unexported there (internal to
	// that file, per the netcompose extraction), so this test cannot reference
	// it directly across the package boundary and instead pins the literal its
	// assertions depend on.
	const maxDocumentRequestBytes = 1 << 20
	const cred, push = 1 << 20, 4 << 20
	got := outerRequestCapBytes(cred, push, 0, 0)
	if got <= push {
		t.Errorf("cap %d not above the largest legit request %d", got, push)
	}
	if outerRequestCapBytes(push, cred, 0, 0) != got {
		t.Error("cap must not depend on argument order (it takes the max)")
	}
	// Even with credential/push configured BELOW the document-class per-RPC cap,
	// the outer bound must still exceed a document-class request plus its JSON
	// base64 inflation — otherwise a legit doc request is rejected pre-auth.
	small := outerRequestCapBytes(4<<10, 4<<10, 4<<10, 0)
	if small <= maxDocumentRequestBytes {
		t.Errorf("outer cap %d does not cover the document class %d when cred/push are tiny", small, maxDocumentRequestBytes)
	}
	if small <= maxDocumentRequestBytes*4/3 {
		t.Errorf("outer cap %d does not cover base64-inflated document request (~4/3 of %d)", small, maxDocumentRequestBytes)
	}
	// A full-size RetainPayload stream shares ONE http.Request for its whole
	// (client-streaming) lifetime, so the outer cap must admit the CUMULATIVE
	// max-retain-payload-size, not just its largest single chunk — otherwise a
	// legitimate large retain is truncated mid-stream by the outer
	// http.MaxBytesHandler, never reaching the per-RPC (per-chunk) read cap.
	const retain = 64 << 20
	gotRetain := outerRequestCapBytes(4<<10, 4<<10, retain, 0)
	if gotRetain <= retain {
		t.Errorf("cap %d not above max-retain-payload-size %d", gotRetain, retain)
	}
	// A zero mirror-batch-bytes argument (cmd/standalone never wires a
	// mirror store) must not widen the outer cap at all — the class simply
	// does not participate when this binary's own posture never mounts it.
	if outerRequestCapBytes(4<<10, 4<<10, 4<<10, 0) != small {
		t.Error("mirror-batch-bytes = 0 must not change the outer cap versus omitting the class entirely")
	}
	// A non-zero mirror-batch-bytes MUST widen the outer cap to cover
	// MirrorLogSegment's OWN derived read cap (max-batch-bytes +
	// maxProofRequestBytes headroom, internal/netcompose's
	// mirrorReadCapBytes) — not the bare max-batch-bytes value — or a
	// legitimate batch-cap-sized segment would be truncated by the outer
	// http.MaxBytesHandler before ever reaching that per-RPC cap.
	const maxBatchBytes = 4 << 20
	const maxProofRequestBytes = 256 << 10 // mirrors internal/netcompose's private constant.
	gotMirror := outerRequestCapBytes(4<<10, 4<<10, 4<<10, maxBatchBytes)
	if gotMirror <= maxBatchBytes+maxProofRequestBytes {
		t.Errorf("outer cap %d does not cover MirrorLogSegment's derived read cap %d", gotMirror, maxBatchBytes+maxProofRequestBytes)
	}
}

// buildServer's TLS path serves a real HTTP/2-over-TLS round-trip; the cleartext
// path serves h2c. This pins the F6 transport-posture wiring (ConfigureServer +
// ListenAndServeTLS + ALPN) beyond field assertions.
func TestBuildServer_TLSPath_ServesHTTPS(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	coreCfg := &core.CoreConfig{
		ListenAddr: "127.0.0.1:0",
		TLS:        core.TLSConfig{CertFile: certFile, KeyFile: keyFile},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	srv, listen, mode, err := buildServer(coreCfg, tlsConf, handler, 1<<20)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	if mode != "direct-tls" {
		t.Errorf("mode = %q, want direct-tls", mode)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Error("server is not pinned to the preflighted TLS 1.2 floor")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Empty paths, as production serves: the preloaded pair in TLSConfig is
	// the material, and the files must not be re-read (P0-6 closure #3).
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_ = listen // production uses ListenAndServeTLS; the test drives ServeTLS on a chosen listener

	// Trust the self-signed cert and require HTTP/2.
	pool := x509.NewCertPool()
	pemBytes, _ := os.ReadFile(certFile)
	pool.AppendCertsFromPEM(pemBytes)
	client := &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	url := "https://" + ln.Addr().String() + "/"
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Get(url)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want 418", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("proto = HTTP/%d.x, want HTTP/2 (ALPN)", resp.ProtoMajor)
	}

	// A cleartext (http://) client must NOT reach the handler over the TLS
	// listener: Go's TLS server answers a plaintext request with a 400 "HTTP
	// request sent to HTTPS server" rather than routing it, so the handler's
	// 418 is never served in the clear.
	plain := &http.Client{Timeout: time.Second}
	if r, perr := plain.Get("http://" + ln.Addr().String() + "/"); perr == nil {
		defer r.Body.Close()
		if r.StatusCode == http.StatusTeapot {
			t.Error("cleartext GET reached the handler over the TLS listener; want it rejected")
		}
	}
}

// The cleartext path selects the h2c mode label, distinguishing loopback from
// an acknowledged non-loopback listener.
func TestBuildServer_CleartextMode(t *testing.T) {
	loop, _, _, err := buildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:8443"}, nil, http.NotFoundHandler(), 1<<20)
	if err != nil || loop == nil {
		t.Fatalf("buildServer(loopback): %v", err)
	}
	_, _, mode, _ := buildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:8443"}, nil, http.NotFoundHandler(), 1<<20)
	if mode != "loopback-cleartext" {
		t.Errorf("loopback mode = %q, want loopback-cleartext", mode)
	}
	_, _, mode, _ = buildServer(&core.CoreConfig{ListenAddr: ":8443", TLS: core.TLSConfig{AllowCleartext: true}}, nil, http.NotFoundHandler(), 1<<20)
	if mode != "cleartext-acknowledged" {
		t.Errorf("non-loopback mode = %q, want cleartext-acknowledged", mode)
	}
}

// writeSelfSignedCert generates an ed25519 self-signed cert for 127.0.0.1 and
// writes cert.pem / key.pem to a temp dir, returning their paths.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
