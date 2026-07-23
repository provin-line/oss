package httpserve_test

// Relocated from cmd/standalone/main_test.go (PR3c: cmd/standalone retired).
// These tests exercise httpserve.BuildServer and httpserve.HTTP2Server
// directly — package-generic behavior with no cmd/standalone-specific
// composition, and (before this move) the ONLY test coverage either
// function had anywhere in the repo: cmd/network and cmd/pipeline both call
// BuildServer from their own main(), but neither carried its own unit test
// for the TLS/h2c server-construction contract itself.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/network/pkg/core"
)

// The HTTP/2 (h2c) server the connection is hijacked into must carry its own
// stall defenses: http.Server's timeouts do not reach HTTP/2 streams, so a
// regression to zero here would reopen the slow-stream DoS (adversarial-review
// F7 / Codex Issue 7).
func TestH2CServer_HasStallTimeouts(t *testing.T) {
	s := httpserve.HTTP2Server()
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
	srv, listen, mode, err := httpserve.BuildServer(coreCfg, tlsConf, handler, 1<<20)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
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
	loop, _, _, err := httpserve.BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:8443"}, nil, http.NotFoundHandler(), 1<<20)
	if err != nil || loop == nil {
		t.Fatalf("BuildServer(loopback): %v", err)
	}
	_, _, mode, _ := httpserve.BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:8443"}, nil, http.NotFoundHandler(), 1<<20)
	if mode != "loopback-cleartext" {
		t.Errorf("loopback mode = %q, want loopback-cleartext", mode)
	}
	_, _, mode, _ = httpserve.BuildServer(&core.CoreConfig{ListenAddr: ":8443", TLS: core.TLSConfig{AllowCleartext: true}}, nil, http.NotFoundHandler(), 1<<20)
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
