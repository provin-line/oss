package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
)

// P0-6 closure #5, ported for the control-plane-only binary: the actual
// network binary, booted from a real config file with an ephemeral
// certificate and ZERO pipeline loops — readiness reached over HTTPS, a
// request served, graceful shutdown on SIGTERM. Every other TLS test in this
// package builds the server in-process, which cannot see what main() does:
// config layering, the guard's position, ListenAndServeTLS with empty paths,
// signal handling. Ported from cmd/standalone/bootsmoke_test.go's
// TestStandalone_ActualBootOverTLS — names/paths adjusted, no pipeline loop
// (this binary must boot with none).
func TestNetwork_ActualBootOverTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("boot smoke builds a binary and starts a broker")
	}
	bin := buildNetworkBinary(t)
	natsURL := runEmbeddedNATS(t)
	certFile, keyFile := writeSelfSignedCert(t)
	port := freePort(t)

	dir := t.TempDir()
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)
	writeBootConfig(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", port),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		NATSURL:    natsURL,
		AccSeed:    accSeedFile,
		TrustSeed:  trustSeedFile,
		ResolveDir: filepath.Join(dir, "resolver"),
		// No PipelineLoops: this binary runs no data plane, so zero loops is
		// the only config that boots (the guard rejects any other).
		// VCStoreBearer: this binary always runs the peer-fetching batch
		// resolver (Task 9), so boot fails closed without one.
		VCStoreBearer: "network-boot-smoke-bearer",
	})

	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr // boot log rides the test output when it fails
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start network: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	client := trustingClient(t, certFile)
	base := fmt.Sprintf("https://127.0.0.1:%d", port)

	// Readiness over HTTPS: the boot is complete only when the node says so.
	deadline := time.Now().Add(30 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("network exited during boot: %v", err)
		default:
		}
		resp, err := client.Get(base + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatal("network never reached readiness over HTTPS within 30s")
	}

	// A served request over the same TLS listener.
	resp, err := client.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d", resp.StatusCode)
	}

	// Graceful shutdown: SIGTERM drains and exits zero. A non-zero exit here
	// would mean the node dies rather than drains — visible only from outside
	// the process, which is why this test execs.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("graceful shutdown exited non-zero: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("network did not exit within 20s of SIGTERM")
	}
}

// runEmbeddedNATS starts an in-process NATS broker for the boot smoke's chain
// operator to publish claims against. Ported from
// cmd/standalone/bootsmoke_test.go.
func runEmbeddedNATS(t *testing.T) string {
	t.Helper()
	srv := natstest.RunServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

// trustingClient returns an HTTP client that trusts the given self-signed
// cert. Ported from cmd/standalone/bootsmoke_test.go.
func trustingClient(t *testing.T, certFile string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
}
