package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
)

// TestPipeline_ActualBoot proves the actual binary — not an in-process
// reimplementation — boots a real source loop over a real (embedded) NATS
// broker, serves /healthz and a fully green /readyz (both configured
// dependencies reachable), and shuts down cleanly on SIGTERM. This is the
// one test that exercises buildDeps + pipeline/runtime.Build together
// end-to-end for this task; a full credential-flow e2e (publish through a
// loop, observe the emitted event) is PR3b Task 9's job per the task brief —
// this smoke stays at "the process boots, serves, and drains", mirroring
// cmd/standalone's own TestStandalone_ActualBootOverTLS scope.
//
// The registry dependency (vc-store-endpoint) is a trivial httptest server
// that answers ANY request (even 404) — this binary's /readyz registry
// check only asks "did something answer" (see readiness.go's doc), and this
// smoke never exercises a real VCResolverService/AuditService/etc RPC (the
// configured source loop has no schema-ref and never emits, so it makes no
// outbound registry call during boot or the readiness window this test
// observes).
//
// No TLS: listen-addr is loopback, so core.LoadCoreConfig's transport-
// security guard permits cleartext (ListenerIsLoopback) — simpler than
// standalone's own TLS-carrying smoke, and orthogonal to what this test
// proves (Deps wiring + lifecycle, not the TLS preflight, already covered by
// cmd/network/cmd/standalone's own suites).
func TestPipeline_ActualBoot(t *testing.T) {
	if testing.Short() {
		t.Skip("boot smoke builds a binary and starts a broker")
	}
	bin := buildPipelineBinary(t)
	natsURL := runEmbeddedNATS(t)
	registry := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(registry.Close)

	dir := t.TempDir()
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)
	port := freePort(t)

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", port),
		DataDir:    filepath.Join(dir, "data"),
		// The registry stand-in below is a loopback httptest server; the SSRF
		// guard blocks loopback outbound targets by default (local-dev-only
		// opt-in), so this smoke needs it explicitly.
		AllowLoopback:   true,
		Transport:       "nats",
		NATSURL:         natsURL,
		AccSeed:         accSeedFile,
		TrustSeed:       trustSeedFile,
		ResolveDir:      filepath.Join(dir, "resolver"),
		NodeDID:         "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node",
		PipelineLoops:   validSourceLoopConf,
		VCStoreEndpoint: registry.URL,
		VCStoreBearer:   "test-bearer",
	})

	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CONFIG_FILE="+confPath)
	cmd.Stdout = os.Stderr // boot log rides the test output when it fails
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pipeline: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Readiness: the boot is complete (NATS dialed, registry reachable) only
	// when the node says so.
	deadline := time.Now().Add(30 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("pipeline exited during boot: %v", err)
		default:
		}
		resp, err := http.Get(base + "/readyz")
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
		t.Fatal("pipeline never reached readiness within 30s")
	}

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz = %d", resp.StatusCode)
	}

	// Graceful shutdown: SIGTERM drains the HTTP server and the data plane
	// (the shared NATS connection closes only after every loop has drained)
	// and exits zero.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("graceful shutdown exited non-zero: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("pipeline did not exit within 20s of SIGTERM")
	}
}

// runEmbeddedNATS starts an in-process NATS broker (no auth/operator config,
// so the account-JWT credentials natstransport.Connect mints are accepted
// unconditionally — the same posture cmd/standalone's own embedded-NATS
// helpers rely on) and returns its client URL. Ported from
// cmd/standalone/bootsmoke_test.go.
func runEmbeddedNATS(t *testing.T) string {
	t.Helper()
	srv := natstest.RunServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}
