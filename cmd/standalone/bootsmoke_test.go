package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"
)

// P0-6 closure #5: the actual binary, booted from a real config file with an
// ephemeral certificate — readiness reached over HTTPS, a request served,
// graceful shutdown on SIGTERM.
//
// Every other TLS test in this package builds the server in-process, which
// cannot see what main() does: config layering, the preflight's position
// relative to side-effectful boot work, ListenAndServeTLS with empty paths,
// signal handling. The P0-6 debate recorded that nobody had ever booted this —
// "read-not-run" was the load-bearing gap. This is the run.
func TestStandalone_ActualBootOverTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("boot smoke builds a binary and starts a broker")
	}
	bin := buildStandaloneBinary(t)
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
	})

	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr // boot log rides the test output when it fails
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start standalone: %v", err)
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
			t.Fatalf("standalone exited during boot: %v", err)
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
		t.Fatal("standalone never reached readiness over HTTPS within 30s")
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
		t.Error("standalone did not exit within 20s of SIGTERM")
	}
}

// A boot whose certificate cannot be loaded must die BEFORE it creates state:
// the preflight's whole purpose (closure #3). Checking it from outside the
// process is the only way to see that the data directory stayed untouched.
func TestStandalone_BadCertificateFailsBootBeforeSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("boot smoke builds a binary")
	}
	bin := buildStandaloneBinary(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	certFile, keyFile := writeSelfSignedCert(t)
	mismatched, _ := writeSelfSignedCert(t) // a cert from a different key

	writeBootConfig(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    dataDir,
		CertFile:   mismatched,
		KeyFile:    keyFile,
		NATSURL:    "nats://127.0.0.1:1", // unreachable on purpose: the cert must fail first
		ResolveDir: filepath.Join(dir, "resolver"),
	})
	_ = certFile

	cmd := exec.Command(bin)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("standalone booted with a mismatched certificate pair")
	}
	if !containsAny(string(out), "TLS preflight", "certificate pair") {
		t.Errorf("boot failure does not name the certificate preflight:\n%s", out)
	}
	// The preflight runs before any store is created. A data directory here
	// would mean the node did side-effectful work before validating that it
	// could serve at all.
	if _, statErr := os.Stat(dataDir); statErr == nil {
		t.Errorf("data dir %s was created despite the cert preflight failing", dataDir)
	}
}

type bootConfig struct {
	ListenAddr string
	DataDir    string
	CertFile   string
	KeyFile    string
	NATSURL    string
	AccSeed    string
	TrustSeed  string
	ResolveDir string
}

func writeBootConfig(t *testing.T, dir string, c bootConfig) {
	t.Helper()
	confDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The account-claims resolver directory is deployment-provided (the
	// nats-server reads it too), so the node expects it to exist.
	if c.ResolveDir != "" {
		if err := os.MkdirAll(c.ResolveDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	conf := fmt.Sprintf(`
provin.network.core {
  listen-addr = "%s"
  data-dir = "%s"
  tls {
    cert-file = "%s"
    key-file  = "%s"
  }
}
provin.network.registry {
  id = "poc.dplaax.dev"
}
provin.network.auth {
  # static backend with an empty allow-list: authorization denies everything,
  # which is the safe default and irrelevant here — this smoke exercises the
  # transport boot, and the unauthenticated readiness routes are what it reads.
  backend = "static"
}
provin.network.chain {
  transport = "nats"
  nats {
    url = "%s"
    account-seed-file = "%s"
    trust-root-seed-file = "%s"
    resolver-dir = "%s"
    node-did = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node"
    resolver-base-url = "https://127.0.0.1:1"
  }
}
`, c.ListenAddr, c.DataDir, c.CertFile, c.KeyFile, c.NATSURL, c.AccSeed, c.TrustSeed, c.ResolveDir)
	if err := os.WriteFile(filepath.Join(confDir, "application.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildStandaloneBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "standalone")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/provin-line/oss/cmd/standalone").CombinedOutput()
	if err != nil {
		t.Fatalf("build standalone: %v\n%s", err, out)
	}
	return bin
}

func runEmbeddedNATS(t *testing.T) string {
	t.Helper()
	srv := natstest.RunServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	t.Cleanup(srv.Shutdown)
	return srv.ClientURL()
}

// writeNKeySeedFiles writes the account and trust-root seeds to files: the
// config surface takes PATHS, never inline key material.
func writeNKeySeedFiles(t *testing.T) (accountSeedFile, trustRootSeedFile string) {
	t.Helper()
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, err := acc.Seed()
	if err != nil {
		t.Fatal(err)
	}
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opSeed, err := op.Seed()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	accountSeedFile = filepath.Join(dir, "account.seed")
	trustRootSeedFile = filepath.Join(dir, "trustroot.seed")
	if err := os.WriteFile(accountSeedFile, append(accSeed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustRootSeedFile, append(opSeed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return accountSeedFile, trustRootSeedFile
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

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

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
