package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// A pipeline loop configured under this binary's config is a boot error: the
// network node is the control-plane-only half of the recomposition (task
// brief) and must die loudly rather than silently ignore data-plane config
// meant for the pipeline runtime. Ported from cmd/standalone/bootsmoke_test.go's
// builder-helper pattern (buildStandaloneBinary / writeBootConfig), adjusted to
// this package's binary path and to carry one pipeline loop.
func TestNetwork_BootRejectsConfiguredPipelineLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildNetworkBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)

	writeBootConfig(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		// Unreachable on purpose: the guard must die BEFORE any chain-operator
		// broker dial, so this URL is never actually contacted.
		NATSURL:       "nats://127.0.0.1:1",
		AccSeed:       accSeedFile,
		TrustSeed:     trustSeedFile,
		ResolveDir:    filepath.Join(dir, "resolver"),
		PipelineLoops: validSourceLoopConf,
	})

	cmd := exec.Command(bin)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("network booted with a configured pipeline loop; want a non-zero exit\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "runs no data plane") {
		t.Errorf("boot failure does not name the control-plane-only guard (want %q):\n%s", "runs no data plane", out)
	}
	// The guard must fire before any store is created — a data directory here
	// would mean the node did side-effectful boot work past the point it
	// decided to refuse to run.
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the pipeline-loop guard rejecting boot")
	}
}

// This binary always runs the peer-fetching batch resolver (Task 9): builders build
// unconditionally now, and unlike cmd/standalone this binary can never gate the runner on
// pipeCfg.HasConsumingLoop() (the guard above enforces zero loops here, so that predicate
// is always false). The resolver's peer fetches present provin.network.pipeline.vc-store-
// bearer against L1-protected peers regardless of local loops, so an empty bearer must
// fail boot rather than silently starve every fetch at runtime.
func TestNetwork_BootRejectsEmptyVCStoreBearer(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildNetworkBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)

	writeBootConfig(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		// Unreachable on purpose: the bearer guard must die BEFORE any chain-operator
		// broker dial, so this URL is never actually contacted.
		NATSURL:    "nats://127.0.0.1:1",
		AccSeed:    accSeedFile,
		TrustSeed:  trustSeedFile,
		ResolveDir: filepath.Join(dir, "resolver"),
		// VCStoreBearer intentionally left empty (the default/absent case).
	})

	cmd := exec.Command(bin)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("network booted with an empty vc-store-bearer; want a non-zero exit\noutput:\n%s", out)
	}
	const wantKey = "provin.network.pipeline.vc-store-bearer"
	if !strings.Contains(string(out), wantKey) {
		t.Errorf("boot failure does not name the config key (want %q):\n%s", wantKey, out)
	}
	// The guard must fire before any store is created — a data directory here would
	// mean the node did side-effectful boot work past the point it decided to refuse.
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the vc-store-bearer guard rejecting boot")
	}
}

// validSourceLoopConf is a single, fully valid "source" loop (mirrors
// network/pkg/pipelineconfig's validSourceLoop fixture) — LoadPipelineConfig
// must succeed so the guard (which runs AFTER it) is what rejects the boot,
// not an unrelated config error.
const validSourceLoopConf = `
    src {
      role = "source"
      ingress-subject = "ingest.src"
      output-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
      issuer {
        did = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"
        key-id = "signing"
        verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing"
      }
      pipeline-id = "pipe"
      process-id = "src"
      transformation-claim = "convert"
      schema-ref = ""
    }
`

// bootConfig is the config-file shape both the boot-reject and boot-smoke
// tests write. PipelineLoops, when non-empty, is embedded verbatim as the body
// of provin.network.pipeline.loops (the raw HOCON block for one or more
// loops); empty means no pipeline block at all (zero loops, the valid default).
// VCStoreBearer, when non-empty, sets provin.network.pipeline.vc-store-bearer;
// empty means the key is omitted (this binary's boot-validation guard requires
// it non-empty regardless of PipelineLoops — Task 9 — since it always runs the
// peer-fetching batch resolver).
type bootConfig struct {
	ListenAddr    string
	DataDir       string
	CertFile      string
	KeyFile       string
	NATSURL       string
	AccSeed       string
	TrustSeed     string
	ResolveDir    string
	PipelineLoops string
	VCStoreBearer string
}

// writeBootConfig writes dir/config/application.conf for the actual binary to
// load via hoconconfig.Load(".", "CONFIG_OVERLAY") (cmd.Dir = dir). Ported
// from cmd/standalone/bootsmoke_test.go's writeBootConfig.
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
  # which is the safe default and irrelevant here — these smokes exercise the
  # transport boot / the pipeline-loop guard, not authorization.
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
	if c.PipelineLoops != "" || c.VCStoreBearer != "" {
		var pipelineBlock strings.Builder
		pipelineBlock.WriteString("\nprovin.network.pipeline {\n")
		if c.VCStoreBearer != "" {
			fmt.Fprintf(&pipelineBlock, "  vc-store-bearer = %q\n", c.VCStoreBearer)
		}
		if c.PipelineLoops != "" {
			fmt.Fprintf(&pipelineBlock, "  loops {\n%s\n  }\n", c.PipelineLoops)
		}
		pipelineBlock.WriteString("}\n")
		conf += pipelineBlock.String()
	}
	if err := os.WriteFile(filepath.Join(confDir, "application.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildNetworkBinary builds the actual cmd/network binary — the boot smokes
// exec it (not an in-process harness) so they see what main() really does
// (config layering, the guard's position, signal handling), not a
// reimplementation of it.
func buildNetworkBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "network")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/provin-line/oss/cmd/network").CombinedOutput()
	if err != nil {
		t.Fatalf("build network: %v\n%s", err, out)
	}
	return bin
}

// writeSelfSignedCert generates an ed25519 self-signed cert for 127.0.0.1 and
// writes cert.pem / key.pem to a temp dir, returning their paths. Ported from
// cmd/standalone/main_test.go.
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

// writeNKeySeedFiles writes the account and trust-root seeds to files: the
// config surface takes PATHS, never inline key material. Ported from
// cmd/standalone/bootsmoke_test.go.
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

// freePort returns an OS-assigned free TCP port. Ported from
// cmd/standalone/bootsmoke_test.go.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
