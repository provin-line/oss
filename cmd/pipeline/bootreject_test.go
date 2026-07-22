package main

import (
	stded25519 "crypto/ed25519"
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

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// This binary exists ONLY to run data-plane loops (the package doc): a config
// declaring zero provin.network.pipeline.loops is a boot error naming the
// control-plane sibling (cmd/network). Mirrors cmd/network's own
// bootreject_test.go builder-helper pattern, adjusted to this binary's own
// CONFIG_FILE convention (a single required config file, not
// config/application.conf + CONFIG_OVERLAY) and its own guards.
func TestPipeline_BootRejectsZeroLoops(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildPipelineBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		Transport:  "nats",
		// A fully valid (but unreachable) NATS block: chainconfig.LoadChainConfig
		// validates it regardless of loop count, and runs BEFORE the zero-loop
		// guard — this config must pass that validation so the zero-loop guard
		// (not an unrelated config error) is what rejects the boot. Unreachable
		// on purpose: the guard must die BEFORE any nats dial.
		NATSURL:    "nats://127.0.0.1:1",
		AccSeed:    accSeedFile,
		TrustSeed:  trustSeedFile,
		ResolveDir: filepath.Join(dir, "resolver"),
		NodeDID:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node",
		// PipelineLoops / VCStoreEndpoint / VCStoreBearer intentionally left
		// empty — the zero-loop guard must fire before either the transport
		// guard or the vc-store guard even considers them.
	})

	out, err := runPipelineBinary(t, bin, dir, confPath)
	if err == nil {
		t.Fatalf("pipeline booted with zero loops; want a non-zero exit\noutput:\n%s", out)
	}
	const want = "this binary exists to run loops"
	if !strings.Contains(out, want) {
		t.Errorf("boot failure does not name the zero-loop guard (want %q):\n%s", want, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the zero-loop guard rejecting boot")
	}
}

// A configured loop on a non-NATS transport is a boot error: the loop has
// nothing to dial (pipelineRuntimeConfigFrom's own transport guard, ported
// verbatim from cmd/standalone's runtimeConfigFrom). transport = "noop"
// needs no NATS fields at all, so this config is deliberately minimal.
func TestPipeline_BootRejectsNonNATSTransportWithLoops(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildPipelineBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr:    fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:       filepath.Join(dir, "data"),
		CertFile:      certFile,
		KeyFile:       keyFile,
		Transport:     "noop",
		PipelineLoops: validSourceLoopConf,
	})

	out, err := runPipelineBinary(t, bin, dir, confPath)
	if err == nil {
		t.Fatalf("pipeline booted with loops on a non-nats transport; want a non-zero exit\noutput:\n%s", out)
	}
	const want = "require the nats transport"
	if !strings.Contains(out, want) {
		t.Errorf("boot failure does not name the transport guard (want %q):\n%s", want, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the transport guard rejecting boot")
	}
}

// Any loop configured requires BOTH vc-store-endpoint and vc-store-bearer:
// this binary treats the vc-store endpoint as the ONE registry base URL for
// every wire dependency it composes (audit, schema, payload), stricter than
// network/pkg/pipelineconfig's own contract (which tolerates an unset
// endpoint for a source-only, non-publishing node).
func TestPipeline_BootRejectsMissingVCStoreEndpointAndBearer(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildPipelineBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		Transport:  "nats",
		// Unreachable on purpose: the vc-store guard must die BEFORE any nats
		// dial, so this URL is never actually contacted.
		NATSURL:       "nats://127.0.0.1:1",
		AccSeed:       accSeedFile,
		TrustSeed:     trustSeedFile,
		ResolveDir:    filepath.Join(dir, "resolver"),
		NodeDID:       "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node",
		PipelineLoops: validSourceLoopConf,
		// VCStoreEndpoint / VCStoreBearer intentionally left empty.
	})

	out, err := runPipelineBinary(t, bin, dir, confPath)
	if err == nil {
		t.Fatalf("pipeline booted without a vc-store endpoint/bearer; want a non-zero exit\noutput:\n%s", out)
	}
	for _, want := range []string{"vc-store-endpoint", pipelineconfig.VCStoreBearerKey} {
		if !strings.Contains(out, want) {
			t.Errorf("boot failure does not name %q:\n%s", want, out)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the vc-store guard rejecting boot")
	}
}

// F8: allow-private-networks=true requires a scoped registry-resolution map
// (registry-base-urls or resolver-base-url) — an unmapped (attacker-supplied)
// registry must not fall back to the open https://{registry} resolution and
// reach private address space. Mirrors internal/netcompose's own
// TestNewDIDResolution_PrivateModeRequiresRegistryScoping, exercised here
// through the actual binary's boot path (newDIDResolution, this binary's own
// equivalent).
func TestPipeline_BootRejectsPrivateNetworksWithoutScopedResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildPipelineBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    filepath.Join(dir, "data"),
		CertFile:   certFile,
		KeyFile:    keyFile,
		Transport:  "nats",
		// Unreachable on purpose: the DID-resolution guard must die BEFORE any
		// nats dial.
		NATSURL:              "nats://127.0.0.1:1",
		AccSeed:              accSeedFile,
		TrustSeed:            trustSeedFile,
		ResolveDir:           filepath.Join(dir, "resolver"),
		NodeDID:              "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node",
		PipelineLoops:        validSourceLoopConf,
		VCStoreEndpoint:      "https://127.0.0.1:1/",
		VCStoreBearer:        "test-bearer",
		AllowPrivateNetworks: true,
		// ResolverBaseURL/RegistryBaseURLs both left unset — the F8 hole.
	})

	out, err := runPipelineBinary(t, bin, dir, confPath)
	if err == nil {
		t.Fatalf("pipeline booted with allow-private-networks=true and no scoped resolution; want a non-zero exit\noutput:\n%s", out)
	}
	const want = "allow-private-networks=true requires configured registry resolution"
	if !strings.Contains(out, want) {
		t.Errorf("boot failure does not name the F8 guard (want %q):\n%s", want, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "data")); statErr == nil {
		t.Errorf("data dir was created despite the F8 guard rejecting boot")
	}
}

// TestPipeline_BootRejectsMissingPayloadRetainKey proves the D9 boot
// preflight (main.go's Boot guard 5, preflightPayloadRetainKeys in
// wiring.go): TWO producing loops with DIFFERENT output subjects — src1
// (provisioned) and src2 (deliberately NOT provisioned) — must reject boot
// naming SPECIFICALLY the loop and output subject missing its key, proving
// the guard checks EVERY producing loop rather than stopping at the first.
func TestPipeline_BootRejectsMissingPayloadRetainKey(t *testing.T) {
	if testing.Short() {
		t.Skip("boot reject builds a binary")
	}
	bin := buildPipelineBinary(t)
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t)
	accSeedFile, trustSeedFile := writeNKeySeedFiles(t)
	dataDir := filepath.Join(dir, "data")

	// Provision ONLY src1's own output-subject key, directly into the
	// DataDir/keys tree the real binary's keystore (main.go) will open — src2's
	// is deliberately left unprovisioned so the guard must name IT, not src1.
	provisionPayloadRetainKey(t, dataDir, "did:dplaax:reg:org:acme:pipeline:pipe1")

	confPath := writeBootConfigFile(t, dir, bootConfig{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		DataDir:    dataDir,
		CertFile:   certFile,
		KeyFile:    keyFile,
		Transport:  "nats",
		// Unreachable on purpose: guard 5 must die BEFORE any nats dial.
		NATSURL:         "nats://127.0.0.1:1",
		AccSeed:         accSeedFile,
		TrustSeed:       trustSeedFile,
		ResolveDir:      filepath.Join(dir, "resolver"),
		NodeDID:         "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node",
		PipelineLoops:   twoProducingLoopsConf,
		VCStoreEndpoint: "https://127.0.0.1:1/",
		VCStoreBearer:   "test-bearer",
	})

	out, err := runPipelineBinary(t, bin, dir, confPath)
	if err == nil {
		t.Fatalf("pipeline booted with src2's payload-retain key missing; want a non-zero exit\noutput:\n%s", out)
	}
	for _, want := range []string{"no signing key for output subject", `"src2"`, "did:dplaax:reg:org:acme:pipeline:pipe2"} {
		if !strings.Contains(out, want) {
			t.Errorf("boot failure does not name the D9 guard (want %q):\n%s", want, out)
		}
	}
	if strings.Contains(out, `"src1"`) {
		t.Errorf("boot failure names src1 (which HAD its key provisioned) — want it to name only src2:\n%s", out)
	}
}

// twoProducingLoopsConf declares TWO source loops with DIFFERENT output
// subjects (pipe1, pipe2) — the exact topology the D9 gap broke: a node
// running more than one producing loop, each needing its OWN payload-retain
// signing key.
const twoProducingLoopsConf = `
    src1 {
      role = "source"
      ingress-subject = "ingest.src1"
      output-subject = "did:dplaax:reg:org:acme:pipeline:pipe1"
      issuer {
        did = "did:dplaax:reg:org:acme:pipeline:pipe1:process:src1"
        key-id = "signing"
        verification-method = "did:dplaax:reg:org:acme:pipeline:pipe1:process:src1#signing"
      }
      pipeline-id = "pipe1"
      process-id = "src1"
      transformation-claim = "convert"
      schema-ref = ""
    }
    src2 {
      role = "source"
      ingress-subject = "ingest.src2"
      output-subject = "did:dplaax:reg:org:acme:pipeline:pipe2"
      issuer {
        did = "did:dplaax:reg:org:acme:pipeline:pipe2:process:src2"
        key-id = "signing"
        verification-method = "did:dplaax:reg:org:acme:pipeline:pipe2:process:src2#signing"
      }
      pipeline-id = "pipe2"
      process-id = "src2"
      transformation-claim = "convert"
      schema-ref = ""
    }
`

// validSourceLoopConf is a single, fully valid "source" loop — LoadPipelineConfig
// must succeed so whichever guard is under test (which runs AFTER it) is what
// rejects the boot, not an unrelated config error. Mirrors cmd/network's own
// fixture of the same name.
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

// bootConfig is the config-file shape every boot-reject test writes.
type bootConfig struct {
	ListenAddr string
	DataDir    string
	CertFile   string
	KeyFile    string

	Transport  string
	NATSURL    string
	AccSeed    string
	TrustSeed  string
	ResolveDir string
	NodeDID    string

	AllowPrivateNetworks bool
	AllowLoopback        bool

	PipelineLoops   string
	VCStoreEndpoint string
	VCStoreBearer   string
}

// writeBootConfigFile writes dir/pipeline.conf for the actual binary to load
// via hoconconfig.LoadFile("CONFIG_FILE") and returns its path. Unlike
// cmd/network/cmd/standalone's writeBootConfig (which writes
// dir/config/application.conf, loaded by the CONFIG_OVERLAY convention),
// this binary's CONFIG_FILE convention names one file directly with no
// fixed location.
func writeBootConfigFile(t *testing.T, dir string, c bootConfig) string {
	t.Helper()
	if c.ResolveDir != "" {
		if err := os.MkdirAll(c.ResolveDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	conf := fmt.Sprintf(`
provin.network.core {
  listen-addr = "%s"
  data-dir = "%s"
  allow-private-networks = %t
  tls {
    cert-file = "%s"
    key-file  = "%s"
  }
  dev {
    allow-loopback = %t
  }
}
provin.network.auth {
  backend = "static"
}
provin.network.chain {
  transport = "%s"
  nats {
    url = "%s"
    account-seed-file = "%s"
    trust-root-seed-file = "%s"
    resolver-dir = "%s"
    node-did = "%s"
    resolver-base-url = ""
  }
}
`, c.ListenAddr, c.DataDir, c.AllowPrivateNetworks, c.CertFile, c.KeyFile, c.AllowLoopback, c.Transport, c.NATSURL, c.AccSeed, c.TrustSeed, c.ResolveDir, c.NodeDID)

	if c.PipelineLoops != "" || c.VCStoreEndpoint != "" || c.VCStoreBearer != "" {
		var b strings.Builder
		b.WriteString("\nprovin.network.pipeline {\n")
		if c.VCStoreEndpoint != "" {
			fmt.Fprintf(&b, "  vc-store-endpoint = %q\n", c.VCStoreEndpoint)
		}
		if c.VCStoreBearer != "" {
			fmt.Fprintf(&b, "  vc-store-bearer = %q\n", c.VCStoreBearer)
		}
		if c.PipelineLoops != "" {
			fmt.Fprintf(&b, "  loops {\n%s\n  }\n", c.PipelineLoops)
		}
		b.WriteString("}\n")
		conf += b.String()
	}

	path := filepath.Join(dir, "pipeline.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// provisionPayloadRetainKey writes a #auth key for subjectDID directly into
// dataDir/keys — the SAME directory main.go's own filestore.New(filepath.
// Join(coreCfg.DataDir, "keys")) opens — so a boot-reject/smoke test can
// satisfy (or deliberately withhold, for the negative case) the D9 boot
// preflight (main.go's Boot guard 5, preflightPayloadRetainKeys in
// wiring.go) for a producing loop's OWN output subject BEFORE the real
// binary ever starts. Shared by TestPipeline_BootRejectsMissingPayloadRetainKey
// (this file) and TestPipeline_ActualBoot (bootsmoke_test.go).
func provisionPayloadRetainKey(t *testing.T, dataDir, subjectDID string) {
	t.Helper()
	ks := ksfilestore.New(filepath.Join(dataDir, "keys"))
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(subjectDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatal(err)
	}
}

// runPipelineBinary execs bin with CONFIG_FILE=confPath and cmd.Dir = dir,
// returning combined output and the exit error.
func runPipelineBinary(t *testing.T, bin, dir, confPath string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CONFIG_FILE="+confPath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// buildPipelineBinary builds the actual cmd/pipeline binary — the boot
// tests exec it (not an in-process harness) so they see what main() really
// does (config loading, guard ordering, signal handling), not a
// reimplementation of it.
func buildPipelineBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pipeline")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/provin-line/oss/cmd/pipeline").CombinedOutput()
	if err != nil {
		t.Fatalf("build pipeline: %v\n%s", err, out)
	}
	return bin
}

// writeSelfSignedCert generates an ed25519 self-signed cert for 127.0.0.1 and
// writes cert.pem / key.pem to a temp dir, returning their paths. Ported from
// cmd/network/bootreject_test.go.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	pub, priv, err := stded25519.GenerateKey(rand.Reader)
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
// cmd/network/bootreject_test.go.
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
// cmd/network/bootreject_test.go.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
