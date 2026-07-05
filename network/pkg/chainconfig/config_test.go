package chainconfig_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/chainconfig"
)

func loadWith(t *testing.T, appConf string) *hoconconfig.Config {
	t.Helper()
	dir := t.TempDir()
	if appConf != "" {
		confDir := filepath.Join(dir, "config")
		if err := os.MkdirAll(confDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(confDir, "application.conf"), []byte(appConf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := hoconconfig.Load(dir, "CHAIN_TEST_OVERLAY_NEVER_SET")
	if err != nil {
		t.Fatalf("hoconconfig.Load: %v", err)
	}
	return cfg
}

// seedFile writes a raw nkey seed (with a trailing newline, to exercise trimming)
// to a temp file and returns its path.
func seedFile(t *testing.T, seed []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(p, append(seed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func natsConf(transport, url, accFile, opFile, dir, nodeDID string) string {
	return `provin.network.chain {
  transport = "` + transport + `"
  nats {
    url = "` + url + `"
    account-seed-file = "` + accFile + `"
    trust-root-seed-file = "` + opFile + `"
    resolver-dir = "` + dir + `"
    node-did = "` + nodeDID + `"
  }
}`
}

const nodeDID = "did:dplaax:poc.dplaax.dev:org:node"

func TestLoad_NATS_Valid(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	cfg := loadWith(t, natsConf("nats", "nats://h:4222",
		seedFile(t, accSeed), seedFile(t, opSeed), "/var/chain/jwts", nodeDID))

	c, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		t.Fatalf("LoadChainConfig: %v", err)
	}
	if c.Transport != chainconfig.TransportNATS {
		t.Errorf("transport = %q", c.Transport)
	}
	if c.NATS.URL != "nats://h:4222" || c.NATS.ResolverDir != "/var/chain/jwts" || c.NATS.NodeDID != nodeDID {
		t.Errorf("nats = %+v", c.NATS)
	}
	// seeds are read from the files and trimmed (no trailing newline).
	if c.NATS.AccountSeed != string(accSeed) || c.NATS.TrustRootSeed != string(opSeed) {
		t.Errorf("seeds not read/trimmed correctly")
	}
}

func TestLoad_NATS_MissingURL(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	cfg := loadWith(t, natsConf("nats", "", seedFile(t, accSeed), seedFile(t, opSeed), "/d", nodeDID))
	if _, err := chainconfig.LoadChainConfig(cfg); err == nil {
		t.Error("missing nats url accepted")
	}
}

func TestLoad_NATS_SwappedSeedTypes(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	// account seed placed in the trust-root slot and vice versa.
	cfg := loadWith(t, natsConf("nats", "nats://h:4222",
		seedFile(t, opSeed), seedFile(t, accSeed), "/d", nodeDID))
	if _, err := chainconfig.LoadChainConfig(cfg); err == nil {
		t.Error("swapped operator/account seeds accepted")
	}
}

func TestLoad_NATS_InvalidNodeDID(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	cfg := loadWith(t, natsConf("nats", "nats://h:4222",
		seedFile(t, accSeed), seedFile(t, opSeed), "/d", "not-a-did"))
	if _, err := chainconfig.LoadChainConfig(cfg); err == nil {
		t.Error("invalid node-did accepted")
	}
}

func TestLoad_NATS_MalformedResolverBaseURL(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	// resolver-base-url set to a number → type mismatch must fail boot, not be
	// silently ignored (convergent review).
	conf := `provin.network.chain {
  transport = "nats"
  nats {
    url = "nats://h:4222"
    account-seed-file = "` + seedFile(t, accSeed) + `"
    trust-root-seed-file = "` + seedFile(t, opSeed) + `"
    resolver-dir = "/d"
    node-did = "` + nodeDID + `"
    resolver-base-url = 123
  }
}`
	if _, err := chainconfig.LoadChainConfig(loadWith(t, conf)); err == nil {
		t.Error("malformed resolver-base-url (number) silently accepted")
	}
}

func TestLoad_Noop(t *testing.T) {
	cfg := loadWith(t, `provin.network.chain {
  transport = "noop"
  dev { allow-noop-transport = true }
}`)
	c, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		t.Fatalf("LoadChainConfig: %v", err)
	}
	if c.Transport != chainconfig.TransportNoop || !c.AllowNoopTransport {
		t.Errorf("noop config = %+v", c)
	}
}

func TestLoad_InvalidTransport(t *testing.T) {
	cfg := loadWith(t, `provin.network.chain { transport = "kafka" }`)
	if _, err := chainconfig.LoadChainConfig(cfg); err == nil {
		t.Error("invalid transport accepted")
	}
}

func TestLoad_NATS_ConnectWait(t *testing.T) {
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	base := natsConf("nats", "nats://h:4222",
		seedFile(t, accSeed), seedFile(t, opSeed), "/var/chain/jwts", nodeDID)

	// Default: 30s boot budget from reference.conf.
	c, err := chainconfig.LoadChainConfig(loadWith(t, base))
	if err != nil {
		t.Fatalf("LoadChainConfig: %v", err)
	}
	if c.NATS.ConnectWait != 30*time.Second {
		t.Errorf("default ConnectWait = %s, want 30s", c.NATS.ConnectWait)
	}

	// Override to strict fail-fast zero.
	c, err = chainconfig.LoadChainConfig(loadWith(t, base+"\nprovin.network.chain.nats.connect-wait = 0s"))
	if err != nil {
		t.Fatalf("LoadChainConfig(0s): %v", err)
	}
	if c.NATS.ConnectWait != 0 {
		t.Errorf("zero override ConnectWait = %s, want 0", c.NATS.ConnectWait)
	}

	// Negative fails boot.
	if _, err := chainconfig.LoadChainConfig(loadWith(t, base+"\nprovin.network.chain.nats.connect-wait = -1s")); err == nil {
		t.Error("negative connect-wait: want boot error")
	}
}
