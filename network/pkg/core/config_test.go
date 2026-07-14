package core_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/core"
)

// loadWith builds a hocon config from the registered reference plus an optional
// application.conf body written into a temp appDir. The overlay env is a name
// that is never set, so only reference + application apply.
func loadWith(t *testing.T, appConf string) *hoconconfig.Config {
	t.Helper()
	dir := t.TempDir()
	if appConf != "" {
		confDir := filepath.Join(dir, "config")
		if err := os.MkdirAll(confDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(confDir, "application.conf"), []byte(appConf), 0o644); err != nil {
			t.Fatalf("write application.conf: %v", err)
		}
	}
	cfg, err := hoconconfig.Load(dir, "CORE_TEST_OVERLAY_NEVER_SET")
	if err != nil {
		t.Fatalf("hoconconfig.Load: %v", err)
	}
	return cfg
}

func TestLoadCoreConfig_Defaults(t *testing.T) {
	cc, err := core.LoadCoreConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadCoreConfig: %v", err)
	}
	if cc.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want :8443", cc.ListenAddr)
	}
	if cc.DataDir != "./data" {
		t.Errorf("DataDir = %q, want ./data", cc.DataDir)
	}
	if cc.AllowLoopback {
		t.Error("AllowLoopback = true, want false (default)")
	}
	if cc.MetricsEnabled {
		t.Error("MetricsEnabled = true, want false (default: /metrics is unauthenticated on a non-loopback listener)")
	}
}

func TestLoadCoreConfig_MetricsEnabledOverride(t *testing.T) {
	cc, err := core.LoadCoreConfig(loadWith(t, "provin.network.core.metrics.enabled = true"))
	if err != nil {
		t.Fatalf("LoadCoreConfig: %v", err)
	}
	if !cc.MetricsEnabled {
		t.Error("MetricsEnabled = false, want true (application.conf opt-in)")
	}
}

func TestLoadCoreConfig_Override(t *testing.T) {
	cc, err := core.LoadCoreConfig(loadWith(t, `provin.network.core {
		listen-addr = "127.0.0.1:9000"
		data-dir = "/var/lib/provin"
		dev { allow-loopback = true }
	}`))
	if err != nil {
		t.Fatalf("LoadCoreConfig: %v", err)
	}
	if cc.ListenAddr != "127.0.0.1:9000" || cc.DataDir != "/var/lib/provin" || !cc.AllowLoopback {
		t.Errorf("override not applied: %+v", cc)
	}
}

func TestLoadCoreConfig_InvalidListenAddr(t *testing.T) {
	cases := map[string]string{
		"no port":      `provin.network.core.listen-addr = "garbage-no-port"`,
		"port range":   `provin.network.core.listen-addr = ":99999"`,
		"port not num": `provin.network.core.listen-addr = ":http"`,
	}
	for name, body := range cases {
		if _, err := core.LoadCoreConfig(loadWith(t, body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestLoadCoreConfig_EmptyDataDir(t *testing.T) {
	if _, err := core.LoadCoreConfig(loadWith(t, `provin.network.core.data-dir = ""`)); err == nil {
		t.Error("empty data-dir: want error")
	}
}

func TestLoadCoreConfig_AllowPrivateNetworks(t *testing.T) {
	cc, err := core.LoadCoreConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadCoreConfig: %v", err)
	}
	if cc.AllowPrivateNetworks {
		t.Error("AllowPrivateNetworks = true, want false (default)")
	}
	cc, err = core.LoadCoreConfig(loadWith(t, `provin.network.core.allow-private-networks = true`))
	if err != nil {
		t.Fatalf("LoadCoreConfig(override): %v", err)
	}
	if !cc.AllowPrivateNetworks {
		t.Error("AllowPrivateNetworks = false, want true (override)")
	}
}
