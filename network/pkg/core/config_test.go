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
	if cc.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8443 (secure-by-default loopback)", cc.ListenAddr)
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

func TestListenerIsLoopback_Contract(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8443", true},
		{"127.0.0.2:8443", true}, // all of 127/8
		{"[::1]:8443", true},
		{"[0:0:0:0:0:0:0:1]:8443", true},  // ::1 long form
		{"[::ffff:127.0.0.1]:8443", true}, // v4-mapped loopback
		{"localhost:8443", false},         // hostname: resolved at bind, not guaranteed loopback
		{"LOCALHOST:8443", false},         // ditto
		{"localhost.:8443", false},        // ditto
		{":8443", false},                  // empty host = all interfaces
		{"0.0.0.0:8443", false},
		{"[::]:8443", false},
		{"10.0.0.5:8443", false},    // private
		{"203.0.113.7:8443", false}, // public
		{"node:8443", false},        // non-localhost DNS name (not resolved)
	} {
		if got := core.ListenerIsLoopback(tc.addr); got != tc.want {
			t.Errorf("ListenerIsLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// The transport-posture boot guard: a non-loopback listener serving cleartext
// (no TLS, no acknowledgement) must fail closed.
func TestLoadCoreConfig_TLSPostureGuard(t *testing.T) {
	ok := func(t *testing.T, body string) {
		t.Helper()
		if _, err := core.LoadCoreConfig(loadWith(t, body)); err != nil {
			t.Errorf("want boot OK, got %v", err)
		}
	}
	fail := func(t *testing.T, body string) {
		t.Helper()
		if _, err := core.LoadCoreConfig(loadWith(t, body)); err == nil {
			t.Error("want boot error (fail-closed)")
		}
	}

	// Default (unset listen-addr) is loopback → boots.
	ok(t, "")
	// Non-loopback + cleartext + no acknowledgement → fail closed.
	fail(t, `provin.network.core.listen-addr = ":8443"`)
	fail(t, `provin.network.core.listen-addr = "0.0.0.0:8443"`)
	// Non-loopback + explicit acknowledgement → OK.
	ok(t, `
provin.network.core.listen-addr = ":8443"
provin.network.core.tls.allow-cleartext = true
`)
	// Non-loopback + TLS cert/key → OK (TLS wins).
	ok(t, `
provin.network.core.listen-addr = ":8443"
provin.network.core.tls.cert-file = "/tmp/x.crt"
provin.network.core.tls.key-file  = "/tmp/x.key"
`)
	// cert/key must be both-or-neither.
	fail(t, `
provin.network.core.listen-addr = "127.0.0.1:8443"
provin.network.core.tls.cert-file = "/tmp/x.crt"
`)
	fail(t, `
provin.network.core.listen-addr = "127.0.0.1:8443"
provin.network.core.tls.key-file = "/tmp/x.key"
`)
	// Explicit loopback + cleartext → OK.
	ok(t, `provin.network.core.listen-addr = "127.0.0.1:8443"`)
}
