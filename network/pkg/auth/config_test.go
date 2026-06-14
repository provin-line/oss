package auth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/auth"
)

func loadWith(t *testing.T, appConf string) *hoconconfig.Config {
	t.Helper()
	dir := t.TempDir()
	if appConf != "" {
		confDir := filepath.Join(dir, "config")
		if err := os.MkdirAll(confDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(confDir, "application.conf"), []byte(appConf), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	cfg, err := hoconconfig.Load(dir, "AUTH_TEST_OVERLAY_NEVER_SET")
	if err != nil {
		t.Fatalf("hoconconfig.Load: %v", err)
	}
	return cfg
}

func TestLoadAuthConfig_Valid(t *testing.T) {
	cc, err := auth.LoadAuthConfig(loadWith(t, `provin.network.auth.policy-verifier-url = "https://pv.internal:3001"`))
	if err != nil {
		t.Fatalf("LoadAuthConfig: %v", err)
	}
	if cc.PolicyVerifierURL != "https://pv.internal:3001" {
		t.Errorf("PolicyVerifierURL = %q", cc.PolicyVerifierURL)
	}
}

func TestLoadAuthConfig_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"empty default": "",                                                             // reference.conf default is ""
		"scheme-less":   `provin.network.auth.policy-verifier-url = "pv.internal:3001"`, // no http(s)://
		"hostless":      `provin.network.auth.policy-verifier-url = "https://"`,         // scheme set, no host
	}
	for name, body := range cases {
		if _, err := auth.LoadAuthConfig(loadWith(t, body)); err == nil {
			t.Errorf("%s: want error (fail-closed)", name)
		}
	}
}
