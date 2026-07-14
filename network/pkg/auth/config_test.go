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

func TestLoadAuthConfig_BackendDefaultsO3co(t *testing.T) {
	// An unset backend must default to o3co so existing deployments (which only
	// set policy-verifier-url) keep their exact behavior.
	cc, err := auth.LoadAuthConfig(loadWith(t, `provin.network.auth.policy-verifier-url = "https://pv.internal:3001"`))
	if err != nil {
		t.Fatalf("LoadAuthConfig: %v", err)
	}
	if cc.Backend != auth.BackendO3co {
		t.Errorf("Backend = %q, want %q (unset must default to o3co)", cc.Backend, auth.BackendO3co)
	}
}

func TestLoadAuthConfig_FailsClosed(t *testing.T) {
	cases := map[string]string{
		"empty default":   "",                                                                               // reference.conf default is "" + backend o3co
		"scheme-less":     `provin.network.auth.policy-verifier-url = "pv.internal:3001"`,                   // no http(s)://
		"hostless":        `provin.network.auth.policy-verifier-url = "https://"`,                           // scheme set, no host
		"userinfo creds":  `provin.network.auth.policy-verifier-url = "https://user:pass@pv.internal:3001"`, // credentials in URL: rejected so they can't leak to logs
		"unknown backend": `provin.network.auth.backend = "bogus"`,
		"opa empty url":   `provin.network.auth.backend = "opa"`, // opa selected, no base-url
		"opa missing policy-path": `
provin.network.auth.backend = "opa"
provin.network.auth.opa.base-url = "https://opa.internal:8181"
`, // base-url set but policy-path (required by the opa backend) empty
	}
	for name, body := range cases {
		if _, err := auth.LoadAuthConfig(loadWith(t, body)); err == nil {
			t.Errorf("%s: want error (fail-closed)", name)
		}
	}
}

func TestLoadAuthConfig_StaticNeedsNoVerifierURL(t *testing.T) {
	// A static deployment must load with no policy-verifier-url, and its
	// allow-list ("resource:action" entries) must be read.
	cc, err := auth.LoadAuthConfig(loadWith(t, `
provin.network.auth.backend = "static"
provin.network.auth.static.allow = ["dids:read", "schemas/*:*"]
`))
	if err != nil {
		t.Fatalf("LoadAuthConfig static: %v", err)
	}
	if cc.Backend != auth.BackendStatic {
		t.Errorf("Backend = %q, want static", cc.Backend)
	}
	want := []auth.StaticAllowRule{{Resource: "dids", Action: "read"}, {Resource: "schemas/*", Action: "*"}}
	if len(cc.Static.Allow) != len(want) {
		t.Fatalf("Static.Allow = %+v, want %+v", cc.Static.Allow, want)
	}
	for i, r := range want {
		if cc.Static.Allow[i] != r {
			t.Errorf("Static.Allow[%d] = %+v, want %+v", i, cc.Static.Allow[i], r)
		}
	}
}

func TestLoadAuthConfig_OPAReadsBaseURLAndPolicyPath(t *testing.T) {
	cc, err := auth.LoadAuthConfig(loadWith(t, `
provin.network.auth.backend = "opa"
provin.network.auth.opa.base-url = "https://opa.internal:8181"
provin.network.auth.opa.policy-path = "provin/authz"
`))
	if err != nil {
		t.Fatalf("LoadAuthConfig opa: %v", err)
	}
	if cc.OPA.BaseURL != "https://opa.internal:8181" || cc.OPA.PolicyPath != "provin/authz" {
		t.Errorf("OPA = %+v", cc.OPA)
	}
}
