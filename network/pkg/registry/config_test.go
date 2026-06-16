package registry_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/registry"
)

// loadWith builds a config from the registered reference plus an optional
// application.conf override written into a fresh temp appDir (per-test isolation).
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
	cfg, err := hoconconfig.Load(dir, "REGISTRY_TEST_OVERLAY_NEVER_SET")
	if err != nil {
		t.Fatalf("hoconconfig.Load: %v", err)
	}
	return cfg
}

func TestLoad_Valid(t *testing.T) {
	rc, err := registry.LoadRegistryConfig(loadWith(t, `provin.network.registry {
		id = "poc.dplaax.io"
		service-endpoints {
		  vc-resolver { type = "VCResolver", url = "https://r.example/vc" }
		  chain       { type = "Chain",      url = "https://r.example/chain" }
		}
	}`))
	if err != nil {
		t.Fatalf("LoadRegistryConfig: %v", err)
	}
	if rc.ID != "poc.dplaax.io" {
		t.Errorf("ID = %q", rc.ID)
	}
	// Sorted by id: chain, vc-resolver.
	if len(rc.Endpoints) != 2 || rc.Endpoints[0].ID != "chain" || rc.Endpoints[1].ID != "vc-resolver" {
		t.Fatalf("endpoints = %+v", rc.Endpoints)
	}
	if rc.Endpoints[1].Type != "VCResolver" || rc.Endpoints[1].ServiceEndpoint != "https://r.example/vc" {
		t.Errorf("vc-resolver endpoint = %+v", rc.Endpoints[1])
	}
}

func TestLoad_NoEndpoints(t *testing.T) {
	rc, err := registry.LoadRegistryConfig(loadWith(t, `provin.network.registry.id = "poc.dplaax.io"`))
	if err != nil {
		t.Fatalf("LoadRegistryConfig: %v", err)
	}
	if len(rc.Endpoints) != 0 {
		t.Errorf("endpoints = %+v, want none", rc.Endpoints)
	}
}

func TestLoad_RejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty id (the reference default)": ``,
		"colon in id":                      `provin.network.registry.id = "poc:dplaax"`,
		"empty endpoint type": `provin.network.registry {
			id = "poc.dplaax.io"
			service-endpoints { e { type = "", url = "https://r/v" } }
		}`,
		"non-http endpoint url": `provin.network.registry {
			id = "poc.dplaax.io"
			service-endpoints { e { type = "T", url = "ftp://r/v" } }
		}`,
		"endpoint url missing host": `provin.network.registry {
			id = "poc.dplaax.io"
			service-endpoints { e { type = "T", url = "https://" } }
		}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := registry.LoadRegistryConfig(loadWith(t, body)); err == nil {
				t.Errorf("%s: want error, got nil", name)
			}
		})
	}
}
