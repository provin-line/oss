package pipelineconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/vc"
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
	cfg, err := hoconconfig.Load(dir, "PIPELINE_TEST_OVERLAY_NEVER_SET")
	if err != nil {
		t.Fatalf("hoconconfig.Load: %v", err)
	}
	return cfg
}

// loopsConf wraps loop bodies in the pipeline.loops block.
func loopsConf(body string) string {
	return "provin.network.pipeline.loops {\n" + body + "\n}\n"
}

const validSourceLoop = `
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

func TestLoad_ValidSource(t *testing.T) {
	cfg := loadWith(t, loopsConf(validSourceLoop))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
	}
	l := pc.Loops[0]
	if l.Name != "src" || l.Role != "source" {
		t.Fatalf("name/role: got %q/%q", l.Name, l.Role)
	}
	if l.IngressSubject != "ingest.src" || l.OutputSubject != "did:dplaax:reg:org:acme:pipeline:pipe" {
		t.Fatalf("subjects: %q / %q", l.IngressSubject, l.OutputSubject)
	}
	if l.Issuer.DID != "did:dplaax:reg:org:acme:pipeline:pipe:process:src" ||
		l.Issuer.KeyID != "signing" ||
		l.Issuer.VerificationMethod != "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing" {
		t.Fatalf("issuer: %+v", l.Issuer)
	}
	if l.PipelineID != "pipe" || l.ProcessID != "src" {
		t.Fatalf("ids: %q / %q", l.PipelineID, l.ProcessID)
	}
	if l.TransformationClaim != vc.ClaimConvert {
		t.Fatalf("claim: got %q want %q", l.TransformationClaim, vc.ClaimConvert)
	}
}

func TestLoad_EmptyLoopsIsZeroLoops(t *testing.T) {
	// No application.conf override: the reference default is an empty loops {}.
	cfg := loadWith(t, "")
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if len(pc.Loops) != 0 {
		t.Fatalf("expected zero loops, got %d", len(pc.Loops))
	}
}

func TestLoad_FailClosed(t *testing.T) {
	mut := func(field, value string) string {
		// Replace one line of the valid loop to produce an invalid variant.
		return strings.Replace(validSourceLoop, field, value, 1)
	}
	cases := []struct {
		name string
		body string
	}{
		{"unknown role", mut(`role = "source"`, `role = "sink"`)},
		{"missing ingress", mut(`ingress-subject = "ingest.src"`, `ingress-subject = ""`)},
		{"output not pipeline DID", mut(
			`output-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`,
			`output-subject = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
		{"issuer not process DID", mut(
			`did = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`,
			`did = "did:dplaax:reg:org:acme:pipeline:pipe"`)},
		{"unknown transformation claim", mut(`transformation-claim = "convert"`, `transformation-claim = "frobnicate"`)},
		{"non-empty schema-ref", mut(`schema-ref = ""`, `schema-ref = "sha256:abc"`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadWith(t, loopsConf(tc.body))
			if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}
