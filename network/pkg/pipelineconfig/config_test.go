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
	if l.IngressSubject != "ingest.src" || l.Source.OutputSubject != "did:dplaax:reg:org:acme:pipeline:pipe" {
		t.Fatalf("subjects: %q / %q", l.IngressSubject, l.Source.OutputSubject)
	}
	if l.Source.Issuer.DID != "did:dplaax:reg:org:acme:pipeline:pipe:process:src" ||
		l.Source.Issuer.KeyID != "signing" ||
		l.Source.Issuer.VerificationMethod != "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing" {
		t.Fatalf("issuer: %+v", l.Source.Issuer)
	}
	if l.Source.PipelineID != "pipe" || l.Source.ProcessID != "src" {
		t.Fatalf("ids: %q / %q", l.Source.PipelineID, l.Source.ProcessID)
	}
	if l.Source.TransformationClaim != vc.ClaimConvert {
		t.Fatalf("claim: got %q want %q", l.Source.TransformationClaim, vc.ClaimConvert)
	}
}

func TestLoad_AbsentSchemaRefIsEmpty(t *testing.T) {
	// schema-ref is optional in slice-17b: omitting it is equivalent to "" and must load.
	body := strings.Replace(validSourceLoop, `schema-ref = ""`, "", 1)
	cfg := loadWith(t, loopsConf(body))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("absent schema-ref should load: %v", err)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
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
		{"unknown role", mut(`role = "source"`, `role = "frobnicate"`)},
		{"chained role unsupported", mut(`role = "source"`, `role = "chained"`)},
		{"missing ingress", mut(`ingress-subject = "ingest.src"`, `ingress-subject = ""`)},
		{"output not pipeline DID", mut(
			`output-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`,
			`output-subject = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
		{"issuer not process DID", mut(
			`did = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`,
			`did = "did:dplaax:reg:org:acme:pipeline:pipe"`)},
		{"unknown transformation claim", mut(`transformation-claim = "convert"`, `transformation-claim = "frobnicate"`)},
		{"non-empty schema-ref", mut(`schema-ref = ""`, `schema-ref = "sha256:abc"`)},
		{"VM names a different DID", mut(
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing"`,
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:other#signing"`)},
		{"VM fragment mismatches key-id", mut(
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing"`,
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#auth"`)},
		{"VM has no fragment", mut(
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing"`,
			`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
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

const validSinkLoop = `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink {
      kind = "observation-only"
      verification-strategy = "adjacent"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
    }
  }
`

func TestLoad_ValidSink(t *testing.T) {
	cfg := loadWith(t, loopsConf(validSinkLoop))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
	}
	l := pc.Loops[0]
	if l.Name != "archive" || l.Role != pipelineconfig.RoleSink {
		t.Fatalf("name/role: got %q/%q", l.Name, l.Role)
	}
	if l.IngressSubject != "did:dplaax:reg:org:acme:pipeline:pipe" {
		t.Fatalf("ingress: %q", l.IngressSubject)
	}
	if l.Sink.Kind != pipelineconfig.SinkObservationOnly ||
		l.Sink.VerificationStrategy != pipelineconfig.StrategyAdjacent ||
		l.Sink.UpstreamEndpoint != "https://acme.example/pipelines/pipe" {
		t.Fatalf("sink: %+v", l.Sink)
	}
	// A sink carries no source identity.
	if l.Source != (pipelineconfig.SourceConfig{}) {
		t.Fatalf("sink loop has a non-zero Source: %+v", l.Source)
	}
}

func TestLoad_FailClosed_Sink(t *testing.T) {
	mut := func(field, value string) string {
		return strings.Replace(validSinkLoop, field, value, 1)
	}
	cases := []struct {
		name string
		body string
	}{
		{"unknown sink kind", mut(`kind = "observation-only"`, `kind = "warehouse"`)},
		{"missing sink kind", mut(`kind = "observation-only"`, `kind = ""`)},
		{"production kind unsupported in 17c", mut(`kind = "observation-only"`, `kind = "production"`)},
		{"archival kind unsupported in 17c", mut(`kind = "observation-only"`, `kind = "archival"`)},
		{"sink ingress not a pipeline DID", mut(
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`,
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
		{"verification-strategy full unsupported", mut(`verification-strategy = "adjacent"`, `verification-strategy = "full"`)},
		{"unknown verification-strategy", mut(`verification-strategy = "adjacent"`, `verification-strategy = "deep"`)},
		{"missing upstream-endpoint", mut(`upstream-endpoint = "https://acme.example/pipelines/pipe"`, `upstream-endpoint = ""`)},
		{"missing ingress", mut(`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`, `ingress-subject = ""`)},
		// Cross-role rejection: a sink carrying a source-only key fails closed.
		{"sink with output-subject", `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    output-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink { kind = "observation-only", verification-strategy = "adjacent", upstream-endpoint = "https://x" }
  }`},
		{"sink with issuer block", `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    issuer { did = "did:dplaax:reg:org:acme:pipeline:pipe:process:src" }
    sink { kind = "observation-only", verification-strategy = "adjacent", upstream-endpoint = "https://x" }
  }`},
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

// TestLoad_SourceWithSinkBlockRejected asserts the mirror cross-role guard: a source
// loop carrying a sink block fails closed.
func TestLoad_SourceWithSinkBlockRejected(t *testing.T) {
	body := strings.Replace(validSourceLoop, `schema-ref = ""`,
		"schema-ref = \"\"\n    sink { kind = \"observation-only\" }", 1)
	cfg := loadWith(t, loopsConf(body))
	if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
		t.Fatal("source loop with a sink block: want error, got nil")
	}
}

const validChainedLoop = `
  relay {
    role = "chained"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    chained {
      output-subject = "did:dplaax:reg:org:beta:pipeline:relay"
      issuer {
        did = "did:dplaax:reg:org:beta:pipeline:relay:process:r1"
        key-id = "signing"
        verification-method = "did:dplaax:reg:org:beta:pipeline:relay:process:r1#signing"
      }
      pipeline-id = "relay"
      process-id = "r1"
      transformation-claim = "convert"
      verification-strategy = "adjacent"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
      converter = "{ 'reading': reading, 'relayed': true }"
      filters = ["reading > 0"]
    }
  }
`

func TestLoad_ValidChained(t *testing.T) {
	cfg := loadWith(t, loopsConf(validChainedLoop))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if len(pc.Loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(pc.Loops))
	}
	l := pc.Loops[0]
	if l.Name != "relay" || l.Role != pipelineconfig.RoleChained {
		t.Fatalf("name/role: got %q/%q", l.Name, l.Role)
	}
	if l.IngressSubject != "did:dplaax:reg:org:acme:pipeline:pipe" {
		t.Fatalf("ingress: %q", l.IngressSubject)
	}
	c := l.Chained
	if c.OutputSubject != "did:dplaax:reg:org:beta:pipeline:relay" ||
		c.Issuer.DID != "did:dplaax:reg:org:beta:pipeline:relay:process:r1" ||
		c.Issuer.KeyID != "signing" ||
		c.PipelineID != "relay" || c.ProcessID != "r1" ||
		c.TransformationClaim != vc.ClaimConvert {
		t.Fatalf("chained producing fields: %+v", c)
	}
	if c.VerificationStrategy != pipelineconfig.StrategyAdjacent ||
		c.UpstreamEndpoint != "https://acme.example/pipelines/pipe" {
		t.Fatalf("chained consuming fields: %+v", c)
	}
	if c.Converter != "{ 'reading': reading, 'relayed': true }" {
		t.Fatalf("converter: %q", c.Converter)
	}
	if len(c.Filters) != 1 || c.Filters[0] != "reading > 0" {
		t.Fatalf("filters: %+v", c.Filters)
	}
	// A chained loop carries no source/sink identity.
	if l.Source != (pipelineconfig.SourceConfig{}) || l.Sink != (pipelineconfig.SinkConfig{}) {
		t.Fatalf("chained loop has non-zero Source/Sink: %+v / %+v", l.Source, l.Sink)
	}
}

func TestLoad_ChainedPassthrough(t *testing.T) {
	// converter + filters omitted = passthrough relay; must load.
	body := strings.Replace(validChainedLoop,
		"      converter = \"{ 'reading': reading, 'relayed': true }\"\n      filters = [\"reading > 0\"]\n", "", 1)
	cfg := loadWith(t, loopsConf(body))
	pc, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		t.Fatalf("passthrough chained should load: %v", err)
	}
	if len(pc.Loops) != 1 || pc.Loops[0].Chained.Converter != "" || len(pc.Loops[0].Chained.Filters) != 0 {
		t.Fatalf("passthrough: %+v", pc.Loops[0].Chained)
	}
}

func TestLoad_FailClosed_Chained(t *testing.T) {
	mut := func(field, value string) string {
		return strings.Replace(validChainedLoop, field, value, 1)
	}
	cases := []struct {
		name string
		body string
	}{
		{"output not pipeline DID", mut(
			`output-subject = "did:dplaax:reg:org:beta:pipeline:relay"`,
			`output-subject = "did:dplaax:reg:org:beta:pipeline:relay:process:r1"`)},
		{"issuer not process DID", mut(
			`did = "did:dplaax:reg:org:beta:pipeline:relay:process:r1"`,
			`did = "did:dplaax:reg:org:beta:pipeline:relay"`)},
		{"VM mismatch", mut(
			`verification-method = "did:dplaax:reg:org:beta:pipeline:relay:process:r1#signing"`,
			`verification-method = "did:dplaax:reg:org:beta:pipeline:relay:process:r1#auth"`)},
		{"unknown claim", mut(`transformation-claim = "convert"`, `transformation-claim = "frobnicate"`)},
		{"strategy full unsupported in 17d", mut(`verification-strategy = "adjacent"`, `verification-strategy = "full"`)},
		{"unknown strategy", mut(`verification-strategy = "adjacent"`, `verification-strategy = "deep"`)},
		{"missing upstream-endpoint", mut(`upstream-endpoint = "https://acme.example/pipelines/pipe"`, `upstream-endpoint = ""`)},
		{"ingress not a pipeline DID", mut(
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`,
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
		{"missing ingress", mut(`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`, `ingress-subject = ""`)},
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

// TestLoad_CrossRoleChainedBlock asserts a chained block is rejected under a source/sink
// loop, and source/sink blocks are rejected under a chained loop.
func TestLoad_CrossRoleChainedBlock(t *testing.T) {
	cases := map[string]string{
		"source with chained block": strings.Replace(validSourceLoop, `schema-ref = ""`,
			"schema-ref = \"\"\n    chained { output-subject = \"x\" }", 1),
		"sink with chained block": strings.Replace(validSinkLoop, `kind = "observation-only"`,
			"kind = \"observation-only\"\n    }\n    chained { output-subject = \"x\" }\n    sink {", 1),
		"chained with sink block": strings.Replace(validChainedLoop, `verification-strategy = "adjacent"`,
			"verification-strategy = \"adjacent\"\n    }\n    sink { kind = \"observation-only\" }\n    chained {", 1),
		"chained with top-level issuer": strings.Replace(validChainedLoop, `role = "chained"`,
			"role = \"chained\"\n    issuer { did = \"x\" }", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := loadWith(t, loopsConf(body))
			if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
				t.Fatalf("%s: want error, got nil", name)
			}
		})
	}
}
