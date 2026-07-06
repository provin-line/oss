package pipelineconfig_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/vc"
)

func TestLoad_BatchResolverAndSizeDefaults(t *testing.T) {
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	br := cfg.BatchResolver
	if br.Interval != 30*time.Second || br.BatchSize != 64 || br.MaxRetries != 5 || br.MaxDepth != 1024 {
		t.Errorf("batch-resolver defaults = %+v", br)
	}
	if cfg.MaxCredentialSize != 1<<20 {
		t.Errorf("max-credential-size = %d, want %d", cfg.MaxCredentialSize, 1<<20)
	}
}

func TestLoad_AuditRunnerDefaults(t *testing.T) {
	cfg, err := pipelineconfig.LoadPipelineConfig(loadWith(t, ""))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	ar := cfg.AuditRunner
	if ar.Interval != 30*time.Second || ar.BatchSize != 64 || ar.MaxAttempts != 10 {
		t.Errorf("audit-runner defaults = %+v", ar)
	}
}

func TestLoad_NonPositiveBatchOrSize_Fails(t *testing.T) {
	for _, override := range []string{
		"provin.network.pipeline.batch-resolver.interval = 0",
		"provin.network.pipeline.batch-resolver.batch-size = 0",
		"provin.network.pipeline.batch-resolver.max-retries = -1",
		"provin.network.pipeline.batch-resolver.max-depth = 0",
		"provin.network.pipeline.max-credential-size = 0",
		"provin.network.pipeline.audit-runner.interval = 0",
		"provin.network.pipeline.audit-runner.batch-size = 0",
		"provin.network.pipeline.audit-runner.max-attempts = -1",
	} {
		t.Run(override, func(t *testing.T) {
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, override)); err == nil {
				t.Errorf("override %q: want error, got nil", override)
			}
		})
	}
}

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

// withBearer adds the node-level vc-store-bearer a consuming-loop config requires.
func withBearer(conf string) string {
	return conf + "provin.network.pipeline.vc-store-bearer = \"tok\"\n"
}

// A consuming loop (sink/chained/aggregate) drives the async chain audit, whose peer
// predecessor fetches present vc-store-bearer against L1-protected peers. An empty
// bearer would not fail until the first cross-node hole silently starves an audit at
// runtime, so it fails closed at boot instead.
func TestLoad_ConsumingLoopRequiresBearer(t *testing.T) {
	for name, body := range map[string]string{
		"sink":      validSinkLoop,
		"chained":   validChainedLoop,
		"aggregate": validAggregateLoop,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(body)))
			if err == nil || !strings.Contains(err.Error(), "vc-store-bearer") {
				t.Fatalf("consuming loop without bearer: want vc-store-bearer error, got %v", err)
			}
		})
	}
}

// A source-only node performs no peer fetches (it accumulates no predecessor holes),
// so it boots without a bearer.
func TestLoad_SourceOnlyWithoutBearerLoads(t *testing.T) {
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(validSourceLoop))); err != nil {
		t.Fatalf("source-only without bearer should load: %v", err)
	}
}

// push-ingress exposes a source loop's NATS ingress as an HTTP push endpoint on the
// node listener (apipush). Source-only; the loop name enters URL space, so it must be
// a safe segment. Absent = false.
func TestLoad_PushIngress(t *testing.T) {
	withPush := strings.Replace(validSourceLoop, `role = "source"`,
		"role = \"source\"\n    push-ingress = true", 1)
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(withPush)))
	if err != nil {
		t.Fatalf("source with push-ingress: %v", err)
	}
	if !pc.Loops[0].Source.PushIngress {
		t.Error("PushIngress = false, want true")
	}

	// Absent key defaults to false.
	pc, err = pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(validSourceLoop)))
	if err != nil {
		t.Fatalf("source without push-ingress: %v", err)
	}
	if pc.Loops[0].Source.PushIngress {
		t.Error("PushIngress = true, want false (absent key)")
	}
}

func TestLoad_PushIngress_NonSourceRejected(t *testing.T) {
	for name, body := range map[string]string{
		"sink":      strings.Replace(validSinkLoop, `role = "sink"`, "role = \"sink\"\n    push-ingress = true", 1),
		"chained":   strings.Replace(validChainedLoop, `role = "chained"`, "role = \"chained\"\n    push-ingress = true", 1),
		"aggregate": strings.Replace(validAggregateLoop, `role = "aggregate"`, "role = \"aggregate\"\n    push-ingress = true", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(body))))
			if err == nil || !strings.Contains(err.Error(), "push-ingress") {
				t.Fatalf("push-ingress on %s: want push-ingress error, got %v", name, err)
			}
		})
	}
}

// A push-enabled loop's name becomes a URL path segment (/ingest/<name>/…), so it
// must satisfy the safe-segment rule; a name that does not is a boot error. The same
// name WITHOUT push-ingress stays legal (no retroactive breakage).
func TestLoad_PushIngress_UnsafeLoopNameRejected(t *testing.T) {
	unsafe := strings.Replace(validSourceLoop, "  src {", `  "src loop" {`, 1)
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(unsafe))); err != nil {
		t.Fatalf("unsafe name without push-ingress should load: %v", err)
	}
	unsafePush := strings.Replace(unsafe, `role = "source"`,
		"role = \"source\"\n    push-ingress = true", 1)
	_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(unsafePush)))
	if err == nil || !strings.Contains(err.Error(), "push-ingress") {
		t.Fatalf("unsafe name with push-ingress: want boot error naming push-ingress, got %v", err)
	}
}

func TestLoad_MaxPushBodySizeDefault(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(validSourceLoop)))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if pc.MaxPushBodySize != 1<<20 {
		t.Errorf("max-push-body-size default = %d, want %d", pc.MaxPushBodySize, 1<<20)
	}
}

func TestLoad_MaxPushBodySize_NonPositiveFails(t *testing.T) {
	conf := loopsConf(validSourceLoop) + "provin.network.pipeline.max-push-body-size = 0\n"
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, conf)); err == nil {
		t.Fatal("max-push-body-size = 0: want error, got nil")
	}
}

// HasConsumingLoop classifies the population that drives the async chain audit: any
// sink/chained/aggregate loop, regardless of siblings; never source-only or zero loops.
func TestHasConsumingLoop(t *testing.T) {
	loops := func(roles ...string) *pipelineconfig.Config {
		c := &pipelineconfig.Config{}
		for _, r := range roles {
			c.Loops = append(c.Loops, pipelineconfig.LoopConfig{Role: r})
		}
		return c
	}
	cases := []struct {
		name string
		cfg  *pipelineconfig.Config
		want bool
	}{
		{"zero loops", loops(), false},
		{"source only", loops(pipelineconfig.RoleSource), false},
		{"sink", loops(pipelineconfig.RoleSink), true},
		{"chained", loops(pipelineconfig.RoleChained), true},
		{"aggregate", loops(pipelineconfig.RoleAggregate), true},
		{"source + sink", loops(pipelineconfig.RoleSource, pipelineconfig.RoleSink), true},
	}
	for _, tc := range cases {
		if got := tc.cfg.HasConsumingLoop(); got != tc.want {
			t.Errorf("%s: HasConsumingLoop() = %v, want %v", tc.name, got, tc.want)
		}
	}
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
			cfg := loadWith(t, withBearer(loopsConf(tc.body)))
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
	cfg := loadWith(t, withBearer(loopsConf(validSinkLoop)))
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
		{"retired full strategy rejected", mut(`verification-strategy = "adjacent"`, `verification-strategy = "full"`)},
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
			cfg := loadWith(t, withBearer(loopsConf(tc.body)))
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
	cfg := loadWith(t, withBearer(loopsConf(validChainedLoop)))
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
	cfg := loadWith(t, withBearer(loopsConf(body)))
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
		{"retired full strategy rejected", mut(`verification-strategy = "adjacent"`, `verification-strategy = "full"`)},
		{"unknown strategy", mut(`verification-strategy = "adjacent"`, `verification-strategy = "deep"`)},
		{"missing upstream-endpoint", mut(`upstream-endpoint = "https://acme.example/pipelines/pipe"`, `upstream-endpoint = ""`)},
		{"ingress not a pipeline DID", mut(
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`,
			`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`)},
		{"missing ingress", mut(`ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`, `ingress-subject = ""`)},
		{"output equals ingress (self-loop)", mut(
			`output-subject = "did:dplaax:reg:org:beta:pipeline:relay"`,
			`output-subject = "did:dplaax:reg:org:acme:pipeline:pipe"`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadWith(t, withBearer(loopsConf(tc.body)))
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
			cfg := loadWith(t, withBearer(loopsConf(body)))
			if _, err := pipelineconfig.LoadPipelineConfig(cfg); err == nil {
				t.Fatalf("%s: want error, got nil", name)
			}
		})
	}
}
