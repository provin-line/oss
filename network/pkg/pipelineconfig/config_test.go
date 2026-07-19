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
	if cfg.MaxRetainChunkSize != 1<<20 {
		t.Errorf("max-retain-chunk-size = %d, want %d", cfg.MaxRetainChunkSize, 1<<20)
	}
	if cfg.MaxRetainPayloadSize != 64<<20 {
		t.Errorf("max-retain-payload-size = %d, want %d", cfg.MaxRetainPayloadSize, 64<<20)
	}
	if cfg.TlogMirror.MaxBatchRecords != 256 {
		t.Errorf("tlog-mirror.max-batch-records = %d, want %d", cfg.TlogMirror.MaxBatchRecords, 256)
	}
	if cfg.TlogMirror.MaxBatchBytes != 4<<20 {
		t.Errorf("tlog-mirror.max-batch-bytes = %d, want %d", cfg.TlogMirror.MaxBatchBytes, 4<<20)
	}
}

func TestLoad_TlogMirrorNonPositiveOverrideFails(t *testing.T) {
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, `provin.network.pipeline.tlog-mirror.max-batch-records = 0`)); err == nil {
		t.Fatal("max-batch-records = 0: want a boot error")
	}
	if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, `provin.network.pipeline.tlog-mirror.max-batch-bytes = -1`)); err == nil {
		t.Fatal("max-batch-bytes = -1: want a boot error")
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
		"provin.network.pipeline.max-retain-chunk-size = 0",
		"provin.network.pipeline.max-retain-payload-size = -1",
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

// A production sink boots once it carries the obligations its kind requires:
// a non-empty issuer allow-list. Receipts are MAY for production (a receipt
// block is optional).
const validProductionSinkLoop = `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink {
      kind = "production"
      verification-strategy = "adjacent"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
      allow-issuers = ["did:dplaax:reg:org:acme:*"]
    }
  }
`

// An archival sink additionally MUST emit receipts, so it carries a receipt
// issuer block (a process identity it signs receipts under).
const validArchivalSinkLoop = `
  archive {
    role = "sink"
    ingress-subject = "did:dplaax:reg:org:acme:pipeline:pipe"
    sink {
      kind = "archival"
      verification-strategy = "adjacent"
      upstream-endpoint = "https://acme.example/pipelines/pipe"
      allow-issuers = ["did:dplaax:reg:org:acme:*"]
      receipt {
        issuer {
          did = "did:dplaax:reg:org:acme:pipeline:pipe:process:archive"
          key-id = "signing"
          verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:archive#signing"
        }
      }
    }
  }
`

func TestLoad_ValidProductionSink(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(validProductionSinkLoop))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig(production): %v", err)
	}
	s := pc.Loops[0].Sink
	if s.Kind != pipelineconfig.SinkProduction {
		t.Errorf("kind = %q, want production", s.Kind)
	}
	if len(s.AllowIssuers) != 1 || s.AllowIssuers[0] != "did:dplaax:reg:org:acme:*" {
		t.Errorf("AllowIssuers = %v", s.AllowIssuers)
	}
	// Receipt is MAY for production and absent here.
	if s.Receipt.Issue {
		t.Errorf("Receipt.Issue = true, want false (no receipt block configured)")
	}
}

func TestLoad_ValidArchivalSink(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(validArchivalSinkLoop))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig(archival): %v", err)
	}
	s := pc.Loops[0].Sink
	if s.Kind != pipelineconfig.SinkArchival {
		t.Errorf("kind = %q, want archival", s.Kind)
	}
	if !s.Receipt.Issue {
		t.Fatalf("Receipt.Issue = false, want true (archival MUST emit receipts)")
	}
	if s.Receipt.Issuer.DID != "did:dplaax:reg:org:acme:pipeline:pipe:process:archive" {
		t.Errorf("Receipt.Issuer.DID = %q", s.Receipt.Issuer.DID)
	}
	// pipeline/process ids derive from the issuer process DID's segments.
	if s.Receipt.PipelineID != "pipe" || s.Receipt.ProcessID != "archive" {
		t.Errorf("Receipt pipeline/process = %q/%q, want pipe/archive", s.Receipt.PipelineID, s.Receipt.ProcessID)
	}
}

// Sink output destination: absent block defaults to console (stdout — today's
// only behaviour, preserved); "file" requires a path.
func TestLoad_SinkOutput(t *testing.T) {
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(validSinkLoop))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if out := pc.Loops[0].Sink.Output; out.Type != pipelineconfig.SinkOutputConsole || out.Path != "" {
		t.Fatalf("default output = %+v, want console with no path", out)
	}

	fileLoop := strings.Replace(validSinkLoop,
		`upstream-endpoint = "https://acme.example/pipelines/pipe"`,
		`upstream-endpoint = "https://acme.example/pipelines/pipe"
      output { type = "file", path = "/var/provin/consumed.ndjson" }`, 1)
	pc, err = pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(fileLoop))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig(file output): %v", err)
	}
	if out := pc.Loops[0].Sink.Output; out.Type != pipelineconfig.SinkOutputFile || out.Path != "/var/provin/consumed.ndjson" {
		t.Fatalf("file output = %+v", out)
	}
}

func TestLoad_FailClosed_SinkOutput(t *testing.T) {
	withOutput := func(block string) string {
		return strings.Replace(validSinkLoop,
			`upstream-endpoint = "https://acme.example/pipelines/pipe"`,
			`upstream-endpoint = "https://acme.example/pipelines/pipe"
      `+block, 1)
	}
	cases := []struct {
		name string
		body string
	}{
		{"file output without path", withOutput(`output { type = "file" }`)},
		{"file output with empty path", withOutput(`output { type = "file", path = "" }`)},
		{"unknown output type", withOutput(`output { type = "warehouse" }`)},
		// A path on a console output is a misconfig (probably meant type=file) —
		// fail closed instead of silently writing to stdout.
		{"console output with a path", withOutput(`output { type = "console", path = "/var/x" }`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(tc.body)))); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
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
		// production/archival require a non-empty issuer allow-list; without one
		// they fail closed (default-distrust would otherwise reject every event).
		{"production without allow-issuers", mut(`kind = "observation-only"`, `kind = "production"`)},
		{"archival without allow-issuers", mut(`kind = "observation-only"`, `kind = "archival"`)},
		// A malformed allow-issuers pattern is caught at boot (allowlist.ValidatePattern),
		// not deferred to the first non-matching event.
		{"production malformed allow-issuers pattern", strings.Replace(validProductionSinkLoop,
			`allow-issuers = ["did:dplaax:reg:org:acme:*"]`, `allow-issuers = ["not-a-did:*"]`, 1)},
		// archival MUST emit receipts, so a receipt issuer block is required.
		{"archival without receipt issuer", strings.Replace(validProductionSinkLoop,
			`kind = "production"`, `kind = "archival"`, 1)},
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
	// A chained loop carries no source/sink identity (a real sink has a Kind).
	if l.Source != (pipelineconfig.SourceConfig{}) || l.Sink.Kind != "" {
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

// A producing output subject is the loop's emission-log identity: two loops
// sharing one would interleave two sequence spaces into one "log" (tlog
// spec boot invariant a).
func TestLoad_DuplicateProducingOutputSubject_Fails(t *testing.T) {
	// Renames the loop key and process id but NOT the output subject (the
	// subject string contains no "src"), so both loops share one log id.
	second := strings.ReplaceAll(validSourceLoop, "src", "src2")
	_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(validSourceLoop+second)))
	if err == nil || !strings.Contains(err.Error(), "share output-subject") {
		t.Fatalf("duplicate producing output-subject: want the uniqueness boot error, got %v", err)
	}
}

// The issuer must structurally belong to its output subject
// (issuer.PipelineDID() == output-subject): the property that makes a tlog
// checkpoint's signed_by verifiable against its log id (boot invariant b).
func TestLoad_IssuerOutsideOutputSubject_Fails(t *testing.T) {
	foreign := strings.Replace(validSourceLoop,
		`did = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"`,
		`did = "did:dplaax:reg:org:acme:pipeline:OTHER:process:src"`, 1)
	foreign = strings.Replace(foreign,
		`verification-method = "did:dplaax:reg:org:acme:pipeline:pipe:process:src#signing"`,
		`verification-method = "did:dplaax:reg:org:acme:pipeline:OTHER:process:src#signing"`, 1)
	_, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(foreign)))
	if err == nil || !strings.Contains(err.Error(), "output-subject") {
		t.Fatalf("issuer outside its output subject: want boot error, got %v", err)
	}
}

func TestLoad_ValidSourceSchemaRef(t *testing.T) {
	withRef := strings.Replace(validSourceLoop, `schema-ref = ""`,
		`schema-ref = "orders@2026-07-10-abcdef0123456789"`, 1)
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(withRef)))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := pc.Loops[0].Source.SchemaRef; got != "orders@2026-07-10-abcdef0123456789" {
		t.Errorf("Source.SchemaRef = %q, want the configured short-form", got)
	}
}

func TestLoad_MalformedSchemaRefRejected(t *testing.T) {
	for _, bad := range []string{"noversion", "has space@1", "@1", "orders@"} {
		withRef := strings.Replace(validSourceLoop, `schema-ref = ""`,
			`schema-ref = "`+bad+`"`, 1)
		if _, err := pipelineconfig.LoadPipelineConfig(loadWith(t, loopsConf(withRef))); err == nil {
			t.Errorf("schema-ref %q: want boot error, got nil", bad)
		}
	}
}

func TestLoad_ChainedSchemaRef(t *testing.T) {
	withRef := strings.Replace(validChainedLoop, `transformation-claim = "convert"`,
		`transformation-claim = "convert"`+"\n      "+`schema-ref = "readings@2026-07-10-abcdef0123456789"`, 1)
	pc, err := pipelineconfig.LoadPipelineConfig(loadWith(t, withBearer(loopsConf(withRef))))
	if err != nil {
		t.Fatalf("LoadPipelineConfig: %v", err)
	}
	if got := pc.Loops[0].Chained.SchemaRef; got != "readings@2026-07-10-abcdef0123456789" {
		t.Errorf("Chained.SchemaRef = %q, want the configured short-form", got)
	}
}
