package netcompose

// Relocated from cmd/standalone/metrics_test.go (PR3c: cmd/standalone
// retired). BuildMetricsHandler/MaybeMountMetrics/WithMetrics are this
// package's own exported functions; these tests exercise them directly with
// fake counters, with no cmd/standalone-specific composition. Before this
// move, cmd/standalone/metrics_test.go was the ONLY test coverage any of the
// three had anywhere in the repo — cmd/network calls MaybeMountMetrics from
// its own main() but carried no unit test of the bridge's own family/gate
// contract.
//
// TestMetrics_RealEmitReachesExposition (a REAL source loop's delivered
// emit reaching this bridge through pipeline/runtime.Build +
// netcomposeMetricsFrom-style field copy) was NOT moved: that composition —
// a data-plane Runtime's LoopMetrics converted and handed to this bridge —
// has no current caller. cmd/network runs no data-plane loops of its own
// (always passes nil loops to MaybeMountMetrics); cmd/pipeline is the data
// -plane composer but does not import this package at all (AGENTS.md layer
// rule 2) and does not yet mount this bridge (see its main.go's own /metrics
// doc comment — a named PR3c follow-up). The family-mapping logic that test
// also exercised is still covered by TestMetricsHandler_FamiliesFollowCapabilities
// below; only the "a REAL dataplane counter increments and becomes visible
// through this bridge" property is presently unproven in any binary.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const metricsTestScope = "github.com/provin-line/oss/internal/netcompose"

type fakeEmits struct{ ok, fail uint64 }

func (f fakeEmits) EmitSuccesses() uint64 { return f.ok }
func (f fakeEmits) EmitFailures() uint64  { return f.fail }

type fakeStripped struct{ n uint64 }

func (f fakeStripped) StrippedPublishFailures() uint64 { return f.n }

type fakeVerify struct{ counts map[string]uint64 }

func (f fakeVerify) Snapshot() map[string]uint64 { return f.counts }

// scrape serves one GET /metrics through h and returns the exposition body.
func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// metricValue finds the sample line of family carrying ALL the given label
// pairs and returns its value; fails the test when absent.
func metricValue(t *testing.T, body, family string, labels ...string) string {
	t.Helper()
	if v, ok := findMetric(body, family, labels...); ok {
		return v
	}
	t.Fatalf("no %s sample with labels %v in exposition:\n%s", family, labels, body)
	return ""
}

func findMetric(body, family string, labels ...string) (string, bool) {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, family+"{") {
			continue
		}
		match := true
		for _, l := range labels {
			if !strings.Contains(line, l) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		fields := strings.Fields(line)
		return fields[len(fields)-1], true
	}
	return "", false
}

// The bridge maps each loop's capabilities to its metric families with the
// stable names: a producing loop gets emit series (and stripped when it
// dual-emits), a consuming loop gets verify series, and the audit family
// appears exactly when a verdict source exists. Families a loop lacks the
// capability for must not appear for it.
func TestMetricsHandler_FamiliesFollowCapabilities(t *testing.T) {
	lms := []LoopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{ok: 3, fail: 1}, Stripped: fakeStripped{n: 2}},
		{Name: "sink-b", Role: "sink", Verify: fakeVerify{counts: map[string]uint64{
			"verified": 4, "failed": 0, "indeterminate": 1, "error": 0,
		}}},
	}
	verdicts := func() map[string]uint64 {
		return map[string]uint64{"verified": 5, "failed": 0, "indeterminate": 1}
	}
	h, err := BuildMetricsHandler(metricsTestScope, lms, verdicts)
	if err != nil {
		t.Fatalf("BuildMetricsHandler: %v", err)
	}
	body := scrape(t, h)

	if v := metricValue(t, body, "provin_pipeline_emit_attempts_total", `loop="src-a"`, `outcome="success"`); v != "3" {
		t.Errorf("emit success = %s, want 3", v)
	}
	if v := metricValue(t, body, "provin_pipeline_emit_attempts_total", `loop="src-a"`, `outcome="failure"`); v != "1" {
		t.Errorf("emit failure = %s, want 1", v)
	}
	if v := metricValue(t, body, "provin_pipeline_emit_stripped_failures_total", `loop="src-a"`); v != "2" {
		t.Errorf("stripped failures = %s, want 2", v)
	}
	if v := metricValue(t, body, "provin_pipeline_verify_results_total", `loop="sink-b"`, `outcome="verified"`); v != "4" {
		t.Errorf("verify verified = %s, want 4", v)
	}
	// Zero-valued series of a registered capability are PRESENT (fixed label set).
	if v := metricValue(t, body, "provin_pipeline_verify_results_total", `loop="sink-b"`, `outcome="error"`); v != "0" {
		t.Errorf("verify error = %s, want 0", v)
	}
	if v := metricValue(t, body, "provin_audit_verdicts_total", `verdict="verified"`); v != "5" {
		t.Errorf("audit verified = %s, want 5", v)
	}
	if v := metricValue(t, body, "provin_audit_verdicts_total", `verdict="failed"`); v != "0" {
		t.Errorf("audit failed = %s, want 0 (present with zero)", v)
	}

	// Capability absence = series absence: a sink emits nothing, a source
	// verifies nothing.
	if _, ok := findMetric(body, "provin_pipeline_emit_attempts_total", `loop="sink-b"`); ok {
		t.Error("sink loop has emit series; want none")
	}
	if _, ok := findMetric(body, "provin_pipeline_verify_results_total", `loop="src-a"`); ok {
		t.Error("source loop has verify series; want none")
	}
}

// Without a verdict source (no audit runner configured) the audit family is
// absent entirely — family presence is the capability contract.
func TestMetricsHandler_NoAuditRunnerNoAuditFamily(t *testing.T) {
	h, err := BuildMetricsHandler(metricsTestScope, []LoopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{}},
	}, nil)
	if err != nil {
		t.Fatalf("BuildMetricsHandler: %v", err)
	}
	body := scrape(t, h)
	if strings.Contains(body, "provin_audit_verdicts") {
		t.Errorf("audit family present without an audit runner:\n%s", body)
	}
	// The configured producing loop's family IS present at zero.
	if v := metricValue(t, body, "provin_pipeline_emit_attempts_total", `loop="src-a"`, `outcome="success"`); v != "0" {
		t.Errorf("emit success = %s, want 0", v)
	}
}

// The config gate (the default-off security ruling): disabled returns the
// inner handler UNCHANGED — /metrics does not exist — and enabled mounts it.
func TestMaybeMountMetrics_GateHonored(t *testing.T) {
	inner := http.NewServeMux() // a real mux: unknown routes 404
	inner.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	disabled, err := MaybeMountMetrics(metricsTestScope, false, inner, nil, nil)
	if err != nil {
		t.Fatalf("MaybeMountMetrics(disabled): %v", err)
	}
	if disabled != http.Handler(inner) {
		t.Error("disabled gate: handler was wrapped, want the inner handler unchanged")
	}
	rec := httptest.NewRecorder()
	disabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled: GET /metrics = %d, want 404", rec.Code)
	}

	enabled, err := MaybeMountMetrics(metricsTestScope, true, inner, nil, nil)
	if err != nil {
		t.Fatalf("MaybeMountMetrics(enabled): %v", err)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("enabled: GET /metrics = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	enabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("enabled: GET /healthz = %d, want 200 (inner routes intact)", rec.Code)
	}
}

// withMetrics mounts /metrics beside the inner handler without disturbing
// its routes.
func TestWithMetrics_RoutesMetricsAndFallsThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinguishable inner marker
	})
	mh, err := BuildMetricsHandler(metricsTestScope, nil, nil)
	if err != nil {
		t.Fatalf("BuildMetricsHandler: %v", err)
	}
	h := WithMetrics(inner, mh)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /metrics = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("GET /healthz = %d, want it to reach the inner handler (418)", rec.Code)
	}
}
