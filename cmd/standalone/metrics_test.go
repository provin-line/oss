package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/chainconfig"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
)

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
	lms := []loopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{ok: 3, fail: 1}, Stripped: fakeStripped{n: 2}},
		{Name: "sink-b", Role: "sink", Verify: fakeVerify{counts: map[string]uint64{
			"verified": 4, "failed": 0, "indeterminate": 1, "error": 0,
		}}},
	}
	verdicts := func() map[string]uint64 {
		return map[string]uint64{"verified": 5, "failed": 0, "indeterminate": 1}
	}
	h, err := buildMetricsHandler(lms, verdicts)
	if err != nil {
		t.Fatalf("buildMetricsHandler: %v", err)
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
	h, err := buildMetricsHandler([]loopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{}},
	}, nil)
	if err != nil {
		t.Fatalf("buildMetricsHandler: %v", err)
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

	disabled, err := maybeMountMetrics(false, inner, nil, nil)
	if err != nil {
		t.Fatalf("maybeMountMetrics(disabled): %v", err)
	}
	if disabled != http.Handler(inner) {
		t.Error("disabled gate: handler was wrapped, want the inner handler unchanged")
	}
	rec := httptest.NewRecorder()
	disabled.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("disabled: GET /metrics = %d, want 404", rec.Code)
	}

	enabled, err := maybeMountMetrics(true, inner, nil, nil)
	if err != nil {
		t.Fatalf("maybeMountMetrics(enabled): %v", err)
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

// Composed path: a REAL source loop's delivered emit reaches the REAL
// exposition — dataplane bookkeeping, accessor forwarding, bridge, and
// exporter working as one.
func TestMetrics_RealEmitReachesExposition(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpPipelineCfg(), dpKeyStore(t), dataPlaneDeps{})
	if err != nil {
		t.Fatalf("buildDataPlane: %v", err)
	}
	h, err := maybeMountMetrics(true, http.NotFoundHandler(), dp.metrics, nil)
	if err != nil {
		t.Fatalf("maybeMountMetrics: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-runDone })

	obs, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	defer obs.Close()
	got := make(chan []byte, 4)
	if err := obs.Subscriber(dpPipelineDID).Subscribe(func(b []byte) { got <- b }); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}
	injector := obs.Publisher(dpIngress)

	// Retry the push until the loop subscribes and one envelope lands.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	_ = injector.Publish([]byte(`{"hello":"metrics"}`))
deliver:
	for {
		select {
		case <-got:
			break deliver
		case <-tick.C:
			_ = injector.Publish([]byte(`{"hello":"metrics"}`))
		case <-deadline:
			t.Fatal("no envelope delivered on the output subject")
		}
	}

	// The observer sees the publish a hair before Emit returns (the counter
	// moves in the deferred outcome accounting), so poll the exposition.
	expoDeadline := time.Now().Add(5 * time.Second)
	for {
		body := scrape(t, h)
		if v, ok := findMetric(body, "provin_pipeline_emit_attempts_total", `loop="src"`, `outcome="success"`); ok && v != "0" {
			break
		}
		if time.Now().After(expoDeadline) {
			t.Fatalf("emit success never reached the exposition:\n%s", scrape(t, h))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// withMetrics mounts /metrics beside the inner handler without disturbing
// its routes.
func TestWithMetrics_RoutesMetricsAndFallsThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinguishable inner marker
	})
	mh, err := buildMetricsHandler(nil, nil)
	if err != nil {
		t.Fatalf("buildMetricsHandler: %v", err)
	}
	h := withMetrics(inner, mh)

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
