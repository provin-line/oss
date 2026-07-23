/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package main

// Mirrors internal/netcompose/metrics_test.go's own four tests (see
// metrics.go's package doc for why this binary carries its own copy rather
// than importing that package). No audit-verdict coverage here: this
// binary's BuildMetricsHandler/MaybeMountMetrics have no verdicts parameter
// at all — TestMetricsHandler_NoAuditFamily below asserts the family can
// never appear, the structural counterpart to netcompose's
// TestMetricsHandler_NoAuditRunnerNoAuditFamily (there, the family is
// merely unregistered for a specific case; here, there is no way to
// register it in the first place).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

const metricsTestScope = "github.com/provin-line/oss/cmd/pipeline"

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
// dual-emits), a consuming loop gets verify series. Families a loop lacks
// the capability for must not appear for it.
func TestMetricsHandler_FamiliesFollowCapabilities(t *testing.T) {
	lms := []pipelineruntime.LoopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{ok: 3, fail: 1}, Stripped: fakeStripped{n: 2}},
		{Name: "sink-b", Role: "sink", Verify: fakeVerify{counts: map[string]uint64{
			"verified": 4, "failed": 0, "indeterminate": 1, "error": 0,
		}}},
	}
	h, err := BuildMetricsHandler(metricsTestScope, lms)
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

	// Capability absence = series absence: a sink emits nothing, a source
	// verifies nothing.
	if _, ok := findMetric(body, "provin_pipeline_emit_attempts_total", `loop="sink-b"`); ok {
		t.Error("sink loop has emit series; want none")
	}
	if _, ok := findMetric(body, "provin_pipeline_verify_results_total", `loop="src-a"`); ok {
		t.Error("source loop has verify series; want none")
	}
}

// This binary runs no audit runner and BuildMetricsHandler/MaybeMountMetrics
// carry no verdicts parameter at all — the audit family can never appear,
// with or without configured loops.
func TestMetricsHandler_NoAuditFamily(t *testing.T) {
	h, err := BuildMetricsHandler(metricsTestScope, []pipelineruntime.LoopMetrics{
		{Name: "src-a", Role: "source", Emits: fakeEmits{}},
	})
	if err != nil {
		t.Fatalf("BuildMetricsHandler: %v", err)
	}
	body := scrape(t, h)
	if strings.Contains(body, "provin_audit_verdicts") {
		t.Errorf("audit family present — this binary runs no audit runner:\n%s", body)
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

	disabled, err := MaybeMountMetrics(metricsTestScope, false, inner, nil)
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

	enabled, err := MaybeMountMetrics(metricsTestScope, true, inner, nil)
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

// WithMetrics mounts /metrics beside the inner handler without disturbing
// its routes.
func TestWithMetrics_RoutesMetricsAndFallsThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinguishable inner marker
	})
	mh, err := BuildMetricsHandler(metricsTestScope, nil)
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
