/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package netcompose

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/network/pkg/auth"
)

func decodeReadyz(t *testing.T, rec *httptest.ResponseRecorder) (string, map[string]struct {
	Status string `json:"status"`
}) {
	t.Helper()
	var body struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("readyz body not JSON: %v", err)
	}
	return body.Status, body.Checks
}

// All checks passing → 200 {"status":"ok"} with every check reported ok.
func TestReadyz_AllOK(t *testing.T) {
	h := NewCachedReadiness([]ReadinessCheck{
		{Name: "a", Check: func(context.Context) error { return nil }},
		{Name: "b", Check: func(context.Context) error { return nil }},
	}, time.Minute).Handler()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	status, checks := decodeReadyz(t, rec)
	if status != "ok" {
		t.Errorf("status = %q, want ok", status)
	}
	for _, name := range []string{"a", "b"} {
		if checks[name].Status != "ok" {
			t.Errorf("check %s = %+v, want ok", name, checks[name])
		}
	}
}

// One failing check → 503 {"status":"degraded"}; the passing check still
// reports ok (operators need the full picture, not just the first failure).
// The failing check's ERROR must NOT appear in the body: /readyz is public
// and check errors carry internal topology (PDP URL, filesystem paths) —
// detail goes to the server log only.
func TestReadyz_OneFailing_Degraded(t *testing.T) {
	h := NewCachedReadiness([]ReadinessCheck{
		{Name: "good", Check: func(context.Context) error { return nil }},
		{Name: "bad", Check: func(context.Context) error { return errors.New("pdp unreachable at http://10.0.0.7:3001") }},
	}, time.Minute).Handler()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "10.0.0.7") {
		t.Errorf("public readyz body leaks the check error: %s", body)
	}
	status, checks := decodeReadyz(t, rec)
	if status != "degraded" {
		t.Errorf("status = %q, want degraded", status)
	}
	if checks["bad"].Status != "failed" {
		t.Errorf("bad check = %+v, want failed", checks["bad"])
	}
	if checks["good"].Status != "ok" {
		t.Errorf("good check = %+v, want ok", checks["good"])
	}
}

// Zero checks (an HTTP-only node with a static PDP) is trivially ready.
func TestReadyz_NoChecks_OK(t *testing.T) {
	rec := httptest.NewRecorder()
	NewCachedReadiness(nil, time.Minute).Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyz_MethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	NewCachedReadiness(nil, time.Minute).Handler()(rec, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestEvidenceStoreCheck(t *testing.T) {
	dir := t.TempDir()
	if err := EvidenceStoreCheck(dir).Check(context.Background()); err != nil {
		t.Errorf("existing dir: %v", err)
	}
	if err := EvidenceStoreCheck(filepath.Join(dir, "missing")).Check(context.Background()); err == nil {
		t.Error("missing dir passed")
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EvidenceStoreCheck(file).Check(context.Background()); err == nil {
		t.Error("plain file passed as evidence dir")
	}
}

func TestNatsCheck(t *testing.T) {
	if err := NATSCheck(func() bool { return true }).Check(context.Background()); err != nil {
		t.Errorf("healthy conn: %v", err)
	}
	if err := NATSCheck(func() bool { return false }).Check(context.Background()); err == nil {
		t.Error("unhealthy conn passed")
	}
}

// Reachability semantics: ANY HTTP response (even 404) proves the PDP is
// there; a refused connection fails the check; the static backend has no
// probe at all.
func TestPdpCheck(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	check, ok := PDPCheck(&auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: srv.URL})
	if !ok {
		t.Fatal("o3co backend produced no pdp check")
	}
	if err := check.Check(context.Background()); err != nil {
		t.Errorf("404-serving PDP counted unreachable: %v", err)
	}

	srv.Close()
	if err := check.Check(context.Background()); err == nil {
		t.Error("closed PDP counted reachable")
	}

	if _, ok := PDPCheck(&auth.AuthConfig{Backend: auth.BackendStatic}); ok {
		t.Error("static backend produced a pdp probe")
	}

	opaSrv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(opaSrv.Close)
	if check, ok := PDPCheck(&auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: opaSrv.URL}}); !ok {
		t.Error("opa backend produced no pdp check")
	} else if err := check.Check(context.Background()); err != nil {
		t.Errorf("opa probe: %v", err)
	}
}

// An unreachable-PDP error (which /readyz logs) must carry only scheme://host,
// never the path or query where a token or internal detail could ride.
func TestPdpCheck_ErrorRedactsToHost(t *testing.T) {
	// A closed port on loopback: the probe fails, producing the log-bound error.
	check, ok := PDPCheck(&auth.AuthConfig{
		Backend:           auth.BackendO3co,
		PolicyVerifierURL: "http://127.0.0.1:1/secret-path?token=shhh",
	})
	if !ok {
		t.Fatal("o3co backend produced no pdp check")
	}
	err := check.Check(context.Background())
	if err == nil {
		t.Fatal("want unreachable error")
	}
	msg := err.Error()
	if strings.Contains(msg, "secret-path") || strings.Contains(msg, "token=shhh") {
		t.Errorf("error leaks path/query: %q", msg)
	}
	if !strings.Contains(msg, "http://127.0.0.1:1") {
		t.Errorf("error should name scheme://host, got %q", msg)
	}
}

func TestHostOnly(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:pass@pv.example:3001/x?q=1": "https://pv.example:3001",
		"http://127.0.0.1:8181":                   "http://127.0.0.1:8181",
		"://bogus":                                "<redacted>",
	} {
		if got := HostOnly(raw); got != want {
			t.Errorf("HostOnly(%q) = %q, want %q", raw, got, want)
		}
	}
}

// The cache bounds outbound probes: a burst of /readyz requests within one TTL
// runs the checks ONCE (amplification defense F7), and the very first request
// refreshes synchronously so a zero snapshot never reads as ready.
func TestCachedReadiness_CoalescesProbes(t *testing.T) {
	var probes int64
	c := NewCachedReadiness([]ReadinessCheck{
		{Name: "pdp", Check: func(context.Context) error { atomic.AddInt64(&probes, 1); return nil }},
	}, time.Minute) // long TTL: everything in this test is one window
	h := c.Handler()

	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, rec.Code)
		}
	}
	if got := atomic.LoadInt64(&probes); got != 1 {
		t.Errorf("check probed %d times across 50 requests, want 1 (cache must coalesce)", got)
	}
}

// A fresh cache must not serve a zero snapshot as ready: the first request
// refreshes synchronously, so a failing check yields 503 on the very first hit.
func TestCachedReadiness_FirstRequestRefreshesSynchronously(t *testing.T) {
	c := NewCachedReadiness([]ReadinessCheck{
		{Name: "bad", Check: func(context.Context) error { return errors.New("down") }},
	}, time.Minute)
	rec := httptest.NewRecorder()
	c.Handler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("first request: status %d, want 503 (must not serve a zero snapshot as ready)", rec.Code)
	}
}

// Past the TTL the cache re-probes: staleness is bounded.
func TestCachedReadiness_RefreshesAfterTTL(t *testing.T) {
	var probes int64
	now := time.Unix(0, 0)
	c := NewCachedReadiness([]ReadinessCheck{
		{Name: "pdp", Check: func(context.Context) error { atomic.AddInt64(&probes, 1); return nil }},
	}, 5*time.Second)
	c.Now = func() time.Time { return now }
	h := c.Handler()

	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil)) // probe 1
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil)) // cached
	now = now.Add(6 * time.Second)                                                 // past TTL
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/readyz", nil)) // probe 2
	if got := atomic.LoadInt64(&probes); got != 2 {
		t.Errorf("probes = %d, want 2 (one per TTL window)", got)
	}
}
