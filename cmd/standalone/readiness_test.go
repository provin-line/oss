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

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	h := readyz([]readinessCheck{
		{Name: "a", Check: func(context.Context) error { return nil }},
		{Name: "b", Check: func(context.Context) error { return nil }},
	})
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
	h := readyz([]readinessCheck{
		{Name: "good", Check: func(context.Context) error { return nil }},
		{Name: "bad", Check: func(context.Context) error { return errors.New("pdp unreachable at http://10.0.0.7:3001") }},
	})
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
	readyz(nil)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestReadyz_MethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	readyz(nil)(rec, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestEvidenceStoreCheck(t *testing.T) {
	dir := t.TempDir()
	if err := evidenceStoreCheck(dir).Check(context.Background()); err != nil {
		t.Errorf("existing dir: %v", err)
	}
	if err := evidenceStoreCheck(filepath.Join(dir, "missing")).Check(context.Background()); err == nil {
		t.Error("missing dir passed")
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := evidenceStoreCheck(file).Check(context.Background()); err == nil {
		t.Error("plain file passed as evidence dir")
	}
}

func TestNatsCheck(t *testing.T) {
	if err := natsCheck(func() bool { return true }).Check(context.Background()); err != nil {
		t.Errorf("healthy conn: %v", err)
	}
	if err := natsCheck(func() bool { return false }).Check(context.Background()); err == nil {
		t.Error("unhealthy conn passed")
	}
}

// Reachability semantics: ANY HTTP response (even 404) proves the PDP is
// there; a refused connection fails the check; the static backend has no
// probe at all.
func TestPdpCheck(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: srv.URL})
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

	if _, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendStatic}); ok {
		t.Error("static backend produced a pdp probe")
	}

	opaSrv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(opaSrv.Close)
	if check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: opaSrv.URL}}); !ok {
		t.Error("opa backend produced no pdp check")
	} else if err := check.Check(context.Background()); err != nil {
		t.Errorf("opa probe: %v", err)
	}
}
