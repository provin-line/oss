package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
)

// ─────────────────────────────────────────────────────────────────────────
// pdpCheck (P2 Codex fix, branch review) — mirrors internal/netcompose.
// PDPCheck's backend switch and reachability semantics exactly.
// ─────────────────────────────────────────────────────────────────────────

func TestPDPCheck_StaticBackend_NoCheck(t *testing.T) {
	_, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendStatic})
	if ok {
		t.Error("pdpCheck(static) = ok, want false (nothing to probe — the decision is in-process)")
	}
}

func TestPDPCheck_UnrecognizedBackend_NoCheck(t *testing.T) {
	_, ok := pdpCheck(&auth.AuthConfig{Backend: ""})
	if ok {
		t.Error(`pdpCheck("") = ok, want false`)
	}
}

func TestPDPCheck_O3coBackend_ProbesPolicyVerifierURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler()) // any response counts as reachable
	defer srv.Close()

	check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: srv.URL})
	if !ok {
		t.Fatal("pdpCheck(o3co) = ok false, want true (external, probeable)")
	}
	if check.name != "pdp" {
		t.Errorf("check.name = %q, want %q", check.name, "pdp")
	}
	if err := check.check(context.Background()); err != nil {
		t.Errorf("check against a reachable server: %v", err)
	}
}

func TestPDPCheck_OPABackend_ProbesOPABaseURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: srv.URL}})
	if !ok {
		t.Fatal("pdpCheck(opa) = ok false, want true")
	}
	if err := check.check(context.Background()); err != nil {
		t.Errorf("check against a reachable OPA server: %v", err)
	}
}

func TestPDPCheck_CedarBackend_ProbesCedarBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendCedar, Cedar: auth.CedarConfig{BaseURL: srv.URL}})
	if !ok {
		t.Fatal("pdpCheck(cedar) = ok false, want true")
	}
	if err := check.check(context.Background()); err != nil {
		t.Errorf("check against a reachable Cedar server: %v", err)
	}
}

func TestPDPCheck_UnreachablePDP_ReportsError(t *testing.T) {
	check, ok := pdpCheck(&auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "http://127.0.0.1:1"})
	if !ok {
		t.Fatal("pdpCheck(o3co) = ok false, want true")
	}
	if err := check.check(context.Background()); err == nil {
		t.Error("check against an unreachable PDP: want error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// buildHandler's /readyz PDP gating — added exactly when hasPushIngress AND
// the backend is external, mirroring netcompose's own gating (which instead
// adds it unconditionally, since cmd/network/cmd/standalone always mount
// PDP-gated ConnectRPC services; cmd/pipeline's ONLY PDP-gated surface is a
// push-ingress route).
// ─────────────────────────────────────────────────────────────────────────

// readyzChecks builds the REAL handler via buildHandler and returns the
// "checks" map GET /readyz reports.
func readyzChecks(t *testing.T, authCfg *auth.AuthConfig, hasPushIngress bool) map[string]string {
	t.Helper()
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	pipeCfg := &pipelineconfig.Config{MaxPushBodySize: 1 << 20, VCStoreEndpoint: "http://127.0.0.1:1"}
	h, err := buildHandler(guard, pipeCfg, authCfg, nil, nil, hasPushIngress)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var body struct {
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode /readyz body: %v", err)
	}
	return body.Checks
}

func TestReadyz_PDPCheckAddedOnlyWhenPushIngressAndExternalBackend(t *testing.T) {
	cases := []struct {
		name           string
		authCfg        *auth.AuthConfig
		hasPushIngress bool
		wantPDPCheck   bool
	}{
		{"push ingress + external backend: pdp check added", &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "http://127.0.0.1:1"}, true, true},
		{"push ingress + static backend: no pdp check", &auth.AuthConfig{Backend: auth.BackendStatic}, true, false},
		{"no push ingress + external backend: no pdp check", &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "http://127.0.0.1:1"}, false, false},
		{"no push ingress + static backend: no pdp check", &auth.AuthConfig{Backend: auth.BackendStatic}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checks := readyzChecks(t, c.authCfg, c.hasPushIngress)
			_, gotPDPCheck := checks["pdp"]
			if gotPDPCheck != c.wantPDPCheck {
				t.Errorf("checks = %v, pdp present = %v, want %v", checks, gotPDPCheck, c.wantPDPCheck)
			}
			// The registry check is unconditional — always present regardless of
			// the pdp-gating decision under test.
			if _, ok := checks["registry"]; !ok {
				t.Errorf("checks = %v, missing the unconditional registry check", checks)
			}
		})
	}
}

// TestReadyz_PDPCheckFailureDegradesReadiness proves the added check is
// actually WIRED into the aggregate readiness decision, not merely present
// in the checks map cosmetically: an unreachable PDP with push-ingress
// mounted reports "degraded" overall (503), naming "pdp" as failed.
func TestReadyz_PDPCheckFailureDegradesReadiness(t *testing.T) {
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	pipeCfg := &pipelineconfig.Config{MaxPushBodySize: 1 << 20, VCStoreEndpoint: "http://127.0.0.1:1"}
	authCfg := &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "http://127.0.0.1:1"} // unreachable
	h, err := buildHandler(guard, pipeCfg, authCfg, nil, nil, true)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz status = %d, want 503 (unreachable registry AND pdp)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"pdp":"failed"`) {
		t.Errorf("body = %s, want it to report the pdp check failed", rec.Body.String())
	}
}
