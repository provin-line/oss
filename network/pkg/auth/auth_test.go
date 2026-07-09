package auth_test

import (
	"context"
	"testing"

	interceptors "github.com/o3co/protobuf.interceptors"
	"github.com/o3co/protobuf.interceptors/endpoint"
	"github.com/provin-line/oss/network/pkg/auth"
)

func TestInterceptors_ReturnsChain(t *testing.T) {
	got := auth.Interceptors(endpoint.NewStaticEndpoint(nil))
	if len(got) != 2 {
		t.Fatalf("Interceptors returned %d, want 2 (policy-option then verification)", len(got))
	}
	// Concrete interceptor types are unexported, so order is not introspectable
	// here; it is verified behaviorally by the allow/deny end-to-end test in
	// enforcement_test.go (and the upstream VerificationInterceptor fails closed
	// with CodeInternal if PolicyOption did not run first).
}

func TestNewVerifier_O3coRequiresExplicitScheme(t *testing.T) {
	// NewO3coEndpoint silently prepends http:// when the scheme is omitted, so
	// our seam rejects a scheme-less URL (fail-closed — no accidental plaintext).
	for _, bad := range []string{
		"policy-verifier.internal:3001", // scheme-less
		"https://",                      // scheme set, hostless
		"https:///pv",                   // scheme set, empty host
	} {
		cfg := &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: bad}
		if _, err := auth.NewVerifier(cfg); err == nil {
			t.Errorf("NewVerifier(o3co, %q): want error (fail-closed)", bad)
		}
	}
	cfg := &auth.AuthConfig{Backend: auth.BackendO3co, PolicyVerifierURL: "https://policy-verifier.internal:3001"}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier o3co happy path: %v", err)
	}
	if v == nil {
		t.Error("NewVerifier returned a nil verifier on the happy path")
	}
}

func TestNewVerifier_StaticDenyAllAndAllow(t *testing.T) {
	// Static backend is in-process authorization: it checks the bearer is
	// PRESENT (not that it is valid — that is why static is not authentication)
	// and matches (resource, action) against the allow-list. An empty allow-list
	// denies everything (safe default); a rule permits its (resource, action).
	ctx := interceptors.WithBearerToken(context.Background(), "present-but-unverified")

	denyAll, err := auth.NewVerifier(&auth.AuthConfig{Backend: auth.BackendStatic})
	if err != nil {
		t.Fatalf("NewVerifier static empty: %v", err)
	}
	if err := denyAll.Verify(ctx, "dids", "read"); err == nil {
		t.Error("empty static allow-list must deny even with a bearer present (got allow)")
	}

	allow := &auth.AuthConfig{Backend: auth.BackendStatic, Static: auth.StaticConfig{
		Allow: []auth.StaticAllowRule{{Resource: "dids", Action: "read"}},
	}}
	v, err := auth.NewVerifier(allow)
	if err != nil {
		t.Fatalf("NewVerifier static with rule: %v", err)
	}
	if err := v.Verify(ctx, "dids", "read"); err != nil {
		t.Errorf("allowed (dids, read) was denied: %v", err)
	}
	if err := v.Verify(ctx, "dids", "revoke"); err == nil {
		t.Error("un-allowed (dids, revoke) must be denied (got allow)")
	}
	// Bearer presence IS required (its value is never verified): no bearer -> deny.
	if err := v.Verify(context.Background(), "dids", "read"); err == nil {
		t.Error("static must deny when no bearer is present (presence check)")
	}
}

func TestNewVerifier_OPACedarRequireBaseURL(t *testing.T) {
	for name, cfg := range map[string]*auth.AuthConfig{
		"opa empty":   {Backend: auth.BackendOPA},
		"cedar empty": {Backend: auth.BackendCedar},
	} {
		if _, err := auth.NewVerifier(cfg); err == nil {
			t.Errorf("%s: want error (fail-closed on empty base-url)", name)
		}
	}
	opa := &auth.AuthConfig{Backend: auth.BackendOPA, OPA: auth.OPAConfig{BaseURL: "https://opa.internal:8181", PolicyPath: "provin/authz"}}
	if v, err := auth.NewVerifier(opa); err != nil || v == nil {
		t.Errorf("NewVerifier opa happy path: v=%v err=%v", v, err)
	}
	cedar := &auth.AuthConfig{Backend: auth.BackendCedar, Cedar: auth.CedarConfig{BaseURL: "https://cedar.internal:8180"}}
	if v, err := auth.NewVerifier(cedar); err != nil || v == nil {
		t.Errorf("NewVerifier cedar happy path: v=%v err=%v", v, err)
	}
}

func TestNewVerifier_UnknownBackendFailsClosed(t *testing.T) {
	if _, err := auth.NewVerifier(&auth.AuthConfig{Backend: "bogus"}); err == nil {
		t.Error("unknown backend must error (fail-closed — never silently pick one)")
	}
}

func TestNewVerifier_UnsetBackendDefaultsO3co(t *testing.T) {
	// A directly-constructed AuthConfig with an unset Backend must behave as the
	// field godoc promises — default to o3co — not be rejected as an unknown
	// backend. (The default lives in validate(), so it holds without going
	// through LoadAuthConfig.)
	cfg := &auth.AuthConfig{PolicyVerifierURL: "https://policy-verifier.internal:3001"}
	v, err := auth.NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier with unset backend: %v", err)
	}
	if v == nil {
		t.Error("NewVerifier returned nil verifier for the defaulted o3co backend")
	}
}
