package auth_test

import (
	"testing"

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

func TestNewVerifier_RequiresExplicitScheme(t *testing.T) {
	// NewO3coEndpoint silently prepends http:// when the scheme is omitted, so
	// our seam rejects a scheme-less URL (fail-closed — no accidental plaintext).
	for _, bad := range []string{
		"policy-verifier.internal:3001", // scheme-less
		"https://",                      // scheme set, hostless
		"https:///pv",                   // scheme set, empty host
	} {
		if _, err := auth.NewVerifier(bad); err == nil {
			t.Errorf("NewVerifier(%q): want error (fail-closed)", bad)
		}
	}
	v, err := auth.NewVerifier("https://policy-verifier.internal:3001")
	if err != nil {
		t.Fatalf("NewVerifier with https URL: want ok, got %v", err)
	}
	if v == nil {
		t.Error("NewVerifier returned a nil verifier on the happy path")
	}
}
