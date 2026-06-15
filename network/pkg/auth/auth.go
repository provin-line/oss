// Package auth is the network layer's authorization-enforcement wiring (the PEP).
// It does not decide policy or issue tokens — those are the external
// auth.policy-verifier (decision) and auth.provider (token issuance) services in
// the three-layer dPLaaX auth stack. This package only adapts the o3co
// enforcement interceptors and the configured verifier endpoint for mounting on
// the network services' ConnectRPC handlers.
//
// Policy is declared per-RPC in the .proto via the o3co.authz.v1.policy method
// option (resource + action); Interceptors enforces it against a
// VerifierEndpoint. An RPC with no policy option is not checked.
package auth

import (
	"fmt"
	"net/url"

	"connectrpc.com/connect"
	o3coconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
)

// Interceptors returns the ordered authorization interceptor chain for a
// ConnectRPC handler: the policy-option interceptor (reads the proto option into
// context) MUST precede the verification interceptor (reads the policy from
// context and calls the verifier), and this constructor guarantees that order.
func Interceptors(verifier endpoint.VerifierEndpoint) []connect.Interceptor {
	return []connect.Interceptor{
		o3coconnect.PolicyOptionInterceptor(),
		o3coconnect.VerificationInterceptor(verifier),
	}
}

// NewVerifier builds the production VerifierEndpoint — the configured
// policy-verifier (PDP) client — for the given base URL. It returns the
// backend-neutral endpoint.VerifierEndpoint interface so callers depend on this
// seam, not on a concrete backend: swapping the PDP backend stays internal to
// this constructor. The URL must carry an explicit http:// or https:// scheme
// (the backend would otherwise silently prepend http://; requiring the scheme
// keeps a plaintext PDP call a deliberate choice, not an accidental default).
//
// Backend tunables are deliberately not exposed here yet: adding a
// backend-neutral option later (auth.VerifierOption translated internally, or
// AuthConfig fields) keeps this seam free of any concrete backend's option type.
func NewVerifier(policyVerifierURL string) (endpoint.VerifierEndpoint, error) {
	if err := validateVerifierURL(policyVerifierURL); err != nil {
		return nil, fmt.Errorf("auth: policy-verifier URL: %w", err)
	}
	return endpoint.NewO3coEndpoint(policyVerifierURL)
}

// validateVerifierURL rejects a URL that is empty, scheme-less, not http(s), or
// hostless. The host check matters because url.Parse accepts "https://" /
// "https:///pv" (scheme set, empty host) and NewO3coEndpoint does not reject it,
// so without it a malformed endpoint would boot and only fail at request time —
// defeating the fail-closed-at-boot intent.
func validateVerifierURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("must not be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must have an explicit http:// or https:// scheme (got %q)", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("must have a host (got %q)", raw)
	}
	return nil
}
