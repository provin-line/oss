// Package auth is the network layer's authorization-enforcement wiring (the PEP).
// It does not decide policy or issue tokens — those are the external
// auth.policy-verifier (decision) and auth.provider (token issuance) services in
// the three-layer dPLaaX auth stack. This package only adapts the o3co
// enforcement interceptors and the configured verifier endpoint for mounting on
// the network services' ConnectRPC handlers.
//
// Policy is declared per-RPC in the .proto via the o3co.authz.v1.policy method
// option (resource + action); Interceptors enforces it against a Verifier.
// An RPC with no policy option is not checked.
package auth

import (
	"context"
	"fmt"
	"net/url"

	"connectrpc.com/connect"
	o3coconnect "github.com/o3co/protobuf.interceptors/connectrpc"
	"github.com/o3co/protobuf.interceptors/endpoint"
)

// Verifier is the authorization verdict seam: one policy check — may the
// caller in ctx perform action on resource; a nil error is the only allow.
// It is package-owned so the exported auth surface carries no upstream type
// identity (the o3co enforcement endpoints satisfy it structurally): swapping
// the enforcement library never breaks this package's signatures. Caller
// identity travels as a bearer token under the o3co interceptors' context
// key (interceptors.WithBearerToken / BearerTokenFromContext) — the seam
// stabilizes the SIGNATURES, and an alternative Verifier implementation must
// still read that ctx convention to see the caller.
type Verifier interface {
	Verify(ctx context.Context, resource, action string) error
}

// Interceptors returns the ordered authorization interceptor chain for a
// ConnectRPC handler: the policy-option interceptor (reads the proto option into
// context) MUST precede the verification interceptor (reads the policy from
// context and calls the verifier), and this constructor guarantees that order.
func Interceptors(verifier Verifier) []connect.Interceptor {
	return []connect.Interceptor{
		o3coconnect.PolicyOptionInterceptor(),
		o3coconnect.VerificationInterceptor(verifier),
	}
}

// NewVerifier builds the production Verifier — the configured PDP client —
// dispatching on cfg.Backend. It returns the backend-neutral, package-owned
// Verifier seam so callers depend on it, not on a concrete backend or the
// upstream enforcement library, and it keeps this package free of any
// backend's option type.
//
// Every backend is fail-closed: the selected backend's required config must
// validate or NewVerifier returns an error (no verifier is built), and an
// unknown backend errors rather than silently picking one. The o3co/opa/cedar
// backends require an explicit http(s):// base URL (the backends would otherwise
// silently prepend http://; requiring the scheme keeps a plaintext PDP call a
// deliberate choice). The static backend builds an in-process allow-list — an
// empty list denies everything (the safe default). Note that static does NOT
// authenticate: it checks only bearer presence, so it is for single-tenant or
// perimeter-authenticated deployments, never one relying on the PDP to
// authenticate callers (see the config godoc and reference.conf).
func NewVerifier(cfg *AuthConfig) (Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	switch cfg.Backend {
	case BackendO3co:
		return endpoint.NewO3coEndpoint(cfg.PolicyVerifierURL)
	case BackendOPA:
		return endpoint.NewOPAEndpoint(cfg.OPA.BaseURL, cfg.OPA.PolicyPath)
	case BackendCedar:
		return endpoint.NewCedarEndpoint(cfg.Cedar.BaseURL)
	case BackendStatic:
		rules := make([]endpoint.StaticRule, len(cfg.Static.Allow))
		for i, r := range cfg.Static.Allow {
			rules[i] = endpoint.StaticRule{Resource: r.Resource, Action: r.Action}
		}
		return endpoint.NewStaticEndpoint(rules), nil
	default:
		// Unreachable: validate() already rejects an unknown backend. Kept so
		// the switch stays total if a backend is added without wiring here.
		return nil, fmt.Errorf("auth: unknown backend %q", cfg.Backend)
	}
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
