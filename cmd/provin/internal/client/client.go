// Package client builds the ConnectRPC clients the provin CLI drives a
// registry with: base-URL validation, the L1 bearer-token interceptor, and
// nothing else — commands own request shaping, this package owns the wire.
package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
)

// DID returns a DIDService client for the registry base URL, presenting token
// as the L1 bearer on every RPC. httpClient nil defaults to
// http.DefaultClient (tests inject an httptest client).
func DID(httpClient connect.HTTPClient, registry, token string) (didpbconnect.DIDServiceClient, error) {
	if err := ValidateBaseURL(registry); err != nil {
		return nil, fmt.Errorf("client: registry URL: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("client: bearer token must not be empty (--token / PROVIN_TOKEN)")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return didpbconnect.NewDIDServiceClient(httpClient, registry, connect.WithInterceptors(bearer(token))), nil
}

// VCResolver returns a VCResolverService client for the registry base URL,
// presenting token as the L1 bearer on every RPC — the credential-fetch
// surface the audit-bundle exporter walks a chain over. Same validation and
// injection rules as DID.
func VCResolver(httpClient connect.HTTPClient, registry, token string) (vcpbconnect.VCResolverServiceClient, error) {
	if err := ValidateBaseURL(registry); err != nil {
		return nil, fmt.Errorf("client: registry URL: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("client: bearer token must not be empty (--token / PROVIN_TOKEN)")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return vcpbconnect.NewVCResolverServiceClient(httpClient, registry, connect.WithInterceptors(bearer(token))), nil
}

// Audit returns an AuditService client for a node base URL, presenting token
// as the L1 bearer on every RPC — the receipt-read surface the
// aggregate-complete exporter walks consumed sets over. Same validation and
// injection rules as DID.
func Audit(httpClient connect.HTTPClient, base, token string) (auditpbconnect.AuditServiceClient, error) {
	if err := ValidateBaseURL(base); err != nil {
		return nil, fmt.Errorf("client: audit base URL: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("client: bearer token must not be empty (--token / PROVIN_TOKEN)")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return auditpbconnect.NewAuditServiceClient(httpClient, base, connect.WithInterceptors(bearer(token))), nil
}

// Schema returns a SchemaService client for the registry base URL, presenting
// token as the L1 bearer on every RPC — the surface `provin schema register`
// drives. Same validation and injection rules as DID.
func Schema(httpClient connect.HTTPClient, registry, token string) (schemapbconnect.SchemaServiceClient, error) {
	if err := ValidateBaseURL(registry); err != nil {
		return nil, fmt.Errorf("client: registry URL: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("client: bearer token must not be empty (--token / PROVIN_TOKEN)")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return schemapbconnect.NewSchemaServiceClient(httpClient, registry, connect.WithInterceptors(bearer(token))), nil
}

// Chain returns a ChainService client for the registry base URL, presenting
// token as the L1 bearer on every RPC — the surface `provin chain subscribe`
// / `chain set-allow` drive. Same validation and injection rules as DID.
func Chain(httpClient connect.HTTPClient, registry, token string) (chainpbconnect.ChainServiceClient, error) {
	if err := ValidateBaseURL(registry); err != nil {
		return nil, fmt.Errorf("client: registry URL: %w", err)
	}
	if token == "" {
		return nil, fmt.Errorf("client: bearer token must not be empty (--token / PROVIN_TOKEN)")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return chainpbconnect.NewChainServiceClient(httpClient, registry, connect.WithInterceptors(bearer(token))), nil
}

// ValidateBaseURL rejects a base URL that is empty, scheme-less, not http(s),
// hostless, or carrying a query/fragment (the Connect client appends the RPC
// procedure to the raw base, so a query or fragment would corrupt every
// request path) — the same fail-closed rules the node applies to its own
// endpoint config. Exported so every base-URL-taking construction in
// cmd/provin shares one contract, including non-ConnectRPC callers (e.g. the
// org commands' raw-HTTP W3C DID-resolution adapter) — not just the Connect
// client constructors below.
func ValidateBaseURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("must not be empty (--registry / PROVIN_REGISTRY)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q must have an explicit http:// or https:// scheme", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%q must have a host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must be a base URL with no query or fragment", raw)
	}
	return nil
}

// bearer stamps the Authorization header on every outgoing RPC.
func bearer(token string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			req.Header().Set("Authorization", "Bearer "+token)
			return next(ctx, req)
		}
	}
}
