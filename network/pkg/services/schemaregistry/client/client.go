// Package client is the production network client for SchemaService's read
// surface: GetSchema resolves one exact (name, version) schema record over
// the wire. SchemaService.GetSchema has no "latest" resolution (schema.proto's
// own package doc: pipelines pin exact versions; drift between stages is the
// failure mode that design prevents) — every caller resolves a pinned
// version, whether a producing loop resolving a config schema-ref at boot or
// a consuming loop resolving a schema content-hash during verification.
//
// It imports only the generated client and connect — never the
// schemaregistry service root (store/service domain logic) and never
// pipeline/ (AGENTS.md layer rule: network and pipeline interact only over
// the wire). Among the existing clients, its shape mirrors
// payloadresolver/client's read side most closely — Config{BaseURL,
// HTTPClient, Bearer} + New, and a remote NotFound maps to this package's own
// ErrNotFound sentinel (errors.Is) — but this client signs no wireauth proof
// (GetSchemaRequest carries no AuthProof field; only L1 bearer authz gates
// GetSchema, per the o3co.authz.v1.policy {resource: "schemas", action:
// "read"} option on the RPC), so unlike its wireauth-signing siblings, Config
// carries no Signer/SignerDID.
package client

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
)

// schemaDocumentReadCapBytes bounds a GetSchema response. Reuses — never
// invents — the VALUE internal/netcompose.maxDocumentRequestBytes assigns the
// document class ("schema bodies, DID documents/delegations, and
// full-replacement allowlists, which can legitimately be larger" than the
// proof class; internal/netcompose/server.go). Duplicated here rather than
// imported: that constant is unexported to internal/netcompose/server.go, and
// even if it were exported, a leaf client package must not import the
// composition root (AGENTS.md layer rule — same posture as this package's
// bearerInterceptor, below).
const schemaDocumentReadCapBytes = 1 << 20 // 1 MiB — internal/netcompose.maxDocumentRequestBytes

// ErrNotFound reports a definitive miss: the registry authoritatively holds
// no record for the requested (name, version). GetSchema has no "latest"
// resolution (see the package doc), so this is never "not yet the newest" —
// a server-side ambiguity — which is why it is distinguished with a sentinel
// (errors.Is) rather than left as an opaque Connect code: a caller whose own
// semantics depend on telling a definitive miss apart from a transient
// transport failure (e.g. a full-chain verifier's indeterminate-vs-failed
// split) can branch on it directly. Mirrors payloadresolver/client.ErrNotFound
// and vcresolver/client's own not-found posture.
var ErrNotFound = errors.New("schemaregistry/client: schema not found")

// Config configures a Client. BaseURL and HTTPClient are required.
type Config struct {
	// BaseURL is the SchemaService's ConnectRPC endpoint.
	BaseURL string
	// HTTPClient dials BaseURL; supply an SSRF-guarded client, e.g.
	// core.URLGuard.HTTPClient(), for a non-local endpoint.
	HTTPClient connect.HTTPClient
	// Bearer, if non-empty, is presented as the Authorization: Bearer header
	// on every call — GetSchema is mounted behind L1 authz (schema.proto's
	// o3co.authz.v1.policy {resource: "schemas", action: "read"} option).
	// Empty presents no header (an unauthenticated-at-L1 PoC node; the
	// server-side interceptor decides whether that is acceptable). Convention
	// mirrors internal/netcompose.BearerInterceptor, replicated here rather
	// than imported (a leaf client package must not import the composition
	// root) — same posture as auditor/client.Config.Bearer and its siblings.
	Bearer string
}

// Client is a node's handle to SchemaService's read surface.
type Client struct {
	svc schemapbconnect.SchemaServiceClient
}

// New returns a Client from cfg.
func New(cfg Config) *Client {
	return &Client{
		svc: schemapbconnect.NewSchemaServiceClient(cfg.HTTPClient, cfg.BaseURL,
			connect.WithInterceptors(bearerInterceptor(cfg.Bearer)),
			connect.WithReadMaxBytes(schemaDocumentReadCapBytes),
		),
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. Mirrors
// internal/netcompose.BearerInterceptor's exact convention (header key,
// value shape, and the token-empty / IsClient guards) — duplicated rather
// than imported, since this client package must stay independent of the
// composition root (AGENTS.md layer rule; see auditor/client's own doc
// comment on staying import-independent siblings, replicated again here
// following the same established convention).
func bearerInterceptor(token string) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if token != "" && req.Spec().IsClient {
				req.Header().Set("Authorization", "Bearer "+token)
			}
			return next(ctx, req)
		}
	})
}

// Schema is one registered schema version, as GetSchema returns it — this
// package's own type, never the generated schemapb.Schema (a leaf client
// package does not leak the wire type to callers; mirrors
// vcresolver/client.StoredCredential's own rationale for a client-local
// result type).
type Schema struct {
	// Version is the exact version key GetSchema resolved
	// ("YYYY-MM-DD-{hash16}").
	Version string
	// Format names the schema language, e.g. "JsonSchema".
	Format string
	// Body is the opaque schema document bytes.
	Body []byte
	// Deprecated is the soft flag; the body is retained even when true — the
	// registry never deletes (see the service's own package doc).
	Deprecated bool
}

// GetSchema fetches the exact (name, version) record. A remote NotFound
// becomes ErrNotFound (errors.Is); any other Connect error is returned as-is
// (no swallowing) — the caller sees the real code (e.g. Unauthenticated /
// PermissionDenied from the L1 gate, InvalidArgument for a malformed
// name/version).
func (c *Client) GetSchema(ctx context.Context, name, version string) (*Schema, error) {
	resp, err := c.svc.GetSchema(ctx, connect.NewRequest(&schemapb.GetSchemaRequest{
		Name:    name,
		Version: version,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		return nil, err
	}
	sc := resp.Msg.GetSchema()
	return &Schema{
		Version:    sc.GetVersion(),
		Format:     sc.GetSchemaFormat(),
		Body:       sc.GetSchemaBody(),
		Deprecated: sc.GetDeprecated(),
	}, nil
}
