// Package reportclient is the production network client for ChainService's
// ReportEmitHealth RPC: a publisher self-reports its stripped-publish health
// with a single wireauth-signed call and receives back the TTL that report
// stays fresh for.
//
// It reproduces the EXACT signed view the handler verifies by calling the
// SAME shared builder the handler does — wirecontract.OpReportEmitHealth and
// wirecontract.ReportEmitHealthFields — so the two derivations cannot drift
// (mirrors auditor/client and payloadresolver/client).
//
// It imports only the generated client, connect, crypto, and the
// chainmanager/wirecontract LEAF — never the chainmanager service ROOT
// (which carries the Service implementation and its store/infra/emithealth
// dependencies; see wirecontract's own package doc) and never pipeline/
// (AGENTS.md layer rule: network and pipeline interact only over the wire).
package reportclient

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wirecontract"
)

// Config configures a Client. Signer, SignerDID, BaseURL, and HTTPClient are
// all required.
type Config struct {
	// Signer signs each call's wireauth proof as SignerDID.
	Signer crypto.Signer
	// SignerDID is the identity ReportEmitHealth proves. The handler requires
	// publisher_did to equal the proven signer DID (a caller reports health
	// only for itself), so a call whose publisherDID argument differs from
	// SignerDID is rejected server-side as PermissionDenied.
	SignerDID string
	// BaseURL is the ChainService operator endpoint (L1-authorized — distinct
	// from the L2 ChainPeerService endpoint peerclient dials).
	BaseURL string
	// HTTPClient dials BaseURL; supply an SSRF-guarded client for a
	// non-local endpoint, e.g. core.URLGuard.HTTPClient().
	HTTPClient connect.HTTPClient
	// Bearer, if non-empty, is presented as the Authorization: Bearer header
	// on every call. ReportEmitHealth is mounted behind L1 authz IN ADDITION
	// to the L2 wireauth proof (wirecontract.OpReportEmitHealth) this client
	// already signs — L2 proves WHO is reporting, L1 decides whether the
	// caller may reach the RPC at all, and this client previously had no way
	// to present anything for the latter. Empty presents no header (an
	// unauthenticated-at-L1 PoC node) — same convention as
	// internal/netcompose.BearerInterceptor, replicated here rather than
	// imported (a leaf client package must not import the composition root).
	Bearer string
}

// Client is a wireauth-signing ConnectRPC client for ChainService's
// ReportEmitHealth RPC. It signs as a single configured identity
// (signerDID + signer).
type Client struct {
	signer    crypto.Signer
	signerDID string
	svc       chainpbconnect.ChainServiceClient
}

// New returns a Client from cfg.
func New(cfg Config) *Client {
	return &Client{
		signer:    cfg.Signer,
		signerDID: cfg.SignerDID,
		svc: chainpbconnect.NewChainServiceClient(cfg.HTTPClient, cfg.BaseURL,
			connect.WithInterceptors(bearerInterceptor(cfg.Bearer))),
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. Mirrors
// internal/netcompose.BearerInterceptor's exact convention (header key,
// value shape, and the token-empty / IsClient guards) — duplicated rather
// than imported, since this client package must stay independent of the
// composition root (AGENTS.md layer rule; see reportclient and
// auditor/client's own doc comments on staying import-independent siblings).
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

// ReportEmitHealth reports healthy for publisherDID (the handler enforces
// that this equals the configured SignerDID — see Config's doc) and returns
// the TTL the server says this report stays fresh for. Any Connect error the
// server returns is returned as-is (no swallowing), mirroring
// auditclient.RegisterEvidence: the caller sees the real code (e.g.
// PermissionDenied for a publisherDID that does not match the signing
// identity).
func (c *Client) ReportEmitHealth(ctx context.Context, publisherDID string, healthy bool) (time.Duration, error) {
	ap, err := c.proof(wirecontract.ReportEmitHealthFields(publisherDID, healthy))
	if err != nil {
		return 0, err
	}
	resp, err := c.svc.ReportEmitHealth(ctx, connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: publisherDID,
		Healthy:      healthy,
		AuthProof:    ap,
	}))
	if err != nil {
		return 0, err
	}
	return resp.Msg.GetTtl().AsDuration(), nil
}

// proof signs wirecontract.OpReportEmitHealth over fields as the configured
// identity and converts the wireauth.Proof to the wire AuthProof (issued_at
// as canonical second-precision UTC RFC 3339 — the exact form the handler's
// strict codec accepts).
func (c *Client) proof(fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("reportclient: nonce: %w", err)
	}
	p, err := wireauth.Sign(c.signer, c.signerDID, wirecontract.OpReportEmitHealth, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("reportclient: sign %s: %w", wirecontract.OpReportEmitHealth, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}
