// Package client is the production network client for AuditService's
// write surface: RegisterEvidence registers evidence (a head's wire variant
// id — StoreVCResult.WireVariantID, not a body content address, see P1-A —
// plus the source content addresses it consumed) with a single
// wireauth-signed call that writes an irreversible receipt; RegisterAuditHead
// registers a head for audit the SAME way but WITHOUT a consumed-set receipt
// (the wire form of the data plane's in-process AuditRegistrar.Add).
//
// Both reproduce the EXACT signed view the handler verifies by calling the
// SAME shared builders the handler does — wirecontract.OpRegisterEvidence /
// wirecontract.RegisterEvidenceFields and wirecontract.OpRegisterAuditHead /
// wirecontract.RegisterAuditHeadFields
// (network/pkg/services/auditor/wirecontract/wireview.go) — so the two
// derivations cannot drift.
//
// It imports only the generated client, connect, crypto, and the auditor
// service's wirecontract LEAF (op names + signed-view builders; PR3b Task 2
// moved these out of the auditor service root so this client never pulls in
// the root's store/runner/handler domain logic) — never the auditor service
// root itself, and never pipeline/ (AGENTS.md layer rule: network and
// pipeline interact only over the wire).
package client

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/auditor/wirecontract"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// Config configures a Client. Signer, SignerDID, BaseURL, and HTTPClient are
// all required.
type Config struct {
	// Signer signs each call's wireauth proof as SignerDID.
	Signer crypto.Signer
	// SignerDID is the identity the write RPCs (RegisterEvidence /
	// RegisterAuditHead) prove — the querying actor IS the signer (the
	// handler runs no separate authorization check; the proven signer_did is
	// authoritative for who registered the evidence).
	SignerDID string
	// BaseURL is the AuditService's ConnectRPC endpoint. Unlike
	// payloadresolver/client (which dials whichever serving boundary is
	// passed per call, since it fetches from arbitrary publishers), this
	// client always registers evidence with ONE node's own AuditService, so
	// the endpoint is fixed at construction rather than passed per call.
	BaseURL string
	// HTTPClient dials BaseURL; supply an SSRF-guarded client, e.g.
	// core.URLGuard.HTTPClient(), for a non-local endpoint.
	HTTPClient connect.HTTPClient
	// Bearer, if non-empty, is presented as the Authorization: Bearer header
	// on every call. Both RegisterEvidence and RegisterAuditHead are mounted
	// behind L1 authz IN ADDITION to the L2 wireauth proof
	// (wirecontract.OpRegisterEvidence / wirecontract.OpRegisterAuditHead) this client
	// already signs — L2 proves WHO is registering, L1 decides whether the
	// caller may reach the RPC at all, and this client previously had no way
	// to present anything for the latter, so a real L1 deployment rejected
	// every call before wireauth was ever checked. Empty
	// presents no header (an unauthenticated-at-L1 PoC node; the server-side
	// interceptor decides whether that is acceptable) — same convention as
	// internal/netcompose.BearerInterceptor, replicated here rather than
	// imported (a leaf client package must not import the composition root).
	Bearer string
}

// Client is a wireauth-signing ConnectRPC client for AuditService's
// write surface (RegisterEvidence, RegisterAuditHead). It signs as a single
// configured identity (signerDID + signer).
type Client struct {
	signer    crypto.Signer
	signerDID string
	svc       auditpbconnect.AuditServiceClient
}

// New returns a Client from cfg.
func New(cfg Config) *Client {
	return &Client{
		signer:    cfg.Signer,
		signerDID: cfg.SignerDID,
		svc: auditpbconnect.NewAuditServiceClient(cfg.HTTPClient, cfg.BaseURL,
			connect.WithInterceptors(bearerInterceptor(cfg.Bearer))),
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. Mirrors
// internal/netcompose.BearerInterceptor's exact convention (header key,
// value shape, and the token-empty / IsClient guards) — duplicated rather
// than imported, since this client package must stay independent of the
// composition root (AGENTS.md layer rule; see auditor/client and
// reportclient's own doc comments on staying import-independent siblings).
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

// RegisterEvidence registers headVariantID's consumed source set with the
// AuditService. headVariantID is the wire variant id a prior StoreVC call
// returned as StoreVCResult.WireVariantID — NOT the body address it also
// returned; the registry resolves the variant server-side to prove admission
// and derives the body address it actually records evidence against (P1-A).
// It:
//
//  1. Canonicalizes consumed via wirecontract.CanonicalizeConsumedSet BEFORE
//     any signing or network call — a malformed set (empty after dedup, or a
//     member that is not a well-formed sha256:<hex> content address) is
//     rejected client-side, in the SAME error class the handler enforces,
//     with no proof minted and no RPC sent.
//  2. Signs wirecontract.OpRegisterEvidence over
//     wirecontract.RegisterEvidenceFields built from the canonical set — the
//     exact bytes the handler reconstructs to verify, so a caller
//     resubmitting the same set in a different order signs and verifies
//     identically.
//  3. Sends the canonical set on the wire (what was signed is what is sent)
//     and returns any Connect error as-is (no swallowing) — the caller sees
//     the real Connect code (e.g. Unauthenticated, InvalidArgument for a
//     malformed variant id, FailedPrecondition for one this node never
//     admitted).
func (c *Client) RegisterEvidence(ctx context.Context, headVariantID string, consumed []string) error {
	canonical, err := wirecontract.CanonicalizeConsumedSet(consumed)
	if err != nil {
		return fmt.Errorf("auditor/client: %w", err)
	}
	ap, err := c.proof(wirecontract.OpRegisterEvidence, wirecontract.RegisterEvidenceFields(headVariantID, canonical))
	if err != nil {
		return err
	}
	_, err = c.svc.RegisterEvidence(ctx, connect.NewRequest(&auditpb.RegisterEvidenceRequest{
		HeadVariantAddress:      headVariantID,
		ConsumedSourceAddresses: canonical,
		AuthProof:               ap,
	}))
	return err
}

// RegisterAuditHead registers headVariantID with the AuditService for async
// audit WITHOUT a consumed-set receipt — the wire form of the data plane's
// in-process AuditRegistrar.Add. headVariantID is the SAME kind of id
// RegisterEvidence takes (a prior StoreVC call's StoreVCResult.WireVariantID,
// never a body address); the registry resolves it server-side to prove
// admission and enqueue by the body address it derives (see
// AuditServiceHandler.RegisterAuditHead's own wire doc for exactly when to
// use this RPC instead of RegisterEvidence). It signs
// wirecontract.OpRegisterAuditHead over wirecontract.RegisterAuditHeadFields
// — the exact bytes the handler reconstructs to verify — and returns any
// Connect error as-is (no swallowing), the same convention RegisterEvidence
// follows.
func (c *Client) RegisterAuditHead(ctx context.Context, headVariantID string) error {
	ap, err := c.proof(wirecontract.OpRegisterAuditHead, wirecontract.RegisterAuditHeadFields(headVariantID))
	if err != nil {
		return err
	}
	_, err = c.svc.RegisterAuditHead(ctx, connect.NewRequest(&auditpb.RegisterAuditHeadRequest{
		HeadVariantAddress: headVariantID,
		AuthProof:          ap,
	}))
	return err
}

// proof signs op over fields as the configured identity and converts the
// wireauth.Proof to the wire AuthProof (issued_at as canonical
// second-precision UTC RFC 3339 — the exact form the handler's strict codec
// accepts). Shared by every write RPC this client signs (RegisterEvidence,
// RegisterAuditHead) — op and fields are the only things that vary between
// them.
func (c *Client) proof(op string, fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("auditor/client: nonce: %w", err)
	}
	p, err := wireauth.Sign(c.signer, c.signerDID, op, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("auditor/client: sign %s: %w", op, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}
