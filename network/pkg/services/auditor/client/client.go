// Package client is the production network client for AuditService's
// evidence-write surface: it registers evidence (a head variant address plus
// the source content addresses it consumed) with a single wireauth-signed
// RegisterEvidence call.
//
// It reproduces the EXACT signed view the handler verifies by calling the
// SAME shared builder the handler does — auditor.OpRegisterEvidence and
// auditor.RegisterEvidenceFields (network/pkg/services/auditor/wireview.go)
// — so the two derivations cannot drift.
//
// It imports only the generated client, connect, and crypto — never
// pipeline/ (AGENTS.md layer rule: network and pipeline interact only over
// the wire).
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
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// Config configures a Client. Signer, SignerDID, BaseURL, and HTTPClient are
// all required.
type Config struct {
	// Signer signs each call's wireauth proof as SignerDID.
	Signer crypto.Signer
	// SignerDID is the identity RegisterEvidence proves — the querying actor
	// IS the signer (the handler runs no separate authorization check; the
	// proven signer_did is authoritative for who registered the evidence).
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
}

// Client is a wireauth-signing ConnectRPC client for AuditService's
// RegisterEvidence RPC. It signs as a single configured identity
// (signerDID + signer).
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
		svc:       auditpbconnect.NewAuditServiceClient(cfg.HTTPClient, cfg.BaseURL),
	}
}

// RegisterEvidence registers headVariantAddr's consumed source set with the
// AuditService. It:
//
//  1. Canonicalizes consumed via auditor.CanonicalizeConsumedSet BEFORE any
//     signing or network call — a malformed set (empty after dedup, or a
//     member that is not a well-formed sha256:<hex> content address) is
//     rejected client-side, in the SAME error class the handler enforces,
//     with no proof minted and no RPC sent.
//  2. Signs auditor.OpRegisterEvidence over auditor.RegisterEvidenceFields
//     built from the canonical set — the exact bytes the handler
//     reconstructs to verify, so a caller resubmitting the same set in a
//     different order signs and verifies identically.
//  3. Sends the canonical set on the wire (what was signed is what is sent)
//     and returns any Connect error as-is (no swallowing) — the caller sees
//     the real Connect code (e.g. Unauthenticated, AlreadyExists,
//     FailedPrecondition).
func (c *Client) RegisterEvidence(ctx context.Context, headVariantAddr string, consumed []string) error {
	canonical, err := auditor.CanonicalizeConsumedSet(consumed)
	if err != nil {
		return fmt.Errorf("auditor/client: %w", err)
	}
	ap, err := c.proof(auditor.RegisterEvidenceFields(headVariantAddr, canonical))
	if err != nil {
		return err
	}
	_, err = c.svc.RegisterEvidence(ctx, connect.NewRequest(&auditpb.RegisterEvidenceRequest{
		HeadVariantAddress:      headVariantAddr,
		ConsumedSourceAddresses: canonical,
		AuthProof:               ap,
	}))
	return err
}

// proof signs auditor.OpRegisterEvidence over fields as the configured
// identity and converts the wireauth.Proof to the wire AuthProof (issued_at
// as canonical second-precision UTC RFC 3339 — the exact form the handler's
// strict codec accepts).
func (c *Client) proof(fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("auditor/client: nonce: %w", err)
	}
	p, err := wireauth.Sign(c.signer, c.signerDID, auditor.OpRegisterEvidence, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("auditor/client: sign %s: %w", auditor.OpRegisterEvidence, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}
