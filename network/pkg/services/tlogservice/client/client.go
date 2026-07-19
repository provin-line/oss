// Package client is the production network client for TlogService's mirror
// surface (spec D-T2/D-T6): it ships checkpoint-aligned segments of a local
// tlog.Log to the registry via MirrorLogSegment, and reads the registry's
// durable resume cursor via GetMirrorState.
//
// It reproduces the EXACT signed view the handler verifies by calling the
// SAME shared builders the handler does — tlogservice.OpMirrorLogSegment,
// tlogservice.MirrorLogSegmentFields, and tlogservice.SegmentDigest
// (network/pkg/services/tlogservice/wireview.go) — so the two derivations
// cannot drift (mirrors auditor/client's own rationale for reusing
// auditor.OpRegisterEvidence/RegisterEvidenceFields).
//
// It imports only the generated client, connect, crypto, and the
// tlogservice package's shared wire-view builders — never pipeline/
// (AGENTS.md layer rule: network and pipeline interact only over the wire).
package client

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	tlogpb "github.com/provin-line/oss/gen/go/dplaax/tlog/v1"
	"github.com/provin-line/oss/gen/go/dplaax/tlog/v1/tlogpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/tlogservice"
	"github.com/provin-line/oss/tlog"
)

// Config configures a Client. Signer, SignerDID, BaseURL, and HTTPClient are
// all required.
type Config struct {
	// Signer signs each MirrorLogSegment call's wireauth proof as SignerDID
	// — the log's OWN writer identity (D-T3: the checkpoint's SignedBy base
	// must equal this proven signer_did). GetMirrorState needs no proof (it
	// rides the L1 interceptor only, same posture as ListLogRecords), so
	// Signer/SignerDID are unused for that call.
	Signer crypto.Signer
	// SignerDID is the identity MirrorLogSegment proves — the log's writer,
	// not a separate "who is asking" actor (the handler threads the proven
	// signer_did straight through to D-T3 enforcement; see
	// tlogservice.MirrorSegmentInput.CallerDID).
	SignerDID string
	// BaseURL is the registry's ConnectRPC endpoint.
	BaseURL string
	// HTTPClient dials BaseURL; supply an SSRF-guarded client for a
	// non-local endpoint.
	HTTPClient connect.HTTPClient
	// Bearer, if non-empty, is presented as the Authorization: Bearer header
	// on every call — the L1 PDP gate MirrorLogSegment/GetMirrorState mount
	// behind, IN ADDITION to MirrorLogSegment's own L2 wireauth proof. Empty
	// presents no header (an unauthenticated-at-L1 PoC node). Same
	// convention as auditor/client.Config.Bearer, replicated here rather
	// than imported (a leaf client package must not import the composition
	// root).
	Bearer string
}

// Client is a wireauth-signing ConnectRPC client for TlogService's mirror
// surface. It signs MirrorLogSegment calls as a single configured identity
// (signerDID + signer).
type Client struct {
	signer    crypto.Signer
	signerDID string
	svc       tlogpbconnect.TlogServiceClient
}

// New returns a Client from cfg.
func New(cfg Config) *Client {
	return &Client{
		signer:    cfg.Signer,
		signerDID: cfg.SignerDID,
		svc: tlogpbconnect.NewTlogServiceClient(cfg.HTTPClient, cfg.BaseURL,
			connect.WithInterceptors(bearerInterceptor(cfg.Bearer))),
	}
}

// bearerInterceptor sets the L1 PDP Authorization bearer on every outgoing
// call. An empty token sets no header. Mirrors
// internal/netcompose.BearerInterceptor's exact convention (header key,
// value shape, and the token-empty / IsClient guards) — duplicated rather
// than imported, since this client package must stay independent of the
// composition root (AGENTS.md layer rule; see auditor/client's own doc
// comment on staying import-independent siblings).
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

// MirrorLogSegment ships one checkpoint-aligned segment [fromIndex,
// fromIndex+len(payloads)) to the registry: cp is the local log's signed
// checkpoint covering EXACTLY this segment's end (D-T2 acceptance rule 1;
// callers — the tlogship shipper — obtain it from the live tlog.Log's own
// Checkpoint(), never synthesized here). It:
//
//  1. Builds segment_digest via the SAME tlogservice.SegmentDigest the
//     handler recomputes, and signs tlogservice.OpMirrorLogSegment over
//     tlogservice.MirrorLogSegmentFields(logID, fromIndex, cp.Head, digest)
//     — the exact view the handler reconstructs to verify.
//  2. Sends logID, fromIndex, payloads, and cp (wire-shaped identically to
//     GetLogCheckpointResponse) on the wire.
//  3. Returns any Connect error as-is (no swallowing) — the caller sees the
//     real Connect code (e.g. FailedPrecondition for a gap/overlap/
//     chain-head mismatch, ResourceExhausted for a cap violation,
//     PermissionDenied for a D-T3 identity failure).
//
// A nil cp is rejected client-side before any signing or network call — a
// MirrorLogSegment call always carries a checkpoint (D-T2 rule 1 requires
// one), so a nil value here is a caller bug, not a wire condition.
func (c *Client) MirrorLogSegment(ctx context.Context, logID string, fromIndex uint64, payloads [][]byte, cp *tlog.Checkpoint) (uint64, error) {
	if cp == nil {
		return 0, fmt.Errorf("tlogservice/client: MirrorLogSegment: nil checkpoint")
	}
	digest := tlogservice.SegmentDigest(payloads)
	fields := tlogservice.MirrorLogSegmentFields(logID, fromIndex, cp.Head, digest)
	ap, err := c.proof(tlogservice.OpMirrorLogSegment, fields)
	if err != nil {
		return 0, err
	}
	resp, err := c.svc.MirrorLogSegment(ctx, connect.NewRequest(&tlogpb.MirrorLogSegmentRequest{
		LogId:          logID,
		FromIndex:      fromIndex,
		RecordPayloads: payloads,
		Checkpoint:     checkpointToWire(cp),
		AuthProof:      ap,
	}))
	if err != nil {
		return 0, err
	}
	return resp.Msg.GetAckedSize(), nil
}

// GetMirrorState reads the registry's durable mirror size for logID — the
// shipper's resume cursor (D-T2 rule 6). No wireauth proof: it rides the L1
// interceptor only, matching the RPC's read-only posture (see
// tlogservice.Service.MirrorState's own doc).
func (c *Client) GetMirrorState(ctx context.Context, logID string) (uint64, error) {
	resp, err := c.svc.GetMirrorState(ctx, connect.NewRequest(&tlogpb.GetMirrorStateRequest{LogId: logID}))
	if err != nil {
		return 0, err
	}
	return resp.Msg.GetAckedSize(), nil
}

// proof signs op over fields as the configured identity and converts the
// wireauth.Proof to the wire AuthProof (issued_at as canonical
// second-precision UTC RFC 3339 — the exact form the handler's strict codec
// accepts).
func (c *Client) proof(op string, fields map[string]any) (*chainpb.AuthProof, error) {
	nonce, err := wireauth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("tlogservice/client: nonce: %w", err)
	}
	p, err := wireauth.Sign(c.signer, c.signerDID, op, fields, nonce, time.Now())
	if err != nil {
		return nil, fmt.Errorf("tlogservice/client: sign %s: %w", op, err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID,
		Nonce:     p.Nonce,
		IssuedAt:  p.IssuedAt.UTC().Format(time.RFC3339),
		Signature: p.Signature,
	}, nil
}

// checkpointToWire converts a tlog.Checkpoint to the
// MirrorLogSegmentRequest.checkpoint wire shape — identical to
// GetLogCheckpointResponse (handler.checkpointFromWire, in
// network/pkg/services/tlogservice/handler/handler.go, is this function's
// inverse). Reproduced rather than imported: the handler package is not a
// dependency of this client (AGENTS.md's handler/service/store layering
// keeps a client from reaching into a handler package's internals), and the
// codebase's own convention for this exact situation — see auditor/handler
// and this client's own bearerInterceptor doc — is to duplicate the small
// codec rather than couple the two packages.
func checkpointToWire(cp *tlog.Checkpoint) *tlogpb.GetLogCheckpointResponse {
	return &tlogpb.GetLogCheckpointResponse{
		LogId:     cp.Origin,
		Size:      strconv.FormatUint(cp.Size, 10),
		Head:      cp.Head,
		Timestamp: cp.Timestamp.UTC().Format(time.RFC3339),
		SignedBy:  cp.SignedBy,
		Signature: cp.Signature,
	}
}
