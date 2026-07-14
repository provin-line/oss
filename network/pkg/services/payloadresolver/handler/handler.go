// Package handler is the proto↔domain boundary for PayloadService: it verifies
// each request's L2 wireauth proof in-band (no L1 interceptor — mirrors the
// chain.v1 peer surface), delegates authorize-then-serve to the serving
// boundary, and streams the returned bytes back. It holds no business logic:
// the owner-set admission decision lives in payloadresolver.ServingBoundary.
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
)

// opResolvePayload is the wireauth op name — it MUST match the client's signed
// view (the bytes are reproduced via wireauth.Sign on the client).
const opResolvePayload = "ResolvePayload"

// chunkSize bounds one streamed frame. A server implementation detail, not
// wire-normative: the client concatenates frames regardless of size.
const chunkSize = 256 * 1024

// Serving is the authorize-then-serve boundary the handler depends on (defined
// here to keep the dependency pointing inward). Serve returns the payload bytes
// iff callerDID is admitted by an owner, else payloadresolver.ErrNotFound —
// identical for a not-admitted caller and an absent hash (F9/F4).
// *payloadresolver.ServingBoundary satisfies it.
type Serving interface {
	Serve(ctx context.Context, hash, callerDID string) ([]byte, error)
}

// Verifier is the wireauth verification seam (an interface so a spy can be
// injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// Handler adapts the payloadresolver serving boundary to the generated
// PayloadServiceHandler.
type Handler struct {
	svc Serving
	v   Verifier
}

var _ payloadpbconnect.PayloadServiceHandler = (*Handler)(nil)

// New returns a Handler backed by the serving boundary and the wireauth verifier.
func New(svc Serving, v Verifier) *Handler {
	return &Handler{svc: svc, v: v}
}

// ResolvePayload verifies the L2 proof, delegates authorize-then-serve to the
// serving boundary (which admits the caller against the payload's owner set and
// reads the bytes only on admission), then streams the bytes in order.
func (h *Handler) ResolvePayload(ctx context.Context, req *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return mapError(err)
	}
	// content_hash is the only signed business field; the querying actor IS the
	// signer (nil authorizer). Admission against the owner set is the serving
	// boundary's job, below.
	fields := map[string]any{"content_hash": req.Msg.GetContentHash()}
	if err := h.v.Verify(ctx, opResolvePayload, fields, proof, nil); err != nil {
		return mapError(err)
	}
	// Serve authorizes on owner metadata and reads the bytes only if admitted; a
	// not-admitted caller and an absent hash both come back as ErrNotFound, so
	// mapError emits an identical CodeNotFound (no existence oracle).
	payload, err := h.svc.Serve(ctx, req.Msg.GetContentHash(), proof.SignerDID)
	if err != nil {
		return mapError(err)
	}
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		if err := stream.Send(&payloadpb.ResolvePayloadResponse{Chunk: payload[off:end]}); err != nil {
			return err // transport error — connect already framed it
		}
	}
	return nil
}

// mapError translates codec, wireauth, and domain sentinels to Connect codes
// (errors.Is, never string matching). Unrecognized errors become CodeInternal.
//
// Note there is deliberately NO PermissionDenied case: the serving boundary
// collapses a not-admitted caller to ErrNotFound so the wire cannot distinguish
// "present but forbidden" from "absent" (F9/F4). Because ErrNotFound carries a
// constant message, the two cases are byte-identical on the wire.
func mapError(err error) error {
	switch {
	// Malformed request / proof shape.
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView),
		errors.Is(err, payloadresolver.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Inbound caller hung up mid-resolution: CodeCanceled, not a server-side
	// "unavailable". Precedes ErrResolverUnavailable, which the cancellation
	// also wraps — order decides the mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	// Transient resolver condition (timeout/capacity): retryable, NOT an
	// identity rejection. Must precede the Unauthenticated cases — the error
	// also wraps ErrResolverUnavailable, and order decides the mapping.
	case errors.Is(err, wireauth.ErrResolverUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	// Failed to prove identity.
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// Absent hash OR not-admitted caller (collapsed by the serving boundary):
	// one code, one constant message.
	case errors.Is(err, payloadresolver.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
