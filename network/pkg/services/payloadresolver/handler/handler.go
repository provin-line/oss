// Package handler is the proto↔domain boundary for PayloadService: it verifies
// each request's L2 wireauth proof in-band (no L1 interceptor — mirrors the
// chain.v1 peer surface), admits the caller against the payload's owner set, and
// streams the bytes back. It holds no business logic.
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
)

// opResolvePayload is the wireauth op name — it MUST match the client's signed
// view (the bytes are reproduced via wireauth.Sign on the client).
const opResolvePayload = "ResolvePayload"

// chunkSize bounds one streamed frame. A server implementation detail, not
// wire-normative: the client concatenates frames regardless of size.
const chunkSize = 256 * 1024

// Service is the consumer-side view of the payloadresolver domain the handler
// depends on (defined here to keep the dependency pointing inward).
// *payloadresolver.Service satisfies it.
type Service interface {
	Resolve(ctx context.Context, hash string) (payload []byte, owners []string, err error)
}

// Verifier is the wireauth verification seam (an interface so a spy can be
// injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// AllowList is the per-pipeline admission seam. Admit returns nil when callerDID
// is admitted by pipelineDID's allow-list, chainmanager.ErrNotAdmitted otherwise.
// *chainmanager.Service satisfies it (its exported Admit).
type AllowList interface {
	Admit(pipelineDID, callerDID string) error
}

// Handler adapts the payloadresolver domain to the generated
// PayloadServiceHandler.
type Handler struct {
	svc    Service
	v      Verifier
	allows AllowList
}

var _ payloadpbconnect.PayloadServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc, the wireauth verifier, and the allow-list
// admission seam.
func New(svc Service, v Verifier, allows AllowList) *Handler {
	return &Handler{svc: svc, v: v, allows: allows}
}

// ResolvePayload verifies the L2 proof, admits the caller against the payload's
// owner set (any-owner-admits), then streams the bytes in order.
func (h *Handler) ResolvePayload(ctx context.Context, req *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return mapError(err)
	}
	// content_hash is the only signed business field; the querying actor IS the
	// signer (nil authorizer). Admission against the owner set happens below,
	// after the payload's owners are known.
	fields := map[string]any{"content_hash": req.Msg.GetContentHash()}
	if err := h.v.Verify(ctx, opResolvePayload, fields, proof, nil); err != nil {
		return mapError(err)
	}
	payload, owners, err := h.svc.Resolve(ctx, req.Msg.GetContentHash())
	if err != nil {
		return mapError(err)
	}
	// any-owner-admits: serve iff the caller passes AT LEAST ONE owner's
	// allow-list. A caller admitted by one owner learns nothing extra from a
	// bit-identical copy owned by a stricter pipeline, so serving on any single
	// owner match preserves confidentiality (spec §3.2.4). An empty owner set
	// (a crash residual) admits no one — fail-closed.
	if !h.admittedByAnyOwner(owners, proof.SignerDID) {
		return mapError(chainmanager.ErrNotAdmitted)
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

func (h *Handler) admittedByAnyOwner(owners []string, callerDID string) bool {
	for _, owner := range owners {
		if err := h.allows.Admit(owner, callerDID); err == nil {
			return true
		}
	}
	return false
}

// mapError translates codec, wireauth, admission, and domain sentinels to
// Connect codes (errors.Is, never string matching). Unrecognized errors become
// CodeInternal.
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
	// also wraps (the later context.Canceled case covers non-resolver paths).
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
	// Authorization (no owner admits the caller).
	case errors.Is(err, chainmanager.ErrNotAdmitted):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, payloadresolver.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
