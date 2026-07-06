// Package handler is the proto↔domain boundary for VCResolverService: it
// converts connect request/response messages to and from the vcresolver domain
// and maps domain sentinel errors to Connect codes. It holds no business logic.
//
// The VC crosses the wire as opaque bytes carrying canonical JSON (D-v1): the
// stored credential marshals through its own JCS MarshalJSON so a consumer can
// recompute the content address from the bytes it receives.
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/pagination"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// Service is the consumer-side view of the vcresolver domain the handler depends
// on (defined here to keep the dependency pointing inward). *vcresolver.Service
// satisfies it.
type Service interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (string, error)
	ResolveVC(ctx context.Context, hash string) (*vc.PipelinePassCredential, error)
	ListSuccessors(ctx context.Context, hash, fromExclusive string, limit int) ([]string, bool, error)
}

// listingSuccessors binds ListSuccessors continuation tokens to this RPC
// (see pagination.EncodeToken).
const listingSuccessors = "dplaax.vc.v1.VCResolverService.ListSuccessors"

// Handler adapts a Service to the generated VCResolverServiceHandler.
type Handler struct {
	svc Service
}

var _ vcpbconnect.VCResolverServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) StoreVC(ctx context.Context, req *connect.Request[vcpb.StoreVCRequest]) (*connect.Response[vcpb.StoreVCResponse], error) {
	// A VC submitted over the wire (a producer publishing, or a peer) is a
	// directly-received credential — assembly depth 0. Depth is a local-only audit
	// concept and never crosses the wire (the request carries no depth field).
	hash, err := h.svc.StoreVC(ctx, req.Msg.GetCredential(), req.Msg.GetUpstreamEndpoint(), 0)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.StoreVCResponse{Hash: hash}), nil
}

func (h *Handler) ResolveVC(ctx context.Context, req *connect.Request[vcpb.ResolveVCRequest]) (*connect.Response[vcpb.ResolveVCResponse], error) {
	cred, err := h.svc.ResolveVC(ctx, req.Msg.GetHash())
	if err != nil {
		return nil, mapError(err)
	}
	// Serve the JCS-canonical bytes via the credential's own MarshalJSON. NOT
	// json.Marshal(cred): encoding/json post-processes a json.Marshaler's output with
	// Go's HTML escaping (< > & → < > &), which would break the wire
	// contract that a consumer can recompute the content address from the bytes it
	// receives (issue #1).
	b, err := cred.MarshalJSON()
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.ResolveVCResponse{Credential: b}), nil
}

// ListSuccessors serves one page of the forward index. The queried hash is
// part of the token fingerprint: a continuation replayed against a different
// hash is InvalidArgument, never a silent cross-hash listing.
func (h *Handler) ListSuccessors(ctx context.Context, req *connect.Request[vcpb.ListSuccessorsRequest]) (*connect.Response[vcpb.ListSuccessorsResponse], error) {
	limit, err := pagination.ClampSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	cursor, err := pagination.DecodeToken(listingSuccessors, req.Msg.GetPageToken(), req.Msg.GetHash())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	page, more, err := h.svc.ListSuccessors(ctx, req.Msg.GetHash(), cursor, limit)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &vcpb.ListSuccessorsResponse{Successors: page}
	if more && len(page) > 0 {
		resp.NextPageToken = pagination.EncodeToken(listingSuccessors, page[len(page)-1], req.Msg.GetHash())
	}
	return connect.NewResponse(resp), nil
}

// mapError translates domain sentinel errors to Connect codes (errors.Is, never
// string matching). Unrecognized errors become CodeInternal.
func mapError(err error) error {
	switch {
	case errors.Is(err, vcresolver.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, vcresolver.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
