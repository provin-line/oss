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
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string, assemblyDepth int) (vcresolver.StoreVCResult, error)
	ResolveVC(ctx context.Context, hash string) (*vc.PipelinePassCredential, error)
	ListSuccessors(ctx context.Context, hash, fromExclusive string, limit int) ([]string, bool, error)
	ResolveVariant(ctx context.Context, bodyAddress, wireVariantID string) ([]byte, error)
	ListVariants(ctx context.Context, bodyAddress, fromExclusive string, limit int) ([]string, bool, error)
}

// Continuation tokens are bound to their RPC (see pagination.EncodeToken), so
// a token from one listing cannot be replayed against another.
const (
	listingSuccessors = "dplaax.vc.v1.VCResolverService.ListSuccessors"
	listingVariants   = "dplaax.vc.v1.VCResolverService.ListVariants"
)

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
	res, err := h.svc.StoreVC(ctx, req.Msg.GetCredential(), req.Msg.GetUpstreamEndpoint(), 0)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.StoreVCResponse{
		Hash:          res.BodyAddress,
		WireVariantId: res.WireVariantID,
	}), nil
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
	// Name the variant served. The projection is a choice over the variants
	// held right now, so a consumer that must not have the document move under
	// it can take this id to ResolveVariant instead of assuming a second
	// ResolveVC returns the same bytes.
	variant, err := cred.WireVariantID()
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.ResolveVCResponse{
		Credential:    b,
		WireVariantId: variant,
	}), nil
}

// ResolveVariant serves the exact bytes of one variant. They are served as the
// store returned them — the store already proved they are the canonical
// projection of the document that id names, and re-serializing here would
// defeat the point of an exact fetch.
func (h *Handler) ResolveVariant(ctx context.Context, req *connect.Request[vcpb.ResolveVariantRequest]) (*connect.Response[vcpb.ResolveVariantResponse], error) {
	wire, err := h.svc.ResolveVariant(ctx, req.Msg.GetBodyAddress(), req.Msg.GetWireVariantId())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.ResolveVariantResponse{Credential: wire}), nil
}

// ListVariants serves one page of a body's variant set. The queried body is
// part of the token fingerprint: a continuation replayed against a different
// body is InvalidArgument, never a silent cross-body listing.
func (h *Handler) ListVariants(ctx context.Context, req *connect.Request[vcpb.ListVariantsRequest]) (*connect.Response[vcpb.ListVariantsResponse], error) {
	limit, err := pagination.ClampSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	cursor, err := pagination.DecodeToken(listingVariants, req.Msg.GetPageToken(), req.Msg.GetBodyAddress())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	page, more, err := h.svc.ListVariants(ctx, req.Msg.GetBodyAddress(), cursor, limit)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &vcpb.ListVariantsResponse{WireVariantIds: page}
	if more && len(page) > 0 {
		resp.NextPageToken = pagination.EncodeToken(listingVariants, page[len(page)-1], req.Msg.GetBodyAddress())
	}
	return connect.NewResponse(resp), nil
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
