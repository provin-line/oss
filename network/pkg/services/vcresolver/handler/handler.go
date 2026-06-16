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
	"encoding/json"
	"errors"

	"connectrpc.com/connect"

	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/vc"
)

// Service is the consumer-side view of the vcresolver domain the handler depends
// on (defined here to keep the dependency pointing inward). *vcresolver.Service
// satisfies it.
type Service interface {
	StoreVC(ctx context.Context, credential []byte, upstreamEndpoint string) (string, error)
	ResolveVC(ctx context.Context, hash string) (*vc.PipelinePassCredential, error)
}

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
	hash, err := h.svc.StoreVC(ctx, req.Msg.GetCredential(), req.Msg.GetUpstreamEndpoint())
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
	b, err := json.Marshal(cred) // PipelinePassCredential.MarshalJSON emits JCS-canonical form
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&vcpb.ResolveVCResponse{Credential: b}), nil
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
