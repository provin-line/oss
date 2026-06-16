// Package handler is the proto↔domain boundary for SignerService: it converts
// connect request/response messages to and from the signer domain and maps
// domain sentinel errors to Connect codes. It holds no business logic.
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	signerpb "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
	"github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	"github.com/provin-line/oss/network/pkg/services/signer"
)

// Service is the consumer-side view of the signer domain the handler depends on
// (defined here, not in the service package, to keep the dependency pointing
// inward). *signer.Service satisfies it.
type Service interface {
	Sign(ctx context.Context, did, keyID string, data []byte) ([]byte, error)
	SignRaw(ctx context.Context, did, keyID string, data []byte) ([]byte, error)
}

// Handler adapts a Service to the generated SignerServiceHandler.
type Handler struct {
	svc Service
}

var _ signerpbconnect.SignerServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Sign(ctx context.Context, req *connect.Request[signerpb.SignRequest]) (*connect.Response[signerpb.SignResponse], error) {
	sig, err := h.svc.Sign(ctx, req.Msg.GetDid(), req.Msg.GetKeyId(), req.Msg.GetData())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&signerpb.SignResponse{Signature: sig}), nil
}

func (h *Handler) SignRaw(ctx context.Context, req *connect.Request[signerpb.SignRawRequest]) (*connect.Response[signerpb.SignRawResponse], error) {
	sig, err := h.svc.SignRaw(ctx, req.Msg.GetDid(), req.Msg.GetKeyId(), req.Msg.GetData())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&signerpb.SignRawResponse{Signature: sig}), nil
}

// mapError translates domain sentinel errors to Connect codes (errors.Is, never
// string matching). A signing error that is neither sentinel — e.g. a malformed
// stored key — becomes CodeInternal; it is never masked as NotFound.
func mapError(err error) error {
	switch {
	case errors.Is(err, signer.ErrKeyNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, signer.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
