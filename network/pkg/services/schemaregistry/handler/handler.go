// Package handler is the proto↔domain boundary for SchemaService: it converts
// connect request/response messages to and from the schemaregistry domain types
// and maps domain sentinel errors to Connect codes. It holds no business logic.
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	schemav1 "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	schemav1connect "github.com/provin-line/oss/gen/go/dplaax/schema/v1/v1connect"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store"
)

// Registry is the consumer-side view of the schemaregistry service the handler
// depends on (defined here, not in the service package, to keep the dependency
// pointing inward). *schemaregistry.Service satisfies it.
type Registry interface {
	Register(ctx context.Context, name, format string, body []byte, prerelease string) (*store.Schema, error)
	Get(ctx context.Context, name, version string) (*store.Schema, error)
	List(ctx context.Context, name string, includeDeprecated, includePrerelease bool) ([]*store.Schema, error)
	Deprecate(ctx context.Context, name, version string) error
}

// Handler adapts a Registry to the generated SchemaServiceHandler.
type Handler struct {
	svc Registry
}

var _ schemav1connect.SchemaServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Registry) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterSchema(ctx context.Context, req *connect.Request[schemav1.RegisterSchemaRequest]) (*connect.Response[schemav1.RegisterSchemaResponse], error) {
	m := req.Msg
	sc, err := h.svc.Register(ctx, m.GetName(), m.GetSchemaFormat(), m.GetSchemaBody(), m.GetPrerelease())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&schemav1.RegisterSchemaResponse{Schema: toProto(sc)}), nil
}

func (h *Handler) GetSchema(ctx context.Context, req *connect.Request[schemav1.GetSchemaRequest]) (*connect.Response[schemav1.GetSchemaResponse], error) {
	m := req.Msg
	sc, err := h.svc.Get(ctx, m.GetName(), m.GetVersion())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&schemav1.GetSchemaResponse{Schema: toProto(sc)}), nil
}

func (h *Handler) ListSchemas(ctx context.Context, req *connect.Request[schemav1.ListSchemasRequest]) (*connect.Response[schemav1.ListSchemasResponse], error) {
	m := req.Msg
	list, err := h.svc.List(ctx, m.GetName(), m.GetIncludeDeprecated(), m.GetIncludePrerelease())
	if err != nil {
		return nil, mapError(err)
	}
	out := make([]*schemav1.Schema, 0, len(list))
	for _, sc := range list {
		out = append(out, toProto(sc))
	}
	return connect.NewResponse(&schemav1.ListSchemasResponse{Schemas: out}), nil
}

func (h *Handler) DeprecateSchema(ctx context.Context, req *connect.Request[schemav1.DeprecateSchemaRequest]) (*connect.Response[schemav1.DeprecateSchemaResponse], error) {
	m := req.Msg
	if err := h.svc.Deprecate(ctx, m.GetName(), m.GetVersion()); err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&schemav1.DeprecateSchemaResponse{}), nil
}

func toProto(s *store.Schema) *schemav1.Schema {
	return &schemav1.Schema{
		Name:         s.Name,
		Version:      s.Version,
		Prerelease:   s.Prerelease,
		SchemaFormat: s.SchemaFormat,
		SchemaBody:   s.SchemaBody,
		Deprecated:   s.Deprecated,
	}
}

// mapError translates domain sentinel errors to Connect codes (errors.Is, never
// string matching). Unrecognized errors become CodeInternal.
func mapError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, schemaregistry.ErrInvalidArgument),
		errors.Is(err, schemaregistry.ErrUnsupportedFormat):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
