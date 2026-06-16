// Package handler is the proto↔domain boundary for DIDService: it converts
// connect request/response messages to and from the didregistry domain types and
// maps domain sentinel errors to Connect codes. It holds no business logic.
//
// DID Documents, delegations, and lifecycle events cross the wire as opaque
// bytes carrying their canonical JSON (the proto does not re-model them, D-d2):
// documents and delegations marshal through their own JSON, and lifecycle events
// marshal through the canonical map shared with the service's hash chain, so a
// consumer can verify the chain from the bytes it receives.
package handler

import (
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
)

// Service is the consumer-side view of the didregistry service the handler
// depends on (defined here, not in the service package, to keep the dependency
// pointing inward). *didregistry.Service satisfies it.
type Service interface {
	RegisterOwner(ctx context.Context, doc *did.DIDDocument, outwardSnapshot []byte) (*did.DIDDocument, error)
	IssuePipeline(ctx context.Context, targetDID string, dlg *delegation.DelegationCredential) (*did.DIDDocument, *delegation.DelegationCredential, error)
	IssueProcess(ctx context.Context, targetDID string, dlg *delegation.DelegationCredential) (*did.DIDDocument, *delegation.DelegationCredential, error)
	ResolveDID(ctx context.Context, didStr string) (*did.DIDDocument, error)
	ResolveDelegation(ctx context.Context, didStr string) (*delegation.DelegationCredential, error)
	UpdateStatus(ctx context.Context, didStr, status string) (*did.DIDDocument, error)
	ListPipelines(ctx context.Context, ownerDID string) ([]store.DIDSummary, error)
	ListProcesses(ctx context.Context, pipelineDID string) ([]store.DIDSummary, error)
	ReadLifecycleLog(ctx context.Context, didStr string) ([]store.LifecycleEvent, error)
}

// Handler adapts a Service to the generated DIDServiceHandler.
type Handler struct {
	svc Service
}

var _ didpbconnect.DIDServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) RegisterOwner(ctx context.Context, req *connect.Request[didpb.RegisterOwnerRequest]) (*connect.Response[didpb.RegisterOwnerResponse], error) {
	doc, err := docFromBytes(req.Msg.GetDidDocument())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.RegisterOwner(ctx, doc, req.Msg.GetOutwardSnapshot())
	if err != nil {
		return nil, mapError(err)
	}
	b, err := docToBytes(out)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.RegisterOwnerResponse{DidDocument: b}), nil
}

func (h *Handler) IssuePipeline(ctx context.Context, req *connect.Request[didpb.IssuePipelineRequest]) (*connect.Response[didpb.IssuePipelineResponse], error) {
	dlg, err := delegationFromBytes(req.Msg.GetDelegation())
	if err != nil {
		return nil, err
	}
	doc, savedDlg, err := h.svc.IssuePipeline(ctx, req.Msg.GetTargetDid(), dlg)
	if err != nil {
		return nil, mapError(err)
	}
	docB, dlgB, err := issuedBytes(doc, savedDlg)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.IssuePipelineResponse{DidDocument: docB, Delegation: dlgB}), nil
}

func (h *Handler) IssueProcess(ctx context.Context, req *connect.Request[didpb.IssueProcessRequest]) (*connect.Response[didpb.IssueProcessResponse], error) {
	dlg, err := delegationFromBytes(req.Msg.GetDelegation())
	if err != nil {
		return nil, err
	}
	doc, savedDlg, err := h.svc.IssueProcess(ctx, req.Msg.GetTargetDid(), dlg)
	if err != nil {
		return nil, mapError(err)
	}
	docB, dlgB, err := issuedBytes(doc, savedDlg)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.IssueProcessResponse{DidDocument: docB, Delegation: dlgB}), nil
}

func (h *Handler) ResolveDID(ctx context.Context, req *connect.Request[didpb.ResolveDIDRequest]) (*connect.Response[didpb.ResolveDIDResponse], error) {
	doc, err := h.svc.ResolveDID(ctx, req.Msg.GetDid())
	if err != nil {
		return nil, mapError(err)
	}
	b, err := docToBytes(doc)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.ResolveDIDResponse{DidDocument: b}), nil
}

func (h *Handler) ResolveDelegation(ctx context.Context, req *connect.Request[didpb.ResolveDelegationRequest]) (*connect.Response[didpb.ResolveDelegationResponse], error) {
	dlg, err := h.svc.ResolveDelegation(ctx, req.Msg.GetDid())
	if err != nil {
		return nil, mapError(err)
	}
	b, err := delegationToBytes(dlg)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.ResolveDelegationResponse{Delegation: b}), nil
}

func (h *Handler) UpdateStatus(ctx context.Context, req *connect.Request[didpb.UpdateStatusRequest]) (*connect.Response[didpb.UpdateStatusResponse], error) {
	doc, err := h.svc.UpdateStatus(ctx, req.Msg.GetDid(), req.Msg.GetStatus())
	if err != nil {
		return nil, mapError(err)
	}
	b, err := docToBytes(doc)
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.UpdateStatusResponse{DidDocument: b}), nil
}

func (h *Handler) ListPipelines(ctx context.Context, req *connect.Request[didpb.ListPipelinesRequest]) (*connect.Response[didpb.ListPipelinesResponse], error) {
	list, err := h.svc.ListPipelines(ctx, req.Msg.GetOwnerDid())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.ListPipelinesResponse{Dids: summaryDIDs(list)}), nil
}

func (h *Handler) ListProcesses(ctx context.Context, req *connect.Request[didpb.ListProcessesRequest]) (*connect.Response[didpb.ListProcessesResponse], error) {
	list, err := h.svc.ListProcesses(ctx, req.Msg.GetPipelineDid())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&didpb.ListProcessesResponse{Dids: summaryDIDs(list)}), nil
}

func (h *Handler) ReadLifecycleLog(ctx context.Context, req *connect.Request[didpb.ReadLifecycleLogRequest]) (*connect.Response[didpb.ReadLifecycleLogResponse], error) {
	events, err := h.svc.ReadLifecycleLog(ctx, req.Msg.GetDid())
	if err != nil {
		return nil, mapError(err)
	}
	out := make([][]byte, 0, len(events))
	for _, ev := range events {
		b, err := jcs.Canonicalize(ev.CanonicalMap())
		if err != nil {
			return nil, mapError(err)
		}
		out = append(out, b)
	}
	return connect.NewResponse(&didpb.ReadLifecycleLogResponse{Events: out}), nil
}

// --- marshalling ------------------------------------------------------------

func docToBytes(doc *did.DIDDocument) ([]byte, error) {
	return json.Marshal(doc) // DIDDocument.MarshalJSON emits the JCS-canonical form
}

// docFromBytes decodes a wire DID Document. A decode failure is a malformed
// request (InvalidArgument), never an internal error.
func docFromBytes(b []byte) (*did.DIDDocument, error) {
	var doc did.DIDDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &doc, nil
}

// delegationToBytes emits the JCS-canonical form. DelegationCredential has no
// MarshalJSON, so a plain json.Marshal would emit Go struct-field order — but the
// opaque-bytes contract is canonical JSON (so a consumer can compare/hash the
// bytes), matching how DID Documents marshal. Round-trip through the strict
// decoder (UseNumber) then canonicalize.
func delegationToBytes(dlg *delegation.DelegationCredential) ([]byte, error) {
	raw, err := json.Marshal(dlg)
	if err != nil {
		return nil, err
	}
	var v any
	if err := canon.NewStrictDecoder(raw).Decode(&v); err != nil {
		return nil, err
	}
	return jcs.Canonicalize(v)
}

// delegationFromBytes decodes an inbound delegation through the strict decoder
// (RFC 8785 duplicate-key rejection, UTF-8 validation) — the protocol-boundary
// discipline: a malformed credential must fail closed as InvalidArgument, never
// be coerced past the boundary into a DID-minting call. A decode failure is a
// malformed request, not an internal error.
func delegationFromBytes(b []byte) (*delegation.DelegationCredential, error) {
	var dlg delegation.DelegationCredential
	if err := canon.NewStrictDecoder(b).Decode(&dlg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return &dlg, nil
}

func issuedBytes(doc *did.DIDDocument, dlg *delegation.DelegationCredential) (docB, dlgB []byte, err error) {
	if docB, err = docToBytes(doc); err != nil {
		return nil, nil, err
	}
	if dlgB, err = delegationToBytes(dlg); err != nil {
		return nil, nil, err
	}
	return docB, dlgB, nil
}

func summaryDIDs(list []store.DIDSummary) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, s.DID)
	}
	return out
}

// mapError translates domain sentinel errors to Connect codes (errors.Is, never
// string matching). Unrecognized errors become CodeInternal.
func mapError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrConflict):
		// A concurrent append lost the slot; the caller may retry.
		return connect.NewError(connect.CodeAborted, err)
	case errors.Is(err, didregistry.ErrUnauthorized):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, didregistry.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}
