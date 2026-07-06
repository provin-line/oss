// Package handler is the proto↔domain boundary for AuditService: it converts the
// recorded auditor.AuditRecord to the wire response and maps the read service's sentinel
// errors to Connect codes (errors.Is, never string matching). It holds no domain logic —
// validation and lookup live in the auditor.StatusService (AGENTS.md: handler = proto↔
// domain + error mapping only).
//
// Coverage projection (slice-17i D-17i-2): each audited scope is its own ScopeVerdict
// message; 17h-era records only ever evaluate the linear chain, so source_commitment is
// never emitted (its absence == not evaluated). A linear-only verdict can never be served
// as a full aggregate one.
package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/network/pkg/pagination"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

// Service is the consumer-side view of the auditor read service the handler depends on
// (defined here to keep the dependency pointing inward). *auditor.StatusService satisfies
// it: it owns content-address validation and the store lookup, returning sentinel errors.
type Service interface {
	GetStatus(ctx context.Context, headHash string) (auditor.AuditRecord, error)
	ListStatuses(ctx context.Context, fromExclusive string, scanLimit int, after, before time.Time) (entries []auditor.HeadStatus, lastScanned string, more bool, err error)
	GetConsumed(ctx context.Context, headHash, fromExclusive string, limit int) (page []string, next string, err error)
}

// Listing identities binding continuation tokens to their issuing RPC (see
// pagination.EncodeToken).
const (
	listingAuditStatuses   = "dplaax.audit.v1.AuditService.ListAuditStatuses"
	listingConsumedSources = "dplaax.audit.v1.AuditService.GetConsumedSources"
)

// Handler adapts a Service to the generated AuditServiceHandler.
type Handler struct {
	svc Service
}

var _ auditpbconnect.AuditServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc.
func New(svc Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) GetAuditStatus(ctx context.Context, req *connect.Request[auditpb.GetAuditStatusRequest]) (*connect.Response[auditpb.GetAuditStatusResponse], error) {
	rec, err := h.svc.GetStatus(ctx, req.Msg.GetHeadHash())
	if err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(statusResponse(rec)), nil
}

// statusResponse projects one recorded verdict to the wire shape — shared by
// the point lookup and the listing (one source of truth for the coverage
// projection).
func statusResponse(rec auditor.AuditRecord) *auditpb.GetAuditStatusResponse {
	resp := &auditpb.GetAuditStatusResponse{
		AuditedAt: rec.AuditedAt.UTC().Format(time.RFC3339),
		// Lifecycle, not confidence: true == the runner exhausted its retries and
		// dropped the head; the per-scope verdicts below are what is final.
		Abandoned: rec.Abandoned,
	}
	// linear_chain is present whenever the spine was verified. The runner always records
	// a recorded audit with Scope.LinearChain true (it walks head→origin before
	// VerifyChain), so this field is in practice always present — an empty response is
	// structurally unreachable. Overall is, in the 17h era, exactly the linear verdict.
	if rec.Scope.LinearChain {
		resp.LinearChain = &auditpb.ScopeVerdict{
			Confidence: confidence(rec.Overall),
			Axes: &auditpb.AxisVerdict{
				DataIntegrity:      confidence(rec.Axes.DataIntegrity),
				SignerAuthenticity: confidence(rec.Axes.SignerAuthenticity),
				ChainConsistency:   confidence(rec.Axes.ChainConsistency),
			},
			Notations: rec.Notations,
		}
	}
	// source_commitment is emitted ONLY when the consumed-set was actually evaluated
	// (slice-17o): its presence IS the coverage signal (17i D-17i-2), and the confidence maps
	// the DISTINCT domain field (never Overall — that is the linear verdict). No axes:
	// VerifySourceCommitment yields a single state outside the three axes. When the flag is
	// false (17h-era or a downstream linear-only audit) the field stays absent.
	if rec.Scope.SourceCommitmentEvaluated {
		resp.SourceCommitment = &auditpb.ScopeVerdict{
			Confidence: confidence(rec.SourceCommitment),
			Notations:  rec.SourceCommitmentNotations,
		}
	}
	return resp
}

// ListAuditStatuses enumerates recorded verdicts: pagination per the repo
// convention (network/pkg/pagination — scan-progress cursor carrying a
// filter fingerprint), time filters parsed here (wire strings), projection
// shared with the point lookup.
func (h *Handler) ListAuditStatuses(ctx context.Context, req *connect.Request[auditpb.ListAuditStatusesRequest]) (*connect.Response[auditpb.ListAuditStatusesResponse], error) {
	if err := ctx.Err(); err != nil {
		return nil, mapError(err)
	}
	limit, err := pagination.ClampSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	filters := []string{req.Msg.GetAuditedAfter(), req.Msg.GetAuditedBefore()}
	cursor, err := pagination.DecodeToken(listingAuditStatuses, req.Msg.GetPageToken(), filters...)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	after, err := parseBound(req.Msg.GetAuditedAfter(), "audited_after")
	if err != nil {
		return nil, err
	}
	before, err := parseBound(req.Msg.GetAuditedBefore(), "audited_before")
	if err != nil {
		return nil, err
	}
	entries, lastScanned, more, err := h.svc.ListStatuses(ctx, cursor, limit, after, before)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &auditpb.ListAuditStatusesResponse{}
	for _, e := range entries {
		entry := &auditpb.AuditStatusEntry{HeadHash: e.Head, Damaged: e.Damaged}
		if !e.Damaged {
			entry.Status = statusResponse(e.Record)
		}
		resp.Entries = append(resp.Entries, entry)
	}
	if more {
		resp.NextPageToken = pagination.EncodeToken(listingAuditStatuses, lastScanned, filters...)
	}
	return connect.NewResponse(resp), nil
}

// GetConsumedSources serves one page of a head's receipt. The head hash
// participates in the token fingerprint: a continuation replayed against a
// different head is InvalidArgument, never a silent cross-head listing.
func (h *Handler) GetConsumedSources(ctx context.Context, req *connect.Request[auditpb.GetConsumedSourcesRequest]) (*connect.Response[auditpb.GetConsumedSourcesResponse], error) {
	if err := ctx.Err(); err != nil {
		return nil, mapError(err)
	}
	limit, err := pagination.ClampSize(req.Msg.GetPageSize())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	cursor, err := pagination.DecodeToken(listingConsumedSources, req.Msg.GetPageToken(), req.Msg.GetHeadHash())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	page, next, err := h.svc.GetConsumed(ctx, req.Msg.GetHeadHash(), cursor, limit)
	if err != nil {
		return nil, mapError(err)
	}
	resp := &auditpb.GetConsumedSourcesResponse{Consumed: page}
	if next != "" {
		resp.NextPageToken = pagination.EncodeToken(listingConsumedSources, next, req.Msg.GetHeadHash())
	}
	return connect.NewResponse(resp), nil
}

// parseBound parses an optional RFC 3339 filter bound; empty is open.
func parseBound(raw, field string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%s %q is not an RFC 3339 timestamp: %w", field, raw, err))
	}
	return ts, nil
}

// mapError translates the read service's sentinel errors to Connect codes. Unrecognized
// errors become CodeInternal.
func mapError(err error) error {
	switch {
	case errors.Is(err, auditor.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, auditor.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
}

// confidence maps the domain three-state (vc.ConfidenceState, Failed=0/Indeterminate=1/
// Verified=2) to the wire enum (UNSPECIFIED=0/FAILED=1/INDETERMINATE=2/VERIFIED=3) with an
// explicit +1 shift — NEVER an int cast, which would map the domain's fail-closed zero
// (Failed) onto the proto's UNSPECIFIED. The default is the unreachable out-of-range sink
// and resolves to UNSPECIFIED (the weakest/fail-closed value), so a bad value can never
// surface as a positive verdict.
func confidence(c vc.ConfidenceState) auditpb.Confidence {
	switch c {
	case vc.ConfidenceFailed:
		return auditpb.Confidence_CONFIDENCE_FAILED
	case vc.ConfidenceIndeterminate:
		return auditpb.Confidence_CONFIDENCE_INDETERMINATE
	case vc.ConfidenceVerified:
		return auditpb.Confidence_CONFIDENCE_VERIFIED
	default:
		return auditpb.Confidence_CONFIDENCE_UNSPECIFIED
	}
}
