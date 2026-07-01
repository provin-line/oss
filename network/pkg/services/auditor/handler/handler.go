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
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/vc"
)

// Service is the consumer-side view of the auditor read service the handler depends on
// (defined here to keep the dependency pointing inward). *auditor.StatusService satisfies
// it: it owns content-address validation and the store lookup, returning sentinel errors.
type Service interface {
	GetStatus(ctx context.Context, headHash string) (auditor.AuditRecord, error)
}

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

	resp := &auditpb.GetAuditStatusResponse{
		AuditedAt: rec.AuditedAt.UTC().Format(time.RFC3339),
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

	return connect.NewResponse(resp), nil
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
