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
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
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

// EvidenceRegistrar is the consumer-side view of the auditor write-path
// service the handler depends on for BOTH evidence-write RPCs (defined here
// to keep the dependency pointing inward). *auditor.EvidenceService
// satisfies it: Register is RegisterEvidence's delegate (receipt-bearing —
// see its own doc for the consumed-set receipt it writes) and RegisterHead
// is RegisterAuditHead's delegate (receiptless — Register minus the receipt
// leg, sharing the same admission gate and queue; see
// EvidenceService.RegisterHead's own doc). headVariantID in both is the
// wire variant id the respective request's head_variant_address field
// carries (P1-A) — the service resolves it to a body address internally;
// this handler never sees that address. registrantDID (Register only) is
// the wireauth-proven caller DID (the proof's SignerDID, verified by h.v
// before Register is ever called) that gets recorded with the receipt;
// RegisterHead records no registrant — it writes no receipt to attribute.
type EvidenceRegistrar interface {
	Register(ctx context.Context, headVariantID string, consumed []string, registrantDID string) error
	RegisterHead(ctx context.Context, headVariantID string) error
}

// Verifier is the wireauth verification seam (an interface so a spy can be
// injected in tests). *wireauth.Verifier satisfies it.
type Verifier interface {
	Verify(ctx context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error
}

// Handler adapts a Service and an EvidenceRegistrar to the generated
// AuditServiceHandler. Every method is implemented explicitly (no
// Unimplemented embedding): both RegisterEvidence and RegisterAuditHead
// verify the caller's L2 wireauth proof in-band (mirrors
// payloadresolver/handler exactly) before delegating to the write-path
// service — RegisterEvidence to its receipt-bearing Register, RegisterAuditHead
// to its receiptless RegisterHead.
type Handler struct {
	svc      Service
	evidence EvidenceRegistrar
	v        Verifier
}

var _ auditpbconnect.AuditServiceHandler = (*Handler)(nil)

// New returns a Handler backed by svc (the read service), evidence (the
// write-path service both RegisterEvidence and RegisterAuditHead delegate
// to), and v (the wireauth verifier both RPCs check the caller's proof
// against).
func New(svc Service, evidence EvidenceRegistrar, v Verifier) *Handler {
	return &Handler{svc: svc, evidence: evidence, v: v}
}

// RegisterEvidence verifies the L2 wireauth proof over the head variant id
// plus the CANONICALIZED consumed-source set (sorted, deduplicated —
// canonicalized BEFORE the signed view is built, so the proof covers the
// canonical set: a caller resubmitting the same set in a different order
// signs and verifies identically), then delegates the atomic
// receipt+enqueue to the evidence-registration service. Canonicalization runs
// before Verify — a malformed consumed set is a structural request defect,
// same posture as the issued_at codec, checked before any signature work.
func (h *Handler) RegisterEvidence(ctx context.Context, req *connect.Request[auditpb.RegisterEvidenceRequest]) (*connect.Response[auditpb.RegisterEvidenceResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}
	canonical, err := auditor.CanonicalizeConsumedSet(req.Msg.GetConsumedSourceAddresses())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	fields := auditor.RegisterEvidenceFields(req.Msg.GetHeadVariantAddress(), canonical)
	// No separate actor field: the proven signer_did is who gets recorded as
	// the registering party (the querying actor IS the signer, nil authorizer).
	if err := h.v.Verify(ctx, auditor.OpRegisterEvidence, fields, proof, nil); err != nil {
		return nil, mapError(err)
	}
	if err := h.evidence.Register(ctx, req.Msg.GetHeadVariantAddress(), canonical, proof.SignerDID); err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&auditpb.RegisterEvidenceResponse{}), nil
}

// RegisterAuditHead verifies the L2 wireauth proof over head_variant_address
// — RegisterEvidence's exact proof-then-delegate shape, minus the consumed
// set this RPC never carries (auditor.RegisterAuditHeadFields signs only
// head_variant_address) — then delegates to the SAME write-path service's
// receiptless RegisterHead (contrast RegisterEvidence, which delegates to
// Register; see EvidenceRegistrar's own doc for how the two differ).
func (h *Handler) RegisterAuditHead(ctx context.Context, req *connect.Request[auditpb.RegisterAuditHeadRequest]) (*connect.Response[auditpb.RegisterAuditHeadResponse], error) {
	proof, err := decodeProof(req.Msg.GetAuthProof())
	if err != nil {
		return nil, mapError(err)
	}
	fields := auditor.RegisterAuditHeadFields(req.Msg.GetHeadVariantAddress())
	// No separate actor field, same posture as RegisterEvidence: the
	// querying actor IS the proven signer, nil authorizer.
	if err := h.v.Verify(ctx, auditor.OpRegisterAuditHead, fields, proof, nil); err != nil {
		return nil, mapError(err)
	}
	if err := h.evidence.RegisterHead(ctx, req.Msg.GetHeadVariantAddress()); err != nil {
		return nil, mapError(err)
	}
	return connect.NewResponse(&auditpb.RegisterAuditHeadResponse{}), nil
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
	//
	// Unresolvable overrides EVERY confidence in this scope (overall + all three axes) to
	// CONFIDENCE_UNRESOLVABLE: chain assembly never obtained the head's own content, so
	// none of Overall/Axes were ever a real verification outcome (they hold their
	// synthesized Indeterminate — projecting that verbatim would misrepresent a resolution
	// failure as an inconclusive verification). Never applies to source_commitment below:
	// an unresolved head never reaches VerifyChain, so SourceCommitmentEvaluated is always
	// false here and that scope stays absent regardless.
	if rec.Scope.LinearChain {
		resp.LinearChain = &auditpb.ScopeVerdict{
			Confidence: projectedConfidence(rec.Overall, rec.Unresolvable),
			Axes: &auditpb.AxisVerdict{
				DataIntegrity:      projectedConfidence(rec.Axes.DataIntegrity, rec.Unresolvable),
				SignerAuthenticity: projectedConfidence(rec.Axes.SignerAuthenticity, rec.Unresolvable),
				ChainConsistency:   projectedConfidence(rec.Axes.ChainConsistency, rec.Unresolvable),
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

// mapError translates the read service's, the evidence service's, and
// RegisterEvidence's wireauth sentinel errors to Connect codes (errors.Is,
// never string matching). Unrecognized errors become CodeInternal.
func mapError(err error) error {
	switch {
	// Malformed request / proof shape (RegisterEvidence's codec + wireauth).
	case errors.Is(err, errMalformedIssuedAt),
		errors.Is(err, wireauth.ErrMissingProof),
		errors.Is(err, wireauth.ErrMalformedProof),
		errors.Is(err, wireauth.ErrInvalidView):
		return connect.NewError(connect.CodeInvalidArgument, err)
	// Inbound caller hung up mid-verification: CodeCanceled, not a server-side
	// "unavailable". Precedes ErrResolverUnavailable, which the cancellation
	// also wraps — order decides the mapping.
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	// Transient resolver condition (timeout/capacity): retryable, NOT an
	// identity rejection. Must precede the Unauthenticated cases — the error
	// also wraps ErrResolverUnavailable, and order decides the mapping.
	case errors.Is(err, wireauth.ErrResolverUnavailable):
		return connect.NewError(connect.CodeUnavailable, err)
	// Failed to prove identity (RegisterEvidence's wireauth verification).
	case errors.Is(err, wireauth.ErrExpired),
		errors.Is(err, wireauth.ErrFromFuture),
		errors.Is(err, wireauth.ErrBeforeEpoch),
		errors.Is(err, wireauth.ErrKeyResolution),
		errors.Is(err, wireauth.ErrSignatureInvalid),
		errors.Is(err, wireauth.ErrReplay):
		return connect.NewError(connect.CodeUnauthenticated, err)
	// The head variant address is not (yet) admitted in the local VC store —
	// the arbitrary-hash amplification guard (D1).
	case errors.Is(err, auditor.ErrHeadNotAdmitted):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	// A recorded receipt already pins a DIFFERENT canonical consumed set for
	// this head — the set never silently changes.
	case errors.Is(err, auditor.ErrReceiptConflict):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, auditor.ErrInvalidArgument):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, auditor.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
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

// projectedConfidence wraps confidence() with the ONE override that lives
// outside the vc.ConfidenceState domain: when unresolvable is true (chain
// assembly could not resolve the head's own chain after max retries — a
// RESOLUTION outcome), it returns CONFIDENCE_UNRESOLVABLE regardless of c,
// never the domain mapping. c is otherwise whatever synthesized
// vc.ConfidenceState the record carries (always Indeterminate in practice —
// a resolution failure never computes a real verification outcome), so
// confidence(c) is deliberately NOT called in that branch: c never held a
// meaningful verification result to project.
func projectedConfidence(c vc.ConfidenceState, unresolvable bool) auditpb.Confidence {
	if unresolvable {
		return auditpb.Confidence_CONFIDENCE_UNRESOLVABLE
	}
	return confidence(c)
}
