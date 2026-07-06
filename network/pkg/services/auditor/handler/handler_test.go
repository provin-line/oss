package handler_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/network/pkg/pagination"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/vc"
)

// fakeService is a handler.Service returning a fixed (record, error). It stands in for
// auditor.StatusService so the handler test exercises only proto↔domain projection and
// error mapping — the validation/lookup logic is the service's own test.
type fakeService struct {
	rec         auditor.AuditRecord
	err         error
	entries     []auditor.HeadStatus
	lastScanned string
	more        bool
	consumed    []string
	next        string
}

func (f fakeService) GetStatus(context.Context, string) (auditor.AuditRecord, error) {
	return f.rec, f.err
}

func (f fakeService) ListStatuses(context.Context, string, int, time.Time, time.Time) ([]auditor.HeadStatus, string, bool, error) {
	if f.err != nil {
		return nil, "", false, f.err
	}
	return f.entries, f.lastScanned, f.more, nil
}

func (f fakeService) GetConsumed(context.Context, string, string, int) ([]string, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	return f.consumed, f.next, nil
}

func get(t *testing.T, svc handler.Service) (*auditpb.GetAuditStatusResponse, error) {
	t.Helper()
	h := handler.New(svc)
	resp, err := h.GetAuditStatus(context.Background(), connect.NewRequest(&auditpb.GetAuditStatusRequest{HeadHash: "sha256:whatever"}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// A real linear-chain verdict projects verbatim: the three-state Overall/Axes (with the
// Failed→FAILED(1) shift), notations, RFC3339 audited_at, and — because 17h-era records
// never set SourceCommitmentEvaluated — source_commitment is ABSENT (presence == coverage).
func TestGetAuditStatus_LinearVerdictProjection(t *testing.T) {
	rec := auditor.AuditRecord{
		Overall: vc.ConfidenceVerified,
		Axes: vc.AxisResult{
			DataIntegrity:      vc.ConfidenceVerified,
			SignerAuthenticity: vc.ConfidenceIndeterminate,
			ChainConsistency:   vc.ConfidenceFailed,
		},
		Notations: []string{"deprecated-cryptosuite"},
		Scope:     auditor.AuditScope{LinearChain: true, SourceCommitmentEvaluated: false},
		AuditedAt: time.Date(2023, 11, 14, 22, 13, 20, 500_000_000, time.UTC),
	}

	msg, err := get(t, fakeService{rec: rec})
	if err != nil {
		t.Fatalf("GetAuditStatus: %v", err)
	}

	lc := msg.GetLinearChain()
	if lc == nil {
		t.Fatal("linear_chain is nil, want present")
	}
	if lc.GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Errorf("linear_chain.confidence = %v, want VERIFIED", lc.GetConfidence())
	}
	if got, want := lc.GetAxes().GetDataIntegrity(), auditpb.Confidence_CONFIDENCE_VERIFIED; got != want {
		t.Errorf("axes.data_integrity = %v, want %v", got, want)
	}
	if got, want := lc.GetAxes().GetSignerAuthenticity(), auditpb.Confidence_CONFIDENCE_INDETERMINATE; got != want {
		t.Errorf("axes.signer_authenticity = %v, want %v", got, want)
	}
	// The load-bearing off-by-one: domain Failed (0) must map to FAILED (1), never to
	// the proto zero UNSPECIFIED (0).
	if got, want := lc.GetAxes().GetChainConsistency(), auditpb.Confidence_CONFIDENCE_FAILED; got != want {
		t.Errorf("axes.chain_consistency = %v, want FAILED (not UNSPECIFIED)", got)
	}
	if got := lc.GetNotations(); len(got) != 1 || got[0] != "deprecated-cryptosuite" {
		t.Errorf("notations = %v, want [deprecated-cryptosuite]", got)
	}
	if got, want := msg.GetAuditedAt(), "2023-11-14T22:13:20Z"; got != want {
		t.Errorf("audited_at = %q, want %q (RFC3339 UTC, second precision)", got, want)
	}
	// Coverage: linear-only record ⇒ source_commitment absent (the FCoT-#3 invariant).
	if msg.GetSourceCommitment() != nil {
		t.Errorf("source_commitment = %+v, want nil (SourceCommitmentEvaluated false)", msg.GetSourceCommitment())
	}
}

// An evaluated aggregate record (slice-17o) emits the source_commitment ScopeVerdict:
// confidence from the DISTINCT domain field (not Overall), its own per-scope notations, and
// no axes (VerifySourceCommitment yields a single state outside the three axes, 17i D-17i-2).
func TestGetAuditStatus_SourceCommitmentEmittedWhenEvaluated(t *testing.T) {
	rec := auditor.AuditRecord{
		Overall:                   vc.ConfidenceVerified, // linear
		Axes:                      vc.AxisResult{DataIntegrity: vc.ConfidenceVerified},
		Notations:                 []string{"linear-note"},
		SourceCommitment:          vc.ConfidenceIndeterminate, // DISTINCT from Overall
		SourceCommitmentNotations: []string{"source-commitment: self-audit (emit locus): 1/2 consumed sources resolved"},
		Scope:                     auditor.AuditScope{LinearChain: true, SourceCommitmentEvaluated: true},
		AuditedAt:                 time.Unix(0, 0).UTC(),
	}
	msg, err := get(t, fakeService{rec: rec})
	if err != nil {
		t.Fatalf("GetAuditStatus: %v", err)
	}
	sc := msg.GetSourceCommitment()
	if sc == nil {
		t.Fatal("source_commitment is nil, want present (SourceCommitmentEvaluated true)")
	}
	// The distinct field, NOT Overall: Indeterminate → INDETERMINATE, while linear is VERIFIED.
	if sc.GetConfidence() != auditpb.Confidence_CONFIDENCE_INDETERMINATE {
		t.Errorf("source_commitment.confidence = %v, want INDETERMINATE (the distinct field)", sc.GetConfidence())
	}
	if msg.GetLinearChain().GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Error("linear_chain.confidence must stay VERIFIED (distinct from source_commitment)")
	}
	if got := sc.GetNotations(); len(got) != 1 || got[0] != rec.SourceCommitmentNotations[0] {
		t.Errorf("source_commitment.notations = %v, want the per-scope note", got)
	}
	if sc.GetAxes() != nil {
		t.Errorf("source_commitment.axes = %+v, want nil (single-state verdict, no axes)", sc.GetAxes())
	}
	// A live (non-abandoned) record serves abandoned=false.
	if msg.GetAbandoned() {
		t.Error("abandoned = true for a live record, want false")
	}
}

// The abandon lifecycle marker is served on the wire: a consumer polling an
// Indeterminate can tell "the runner gave up" from "still being retried".
func TestGetAuditStatus_AbandonedServed(t *testing.T) {
	i := vc.ConfidenceIndeterminate
	rec := auditor.AuditRecord{
		Overall:   i,
		Axes:      vc.AxisResult{DataIntegrity: i, SignerAuthenticity: i, ChainConsistency: i},
		Notations: []string{"audit abandoned: exhausted 3 attempts (non-hole verify error)"},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Unix(0, 0).UTC(),
		Abandoned: true,
	}
	msg, err := get(t, fakeService{rec: rec})
	if err != nil {
		t.Fatalf("GetAuditStatus: %v", err)
	}
	if !msg.GetAbandoned() {
		t.Error("abandoned = false, want true")
	}
	// The verdict itself stays Indeterminate — abandoned is lifecycle, not confidence.
	if msg.GetLinearChain().GetConfidence() != auditpb.Confidence_CONFIDENCE_INDETERMINATE {
		t.Errorf("linear_chain.confidence = %v, want INDETERMINATE", msg.GetLinearChain().GetConfidence())
	}
}

// Each domain three-state maps to its proto counterpart with the +1 shift.
func TestGetAuditStatus_ConfidenceMapping(t *testing.T) {
	cases := []struct {
		in   vc.ConfidenceState
		want auditpb.Confidence
	}{
		{vc.ConfidenceFailed, auditpb.Confidence_CONFIDENCE_FAILED},
		{vc.ConfidenceIndeterminate, auditpb.Confidence_CONFIDENCE_INDETERMINATE},
		{vc.ConfidenceVerified, auditpb.Confidence_CONFIDENCE_VERIFIED},
	}
	for _, c := range cases {
		msg, err := get(t, fakeService{rec: auditor.AuditRecord{Overall: c.in, Scope: auditor.AuditScope{LinearChain: true}}})
		if err != nil {
			t.Fatalf("Overall=%v: %v", c.in, err)
		}
		if got := msg.GetLinearChain().GetConfidence(); got != c.want {
			t.Errorf("Overall %v → %v, want %v", c.in, got, c.want)
		}
	}
}

// The handler maps the service's sentinel errors to Connect codes (errors.Is), holding no
// validation logic of its own.
func TestGetAuditStatus_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"invalid argument", fmt.Errorf("%w: bad", auditor.ErrInvalidArgument), connect.CodeInvalidArgument},
		{"not found", fmt.Errorf("%w: absent", auditor.ErrNotFound), connect.CodeNotFound},
		{"unknown", fmt.Errorf("boom"), connect.CodeInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := get(t, fakeService{err: c.err})
			if connect.CodeOf(err) != c.want {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), c.want)
			}
		})
	}
}

// The listing projects each intact entry through the SAME status projection
// as the point lookup, marks damaged entries without a status, and issues a
// continuation token only when the scan has more.
func TestListAuditStatuses_ProjectionAndToken(t *testing.T) {
	rec := auditor.AuditRecord{
		Overall:   vc.ConfidenceVerified,
		Axes:      vc.AxisResult{DataIntegrity: vc.ConfidenceVerified, SignerAuthenticity: vc.ConfidenceVerified, ChainConsistency: vc.ConfidenceVerified},
		Scope:     auditor.AuditScope{LinearChain: true},
		AuditedAt: time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC),
	}
	h := handler.New(fakeService{
		entries: []auditor.HeadStatus{
			{Head: "sha256:" + strings.Repeat("aa", 32), Record: rec},
			{Head: "sha256:" + strings.Repeat("bb", 32), Damaged: true},
		},
		lastScanned: "sha256:" + strings.Repeat("bb", 32),
		more:        true,
	})
	resp, err := h.ListAuditStatuses(context.Background(), connect.NewRequest(&auditpb.ListAuditStatusesRequest{}))
	if err != nil {
		t.Fatalf("ListAuditStatuses: %v", err)
	}
	entries := resp.Msg.GetEntries()
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].GetDamaged() || entries[0].GetStatus().GetLinearChain().GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Errorf("intact entry projected wrong: %+v", entries[0])
	}
	if !entries[1].GetDamaged() || entries[1].GetStatus() != nil {
		t.Errorf("damaged entry must carry damaged=true and NO status: %+v", entries[1])
	}
	tok := resp.Msg.GetNextPageToken()
	if tok == "" {
		t.Fatal("more=true must issue a continuation token")
	}
	// The token round-trips only with the SAME filters.
	if _, err := pagination.DecodeToken("dplaax.audit.v1.AuditService.ListAuditStatuses", tok, "", ""); err != nil {
		t.Errorf("token does not decode with the issuing filters: %v", err)
	}
	if _, err := pagination.DecodeToken("dplaax.audit.v1.AuditService.ListAuditStatuses", tok, "2026-01-01T00:00:00Z", ""); err == nil {
		t.Error("token decoded with different filters — cross-filter replay must be rejected")
	}
}

func TestListAuditStatuses_InvalidInputs(t *testing.T) {
	h := handler.New(fakeService{})
	cases := []*auditpb.ListAuditStatusesRequest{
		{PageSize: -1},
		{PageToken: "garbage!!!"},
		{AuditedAfter: "yesterday-ish"},
		{AuditedBefore: "2026-13-99"},
	}
	for _, req := range cases {
		_, err := h.ListAuditStatuses(context.Background(), connect.NewRequest(req))
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("req %+v: code = %v, want InvalidArgument", req, connect.CodeOf(err))
		}
	}
}

func TestGetConsumedSources_PageAndErrors(t *testing.T) {
	head := "sha256:" + strings.Repeat("cc", 32)
	consumed := []string{"sha256:" + strings.Repeat("11", 32), "sha256:" + strings.Repeat("22", 32)}
	h := handler.New(fakeService{consumed: consumed, next: consumed[1]})
	resp, err := h.GetConsumedSources(context.Background(), connect.NewRequest(&auditpb.GetConsumedSourcesRequest{HeadHash: head}))
	if err != nil {
		t.Fatalf("GetConsumedSources: %v", err)
	}
	if got := resp.Msg.GetConsumed(); len(got) != 2 || got[0] != consumed[0] {
		t.Fatalf("consumed = %v, want %v", got, consumed)
	}
	tok := resp.Msg.GetNextPageToken()
	if tok == "" {
		t.Fatal("non-empty next cursor must issue a token")
	}
	// The head hash is part of the token fingerprint: replay against another
	// head must be rejected, never silently list the wrong receipt.
	if _, err := pagination.DecodeToken("dplaax.audit.v1.AuditService.GetConsumedSources", tok, head); err != nil {
		t.Errorf("token does not decode for its own head: %v", err)
	}
	if _, err := pagination.DecodeToken("dplaax.audit.v1.AuditService.GetConsumedSources", tok, "sha256:"+strings.Repeat("dd", 32)); err == nil {
		t.Error("token decoded for a different head — cross-head replay must be rejected")
	}

	// Sentinel mapping flows through the shared mapError.
	notFound := handler.New(fakeService{err: fmt.Errorf("wrap: %w", auditor.ErrNotFound)})
	if _, err := notFound.GetConsumedSources(context.Background(), connect.NewRequest(&auditpb.GetConsumedSourcesRequest{HeadHash: head})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("no receipt: code = %v, want NotFound", connect.CodeOf(err))
	}
	damaged := handler.New(fakeService{err: errors.New("damaged receipt")})
	if _, err := damaged.GetConsumedSources(context.Background(), connect.NewRequest(&auditpb.GetConsumedSourcesRequest{HeadHash: head})); connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("damaged receipt: code = %v, want Internal", connect.CodeOf(err))
	}
}
