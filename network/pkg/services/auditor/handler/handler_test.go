package handler_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/vc"
)

// fakeService is a handler.Service returning a fixed (record, error). It stands in for
// auditor.StatusService so the handler test exercises only proto↔domain projection and
// error mapping — the validation/lookup logic is the service's own test.
type fakeService struct {
	rec auditor.AuditRecord
	err error
}

func (f fakeService) GetStatus(context.Context, string) (auditor.AuditRecord, error) {
	return f.rec, f.err
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
