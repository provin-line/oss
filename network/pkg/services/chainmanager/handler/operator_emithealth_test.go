package handler_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

const ttl90s = 90 * time.Second

// spyEmitHealth is a handler.EmitHealthReporter spy: it records whether Report
// was called and the exact arguments it was handed.
type spyEmitHealth struct {
	called          bool
	gotPublisherDID string
	gotHealthy      bool
	gotAt           time.Time
}

func (s *spyEmitHealth) Report(publisherDID string, healthy bool, now time.Time) {
	s.called = true
	s.gotPublisherDID = publisherDID
	s.gotHealthy = healthy
	s.gotAt = now
}

// TestOperatorHandler_ReportEmitHealth_VerifyContract pins the wireauth view:
// the op name and the exact fields (publisher_did verbatim, healthy encoded
// as the literal string "true") the handler signs the proof against, plus the
// TTL round trip and the Report() call it gates.
func TestOperatorHandler_ReportEmitHealth_VerifyContract(t *testing.T) {
	v := &spyVerifier{}
	reporter := &spyEmitHealth{}
	h := handler.NewOperator(nil, handler.WithEmitHealth(reporter, v, ttl90s))
	pub := "did:dplaax:reg:org:acme:pipeline:p1"

	resp, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: pub,
		Healthy:      true,
		AuthProof:    proofMsg(pub, goodIssuedAt),
	}))
	if err != nil {
		t.Fatalf("ReportEmitHealth: %v", err)
	}
	if !v.called || v.gotOp != chainmanager.OpReportEmitHealth {
		t.Errorf("verify op = %q, called=%v, want %q", v.gotOp, v.called, chainmanager.OpReportEmitHealth)
	}
	wantFields := map[string]any{"publisher_did": pub, "healthy": "true"}
	if !reflect.DeepEqual(v.gotFields, wantFields) {
		t.Errorf("fields = %+v, want %+v", v.gotFields, wantFields)
	}
	if !reporter.called || reporter.gotPublisherDID != pub || !reporter.gotHealthy {
		t.Errorf("reporter = %+v, want called with (%q, true)", reporter, pub)
	}
	if got := resp.Msg.GetTtl().AsDuration(); got != ttl90s {
		t.Errorf("ttl = %v, want %v", got, ttl90s)
	}
}

// healthy=false must encode as the string "false" — not a Go bool, not "0" —
// the deterministic encoding chainmanager.ReportEmitHealthFields documents.
func TestOperatorHandler_ReportEmitHealth_HealthyFalseFieldEncoding(t *testing.T) {
	v := &spyVerifier{}
	reporter := &spyEmitHealth{}
	h := handler.NewOperator(nil, handler.WithEmitHealth(reporter, v, ttl90s))
	pub := "did:dplaax:reg:org:acme:pipeline:p1"

	if _, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: pub,
		Healthy:      false,
		AuthProof:    proofMsg(pub, goodIssuedAt),
	})); err != nil {
		t.Fatalf("ReportEmitHealth: %v", err)
	}
	if got := v.gotFields["healthy"]; got != "false" {
		t.Errorf("healthy field = %#v, want the string \"false\"", got)
	}
	if reporter.gotHealthy {
		t.Error("reporter recorded healthy=true, want false")
	}
}

// The proto's own contract: publisher_did MUST equal the wireauth-proven
// signer DID. A mismatched signer is rejected as PermissionDenied and Report
// is never called.
func TestOperatorHandler_ReportEmitHealth_PublisherMismatch(t *testing.T) {
	v := &spyVerifier{runAuth: true}
	reporter := &spyEmitHealth{}
	h := handler.NewOperator(nil, handler.WithEmitHealth(reporter, v, ttl90s))

	_, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
		Healthy:      true,
		AuthProof:    proofMsg("did:dplaax:reg:org:other:pipeline:p2", goodIssuedAt), // signer != publisher_did
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if reporter.called {
		t.Error("Report must not be called when the publisher_did binding fails")
	}
}

// Without WithEmitHealth the RPC reports Unimplemented — the deferral is
// explicit, never an accidental silent success (production always wires it
// on cmd/network).
func TestOperatorHandler_ReportEmitHealth_UnwiredUnimplemented(t *testing.T) {
	h := handler.NewOperator(nil) // no WithEmitHealth
	pub := "did:dplaax:reg:org:acme:pipeline:p1"
	_, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: pub,
		Healthy:      true,
		AuthProof:    proofMsg(pub, goodIssuedAt),
	}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("code = %v, want Unimplemented", connect.CodeOf(err))
	}
}

func TestOperatorHandler_ReportEmitHealth_MissingAuthProof(t *testing.T) {
	v := &spyVerifier{}
	reporter := &spyEmitHealth{}
	h := handler.NewOperator(nil, handler.WithEmitHealth(reporter, v, ttl90s))
	_, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
		PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
		Healthy:      true,
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
	if reporter.called {
		t.Error("Report must not be called without a proof")
	}
}

// Wireauth verification failures map to the same codes as the peer surface
// (mirrors TestPeerHandler's own verify-failure mapping tests).
func TestOperatorHandler_ReportEmitHealth_VerifyFailure_Mapped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"expired", wireauth.ErrExpired, connect.CodeUnauthenticated},
		{"from future", wireauth.ErrFromFuture, connect.CodeUnauthenticated},
		{"signature invalid", wireauth.ErrSignatureInvalid, connect.CodeUnauthenticated},
		{"replay", wireauth.ErrReplay, connect.CodeUnauthenticated},
		{"resolver unavailable", wireauth.ErrResolverUnavailable, connect.CodeUnavailable},
		// ErrBeforeEpoch is a boot-window rejection, not an identity verdict:
		// an honest re-signed retry clears it once the verifier is past its
		// restart epoch, so it maps to Unavailable (retryable), NOT
		// Unauthenticated.
		{"before epoch", wireauth.ErrBeforeEpoch, connect.CodeUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &spyVerifier{err: c.err}
			reporter := &spyEmitHealth{}
			h := handler.NewOperator(nil, handler.WithEmitHealth(reporter, v, ttl90s))
			pub := "did:dplaax:reg:org:acme:pipeline:p1"
			_, err := h.ReportEmitHealth(context.Background(), connect.NewRequest(&chainpb.ReportEmitHealthRequest{
				PublisherDid: pub,
				Healthy:      true,
				AuthProof:    proofMsg(pub, goodIssuedAt),
			}))
			if connect.CodeOf(err) != c.want {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), c.want)
			}
			if reporter.called {
				t.Error("Report must not be called when verification fails")
			}
		})
	}
}
