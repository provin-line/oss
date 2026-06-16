package handler_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// spyVerifier records the (op, fields, proof) the handler passes and, optionally,
// runs the authorizer or returns a preset error — letting the handler tests pin
// the D-p4 view contract, the "handler actually calls Verify" contract (slice-9
// D-c1), and the authorizer binding without a real signature.
type spyVerifier struct {
	called    bool
	gotOp     string
	gotFields map[string]any
	gotProof  wireauth.Proof
	err       error // returned from Verify (simulating a wireauth failure)
	runAuth   bool  // invoke the authorizer with gotProof.SignerDID
}

func (s *spyVerifier) Verify(_ context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error {
	s.called = true
	s.gotOp, s.gotFields, s.gotProof = op, fields, proof
	if s.err != nil {
		return s.err
	}
	if s.runAuth && authorize != nil {
		return authorize(proof.SignerDID, nil, fields)
	}
	return nil
}

// fakePeer records which domain method was called and returns preset values.
type fakePeer struct {
	publisherInfo, register, disconnect bool
	pubType                             string
	modes                               []string
	sub                                 *store.Subscription
	err                                 error
}

func (f *fakePeer) PublisherInfo(_ context.Context, _, _ string) (string, []string, error) {
	f.publisherInfo = true
	return f.pubType, f.modes, f.err
}
func (f *fakePeer) RegisterSubscription(_ context.Context, _, _, _ string) (*store.Subscription, error) {
	f.register = true
	return f.sub, f.err
}
func (f *fakePeer) Disconnect(_ context.Context, _, _ string) error {
	f.disconnect = true
	return f.err
}

const goodIssuedAt = "2026-06-17T12:00:00Z"

func proofMsg(signer, issuedAt string) *chainpb.AuthProof {
	return &chainpb.AuthProof{SignerDid: signer, Nonce: "n1", IssuedAt: issuedAt, Signature: []byte("sig")}
}

func TestPeerHandler_GetPublisherInfo_VerifyContract(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{pubType: "noop", modes: []string{"by-reference"}}
	h := handler.NewPeer(svc, v)
	resp, err := h.GetPublisherInfo(context.Background(), connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof: proofMsg("did:dplaax:reg:org:sub", goodIssuedAt), PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if err != nil {
		t.Fatalf("GetPublisherInfo: %v", err)
	}
	if !v.called || v.gotOp != "GetPublisherInfo" {
		t.Errorf("verify op = %q, called=%v", v.gotOp, v.called)
	}
	if v.gotFields["publisher_did"] != "did:dplaax:reg:org:acme:pipeline:p1" || len(v.gotFields) != 1 {
		t.Errorf("fields = %+v", v.gotFields)
	}
	if v.gotProof.SignerDID != "did:dplaax:reg:org:sub" || v.gotProof.Nonce != "n1" {
		t.Errorf("proof = %+v", v.gotProof)
	}
	if !svc.publisherInfo || resp.Msg.GetPublishType() != "noop" {
		t.Errorf("svc.publisherInfo=%v resp=%+v", svc.publisherInfo, resp.Msg)
	}
}

func TestPeerHandler_RegisterSubscription_VerifyContract(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1", PublishType: "noop", PayloadDelivery: "inline", ConnectionInfo: map[string]string{"subject": "x"}}}
	h := handler.NewPeer(svc, v)
	resp, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg("did:dplaax:reg:org:sub", goodIssuedAt),
		SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1", PayloadDelivery: "inline",
	}))
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if v.gotOp != "RegisterSubscription" {
		t.Errorf("op = %q", v.gotOp)
	}
	want := map[string]string{"subscriber_did": "did:dplaax:reg:org:sub", "publisher_did": "did:dplaax:reg:org:acme:pipeline:p1", "payload_delivery": "inline"}
	for k, w := range want {
		if v.gotFields[k] != w {
			t.Errorf("fields[%q] = %v, want %q", k, v.gotFields[k], w)
		}
	}
	if len(v.gotFields) != 3 {
		t.Errorf("fields = %+v, want exactly 3 keys", v.gotFields)
	}
	if !svc.register || resp.Msg.GetSubscriptionId() != "s1" || resp.Msg.GetPayloadDelivery() != "inline" {
		t.Errorf("resp = %+v", resp.Msg)
	}
}

// payload_delivery is signed verbatim — an empty requested mode must appear as an
// empty string in the signed fields, not normalized to by-reference (D-p4).
func TestPeerHandler_RegisterSubscription_EmptyModeSignedVerbatim(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1"}}
	h := handler.NewPeer(svc, v)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg("did:dplaax:reg:org:sub", goodIssuedAt),
		SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1", PayloadDelivery: "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if pd, ok := v.gotFields["payload_delivery"]; !ok || pd != "" {
		t.Errorf("payload_delivery in signed fields = %v (ok=%v), want empty string verbatim", pd, ok)
	}
}

func TestPeerHandler_Disconnect_VerifyContract(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{}
	h := handler.NewPeer(svc, v)
	_, err := h.Disconnect(context.Background(), connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof: proofMsg("did:dplaax:reg:org:sub", goodIssuedAt), SubscriptionId: "s1",
	}))
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if v.gotOp != "Disconnect" || v.gotFields["subscription_id"] != "s1" || len(v.gotFields) != 1 {
		t.Errorf("op=%q fields=%+v", v.gotOp, v.gotFields)
	}
	if !svc.disconnect {
		t.Error("domain Disconnect not called")
	}
}

func TestPeerHandler_VerifyFailure_Mapped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"signature invalid", wireauth.ErrSignatureInvalid, connect.CodeUnauthenticated},
		{"replay", wireauth.ErrReplay, connect.CodeUnauthenticated},
		{"key resolution", wireauth.ErrKeyResolution, connect.CodeUnauthenticated},
		{"missing proof", wireauth.ErrMissingProof, connect.CodeInvalidArgument},
		{"malformed proof", wireauth.ErrMalformedProof, connect.CodeInvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &spyVerifier{err: c.err}
			svc := &fakePeer{}
			h := handler.NewPeer(svc, v)
			_, err := h.GetPublisherInfo(context.Background(), connect.NewRequest(&chainpb.GetPublisherInfoRequest{
				AuthProof: proofMsg("did:dplaax:reg:org:sub", goodIssuedAt), PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
			}))
			if connect.CodeOf(err) != c.want {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), c.want)
			}
			if svc.publisherInfo {
				t.Error("domain called despite Verify failure")
			}
		})
	}
}

func TestPeerHandler_IssuedAtCodecFailure(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{}
	h := handler.NewPeer(svc, v)
	_, err := h.GetPublisherInfo(context.Background(), connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof: proofMsg("did:dplaax:reg:org:sub", "2026-06-17T12:00:00.5Z"), PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
	if v.called {
		t.Error("Verify called despite a malformed issued_at (codec must reject first)")
	}
}

func TestPeerHandler_MissingAuthProof(t *testing.T) {
	v := &spyVerifier{}
	h := handler.NewPeer(&fakePeer{}, v)
	_, err := h.Disconnect(context.Background(), connect.NewRequest(&chainpb.DisconnectRequest{SubscriptionId: "s1"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
	if v.called {
		t.Error("Verify called with no auth_proof")
	}
}

// The RegisterSubscription authorizer must bind signer to the claimed subscriber:
// a proof signed by one DID claiming to register a different subscriber is denied.
func TestPeerHandler_RegisterBindingMismatch(t *testing.T) {
	v := &spyVerifier{runAuth: true}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1"}}
	h := handler.NewPeer(svc, v)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg("did:dplaax:reg:org:attacker", goodIssuedAt),
		SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if svc.register {
		t.Error("domain RegisterSubscription called despite a signer/subscriber mismatch")
	}
}

func TestPeerHandler_DomainError_Mapped(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"not admitted", chainmanager.ErrNotAdmitted, connect.CodePermissionDenied},
		{"unsupported mode", chainmanager.ErrPayloadModeUnsupported, connect.CodeInvalidArgument},
		{"invalid publisher", chainmanager.ErrInvalidPipelineDID, connect.CodeInvalidArgument},
		{"infra unavailable", chainmanager.ErrInfraUnavailable, connect.CodeInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := &spyVerifier{}
			svc := &fakePeer{err: c.err}
			h := handler.NewPeer(svc, v)
			_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
				AuthProof:     proofMsg("did:dplaax:reg:org:sub", goodIssuedAt),
				SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
			}))
			if connect.CodeOf(err) != c.want {
				t.Errorf("code = %v, want %v", connect.CodeOf(err), c.want)
			}
		})
	}
}
