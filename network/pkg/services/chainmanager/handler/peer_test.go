package handler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/keystore"
	keyfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/evidence"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/filelog"
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
	err       error            // returned from Verify (simulating a wireauth failure)
	runAuth   bool             // invoke the authorizer with gotProof.SignerDID
	authDoc   *did.DIDDocument // doc handed to the authorizer when runAuth is set (nil by default, matching the prior hardcoded nil)
}

func (s *spyVerifier) Verify(_ context.Context, op string, fields map[string]any, proof wireauth.Proof, authorize wireauth.Authorizer) error {
	s.called = true
	s.gotOp, s.gotFields, s.gotProof = op, fields, proof
	if s.err != nil {
		return s.err
	}
	if s.runAuth && authorize != nil {
		return authorize(proof.SignerDID, s.authDoc, fields)
	}
	return nil
}

// spyRecorder is a handler.RelationshipRecorder spy: it records whether it was
// called and the Record it was handed, or returns a preset error (simulating
// an evidence-log failure).
type spyRecorder struct {
	called bool
	gotRec evidence.Record
	err    error
}

func (s *spyRecorder) Record(_ context.Context, r evidence.Record) (*tlog.Record, error) {
	s.called = true
	s.gotRec = r
	if s.err != nil {
		return nil, s.err
	}
	return &tlog.Record{Index: 0, Payload: nil, Hash: "h"}, nil
}

// authDoc builds a DID Document listing pub as subject's #auth key under the
// authentication relationship, controlled by subject — the same fixture shape
// wireauth's own tests use (wireauth/verify_test.go's authDoc).
func authDoc(subject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: subject, Controller: subject,
		VerificationMethod: []did.VerificationMethod{{
			ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject,
			PublicKeyJWK: map[string]any{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		Authentication: []string{subject + "#auth"},
	})
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
		// ErrBeforeEpoch is a boot-window rejection, not an identity verdict:
		// an honest re-signed retry clears it once the verifier is past its
		// restart epoch, so it maps to Unavailable (retryable), NOT
		// Unauthenticated.
		{"before epoch", wireauth.ErrBeforeEpoch, connect.CodeUnavailable},
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
		{"unsafe subject", chainmanager.ErrUnsafeSubject, connect.CodeInvalidArgument},
		{"mixed mode", chainmanager.ErrMixedModeSubscription, connect.CodeFailedPrecondition},
		{"export subject missing", chainmanager.ErrExportSubjectMissing, connect.CodeInternal},
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

// pubForEvidence is a fixture #auth public key (Ed25519 length) used only to
// exercise did.ExtractPublicKey through authDoc — never a real signature
// check (the spyVerifier does not verify anything).
var pubForEvidence = bytes.Repeat([]byte{7}, 32)

// A successful RegisterSubscription, with evidence configured, records the
// resolved doc's #auth key material alongside the signed view — AFTER the
// domain call succeeds.
func TestPeerHandler_RegisterSubscription_RecordsEvidence(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1"}}
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg(signer, goodIssuedAt),
		SubscriberDid: signer, PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1", PayloadDelivery: "inline",
	}))
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if !rec.called {
		t.Fatal("evidence not recorded")
	}
	if !svc.register {
		t.Error("domain RegisterSubscription not called")
	}
	if rec.gotRec.Op != "RegisterSubscription" || rec.gotRec.SignerDID != signer || rec.gotRec.Nonce != "n1" {
		t.Errorf("recorded evidence = %+v", rec.gotRec)
	}
	if rec.gotRec.ViewVersion != wireauth.ViewVersion {
		t.Errorf("recorded ViewVersion = %d, want %d", rec.gotRec.ViewVersion, wireauth.ViewVersion)
	}
	if rec.gotRec.Fields["subscriber_did"] != signer || rec.gotRec.Fields["publisher_did"] != "did:dplaax:reg:org:acme:pipeline:p1" || rec.gotRec.Fields["payload_delivery"] != "inline" {
		t.Errorf("recorded fields = %+v", rec.gotRec.Fields)
	}
	wantKeyID := signer + "#auth"
	if rec.gotRec.KeyMaterial.Method != wantKeyID {
		t.Errorf("KeyMaterial.Method = %q, want %q", rec.gotRec.KeyMaterial.Method, wantKeyID)
	}
	if string(rec.gotRec.KeyMaterial.PublicKey) != string(pubForEvidence) {
		t.Errorf("KeyMaterial.PublicKey = %v, want %v", rec.gotRec.KeyMaterial.PublicKey, pubForEvidence)
	}
	if rec.gotRec.KeyMaterial.Type != string(did.RelationshipAuthentication) {
		t.Errorf("KeyMaterial.Type = %q, want %q", rec.gotRec.KeyMaterial.Type, did.RelationshipAuthentication)
	}
}

// A successful Disconnect, with evidence configured, records evidence too —
// Disconnect passes no signer-binding authorizer of its own, so the handler
// must supply a capturing one when evidence is configured.
func TestPeerHandler_Disconnect_RecordsEvidence(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{}
	svc := &fakePeer{}
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.Disconnect(context.Background(), connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof: proofMsg(signer, goodIssuedAt), SubscriptionId: "s1",
	}))
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if !rec.called {
		t.Fatal("evidence not recorded")
	}
	if !svc.disconnect {
		t.Error("domain Disconnect not called")
	}
	if rec.gotRec.Op != "Disconnect" || rec.gotRec.SignerDID != signer {
		t.Errorf("recorded evidence = %+v", rec.gotRec)
	}
	if rec.gotRec.Fields["subscription_id"] != "s1" {
		t.Errorf("recorded fields = %+v", rec.gotRec.Fields)
	}
}

// Evidence-record failure fails the RPC with Internal — but only AFTER the
// domain mutation already succeeded (evidence is recorded post-domain so a
// rejected registration is never retained; the price is that a record failure
// surfaces after an established relationship).
func TestPeerHandler_RegisterSubscription_EvidenceFailure_Internal(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{err: errors.New("evidence log: disk full")}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1"}}
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg(signer, goodIssuedAt),
		SubscriberDid: signer, PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want Internal", connect.CodeOf(err))
	}
	if !svc.register {
		t.Error("domain RegisterSubscription must run before evidence is recorded (record failure is post-domain)")
	}
}

// Evidence-record failure fails Disconnect the same way — post-domain.
func TestPeerHandler_Disconnect_EvidenceFailure_Internal(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{err: errors.New("evidence log: disk full")}
	svc := &fakePeer{}
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.Disconnect(context.Background(), connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof: proofMsg(signer, goodIssuedAt), SubscriptionId: "s1",
	}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Errorf("code = %v, want Internal", connect.CodeOf(err))
	}
	if !svc.disconnect {
		t.Error("domain Disconnect must run before evidence is recorded (record failure is post-domain)")
	}
}

// The point of recording post-domain: when the DOMAIN call fails, NO evidence
// is recorded — a rejected/failed relationship change must never be retained as
// established.
func TestPeerHandler_RegisterSubscription_DomainFailure_NoEvidence(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{}
	svc := &fakePeer{err: chainmanager.ErrNotAdmitted} // publisher rejects the subscriber
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg(signer, goodIssuedAt),
		SubscriberDid: signer, PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if rec.called {
		t.Error("evidence recorded despite a rejected domain RegisterSubscription")
	}
}

// Same for Disconnect: a failed domain call records no evidence.
func TestPeerHandler_Disconnect_DomainFailure_NoEvidence(t *testing.T) {
	signer := "did:dplaax:reg:org:sub"
	v := &spyVerifier{runAuth: true, authDoc: authDoc(signer, pubForEvidence)}
	rec := &spyRecorder{}
	svc := &fakePeer{err: chainmanager.ErrNotOwner} // caller does not own the subscription
	h := handler.NewPeerWithEvidence(svc, v, rec)
	_, err := h.Disconnect(context.Background(), connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof: proofMsg(signer, goodIssuedAt), SubscriptionId: "s1",
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if rec.called {
		t.Error("evidence recorded despite a failed domain Disconnect")
	}
}

// A nil recorder (NewPeer, or NewPeerWithEvidence with a nil rec) leaves
// behavior unchanged: no recording attempted, the domain still called.
func TestPeerHandler_NilRecorder_Unchanged(t *testing.T) {
	v := &spyVerifier{}
	svc := &fakePeer{sub: &store.Subscription{ID: "s1"}}
	h := handler.NewPeerWithEvidence(svc, v, nil)
	_, err := h.RegisterSubscription(context.Background(), connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     proofMsg("did:dplaax:reg:org:sub", goodIssuedAt),
		SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if !svc.register {
		t.Error("domain RegisterSubscription not called")
	}
}

// evResolver resolves DIDs from an in-memory table (a real wireauth.DIDResolver).
type evResolver map[string]*did.DIDDocument

func (m evResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, errors.New("evResolver: not found")
	}
	return doc, nil
}

// The DEFINING contract of the evidence log, driven end-to-end with a REAL
// signature: a RegisterSubscription signed by a real key, verified by a real
// *wireauth.Verifier through the handler (so the handler→verifier doc callback
// and did.ExtractPublicKey are exercised), recorded to a real evidence.Log over
// a filelog, then reloaded across a restart — and the retained Record alone is
// sufficient to reconstruct the JCS signed view (using rec.ViewVersion for the
// "v" member) and re-verify the counterparty signature against the snapshotted
// public key. This is RED without FIX 1: a zero ViewVersion serializes "v":0,
// diverging from the "v":1 the signer used, so the signature fails to verify.
func TestPeerHandler_RegisterSubscription_EvidenceReVerifiesAcrossRestart(t *testing.T) {
	ctx := context.Background()
	const (
		subscriber = "did:dplaax:reg:org:sub"
		publisher  = "did:dplaax:reg:org:acme:pipeline:p1"
	)
	// A real #auth signing key for the subscriber.
	ks := keyfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(subscriber, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	signer := ks

	// A real wireauth verifier resolving the subscriber's #auth document. Clock
	// sits 1s after the signing instant (proof just inside the past window) and
	// epoch well before it (so the epoch barrier does not interfere).
	signedAt := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	verifier, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: evResolver{subscriber: authDoc(subscriber, kp.PublicKey)},
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Clock:    func() time.Time { return signedAt.Add(time.Second) },
		Epoch:    signedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// A real proof over the exact fields the handler reconstructs for this RPC.
	fields := map[string]any{
		"subscriber_did":   subscriber,
		"publisher_did":    publisher,
		"payload_delivery": "inline",
	}
	proof, err := wireauth.Sign(signer, subscriber, "RegisterSubscription", fields, "n-closed-loop", signedAt)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// A real evidence log over a filelog.
	dir := t.TempDir()
	fl, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("filelog.New: %v", err)
	}
	evLog := evidence.New(fl)

	h := handler.NewPeerWithEvidence(&fakePeer{sub: &store.Subscription{ID: "s1"}}, verifier, evLog)
	if _, err := h.RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof:     &chainpb.AuthProof{SignerDid: subscriber, Nonce: proof.Nonce, IssuedAt: proof.IssuedAt.UTC().Format(time.RFC3339), Signature: proof.Signature},
		SubscriberDid: subscriber, PublisherDid: publisher, PayloadDelivery: "inline",
	})); err != nil {
		t.Fatalf("RegisterSubscription: %v (code %v)", err, connect.CodeOf(err))
	}
	if err := fl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Restart: reopen the evidence log over the same dir and reload the record.
	fl2, err := filelog.New(dir)
	if err != nil {
		t.Fatalf("filelog.New (restart): %v", err)
	}
	defer fl2.Close()
	rec, err := evidence.New(fl2).Get(ctx, 0)
	if err != nil {
		t.Fatalf("Get (restart): %v", err)
	}

	// Reconstruct the JCS signed view from the retained record ALONE and
	// re-verify the counterparty signature against the snapshotted key.
	view, err := jcs.Canonicalize(map[string]any{
		"signerDID": rec.SignerDID,
		"op":        rec.Op,
		"v":         rec.ViewVersion,
		"nonce":     rec.Nonce,
		"issuedAt":  rec.IssuedAt,
		"fields":    rec.Fields,
	})
	if err != nil {
		t.Fatalf("reconstruct view: %v", err)
	}
	ok, err := (ed25519.Verifier{}).Verify(rec.KeyMaterial.PublicKey, view, rec.Signature)
	if err != nil {
		t.Fatalf("re-verify: %v", err)
	}
	if !ok {
		t.Errorf("retained record did not re-verify: the signed view reconstructed from the record (v=%d) does not match the counterparty signature", rec.ViewVersion)
	}
}
