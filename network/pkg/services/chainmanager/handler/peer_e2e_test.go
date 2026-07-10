package handler_test

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/noop"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

const (
	e2eSub      = "did:dplaax:poc.dplaax.dev:org:sub"
	e2eStranger = "did:dplaax:poc.dplaax.dev:org:stranger"
	e2ePub      = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
)

func e2eAt() time.Time { return time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC) }

func e2eJWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func e2eAuthDoc(subject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: subject, Controller: subject,
		VerificationMethod: []did.VerificationMethod{{
			ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject,
			PublicKeyJWK: e2eJWK(pub),
		}},
		Authentication: []string{subject + "#auth"},
	})
}

type e2eResolver map[string]*did.DIDDocument

func (m e2eResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, wireauth.ErrKeyResolution
	}
	return doc, nil
}

func e2eSigner(t *testing.T, subject string) (crypto.Signer, []byte) {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return ed25519.NewSigner(ks), kp.PublicKey
}

func e2eNonce(t *testing.T) string {
	t.Helper()
	n, err := wireauth.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// authProof signs the given op+fields and packages it as the wire AuthProof,
// serializing issued_at as the canonical RFC 3339 UTC second-precision string.
func authProof(t *testing.T, signer crypto.Signer, signerDID, op string, fields map[string]any, nonce string) *chainpb.AuthProof {
	t.Helper()
	p, err := wireauth.Sign(signer, signerDID, op, fields, nonce, e2eAt())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return &chainpb.AuthProof{
		SignerDid: p.SignerDID, Nonce: p.Nonce,
		IssuedAt: p.IssuedAt.UTC().Format(time.RFC3339), Signature: p.Signature,
	}
}

// e2eSetup stands up the peer server over httptest with a real wireauth verifier
// (clock 1s after e2eAt so a proof issued at e2eAt is just inside the past
// window), noop infra, and an allow-list admitting e2eSub. Both e2eSub and
// e2eStranger are resolvable; only e2eSub is allow-listed.
func e2eSetup(t *testing.T) (chainpbconnect.ChainPeerServiceClient, crypto.Signer, crypto.Signer) {
	t.Helper()
	subSigner, subPub := e2eSigner(t, e2eSub)
	strangerSigner, strangerPub := e2eSigner(t, e2eStranger)
	resolver := e2eResolver{
		e2eSub:      e2eAuthDoc(e2eSub, subPub),
		e2eStranger: e2eAuthDoc(e2eStranger, strangerPub),
	}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
		Clock: func() time.Time { return e2eAt().Add(time.Second) }, Epoch: e2eAt().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	allows := memstore.NewAllowListStore()
	if err := allows.Save(e2ePub, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	svc := chainmanager.New(memstore.NewSubscriptionStore(), allows, chainmanager.WithInfraOperator(noop.New()))
	_, h := chainpbconnect.NewChainPeerServiceHandler(handler.NewPeer(svc, v)) // L2: no authz interceptor
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return chainpbconnect.NewChainPeerServiceClient(srv.Client(), srv.URL), subSigner, strangerSigner
}

// The full subscriber-initiated round-trip with a real signature proves the D-p4
// view contract (handler reconstructs exactly what the subscriber signed) end to
// end over the mux.
func TestPeerE2E_HappyPath(t *testing.T) {
	ctx := context.Background()
	client, sub, _ := e2eSetup(t)

	gi, err := client.GetPublisherInfo(ctx, connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof:    authProof(t, sub, e2eSub, "GetPublisherInfo", map[string]any{"publisher_did": e2ePub}, e2eNonce(t)),
		PublisherDid: e2ePub,
	}))
	if err != nil {
		t.Fatalf("GetPublisherInfo: %v (code %v)", err, connect.CodeOf(err))
	}
	if gi.Msg.GetPublishType() != "noop" || len(gi.Msg.GetSupportedPayloadDelivery()) == 0 {
		t.Errorf("GetPublisherInfo resp = %+v", gi.Msg)
	}

	rs, err := client.RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof: authProof(t, sub, e2eSub, "RegisterSubscription",
			map[string]any{"subscriber_did": e2eSub, "publisher_did": e2ePub, "payload_delivery": "inline"}, e2eNonce(t)),
		SubscriberDid: e2eSub, PublisherDid: e2ePub, PayloadDelivery: "inline",
	}))
	if err != nil {
		t.Fatalf("RegisterSubscription: %v (code %v)", err, connect.CodeOf(err))
	}
	if rs.Msg.GetSubscriptionId() == "" || rs.Msg.GetPayloadDelivery() != "inline" || rs.Msg.GetConnectionInfo()["subject"] != e2ePub {
		t.Errorf("RegisterSubscription resp = %+v", rs.Msg)
	}

	if _, err := client.Disconnect(ctx, connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof:      authProof(t, sub, e2eSub, "Disconnect", map[string]any{"subscription_id": rs.Msg.GetSubscriptionId()}, e2eNonce(t)),
		SubscriptionId: rs.Msg.GetSubscriptionId(),
	})); err != nil {
		t.Fatalf("Disconnect: %v (code %v)", err, connect.CodeOf(err))
	}
}

func TestPeerE2E_NotAdmitted(t *testing.T) {
	ctx := context.Background()
	client, _, stranger := e2eSetup(t)
	// A resolvable, validly-signed, but non-allow-listed caller.
	_, err := client.GetPublisherInfo(ctx, connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof:    authProof(t, stranger, e2eStranger, "GetPublisherInfo", map[string]any{"publisher_did": e2ePub}, e2eNonce(t)),
		PublisherDid: e2ePub,
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("not-admitted: code = %v, want PermissionDenied", connect.CodeOf(err))
	}
}

func TestPeerE2E_TamperedSignature(t *testing.T) {
	ctx := context.Background()
	client, sub, _ := e2eSetup(t)
	ap := authProof(t, sub, e2eSub, "GetPublisherInfo", map[string]any{"publisher_did": e2ePub}, e2eNonce(t))
	ap.Signature[0] ^= 0xFF // flip a byte
	_, err := client.GetPublisherInfo(ctx, connect.NewRequest(&chainpb.GetPublisherInfoRequest{
		AuthProof: ap, PublisherDid: e2ePub,
	}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("tampered signature: code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

func TestPeerE2E_UnsupportedMode(t *testing.T) {
	ctx := context.Background()
	client, sub, _ := e2eSetup(t)
	_, err := client.RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof: authProof(t, sub, e2eSub, "RegisterSubscription",
			map[string]any{"subscriber_did": e2eSub, "publisher_did": e2ePub, "payload_delivery": "carrier-pigeon"}, e2eNonce(t)),
		SubscriberDid: e2eSub, PublisherDid: e2ePub, PayloadDelivery: "carrier-pigeon",
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("unsupported mode: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestPeerE2E_NonceReplay(t *testing.T) {
	ctx := context.Background()
	client, sub, _ := e2eSetup(t)
	nonce := e2eNonce(t)
	req := func() *connect.Request[chainpb.GetPublisherInfoRequest] {
		return connect.NewRequest(&chainpb.GetPublisherInfoRequest{
			AuthProof:    authProof(t, sub, e2eSub, "GetPublisherInfo", map[string]any{"publisher_did": e2ePub}, nonce),
			PublisherDid: e2ePub,
		})
	}
	if _, err := client.GetPublisherInfo(ctx, req()); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Same nonce again → replay.
	if _, err := client.GetPublisherInfo(ctx, req()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("replay: code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

func TestPeerE2E_NotOwner(t *testing.T) {
	ctx := context.Background()
	client, sub, stranger := e2eSetup(t)
	rs, err := client.RegisterSubscription(ctx, connect.NewRequest(&chainpb.RegisterSubscriptionRequest{
		AuthProof: authProof(t, sub, e2eSub, "RegisterSubscription",
			map[string]any{"subscriber_did": e2eSub, "publisher_did": e2ePub, "payload_delivery": "inline"}, e2eNonce(t)),
		SubscriberDid: e2eSub, PublisherDid: e2ePub, PayloadDelivery: "inline",
	}))
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	// The stranger (validly signed) tries to disconnect someone else's subscription.
	_, err = client.Disconnect(ctx, connect.NewRequest(&chainpb.DisconnectRequest{
		AuthProof:      authProof(t, stranger, e2eStranger, "Disconnect", map[string]any{"subscription_id": rs.Msg.GetSubscriptionId()}, e2eNonce(t)),
		SubscriptionId: rs.Msg.GetSubscriptionId(),
	}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("not-owner: code = %v, want PermissionDenied", connect.CodeOf(err))
	}
}
