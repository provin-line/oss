package handler_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
)

const (
	nodeDID  = "did:dplaax:poc.dplaax.dev:org:consumer"
	ownerPBA = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:pa"
)

func jwk(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func authDoc(subject string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: subject, Controller: subject,
		VerificationMethod: []did.VerificationMethod{{
			ID: subject + "#auth", Type: "JsonWebKey2020", Controller: subject,
			PublicKeyJWK: jwk(pub),
		}},
		Authentication: []string{subject + "#auth"},
	})
}

type didResolver map[string]*did.DIDDocument

func (m didResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, wireauth.ErrKeyResolution
	}
	return doc, nil
}

func signer(t *testing.T, subject string) (crypto.Signer, []byte) {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return ks, kp.PublicKey
}

// allowStub is a per-pipeline admission stub. admit[pipeline][caller] == true
// means the caller passes that pipeline's allow-list.
type allowStub map[string]map[string]bool

func (a allowStub) Admit(pipelineDID, callerDID string) error {
	if a[pipelineDID][callerDID] {
		return nil
	}
	return chainmanager.ErrNotAdmitted
}

// harness wires a PayloadService over httptest with the real streaming client,
// the node signing as nodeDID and admitted (by default) for ownerPBA.
type harness struct {
	svc    *payloadresolver.Service
	client *client.Resolver
	url    string
	allow  allowStub
}

func newHarness(t *testing.T, maxBytes int) *harness {
	t.Helper()
	sgn, pub := signer(t, nodeDID)
	res := didResolver{nodeDID: authDoc(nodeDID, pub)}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: res,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		// The real client signs with time.Now(); a past epoch + generous window
		// keep the proof inside the acceptance boundary without a fixed clock.
		Epoch:  time.Now().Add(-time.Hour),
		Window: wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	svc := payloadresolver.New(memstore.New())
	allow := allowStub{ownerPBA: {nodeDID: true}}
	serving := payloadresolver.NewServingBoundary(svc, allow)
	path, h := payloadpbconnect.NewPayloadServiceHandler(handler.New(serving, v))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{
		svc:    svc,
		client: client.New(client.Config{Signer: sgn, SignerDID: nodeDID, HTTPClient: srv.Client(), MaxBytes: maxBytes}),
		url:    srv.URL,
		allow:  allow,
	}
}

// TestPayloadService_RoundTrip serves a stored payload end-to-end through the
// streaming client, admitted via the owner's allow-list.
func TestPayloadService_RoundTrip(t *testing.T) {
	h := newHarness(t, 0)
	payload := []byte("the produced data bytes, delivered by reference")
	hash, err := h.svc.Store(context.Background(), payload, ownerPBA)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := h.client.ResolvePayload(context.Background(), h.url, hash)
	if err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// TestPayloadService_NotAdmitted denies a caller no owner admits (PermissionDenied).
// TestPayloadService_NotAdmitted proves the F9/F4 existence-oracle closure: a
// valid-signer-but-not-admitted caller gets the SAME client.ErrNotFound as a
// well-formed miss (TestPayloadService_NotFound), so a caller who may not receive
// the bytes cannot tell "present but forbidden" from "absent" — same code AND
// same message on the wire (was CodePermissionDenied before P1-4d).
func TestPayloadService_NotAdmitted(t *testing.T) {
	h := newHarness(t, 0)
	delete(h.allow, ownerPBA) // node no longer admitted by the sole owner
	payload := []byte("confidential bytes")
	hash, err := h.svc.Store(context.Background(), payload, ownerPBA)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	_, err = h.client.ResolvePayload(context.Background(), h.url, hash)
	// The client re-maps a wire NotFound to client.ErrNotFound — the SAME error
	// it returns for a well-formed miss (TestPayloadService_NotFound). Identical
	// error ⇒ the caller cannot distinguish "present but forbidden" from "absent".
	if !errors.Is(err, client.ErrNotFound) {
		t.Errorf("err = %v, want client.ErrNotFound — identical to an absent hash (oracle closed)", err)
	}
}

// TestPayloadService_NotFound maps a well-formed miss to client.ErrNotFound.
func TestPayloadService_NotFound(t *testing.T) {
	h := newHarness(t, 0)
	missing := "sha256:" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	_, err := h.client.ResolvePayload(context.Background(), h.url, missing)
	if !errors.Is(err, client.ErrNotFound) {
		t.Errorf("err = %v, want client.ErrNotFound", err)
	}
}

// TestPayloadService_MaxBytes aborts when the assembled payload exceeds the cap.
func TestPayloadService_MaxBytes(t *testing.T) {
	h := newHarness(t, 16) // 16-byte cap
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	hash, err := h.svc.Store(context.Background(), payload, ownerPBA)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	_, err = h.client.ResolvePayload(context.Background(), h.url, hash)
	if err == nil {
		t.Fatal("ResolvePayload over cap: want error, got nil")
	}
}
