package reportclient_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/reportclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

const publisherDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"

const ttl = 90 * time.Second

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

// signer returns a fresh keystore-backed crypto.Signer for subject plus its
// public key, mirroring auditor/client's own e2e test helper.
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

// harness wires a real OperatorHandler (ReportEmitHealth only, backed by a
// real emithealth.Store) behind a real wireauth.Verifier, served over
// httptest, with the real reportclient.Client signing every call as
// publisherDID.
type harness struct {
	store  *emithealth.Store
	client *reportclient.Client
	url    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	sgn, pub := signer(t, publisherDID)
	res := didResolver{publisherDID: authDoc(publisherDID, pub)}
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

	store := emithealth.New(ttl)
	h := handler.NewOperator(nil, handler.WithEmitHealth(store, v, ttl))
	path, hh := chainpbconnect.NewChainServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &harness{
		store:  store,
		client: reportclient.New(reportclient.Config{Signer: sgn, SignerDID: publisherDID, BaseURL: srv.URL, HTTPClient: srv.Client()}),
		url:    srv.URL,
	}
}

// TestReportEmitHealth_RoundTrip proves the client's signed view is exactly
// what the real handler verifies end-to-end: the report lands in the store
// (State reads HealthyReported) and the returned TTL matches the server's
// configured value.
func TestReportEmitHealth_RoundTrip(t *testing.T) {
	h := newHarness(t)

	got, err := h.client.ReportEmitHealth(context.Background(), publisherDID, true)
	if err != nil {
		t.Fatalf("ReportEmitHealth: %v", err)
	}
	if got != ttl {
		t.Errorf("ttl = %v, want %v", got, ttl)
	}
	if state := h.store.State(publisherDID, time.Now()); state != emithealth.HealthyReported {
		t.Errorf("store state = %v, want HealthyReported", state)
	}
}

// A healthy=false report round-trips too, landing as UnhealthyReported.
func TestReportEmitHealth_RoundTrip_Unhealthy(t *testing.T) {
	h := newHarness(t)

	if _, err := h.client.ReportEmitHealth(context.Background(), publisherDID, false); err != nil {
		t.Fatalf("ReportEmitHealth: %v", err)
	}
	if state := h.store.State(publisherDID, time.Now()); state != emithealth.UnhealthyReported {
		t.Errorf("store state = %v, want UnhealthyReported", state)
	}
}

// The proto's own contract (publisher_did MUST equal the proven signer DID)
// applies at the client's own level too: a client configured to sign as
// publisherDID but asked to report for a DIFFERENT publisherDID is rejected
// PermissionDenied, and nothing lands in the store.
func TestReportEmitHealth_PublisherMismatch_PermissionDenied(t *testing.T) {
	h := newHarness(t)
	otherPub := "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p2"

	_, err := h.client.ReportEmitHealth(context.Background(), otherPub, true)
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", connect.CodeOf(err))
	}
	if state := h.store.State(otherPub, time.Now()); state != emithealth.NeverReported {
		t.Errorf("store state = %v, want NeverReported (nothing must land on a rejected report)", state)
	}
}

// TestReportEmitHealth_MismatchedKey_Unauthenticated proves the wireauth
// tamper-resistance property at the client's own level: a client signing as
// publisherDID with a key OTHER than the one the verifier's resolver has
// bound to publisherDID is rejected Unauthenticated, and nothing lands in the
// store.
func TestReportEmitHealth_MismatchedKey_Unauthenticated(t *testing.T) {
	h := newHarness(t)
	wrongSigner, _ := signer(t, publisherDID) // a DIFFERENT keypair than the one bound to publisherDID above
	bad := reportclient.New(reportclient.Config{Signer: wrongSigner, SignerDID: publisherDID, BaseURL: h.url, HTTPClient: http.DefaultClient})

	_, err := bad.ReportEmitHealth(context.Background(), publisherDID, true)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("code = %v, want Unauthenticated", connect.CodeOf(err))
	}
	if state := h.store.State(publisherDID, time.Now()); state != emithealth.NeverReported {
		t.Errorf("store state = %v, want NeverReported (a signature that must not verify must not land)", state)
	}
}
