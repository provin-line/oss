package client_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"net/http/httptest"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	auditclient "github.com/provin-line/oss/network/pkg/services/auditor/client"
	"github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

const nodeDID = "did:dplaax:poc.dplaax.dev:org:pipeline"

func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

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
// public key, mirroring payloadresolver/handler's own e2e test helper.
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

// countingHTTPClient wraps a connect.HTTPClient and counts Do calls — the
// harness for proving a client-side rejection never reaches the network.
type countingHTTPClient struct {
	inner connect.HTTPClient
	calls int
}

func (c *countingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.calls++
	return c.inner.Do(req)
}

// harness wires a real AuditService (real EvidenceService over in-memory
// receipt/queue stores) behind a real wireauth.Verifier, served over
// httptest, with the real streaming-free unary auditclient.Client signing
// every call as nodeDID.
type harness struct {
	receipts *auditor.MemReceiptStore
	queue    *auditor.MemQueue
	client   *auditclient.Client
	url      string
	httpc    *countingHTTPClient
}

func newHarness(t *testing.T) *harness {
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

	receipts := auditor.NewMemReceiptStore()
	queue := auditor.NewMemQueue()
	admitted := func(context.Context, string) (bool, error) { return true, nil }
	evidence := auditor.NewEvidenceService(receipts, queue, admitted)

	h := handler.New(nil, evidence, v)
	path, hh := auditpbconnect.NewAuditServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	httpc := &countingHTTPClient{inner: srv.Client()}
	return &harness{
		receipts: receipts,
		queue:    queue,
		client:   auditclient.New(auditclient.Config{Signer: sgn, SignerDID: nodeDID, BaseURL: srv.URL, HTTPClient: httpc}),
		url:      srv.URL,
		httpc:    httpc,
	}
}

// TestRegisterEvidence_RoundTrip proves the client's signed view is exactly
// what the real handler verifies end-to-end: a deliberately unsorted +
// duplicated consumed set still registers, and the receipt/queue land in
// their CANONICAL (sorted, deduplicated) form.
func TestRegisterEvidence_RoundTrip(t *testing.T) {
	h := newHarness(t)
	head := addr("a")
	consumed := []string{addr("c"), addr("b"), addr("b")} // deliberately unsorted + duplicated

	if err := h.client.RegisterEvidence(context.Background(), head, consumed); err != nil {
		t.Fatalf("RegisterEvidence: %v", err)
	}
	if h.httpc.calls == 0 {
		t.Error("expected the RPC to reach the network")
	}

	got, err := h.receipts.Get(head)
	if err != nil {
		t.Fatalf("receipts.Get: %v", err)
	}
	want := []string{addr("b"), addr("c")}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("receipt = %v, want canonical %v", got, want)
	}

	cands, err := h.queue.ListNewest(10)
	if err != nil {
		t.Fatalf("ListNewest: %v", err)
	}
	if len(cands) != 1 || cands[0].HeadHash != head {
		t.Errorf("queue = %+v, want exactly one candidate for %q", cands, head)
	}
}

// TestRegisterEvidence_MismatchedKey_Unauthenticated proves the wireauth
// tamper-resistance property at the client's own level: a client signing as
// nodeDID with a key OTHER than the one the verifier's resolver has bound to
// nodeDID (equivalent to a corrupted/substituted signature — the verifier's
// rebuilt view never matches) is rejected as CodeUnauthenticated, and the
// evidence never lands.
func TestRegisterEvidence_MismatchedKey_Unauthenticated(t *testing.T) {
	h := newHarness(t)
	wrongSigner, _ := signer(t, nodeDID) // a DIFFERENT keypair than the one bound to nodeDID above
	bad := auditclient.New(auditclient.Config{Signer: wrongSigner, SignerDID: nodeDID, BaseURL: h.url, HTTPClient: h.httpc})

	head := addr("d")
	err := bad.RegisterEvidence(context.Background(), head, []string{addr("e")})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("mismatched key: code = %v, want Unauthenticated", connect.CodeOf(err))
	}
	if _, getErr := h.receipts.Get(head); getErr == nil {
		t.Error("receipt recorded despite a signature that must not verify")
	}
}

// TestRegisterEvidence_MalformedConsumedSet_ClientSideRejection proves the
// client rejects a malformed consumed set BEFORE signing or dialing the
// network — the same canonicalization (auditor.CanonicalizeConsumedSet) the
// handler enforces, applied client-side.
func TestRegisterEvidence_MalformedConsumedSet_ClientSideRejection(t *testing.T) {
	h := newHarness(t)
	err := h.client.RegisterEvidence(context.Background(), addr("a"), nil)
	if err == nil {
		t.Fatal("RegisterEvidence with an empty consumed set: want error, got nil")
	}
	if h.httpc.calls != 0 {
		t.Errorf("HTTP calls = %d, want 0 (malformed set must be rejected before any network call)", h.httpc.calls)
	}

	err = h.client.RegisterEvidence(context.Background(), addr("a"), []string{"not-a-content-address"})
	if err == nil {
		t.Fatal("RegisterEvidence with a malformed member: want error, got nil")
	}
	if h.httpc.calls != 0 {
		t.Errorf("HTTP calls = %d, want 0 (malformed member must be rejected before any network call)", h.httpc.calls)
	}
}
