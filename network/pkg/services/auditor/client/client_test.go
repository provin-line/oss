package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net/http/httptest"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	auditclient "github.com/provin-line/oss/network/pkg/services/auditor/client"
	"github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	"github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/vc"
)

const nodeDID = "did:dplaax:poc.dplaax.dev:org:pipeline"

func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

// variantAddr builds a well-formed but NEVER-ADMITTED wire variant id — the
// grammar RegisterEvidence now requires (P1-A), for tests that need a
// syntactically valid head without going through a real StoreVC (e.g. because
// the request is rejected before admission is ever checked).
func variantAddr(hexDigit string) string {
	return vc.WireVariantIDFromHex(strings.Repeat(hexDigit, 64))
}

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

// harness wires a real AuditService — a real EvidenceService over a REAL
// filestore.ReceiptStore (rooted at receiptDir, so tests can inspect the raw on-disk
// envelope — the registrant DID has no public Go reader; the file envelope IS the audit
// record, see auditor.ReceiptStore.Put's doc) and an in-memory queue, gated by a real
// vcresolver.Service's ResolveVariantBody (the SAME admission wiring
// internal/netcompose.BuildHandler uses, not a stub) — behind a real wireauth.Verifier,
// served over httptest, with the real streaming-free unary auditclient.Client signing
// every call as nodeDID.
type harness struct {
	receipts   auditor.ReceiptStore
	receiptDir string
	queue      *auditor.MemQueue
	vcSvc      *vcresolver.Service
	client     *auditclient.Client
	url        string
	httpc      *countingHTTPClient
	// signer is the crypto.Signer bound to nodeDID via the harness's DID
	// resolver — populated by newL1Harness so its callers can build their own
	// auditclient.Client (with a Bearer under test) that still signs a
	// wireauth proof the harness's verifier accepts.
	signer crypto.Signer
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

	receiptDir := t.TempDir()
	receipts, err := filestore.NewReceiptStore(receiptDir)
	if err != nil {
		t.Fatalf("NewReceiptStore: %v", err)
	}
	queue := auditor.NewMemQueue()
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), memstore.NewPool())
	// admitted mirrors internal/netcompose.BuildHandler's auditAdmitted
	// exactly (P1-A): ResolveVariantBody proves the variant is admitted AND
	// resolves the body address Register keys receipts/queue by.
	admitted := func(ctx context.Context, headVariantID string) (string, bool, error) {
		bodyAddress, err := vcSvc.ResolveVariantBody(ctx, headVariantID)
		if err != nil {
			if errors.Is(err, vcresolver.ErrNotFound) {
				return "", false, nil
			}
			return "", false, err
		}
		return bodyAddress, true, nil
	}
	evidence := auditor.NewEvidenceService(receipts, queue, admitted)

	h := handler.New(nil, evidence, v)
	path, hh := auditpbconnect.NewAuditServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	httpc := &countingHTTPClient{inner: srv.Client()}
	return &harness{
		receipts:   receipts,
		receiptDir: receiptDir,
		queue:      queue,
		vcSvc:      vcSvc,
		client:     auditclient.New(auditclient.Config{Signer: sgn, SignerDID: nodeDID, BaseURL: srv.URL, HTTPClient: httpc}),
		url:        srv.URL,
		httpc:      httpc,
		signer:     sgn,
	}
}

// storeCred admits a minimal signed credential into h's vcresolver.Service
// (the SAME store the harness's admission gate reads) and returns the
// server-recomputed identity — the (BodyAddress, WireVariantID) pair a real
// registering caller would hold after its own StoreVC call. Distinct
// proofValues (and this test package's own issuer, so a run never collides
// with vcresolver's own test fixtures) yield distinct variants/bodies.
func storeCred(t *testing.T, vcSvc *vcresolver.Service, proofValue string) vcresolver.StoreVCResult {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": proofValue},
		"proof": map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod", "created": "2026-07-01T00:00:01Z",
			"proofValue": proofValue,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := vcSvc.StoreVC(context.Background(), raw, "", 0)
	if err != nil {
		t.Fatalf("storeCred: StoreVC: %v", err)
	}
	return res
}

// TestRegisterEvidence_RoundTrip proves the client's signed view is exactly
// what the real handler verifies end-to-end (P1-A: StoreVC via the
// vcresolver service -> the returned WireVariantID is what RegisterEvidence
// actually accepts on the wire): a deliberately unsorted + duplicated
// consumed set still registers, and the receipt/queue land keyed by the
// resolved BODY address (never the variant id), in their CANONICAL (sorted,
// deduplicated) form. It also proves the wireauth-proven signer_did (nodeDID,
// what h.client signs every call as) is what lands as the receipt's recorded
// registrant — read from the raw on-disk envelope, since registrantDID has no
// public Go reader (the file envelope IS the audit record).
func TestRegisterEvidence_RoundTrip(t *testing.T) {
	h := newHarness(t)
	stored := storeCred(t, h.vcSvc, "roundtrip-proof")
	consumed := []string{addr("c"), addr("b"), addr("b")} // deliberately unsorted + duplicated

	if err := h.client.RegisterEvidence(context.Background(), stored.WireVariantID, consumed); err != nil {
		t.Fatalf("RegisterEvidence: %v", err)
	}
	if h.httpc.calls == 0 {
		t.Error("expected the RPC to reach the network")
	}

	got, err := h.receipts.Get(stored.BodyAddress)
	if err != nil {
		t.Fatalf("receipts.Get(body address): %v", err)
	}
	want := []string{addr("b"), addr("c")}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("receipt = %v, want canonical %v", got, want)
	}

	raw, err := os.ReadFile(filepath.Join(h.receiptDir, strings.TrimPrefix(stored.BodyAddress, "sha256:")+".json"))
	if err != nil {
		t.Fatalf("read receipt envelope: %v", err)
	}
	var envelope struct {
		RegistrantDID string `json:"registrant_did"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal receipt envelope: %v", err)
	}
	if envelope.RegistrantDID != nodeDID {
		t.Errorf("receipt registrant_did = %q, want the proof's signer_did %q", envelope.RegistrantDID, nodeDID)
	}

	cands, err := h.queue.ListNewest(10)
	if err != nil {
		t.Fatalf("ListNewest: %v", err)
	}
	if len(cands) != 1 || cands[0].HeadHash != stored.BodyAddress {
		t.Errorf("queue = %+v, want exactly one candidate for the BODY address %q", cands, stored.BodyAddress)
	}
}

// TestRegisterEvidence_BareBodyAddress_InvalidArgument proves the P1-A grammar
// fix end-to-end: a bare sha256:<hex> content address — a real body address,
// but NOT the wire variant id RegisterEvidence documents and requires — is
// rejected InvalidArgument, never silently accepted as if it were a variant.
func TestRegisterEvidence_BareBodyAddress_InvalidArgument(t *testing.T) {
	h := newHarness(t)
	err := h.client.RegisterEvidence(context.Background(), addr("a"), []string{addr("b")})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("bare body address: code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// TestRegisterEvidence_UnknownVariant_FailedPrecondition proves the
// arbitrary-hash amplification guard (D1) still holds under the new grammar:
// a well-formed wire variant id this node never admitted (no StoreVC call
// preceded it) is FailedPrecondition, never silently registered.
func TestRegisterEvidence_UnknownVariant_FailedPrecondition(t *testing.T) {
	h := newHarness(t)
	err := h.client.RegisterEvidence(context.Background(), variantAddr("9"), []string{addr("b")})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("unknown variant: code = %v, want FailedPrecondition", connect.CodeOf(err))
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

	head := variantAddr("d")
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
	err := h.client.RegisterEvidence(context.Background(), variantAddr("a"), nil)
	if err == nil {
		t.Fatal("RegisterEvidence with an empty consumed set: want error, got nil")
	}
	if h.httpc.calls != 0 {
		t.Errorf("HTTP calls = %d, want 0 (malformed set must be rejected before any network call)", h.httpc.calls)
	}

	err = h.client.RegisterEvidence(context.Background(), variantAddr("a"), []string{"not-a-content-address"})
	if err == nil {
		t.Fatal("RegisterEvidence with a malformed member: want error, got nil")
	}
	if h.httpc.calls != 0 {
		t.Errorf("HTTP calls = %d, want 0 (malformed member must be rejected before any network call)", h.httpc.calls)
	}
}

// --- P1-C: RegisterEvidence is mounted behind L1 authz IN ADDITION to the L2
// wireauth proof newHarness above exercises. newHarness deliberately mounts NO
// L1 interceptor (it isolates the wireauth layer); these tests add it back —
// a real deployment's actual mounting (see internal/netcompose.BuildHandler's
// authz := connect.WithInterceptors(auth.Interceptors(verifier)...)) — to
// prove auditclient can now present the bearer that gate requires.

// l1Harness is newHarness's L1-gated sibling: the SAME real AuditService and
// wireauth verifier, but the generated handler is ALSO mounted behind
// auth.Interceptors(a static verifier restricted to rules), matching
// production. A static (bearer-presence-only) verifier is the same fake the
// repo's own auth/e2e tests use (network/pkg/auth/auth_test.go,
// internal/netcompose/server_test.go) — it does not need to validate the
// bearer's VALUE, only that RegisterEvidence presents one when the mounted
// gate demands it.
func newL1Harness(t *testing.T, rules []endpoint.StaticRule) *harness {
	t.Helper()
	sgn, pub := signer(t, nodeDID)
	res := didResolver{nodeDID: authDoc(nodeDID, pub)}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: res,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Epoch:    time.Now().Add(-time.Hour),
		Window:   wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	receipts := auditor.NewMemReceiptStore()
	queue := auditor.NewMemQueue()
	// This harness isolates the L1 bearer layer, not the admission grammar —
	// any well-formed variant id is treated as admitted, mapped to an
	// arbitrary fixed body address (the tests below don't inspect receipts/
	// queue content).
	admitted := func(_ context.Context, headVariantID string) (string, bool, error) { return addr("0"), true, nil }
	evidence := auditor.NewEvidenceService(receipts, queue, admitted)

	authz := connect.WithInterceptors(auth.Interceptors(endpoint.NewStaticEndpoint(rules))...)
	h := handler.New(nil, evidence, v)
	path, hh := auditpbconnect.NewAuditServiceHandler(h, authz)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	httpc := &countingHTTPClient{inner: srv.Client()}
	return &harness{
		receipts: receipts,
		queue:    queue,
		client:   nil, // callers build their own client with the Bearer config under test
		url:      srv.URL,
		httpc:    httpc,
		signer:   sgn,
	}
}

// TestRegisterEvidence_BearerPresented_L1Passes proves a client configured
// with Config.Bearer reaches an L1-gated RegisterEvidence: the static
// verifier here checks ONLY bearer presence + the (audit, register) rule,
// so this fails unless the client actually sets the Authorization header.
func TestRegisterEvidence_BearerPresented_L1Passes(t *testing.T) {
	h := newL1Harness(t, []endpoint.StaticRule{{Resource: "audit", Action: "register"}})
	client := auditclient.New(auditclient.Config{
		Signer: h.signer, SignerDID: nodeDID, BaseURL: h.url, HTTPClient: h.httpc, Bearer: "test-l1-token",
	})
	if err := client.RegisterEvidence(context.Background(), variantAddr("a"), []string{addr("b")}); err != nil {
		t.Fatalf("RegisterEvidence with Bearer set: %v", err)
	}
}

// TestRegisterEvidence_NoBearer_L1RejectionPassesThrough proves that WITHOUT
// Config.Bearer, the client presents no Authorization header and the real L1
// rejection code (Unauthenticated — the static verifier's bearer-presence
// check, see endpoint.staticEndpoint.Verify) passes through unmangled, exactly
// as any other Connect error from this client does.
func TestRegisterEvidence_NoBearer_L1RejectionPassesThrough(t *testing.T) {
	h := newL1Harness(t, []endpoint.StaticRule{{Resource: "audit", Action: "register"}})
	client := auditclient.New(auditclient.Config{
		Signer: h.signer, SignerDID: nodeDID, BaseURL: h.url, HTTPClient: h.httpc,
	})
	err := client.RegisterEvidence(context.Background(), variantAddr("a"), []string{addr("b")})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no bearer: code = %v, want Unauthenticated (the L1 gate's bearer-presence rejection)", connect.CodeOf(err))
	}
}
