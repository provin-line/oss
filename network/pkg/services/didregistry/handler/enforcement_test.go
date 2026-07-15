package handler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	"github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/services/didregistry"
	"github.com/provin-line/oss/network/pkg/services/didregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/vc"
)

const (
	registry    = "poc.dplaax.dev"
	ownerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
	processDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
)

// --- in-memory keystore -----------------------------------------------------

type memKeyStore struct {
	mu   sync.Mutex
	keys map[string]map[keystore.KeyID]*crypto.KeyPair
}

func newMemKS() *memKeyStore {
	return &memKeyStore{keys: map[string]map[keystore.KeyID]*crypto.KeyPair{}}
}

func (m *memKeyStore) SaveKeyPair(d string, ks map[keystore.KeyID]*crypto.KeyPair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[d] = ks
	return nil
}

func (m *memKeyStore) GetPrivateKey(d string, keyID keystore.KeyID) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ks, ok := m.keys[d]; ok {
		if kp, ok := ks[keyID]; ok {
			return kp.PrivateKey, nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, nil)
}

func (m *memKeyStore) Sign(d string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(d, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
}

func (m *memKeyStore) DeleteKeys(d string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, d)
	return nil
}

// --- fixtures ---------------------------------------------------------------

func newSvc(t *testing.T) (*didregistry.Service, crypto.Signer, []byte) {
	t.Helper()
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	ownerKS := newMemKS()
	ownerKS.SaveKeyPair(ownerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP})
	svc := didregistry.New(
		yamlstore.New(t.TempDir()), newMemKS(), ed25519.Generator{}, ed25519.Verifier{}, registry,
		didregistry.WithClock(func() time.Time { return time.Date(2026, 6, 16, 9, 0, 0, 0, time.UTC) }),
	)
	return svc, ownerKS, ownerKP.PublicKey
}

func authClient(t *testing.T, svc *didregistry.Service, rules []endpoint.StaticRule) didpbconnect.DIDServiceClient {
	t.Helper()
	_, h := didpbconnect.NewDIDServiceHandler(
		handler.New(svc),
		connect.WithInterceptors(auth.Interceptors(endpoint.NewStaticEndpoint(rules))...),
	)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
}

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func signedOwnerDocBytes(t *testing.T, signer crypto.Signer, signPub []byte) []byte {
	t.Helper()
	// Multikey + issued contexts: this fixture models a NEW owner
	// (signer.suite.eddsa-jcs-2022 requires Multikey for the W3C-shaped proof
	// the production CreateProof now emits).
	vm, err := did.NewMultikeyVerificationMethod(ownerDID+"#signing", ownerDID, signPub)
	if err != nil {
		t.Fatalf("NewMultikeyVerificationMethod: %v", err)
	}
	base := did.New(did.DocumentFields{
		Context: did.IssuedDocumentContexts(),
		ID:      ownerDID, Controller: ownerDID,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{ownerDID + "#signing"},
	})
	body := base.Body()
	proof, err := vc.CreateProof(signer, ownerDID, string(keystore.KeyIDSigning), ownerDID+"#signing", body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	pb, _ := json.Marshal(proof)
	var pm map[string]any
	json.Unmarshal(pb, &pm)
	body["proof"] = pm
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func delegationBytes(t *testing.T, signer crypto.Signer, subject string) []byte {
	t.Helper()
	dlg, err := delegation.Build(signer, ownerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: ownerDID})
	if err != nil {
		t.Fatalf("delegation.Build: %v", err)
	}
	b, _ := json.Marshal(dlg)
	return b
}

func registerReq(t *testing.T, signer crypto.Signer, signPub []byte, token string) *connect.Request[didpb.RegisterOwnerRequest] {
	req := connect.NewRequest(&didpb.RegisterOwnerRequest{DidDocument: signedOwnerDocBytes(t, signer, signPub)})
	if token != "" {
		req.Header().Set("Authorization", "Bearer "+token)
	}
	return req
}

// --- authz enforcement (slice-3 pattern) ------------------------------------

func TestEnforcement_Allowed(t *testing.T) {
	svc, signer, pub := newSvc(t)
	c := authClient(t, svc, []endpoint.StaticRule{{Resource: "dids", Action: "register"}})
	if _, err := c.RegisterOwner(context.Background(), registerReq(t, signer, pub, "dummy")); err != nil {
		t.Errorf("allowed register: want success, got %v (code %v)", err, connect.CodeOf(err))
	}
}

func TestEnforcement_Denied(t *testing.T) {
	svc, signer, pub := newSvc(t)
	// Only "read" is allowed; "register" must be denied.
	c := authClient(t, svc, []endpoint.StaticRule{{Resource: "dids", Action: "read"}})
	_, err := c.RegisterOwner(context.Background(), registerReq(t, signer, pub, "dummy"))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("denied register: want PermissionDenied, got %v (%v)", connect.CodeOf(err), err)
	}
}

func TestEnforcement_MissingToken(t *testing.T) {
	svc, signer, pub := newSvc(t)
	c := authClient(t, svc, []endpoint.StaticRule{{Resource: "dids", Action: "register"}})
	_, err := c.RegisterOwner(context.Background(), registerReq(t, signer, pub, ""))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("missing token: want Unauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}
}

// --- end-to-end over connect (register → issue → resolve) -------------------

func TestE2E_RegisterIssueResolve(t *testing.T) {
	ctx := context.Background()
	svc, signer, pub := newSvc(t)
	c := authClient(t, svc, []endpoint.StaticRule{
		{Resource: "dids", Action: "register"},
		{Resource: "dids", Action: "issue"},
		{Resource: "dids", Action: "read"},
	})

	// Register the owner.
	regReq := connect.NewRequest(&didpb.RegisterOwnerRequest{DidDocument: signedOwnerDocBytes(t, signer, pub)})
	regReq.Header().Set("Authorization", "Bearer dummy")
	if _, err := c.RegisterOwner(ctx, regReq); err != nil {
		t.Fatalf("RegisterOwner: %v (code %v)", err, connect.CodeOf(err))
	}

	// Issue a pipeline, then a process under it.
	pipeReq := connect.NewRequest(&didpb.IssuePipelineRequest{TargetDid: pipelineDID, Delegation: delegationBytes(t, signer, pipelineDID)})
	pipeReq.Header().Set("Authorization", "Bearer dummy")
	if _, err := c.IssuePipeline(ctx, pipeReq); err != nil {
		t.Fatalf("IssuePipeline: %v (code %v)", err, connect.CodeOf(err))
	}
	procReq := connect.NewRequest(&didpb.IssueProcessRequest{TargetDid: processDID, Delegation: delegationBytes(t, signer, processDID)})
	procReq.Header().Set("Authorization", "Bearer dummy")
	procResp, err := c.IssueProcess(ctx, procReq)
	if err != nil {
		t.Fatalf("IssueProcess: %v (code %v)", err, connect.CodeOf(err))
	}

	// The issued process document round-trips through the opaque bytes.
	var procDoc did.DIDDocument
	if err := json.Unmarshal(procResp.Msg.GetDidDocument(), &procDoc); err != nil {
		t.Fatalf("unmarshal issued process doc: %v", err)
	}
	if procDoc.ID() != processDID || procDoc.Controller() != pipelineDID {
		t.Errorf("issued process doc id=%q controller=%q", procDoc.ID(), procDoc.Controller())
	}

	// Resolve the process DID over the wire.
	resReq := connect.NewRequest(&didpb.ResolveDIDRequest{Did: processDID})
	resReq.Header().Set("Authorization", "Bearer dummy")
	resResp, err := c.ResolveDID(ctx, resReq)
	if err != nil {
		t.Fatalf("ResolveDID: %v (code %v)", err, connect.CodeOf(err))
	}
	var resolved did.DIDDocument
	if err := json.Unmarshal(resResp.Msg.GetDidDocument(), &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.ID() != processDID {
		t.Errorf("resolved id=%q, want %q", resolved.ID(), processDID)
	}

	// The lifecycle log is served as canonical-JSON events whose SHA-256 the
	// next event's PrevEventHash would chain to.
	logReq := connect.NewRequest(&didpb.ReadLifecycleLogRequest{Did: processDID})
	logReq.Header().Set("Authorization", "Bearer dummy")
	logResp, err := c.ReadLifecycleLog(ctx, logReq)
	if err != nil {
		t.Fatalf("ReadLifecycleLog: %v", err)
	}
	if len(logResp.Msg.GetEvents()) != 1 {
		t.Errorf("process lifecycle log has %d events, want 1 (register)", len(logResp.Msg.GetEvents()))
	}
}

// The domain→Connect error mapping — this phase's core contract — is asserted
// over the wire for each code, not just the happy path.
func TestWireErrorMapping(t *testing.T) {
	ctx := context.Background()
	svc, signer, pub := newSvc(t)
	c := authClient(t, svc, []endpoint.StaticRule{
		{Resource: "dids", Action: "register"},
		{Resource: "dids", Action: "issue"},
		{Resource: "dids", Action: "read"},
	})
	auth := func(r interface{ Header() http.Header }) { r.Header().Set("Authorization", "Bearer dummy") }

	// (a) ResolveDID of an absent DID → NotFound.
	r1 := connect.NewRequest(&didpb.ResolveDIDRequest{Did: ownerDID})
	auth(r1)
	if _, err := c.ResolveDID(ctx, r1); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("absent resolve: want NotFound, got %v (%v)", connect.CodeOf(err), err)
	}

	// (b) Malformed did_document bytes → InvalidArgument (the docFromBytes boundary).
	r2 := connect.NewRequest(&didpb.RegisterOwnerRequest{DidDocument: []byte("{not json")})
	auth(r2)
	if _, err := c.RegisterOwner(ctx, r2); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("malformed doc: want InvalidArgument, got %v (%v)", connect.CodeOf(err), err)
	}

	// (c) Malformed delegation bytes → InvalidArgument (the strict-decoder boundary).
	r3 := connect.NewRequest(&didpb.IssuePipelineRequest{TargetDid: pipelineDID, Delegation: []byte(`{"dup":1,"dup":2}`)})
	auth(r3)
	if _, err := c.IssuePipeline(ctx, r3); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("malformed/duplicate-key delegation: want InvalidArgument, got %v (%v)", connect.CodeOf(err), err)
	}

	// (d) Duplicate issuance of the same target → AlreadyExists.
	reg := connect.NewRequest(&didpb.RegisterOwnerRequest{DidDocument: signedOwnerDocBytes(t, signer, pub)})
	auth(reg)
	if _, err := c.RegisterOwner(ctx, reg); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := 0; i < 2; i++ {
		ip := connect.NewRequest(&didpb.IssuePipelineRequest{TargetDid: pipelineDID, Delegation: delegationBytes(t, signer, pipelineDID)})
		auth(ip)
		_, err := c.IssuePipeline(ctx, ip)
		if i == 0 && err != nil {
			t.Fatalf("first issue: %v", err)
		}
		if i == 1 && connect.CodeOf(err) != connect.CodeAlreadyExists {
			t.Errorf("duplicate issue: want AlreadyExists, got %v (%v)", connect.CodeOf(err), err)
		}
	}
}
