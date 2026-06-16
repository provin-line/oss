package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/o3co/protobuf.interceptors/endpoint"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	chainpbconnect "github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	didpb "github.com/provin-line/oss/gen/go/dplaax/did/v1"
	didpbconnect "github.com/provin-line/oss/gen/go/dplaax/did/v1/didpbconnect"
	signerpb "github.com/provin-line/oss/gen/go/dplaax/signer/v1"
	signerpbconnect "github.com/provin-line/oss/gen/go/dplaax/signer/v1/signerpbconnect"
	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	vcpbconnect "github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/vc"
)

const (
	registryID  = "poc.dplaax.dev"
	ownerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"
)

// assembled stands up the full mux over httptest with a static authorizer
// granting the rules the e2e exercises, and returns it with an owner signer
// (CLI-local key) and the owner's signing public key.
func assembled(t *testing.T) (*httptest.Server, crypto.Signer, []byte) {
	t.Helper()
	coreCfg := &core.CoreConfig{DataDir: t.TempDir(), ListenAddr: ":0", AllowLoopback: true}
	regCfg := &registry.RegistryConfig{ID: registryID}
	verifier := endpoint.NewStaticEndpoint([]endpoint.StaticRule{
		{Resource: "dids", Action: "register"},
		{Resource: "dids", Action: "issue"},
		{Resource: "dids", Action: "read"},
		{Resource: "signer", Action: "sign-vc"},
		{Resource: "vc", Action: "store"},
		{Resource: "vc", Action: "read"},
		{Resource: "chain", Action: "read"},
		{Resource: "chain", Action: "update-allowlist"},
	})
	h, err := BuildHandler(coreCfg, regCfg, verifier)
	if err != nil {
		t.Fatalf("BuildHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Owner's CLI-local signing key (held by the owner, not the registry).
	ownerKS := filestore.New(t.TempDir())
	ownerKP, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	if err := ownerKS.SaveKeyPair(ownerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: ownerKP}); err != nil {
		t.Fatalf("save owner key: %v", err)
	}
	return srv, ed25519.NewSigner(ownerKS), ownerKP.PublicKey
}

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func signedOwnerDocBytes(t *testing.T, signer crypto.Signer, signPub []byte) []byte {
	t.Helper()
	base := did.New(did.DocumentFields{
		ID: ownerDID, Controller: ownerDID,
		VerificationMethod: []did.VerificationMethod{{
			ID: ownerDID + "#signing", Type: "JsonWebKey2020", Controller: ownerDID,
			PublicKeyJWK: ed25519JWK(signPub),
		}},
		AssertionMethod: []string{ownerDID + "#signing"},
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

func bearer[T any](req *connect.Request[T]) *connect.Request[T] {
	req.Header().Set("Authorization", "Bearer dummy")
	return req
}

// The walking-skeleton proof: register → issue → resolve → sign across all three
// services in one assembled process, sharing one file keystore.
func TestBoot_RegisterIssueResolveSign(t *testing.T) {
	ctx := context.Background()
	srv, ownerSigner, ownerPub := assembled(t)
	didClient := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
	signerClient := signerpbconnect.NewSignerServiceClient(srv.Client(), srv.URL)

	// Register the owner.
	if _, err := didClient.RegisterOwner(ctx, bearer(connect.NewRequest(&didpb.RegisterOwnerRequest{
		DidDocument: signedOwnerDocBytes(t, ownerSigner, ownerPub),
	}))); err != nil {
		t.Fatalf("RegisterOwner: %v (code %v)", err, connect.CodeOf(err))
	}

	// Issue a pipeline (registry generates + stores its keys in the shared keystore).
	dlg, err := delegation.Build(ownerSigner, ownerDID, delegation.DelegationSubject{ID: pipelineDID, DelegatedBy: ownerDID})
	if err != nil {
		t.Fatalf("delegation.Build: %v", err)
	}
	dlgBytes, _ := json.Marshal(dlg)
	issued, err := didClient.IssuePipeline(ctx, bearer(connect.NewRequest(&didpb.IssuePipelineRequest{
		TargetDid: pipelineDID, Delegation: dlgBytes,
	})))
	if err != nil {
		t.Fatalf("IssuePipeline: %v (code %v)", err, connect.CodeOf(err))
	}

	// Resolve the pipeline over the RPC.
	res, err := didClient.ResolveDID(ctx, bearer(connect.NewRequest(&didpb.ResolveDIDRequest{Did: pipelineDID})))
	if err != nil {
		t.Fatalf("ResolveDID: %v", err)
	}
	var resolved did.DIDDocument
	if err := json.Unmarshal(res.Msg.GetDidDocument(), &resolved); err != nil {
		t.Fatalf("unmarshal resolved: %v", err)
	}
	if resolved.ID() != pipelineDID {
		t.Errorf("resolved id = %q, want %q", resolved.ID(), pipelineDID)
	}

	// Sign with the pipeline's registry-held #signing key via the Signer service,
	// and verify against the issued document's signing key — proving did + signer
	// + keystore interoperate over the shared store.
	var issuedDoc did.DIDDocument
	if err := json.Unmarshal(issued.Msg.GetDidDocument(), &issuedDoc); err != nil {
		t.Fatalf("unmarshal issued: %v", err)
	}
	signPub, err := did.ExtractPublicKey(&issuedDoc, pipelineDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey: %v", err)
	}
	data := []byte("payload to sign")
	sigResp, err := signerClient.Sign(ctx, bearer(connect.NewRequest(&signerpb.SignRequest{
		Did: pipelineDID, KeyId: "signing", Data: data,
	})))
	if err != nil {
		t.Fatalf("Signer.Sign: %v (code %v)", err, connect.CodeOf(err))
	}
	ok, err := (ed25519.Verifier{}).Verify(signPub, data, sigResp.Msg.GetSignature())
	if err != nil || !ok {
		t.Fatalf("signature verify: ok=%v err=%v", ok, err)
	}
}

// The ChainService (L1 operator surface) is mounted in the assembled stack: an
// authorized UpdateAllowList and ListSubscriptions route through the mux and the
// authz gate. This covers routing + the gate, not write-content (the allow-list
// has no read RPC and ListSubscriptions reads a different store); rule-persistence
// correctness is covered at the domain/handler level.
func TestBoot_ChainOperator(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := assembled(t)
	chainClient := chainpbconnect.NewChainServiceClient(srv.Client(), srv.URL)

	if _, err := chainClient.UpdateAllowList(ctx, bearer(connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: pipelineDID,
		Rules:       []*chainpb.AllowRule{{Pattern: "did:dplaax:*:org:acme:*"}},
	}))); err != nil {
		t.Fatalf("UpdateAllowList: %v (code %v)", err, connect.CodeOf(err))
	}
	resp, err := chainClient.ListSubscriptions(ctx, bearer(connect.NewRequest(&chainpb.ListSubscriptionsRequest{})))
	if err != nil {
		t.Fatalf("ListSubscriptions: %v (code %v)", err, connect.CodeOf(err))
	}
	if len(resp.Msg.GetSubscriptions()) != 0 {
		t.Errorf("fresh store ListSubscriptions = %d, want 0", len(resp.Msg.GetSubscriptions()))
	}
}

func TestBoot_Healthz(t *testing.T) {
	srv, _, _ := assembled(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestBoot_PublicResolution(t *testing.T) {
	ctx := context.Background()
	srv, ownerSigner, ownerPub := assembled(t)
	didClient := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
	if _, err := didClient.RegisterOwner(ctx, bearer(connect.NewRequest(&didpb.RegisterOwnerRequest{
		DidDocument: signedOwnerDocBytes(t, ownerSigner, ownerPub),
	}))); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	// The resolution route is public (no auth header).
	resp, err := http.Get(srv.URL + "/did/org/acme/did.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolution status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/did+json" {
		t.Errorf("content-type = %q, want application/did+json", ct)
	}
	var doc did.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID() != ownerDID {
		t.Errorf("resolved id = %q, want %q", doc.ID(), ownerDID)
	}
}

func TestBoot_RPCRequiresAuth(t *testing.T) {
	// The connect services sit behind the interceptor: no bearer token → Unauthenticated.
	srv, _, _ := assembled(t)
	didClient := didpbconnect.NewDIDServiceClient(srv.Client(), srv.URL)
	_, err := didClient.ResolveDID(context.Background(), connect.NewRequest(&didpb.ResolveDIDRequest{Did: ownerDID}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no token: want Unauthenticated, got %v (%v)", connect.CodeOf(err), err)
	}
}

// VCResolverService is mounted in the assembled stack: store a VC and resolve it
// back at its returned content address. The unresolved-pool enqueue path is
// unit-covered (vcresolver_test) rather than here: the pool has no wire surface
// this slice (ListUnresolved is deferred), so it is intentionally unobservable
// over the assembled mux.
func TestBoot_VCStoreResolve(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := assembled(t)
	vcClient := vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL)

	credential, _ := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            pipelineDID,
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "proc1"},
	})
	stored, err := vcClient.StoreVC(ctx, bearer(connect.NewRequest(&vcpb.StoreVCRequest{Credential: credential})))
	if err != nil {
		t.Fatalf("StoreVC: %v (code %v)", err, connect.CodeOf(err))
	}
	hash := stored.Msg.GetHash()
	if hash == "" {
		t.Fatal("empty hash")
	}
	got, err := vcClient.ResolveVC(ctx, bearer(connect.NewRequest(&vcpb.ResolveVCRequest{Hash: hash})))
	if err != nil {
		t.Fatalf("ResolveVC: %v", err)
	}
	var resolved vc.PipelinePassCredential
	if err := json.Unmarshal(got.Msg.GetCredential(), &resolved); err != nil {
		t.Fatalf("unmarshal resolved: %v", err)
	}
	if resolved.Issuer() != pipelineDID {
		t.Errorf("resolved issuer = %q, want %q", resolved.Issuer(), pipelineDID)
	}
}
