package commands_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	vcpb "github.com/provin-line/oss/gen/go/dplaax/vc/v1"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

const (
	bundleOriginDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:src"
	bundleChildDID  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:relay"
)

// bundleMemKS is the minimal keystore the credential builder needs.
type bundleMemKS struct{ keys map[string][]byte }

func (m *bundleMemKS) SaveKeyPair(didStr string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[didStr+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}

func (m *bundleMemKS) GetPrivateKey(didStr string, keyID keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[didStr+"#"+string(keyID)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return k, nil
}

func (m *bundleMemKS) DeleteKeys(string) error { return nil }

// stubVCResolver serves credentials from a map over the real ConnectRPC
// handler surface.
type stubVCResolver struct {
	vcpbconnect.UnimplementedVCResolverServiceHandler
	creds map[string][]byte
}

func (s stubVCResolver) ResolveVC(_ context.Context, req *connect.Request[vcpb.ResolveVCRequest]) (*connect.Response[vcpb.ResolveVCResponse], error) {
	b, ok := s.creds[req.Msg.GetHash()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such credential"))
	}
	return connect.NewResponse(&vcpb.ResolveVCResponse{Credential: b}), nil
}

func bundleDoc(t *testing.T, id, controller string, pub []byte) []byte {
	t.Helper()
	fields := did.DocumentFields{ID: id, Controller: controller}
	if pub != nil {
		vmID := id + "#signing"
		fields.VerificationMethod = []did.VerificationMethod{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: id,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}}
		fields.AssertionMethod = []string{vmID}
	}
	raw, err := did.New(fields).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal doc %s: %v", id, err)
	}
	return raw
}

// didRoutePath is the public resolution route for a DID under this registry.
func didRoutePath(didStr string) string {
	rest := strings.TrimPrefix(didStr, "did:dplaax:"+registryID+":")
	return "/did/" + strings.ReplaceAll(rest, ":", "/") + "/did.json"
}

// newBundleNode stands up the two wire surfaces bundle export consumes: the
// L1-gated VCResolverService and the public /did/ route.
func newBundleNode(t *testing.T) (srv *httptest.Server, head string) {
	t.Helper()
	gen := ed25519.Generator{}
	kpA, _ := gen.Generate()
	kpB, _ := gen.Generate()
	ks := &bundleMemKS{keys: map[string][]byte{}}
	_ = ks.SaveKeyPair(bundleOriginDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpA})
	_ = ks.SaveKeyPair(bundleChildDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpB})
	b := vc.NewBuilder(ed25519.NewSigner(ks))

	origin, err := b.BuildFirstDrop(bundleOriginDID, string(keystore.KeyIDSigning), bundleOriginDID+"#signing",
		vc.CredentialSubjectFields{
			PipelineID: "p1", ProcessID: "src", TransformationClaim: vc.ClaimConvert,
			InputHash:  "sha256:" + strings.Repeat("11", 32),
			OutputHash: "sha256:" + strings.Repeat("22", 32),
		}, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	child, err := b.BuildChainPreserving(bundleChildDID, string(keystore.KeyIDSigning), bundleChildDID+"#signing",
		vc.CredentialSubjectFields{
			PipelineID: "p1", ProcessID: "relay", TransformationClaim: vc.ClaimConvert,
			InputHash:  "sha256:" + strings.Repeat("22", 32),
			OutputHash: "sha256:" + strings.Repeat("33", 32),
		}, origin, nil)
	if err != nil {
		t.Fatalf("BuildChainPreserving: %v", err)
	}

	creds := map[string][]byte{}
	for _, c := range []*vc.PipelinePassCredential{origin, child} {
		h, _ := c.Hash()
		raw, _ := c.MarshalJSON()
		creds[h] = raw
	}
	head, _ = child.Hash()

	docs := map[string][]byte{
		didRoutePath(bundleOriginDID): bundleDoc(t, bundleOriginDID, ownerDID, kpA.PublicKey),
		didRoutePath(bundleChildDID):  bundleDoc(t, bundleChildDID, ownerDID, kpB.PublicKey),
		didRoutePath(ownerDID):        bundleDoc(t, ownerDID, ownerDID, nil),
	}

	mux := http.NewServeMux()
	rpcPath, h := vcpbconnect.NewVCResolverServiceHandler(stubVCResolver{creds: creds})
	mux.Handle(rpcPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/did/", func(w http.ResponseWriter, r *http.Request) {
		raw, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(raw)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, head
}

func TestBundleExportAndVerify_RoundTrip(t *testing.T) {
	srv, head := newBundleNode(t)
	dir := filepath.Join(t.TempDir(), "bundle")

	out := &bytes.Buffer{}
	err := commands.BundleExport(context.Background(), env(srv, out), commands.BundleExportConfig{
		Head:          head,
		Out:           dir,
		DIDBases:      map[string]string{registryID: srv.URL},
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("BundleExport: %v", err)
	}
	var digest string
	for _, line := range strings.Split(out.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "bundle digest: "); ok {
			digest = strings.TrimSpace(rest)
		}
	}
	if digest == "" {
		t.Fatalf("export output does not print the bundle digest:\n%s", out)
	}

	vout := &bytes.Buffer{}
	err = commands.BundleVerify(context.Background(), commands.Env{Stdout: vout}, commands.BundleVerifyConfig{
		Dir:    dir,
		Head:   head,
		Digest: digest,
	})
	if err != nil {
		t.Fatalf("BundleVerify: %v\noutput:\n%s", err, vout)
	}
	if !strings.Contains(vout.String(), "VERIFIED") {
		t.Errorf("verify output missing VERIFIED:\n%s", vout)
	}
}

func TestBundleVerify_RequiresAnAnchor(t *testing.T) {
	err := commands.BundleVerify(context.Background(), commands.Env{}, commands.BundleVerifyConfig{Dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("verify without anchors: err=%v, want anchor-required error", err)
	}
}

func TestBundleExport_RequiresToken(t *testing.T) {
	srv, head := newBundleNode(t)
	e := env(srv, &bytes.Buffer{})
	e.Token = ""
	err := commands.BundleExport(context.Background(), e, commands.BundleExportConfig{
		Head: head, Out: filepath.Join(t.TempDir(), "b"),
	})
	if err == nil {
		t.Fatal("export without a token: want error")
	}
}
