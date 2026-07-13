package commands_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/cmd/provin/internal/commands"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
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
		return nil, fmt.Errorf("key not found: %w", keystore.ErrNotFound)
	}
	return k, nil
}

func (m *bundleMemKS) Sign(didStr string, keyID string, data []byte) ([]byte, error) {
	priv, err := m.GetPrivateKey(didStr, keystore.KeyID(keyID))
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, data)
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
	b := vc.NewBuilder(ks)

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

// --- aggregate-complete -------------------------------------------------------

const (
	aggIssuerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:agg:process:g1"
	sensAIssuer  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:sensa:process:a1"
	sensBIssuer  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:sensb:process:b1"
)

// stubAudit serves one consumed set, ONE ENTRY PER PAGE — exercising the
// CLI's continuation-token loop for real.
type stubAudit struct {
	auditpbconnect.UnimplementedAuditServiceHandler
	head     string
	consumed []string
}

func (s stubAudit) GetConsumedSources(_ context.Context, req *connect.Request[auditpb.GetConsumedSourcesRequest]) (*connect.Response[auditpb.GetConsumedSourcesResponse], error) {
	if req.Msg.GetHeadHash() != s.head {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no receipt"))
	}
	idx := 0
	if tok := req.Msg.GetPageToken(); tok != "" {
		i, err := strconv.Atoi(tok)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
		idx = i
	}
	resp := &auditpb.GetConsumedSourcesResponse{Consumed: []string{s.consumed[idx]}}
	if idx+1 < len(s.consumed) {
		resp.NextPageToken = strconv.Itoa(idx + 1)
	}
	return connect.NewResponse(resp), nil
}

// serviceDoc builds a DID document that ALSO advertises a #vc-resolver
// service — what the CLI's normative endpoint derivation resolves.
func serviceDoc(t *testing.T, id, controller string, pub []byte, vcResolverURL string) []byte {
	t.Helper()
	fields := did.DocumentFields{ID: id, Controller: controller}
	if pub != nil {
		vmID := id + "#signing"
		fields.VerificationMethod = []did.VerificationMethod{{
			ID: vmID, Type: "JsonWebKey2020", Controller: id,
			PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)},
		}}
		fields.AssertionMethod = []string{vmID}
	}
	if vcResolverURL != "" {
		fields.Service = []did.ServiceEndpoint{{ID: id + "#vc-resolver", Type: "VCResolver", ServiceEndpoint: vcResolverURL}}
	}
	raw, err := did.New(fields).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newAggregateNode stands up the aggregate-evidence wire surfaces: the
// L1-gated VCResolver + AuditService (one consumed entry per receipt page)
// and the public /did/ route. advertise selects what the issuer docs
// carry as their #vc-resolver service: "self" = the server's own URL
// (the normative derivation path), "" = nothing (only a split-horizon
// override can route source fetches).
func newAggregateNode(t *testing.T, advertise string) (srv *httptest.Server, head string, consumed []string) {
	t.Helper()
	gen := ed25519.Generator{}
	ks := &bundleMemKS{keys: map[string][]byte{}}
	pubs := map[string][]byte{}
	for _, d := range []string{sensAIssuer, sensBIssuer, aggIssuerDID} {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		_ = ks.SaveKeyPair(d, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp})
		pubs[d] = kp.PublicKey
	}
	b := vc.NewBuilder(ks)
	mk := func(issuer, pipe, proc, in string) *vc.PipelinePassCredential {
		c, err := b.BuildFirstDrop(issuer, string(keystore.KeyIDSigning), issuer+"#signing",
			vc.CredentialSubjectFields{PipelineID: pipe, ProcessID: proc, TransformationClaim: vc.ClaimConvert,
				InputHash: in, OutputHash: in}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	srcA := mk(sensAIssuer, "sensa", "a1", "sha256:"+strings.Repeat("11", 32))
	srcB := mk(sensBIssuer, "sensb", "b1", "sha256:"+strings.Repeat("22", 32))
	sources := []*vc.PipelinePassCredential{srcA, srcB}
	root, err := vc.ComputeSourceRoot(sources, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	issuers := []string{sensAIssuer, sensBIssuer}
	sort.Strings(issuers)
	agg, err := b.BuildFirstDrop(aggIssuerDID, string(keystore.KeyIDSigning), aggIssuerDID+"#signing",
		vc.CredentialSubjectFields{PipelineID: "agg", ProcessID: "g1", TransformationClaim: vc.ClaimAggregate,
			OutputHash: "sha256:" + strings.Repeat("33", 32)},
		&vc.SourceCommitment{DerivedFrom: issuers, SourceRoot: root, SourceRootCanonical: vc.SourceRootCanonicalJCS})
	if err != nil {
		t.Fatal(err)
	}
	head, _ = agg.Hash()
	aHash, _ := srcA.Hash()
	bHash, _ := srcB.Hash()
	consumed = []string{aHash, bHash}
	sort.Strings(consumed)

	creds := map[string][]byte{}
	for _, c := range []*vc.PipelinePassCredential{srcA, srcB, agg} {
		h, _ := c.Hash()
		raw, _ := c.MarshalJSON()
		creds[h] = raw
	}

	mux := http.NewServeMux()
	var advertiseURL string // set after NewServer; the doc handler closure reads it
	rpcPath, h := vcpbconnect.NewVCResolverServiceHandler(stubVCResolver{creds: creds})
	mux.Handle(rpcPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	auditPath, ah := auditpbconnect.NewAuditServiceHandler(stubAudit{head: head, consumed: consumed})
	mux.Handle(auditPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		ah.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/did/", func(w http.ResponseWriter, r *http.Request) {
		docs := map[string][]byte{
			didRoutePath(sensAIssuer):  serviceDoc(t, sensAIssuer, ownerDID, pubs[sensAIssuer], advertiseURL),
			didRoutePath(sensBIssuer):  serviceDoc(t, sensBIssuer, ownerDID, pubs[sensBIssuer], advertiseURL),
			didRoutePath(aggIssuerDID): serviceDoc(t, aggIssuerDID, ownerDID, pubs[aggIssuerDID], advertiseURL),
			didRoutePath(ownerDID):     serviceDoc(t, ownerDID, ownerDID, nil, ""),
		}
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
	if advertise == "self" {
		advertiseURL = srv.URL
	}
	return srv, head, consumed
}

func TestBundleExportAggregateComplete_RoundTrip(t *testing.T) {
	ctx := context.Background()
	srv, head, _ := newAggregateNode(t, "self")

	dir := filepath.Join(t.TempDir(), "bundle")
	out := &bytes.Buffer{}
	err := commands.BundleExport(ctx, env(srv, out), commands.BundleExportConfig{
		Head:              head,
		Out:               dir,
		DIDBases:          map[string]string{registryID: srv.URL},
		AllowLoopback:     true, // the guard now covers the DERIVED endpoints too
		AggregateComplete: true,
	})
	if err != nil {
		t.Fatalf("aggregate-complete BundleExport: %v", err)
	}
	if !strings.Contains(out.String(), "scope:          aggregate-complete") || !strings.Contains(out.String(), "receipts:       1 aggregate(s)") {
		t.Fatalf("export output missing aggregate lines:\n%s", out)
	}
	var digest string
	for _, line := range strings.Split(out.String(), "\n") {
		if rest, ok := strings.CutPrefix(line, "bundle digest: "); ok {
			digest = strings.TrimSpace(rest)
		}
	}

	vout := &bytes.Buffer{}
	if err := commands.BundleVerify(ctx, commands.Env{Stdout: vout}, commands.BundleVerifyConfig{
		Dir: dir, Head: head, Digest: digest,
	}); err != nil {
		t.Fatalf("BundleVerify: %v\n%s", err, vout)
	}
	if !strings.Contains(vout.String(), "source commitments:  1 over 2 bundled source(s)") {
		t.Fatalf("verify output missing the source-commitment line:\n%s", vout)
	}
}

// Without --allow-loopback the URLGuard rejects loopback targets across the
// WHOLE export path — the DID-document fetches and (Codex P1) the DERIVED
// endpoints (issuer registry base / advertised #vc-resolver) alike: the
// exporter must not be a bearer-carrying SSRF proxy. (The derived-endpoint
// guard shares the same URLGuard instance, asserted here through the
// fail-closed default.)
func TestBundleExportAggregateComplete_GuardRejectsDerivedLoopback(t *testing.T) {
	srv, head := newBundleNode(t)
	err := commands.BundleExport(context.Background(), env(srv, &bytes.Buffer{}), commands.BundleExportConfig{
		Head:              head,
		Out:               filepath.Join(t.TempDir(), "b"),
		DIDBases:          map[string]string{registryID: srv.URL},
		AllowLoopback:     false,
		AggregateComplete: true,
	})
	if err == nil {
		t.Fatal("derived loopback endpoints without --allow-loopback: want guard rejection")
	}
}

// The split-horizon override: when a registry's #vc-resolver advertisement
// is unreachable from the relying party's vantage (container DNS, NAT), an
// explicit --vc-resolver-base mapping substitutes the published address —
// here pinned by docs that advertise NOTHING, so only the override can
// make the export succeed.
func TestBundleExportAggregateComplete_VCResolverOverride(t *testing.T) {
	srv, head, _ := newAggregateNode(t, "" /* advertise nothing */)
	dir := filepath.Join(t.TempDir(), "bundle")
	out := &bytes.Buffer{}
	err := commands.BundleExport(context.Background(), env(srv, out), commands.BundleExportConfig{
		Head:              head,
		Out:               dir,
		DIDBases:          map[string]string{registryID: srv.URL},
		VCResolverBases:   map[string]string{registryID: srv.URL},
		AllowLoopback:     true,
		AggregateComplete: true,
	})
	if err != nil {
		t.Fatalf("export with the split-horizon override: %v", err)
	}
	if !strings.Contains(out.String(), "receipts:       1 aggregate(s)") {
		t.Fatalf("override export output:\n%s", out)
	}
}
