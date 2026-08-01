package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	auditpbconnect "github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	schemapb "github.com/provin-line/oss/gen/go/dplaax/schema/v1"
	"github.com/provin-line/oss/gen/go/dplaax/schema/v1/schemapbconnect"
	vcpbconnect "github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	auditorfilestore "github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	audithandler "github.com/provin-line/oss/network/pkg/services/auditor/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/storehandler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemaclient "github.com/provin-line/oss/network/pkg/services/schemaregistry/client"
	schemahandler "github.com/provin-line/oss/network/pkg/services/schemaregistry/handler"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	vcresolvermemstore "github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/vc"
)

// ─────────────────────────────────────────────────────────────────────────
// pipelineRuntimeConfigFrom — the transport guard + a basic field-level
// round-trip (the full per-role field mapping originally mirrored
// cmd/standalone's own runtimewiring_test.go golden test, now retired; this
// remains a lighter pin, not a full golden-mapping fixture).
// ─────────────────────────────────────────────────────────────────────────

func TestPipelineRuntimeConfigFrom_NonNATSTransportWithLoopsErrors(t *testing.T) {
	chainCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	pipeCfg := &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{Name: "src", Role: pipelineconfig.RoleSource}}}
	_, err := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, "")
	if err == nil {
		t.Fatal("want error for loops on a non-nats transport, got nil")
	}
	if got := err.Error(); got != `data-plane loops require the nats transport, got "noop"` {
		t.Errorf("err = %q, want the exact transport-guard message", got)
	}
}

func TestPipelineRuntimeConfigFrom_NonNATSTransportZeroLoopsOK(t *testing.T) {
	chainCfg := &chainconfig.Config{Transport: chainconfig.TransportNoop}
	pipeCfg := &pipelineconfig.Config{}
	cfg, err := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, "")
	if err != nil {
		t.Fatalf("zero loops on a non-nats transport: %v", err)
	}
	if len(cfg.Loops) != 0 {
		t.Errorf("Loops = %+v, want empty", cfg.Loops)
	}
}

func TestPipelineRuntimeConfigFrom_MapsNATSAndDataDirDerivedPaths(t *testing.T) {
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS: chainconfig.NATSConfig{
			URL:         "nats://broker.example:4222",
			AccountSeed: "SAAAACCOUNTSEED",
			ConnectWait: 7 * time.Second,
		},
	}
	pipeCfg := &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "src",
		Role:           pipelineconfig.RoleSource,
		IngressSubject: "ingest.src",
		Source: pipelineconfig.SourceConfig{
			OutputSubject: "did:dplaax:reg:org:acme:pipeline:src",
			Issuer: pipelineconfig.IssuerConfig{
				DID: "did:dplaax:reg:org:acme:pipeline:src:process:s1", KeyID: "signing",
				VerificationMethod: "did:dplaax:reg:org:acme:pipeline:src:process:s1#signing",
			},
			PipelineID: "src", ProcessID: "s1", TransformationClaim: vc.ClaimConvert,
		},
	}}}

	cfg, err := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, "/data")
	if err != nil {
		t.Fatalf("pipelineRuntimeConfigFrom: %v", err)
	}
	if cfg.NATS != (pipelineruntime.NATSConfig{URL: "nats://broker.example:4222", AccountSeed: "SAAAACCOUNTSEED", ConnectWait: 7 * time.Second}) {
		t.Errorf("NATS = %+v", cfg.NATS)
	}
	if cfg.TlogDir != "/data/tlog" {
		t.Errorf("TlogDir = %q, want /data/tlog", cfg.TlogDir)
	}
	if cfg.RejectLogDir != "/data/evidence/sink-rejects" {
		t.Errorf("RejectLogDir = %q, want /data/evidence/sink-rejects", cfg.RejectLogDir)
	}
	if len(cfg.Loops) != 1 || cfg.Loops[0].Name != "src" || cfg.Loops[0].Source.OutputSubject != "did:dplaax:reg:org:acme:pipeline:src" {
		t.Errorf("Loops = %+v", cfg.Loops)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// auditClientFactory — cache-per-DID (pure, no network).
// ─────────────────────────────────────────────────────────────────────────

func TestAuditClientFactory_CachesPerDID(t *testing.T) {
	f := newAuditClientFactory(nil, "http://example.invalid", "", http.DefaultClient)
	a1 := f.For("did:dplaax:reg:org:acme:pipeline:agg:process:a1")
	a2 := f.For("did:dplaax:reg:org:acme:pipeline:agg:process:a1")
	if a1 != a2 {
		t.Error("For(sameDID) returned two different clients, want the cached one")
	}
	b1 := f.For("did:dplaax:reg:org:acme:pipeline:agg:process:b1")
	if a1 == b1 {
		t.Error("For(differentDID) returned the SAME client as another DID")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// wireSchemaGetter / wireSchemaBridge — real SchemaService over httptest,
// mirroring network/pkg/services/schemaregistry/client/client_test.go's own
// harness and internal/netcompose/schemaresolver_test.go's assertions (the
// bridge this type must mirror EXACTLY).
// ─────────────────────────────────────────────────────────────────────────

func schemaRegistryServer(t *testing.T) (url string, httpc *http.Client, seed schemapbconnect.SchemaServiceClient) {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC) }
	svc := schemaregistry.New(yamlstore.New(t.TempDir()), schemaregistry.WithClock(clock))
	_, h := schemapbconnect.NewSchemaServiceHandler(schemahandler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client(), schemapbconnect.NewSchemaServiceClient(srv.Client(), srv.URL)
}

func TestWireSchemaGetter_Get(t *testing.T) {
	url, httpc, seed := schemaRegistryServer(t)
	body := []byte(`{"type":"object"}`)
	resp, err := seed.RegisterSchema(context.Background(), connect.NewRequest(&schemapb.RegisterSchemaRequest{
		Name: "reading", SchemaFormat: "JsonSchema", SchemaBody: body,
	}))
	if err != nil {
		t.Fatalf("RegisterSchema: %v", err)
	}
	version := resp.Msg.GetSchema().GetVersion()

	g := wireSchemaGetter{client: schemaclient.New(schemaclient.Config{BaseURL: url, HTTPClient: httpc})}

	got, err := g.Get(context.Background(), "reading", version)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Format != "JsonSchema" || string(got.Body) != string(body) || got.Deprecated {
		t.Errorf("Get = %+v", got)
	}

	if _, err := g.Get(context.Background(), "reading", "2026-06-14-deadbeefdeadbeef"); !errors.Is(err, pipelineruntime.ErrSchemaNotFound) {
		t.Errorf("Get(unknown) err = %v, want pipelineruntime.ErrSchemaNotFound", err)
	}
}

func TestWireSchemaBridge_ResolveSchema(t *testing.T) {
	url, httpc, seed := schemaRegistryServer(t)
	body := []byte(`{"type":"object"}`)
	resp, err := seed.RegisterSchema(context.Background(), connect.NewRequest(&schemapb.RegisterSchemaRequest{
		Name: "orders", SchemaFormat: "JsonSchema", SchemaBody: body,
	}))
	if err != nil {
		t.Fatalf("RegisterSchema: %v", err)
	}
	version := resp.Msg.GetSchema().GetVersion()

	r := wireSchemaBridge{client: schemaclient.New(schemaclient.Config{BaseURL: url, HTTPClient: httpc})}

	// Valid canonical URI resolves to body + format.
	got, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: "dplaax:schema/orders@" + version})
	if err != nil {
		t.Fatalf("ResolveSchema: %v", err)
	}
	if got.Format != "JsonSchema" || string(got.Body) != string(body) {
		t.Errorf("resolved = %+v, want JsonSchema + body", got)
	}

	// Malformed IDs -> ErrSchemaInvalidRef (deterministic, mapped to failed).
	for _, bad := range []string{"not-a-schema-uri", "dplaax:schema/.@" + version, "dplaax:schema/..@" + version} {
		if _, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: bad}); !errors.Is(err, vc.ErrSchemaInvalidRef) {
			t.Errorf("ResolveSchema(%q) err = %v, want ErrSchemaInvalidRef", bad, err)
		}
	}

	// Well-formed but unregistered -> ErrSchemaNotFound (definitive).
	if _, err := r.ResolveSchema(context.Background(), vc.SchemaRef{ID: "dplaax:schema/gone@" + version}); !errors.Is(err, vc.ErrSchemaNotFound) {
		t.Errorf("missing schema err = %v, want ErrSchemaNotFound", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// vcStoreAdapter — real VCResolverService over httptest, mirroring
// network/pkg/services/vcresolver/client/client_test.go's own harness.
// ─────────────────────────────────────────────────────────────────────────

func newVCStoreAdapter(t *testing.T) (vcStoreAdapter, string, *http.Client) {
	t.Helper()
	svc := vcresolver.New(vcresolver.NewVariantStore(vcresolvermemstore.NewBackend()), vcresolvermemstore.NewPool())
	_, h := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(svc))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL))
	return vcStoreAdapter{client: client}, srv.URL, srv.Client()
}

func minimalCredentialBytes(t *testing.T, issuer string, prev any) []byte {
	t.Helper()
	subject := map[string]any{"pipelineId": "p1", "processId": "proc1"}
	if prev != nil {
		subject["previousCredential"] = prev
	}
	b, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuer,
		"credentialSubject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVCStoreAdapter_StoreVC_RoundTrip(t *testing.T) {
	adapter, _, _ := newVCStoreAdapter(t)
	credBytes := minimalCredentialBytes(t, "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1", nil)

	head, err := adapter.StoreVC(context.Background(), credBytes, "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}
	if head.BodyAddress == "" || head.WireVariantID == "" {
		t.Errorf("StoreVC head = %+v, want both fields populated", head)
	}

	// The wire StoreVC RPC has no assembly-depth field: a non-zero value must
	// fail loud, never be silently dropped.
	if _, err := adapter.StoreVC(context.Background(), credBytes, "", 1); err == nil {
		t.Error("StoreVC with assemblyDepth=1: want error, got nil")
	}
}

func TestVCStoreAdapter_StoreCredential_RoundTrip(t *testing.T) {
	adapter, _, _ := newVCStoreAdapter(t)
	var cred vc.PipelinePassCredential
	if err := json.Unmarshal(minimalCredentialBytes(t, "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1", nil), &cred); err != nil {
		t.Fatal(err)
	}

	want, err := cred.Hash()
	if err != nil {
		t.Fatal(err)
	}
	sc, err := adapter.StoreCredential(context.Background(), &cred, "")
	if err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if sc.BodyAddress != want {
		t.Errorf("BodyAddress = %q, want %q", sc.BodyAddress, want)
	}
}

func TestFallbackCredentialResolver_UsesDeclaredUpstreamAfterLocalMiss(t *testing.T) {
	localStore, _, _ := newVCStoreAdapter(t)
	upstreamStore, _, _ := newVCStoreAdapter(t)
	var credential vc.PipelinePassCredential
	if err := json.Unmarshal(minimalCredentialBytes(t, "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1", nil), &credential); err != nil {
		t.Fatal(err)
	}
	stored, err := upstreamStore.StoreCredential(context.Background(), &credential, "")
	if err != nil {
		t.Fatal(err)
	}
	resolver := fallbackCredentialResolver{local: localStore.client, upstream: upstreamStore.client}
	got, err := resolver.ResolveCredential(context.Background(), stored.BodyAddress)
	if err != nil {
		t.Fatalf("fallback resolve: %v", err)
	}
	gotAddress, err := got.Hash()
	if err != nil || gotAddress != stored.BodyAddress {
		t.Fatalf("resolved address=%q err=%v, want %q", gotAddress, err, stored.BodyAddress)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// wireAuditRegistrar + wireReceiptWriter — a combined VCResolverService +
// AuditService harness over ONE httptest server (the "ONE registry base
// URL" this binary always assumes), a real wireauth.Verifier, and the
// production auditClientFactory/vcresolverclient this file's own adapters
// wrap. Mirrors network/pkg/services/auditor/client/client_test.go's own
// harness shape.
// ─────────────────────────────────────────────────────────────────────────

const wireNodeDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:node:process:n1"
const wireAggregateIssuerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:agg:process:a1"

func addr(hexDigit string) string { return "sha256:" + strings.Repeat(hexDigit, 64) }

type fakeDIDResolver map[string]*did.DIDDocument

func (m fakeDIDResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, wireauth.ErrKeyResolution
	}
	return doc, nil
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

// wireHarness stands up a real VCResolverService + AuditService (evidence
// write surface) on ONE httptest server, backed by a real vcresolver.Service
// and a real file-backed auditor.ReceiptStore (so the test can read the raw
// on-disk envelope, mirroring auditor/client's own round-trip test — the
// registrant DID has no public Go reader).
type wireHarness struct {
	vcSvc      *vcresolver.Service
	receipts   auditor.ReceiptStore
	receiptDir string
	queue      *auditor.MemQueue
	url        string
	httpc      *http.Client
	signer     crypto.Signer
}

func newWireHarness(t *testing.T) *wireHarness {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}

	resolver := fakeDIDResolver{}
	sign := func(subject string) {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
			t.Fatal(err)
		}
		resolver[subject] = authDoc(subject, kp.PublicKey)
	}
	sign(wireNodeDID)
	sign(wireAggregateIssuerDID)

	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Epoch:    time.Now().Add(-time.Hour),
		Window:   wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	receiptDir := t.TempDir()
	receipts, err := auditorfilestore.NewReceiptStore(receiptDir)
	if err != nil {
		t.Fatalf("NewReceiptStore: %v", err)
	}
	queue := auditor.NewMemQueue()
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(vcresolvermemstore.NewBackend()), vcresolvermemstore.NewPool())
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

	mux := http.NewServeMux()
	vcPath, vcHandler := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(vcSvc))
	mux.Handle(vcPath, vcHandler)
	auditPath, auditHandler := auditpbconnect.NewAuditServiceHandler(audithandler.New(nil, evidence, v))
	mux.Handle(auditPath, auditHandler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &wireHarness{
		vcSvc:      vcSvc,
		receipts:   receipts,
		receiptDir: receiptDir,
		queue:      queue,
		url:        srv.URL,
		httpc:      srv.Client(),
		signer:     ks,
	}
}

func (h *wireHarness) vcClient() *vcresolverclient.Resolver {
	return vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(h.httpc, h.url))
}

func TestWireAuditRegistrar_Add_RoundTrip(t *testing.T) {
	h := newWireHarness(t)
	store := vcStoreAdapter{client: h.vcClient()}
	head, err := store.StoreVC(context.Background(), minimalCredentialBytes(t, wireNodeDID, nil), "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}

	factory := newAuditClientFactory(h.signer, h.url, "", h.httpc)
	registrar := wireAuditRegistrar{client: factory.For(wireNodeDID)}
	if err := registrar.Add(head); err != nil {
		t.Fatalf("Add: %v", err)
	}

	cands, err := h.queue.ListNewest(10)
	if err != nil {
		t.Fatalf("ListNewest: %v", err)
	}
	if len(cands) != 1 || cands[0].HeadHash != head.BodyAddress {
		t.Errorf("queue = %+v, want exactly one candidate for %q", cands, head.BodyAddress)
	}
}

// receiptEnvelope mirrors the on-disk shape auditor/filestore.ReceiptStore
// writes — registrant_did has no public Go reader (see
// auditor.ReceiptStore.Put's own doc), so reading the raw file is the only
// way to assert who a registration recorded as registrant, exactly as
// auditor/client/client_test.go's own round-trip test does.
type receiptEnvelope struct {
	RegistrantDID string `json:"registrant_did"`
}

func readReceiptEnvelope(t *testing.T, dir, bodyAddress string) receiptEnvelope {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(bodyAddress, "sha256:")+".json"))
	if err != nil {
		t.Fatalf("read receipt envelope: %v", err)
	}
	var env receiptEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal receipt envelope: %v", err)
	}
	return env
}

// TestWireReceiptWriter_Put_ResolvesVariantAndSignsAsRegistrant proves the
// resolve round-trip this adapter's doc comment describes: Put receives only
// a BODY address (headHash), re-resolves the credential over the wire,
// recomputes the wire variant, and registers evidence signed as
// registrantDID — read back via the raw receipt envelope's registrant_did
// field, the same verification auditor/client's own round-trip test uses.
func TestWireReceiptWriter_Put_ResolvesVariantAndSignsAsRegistrant(t *testing.T) {
	h := newWireHarness(t)
	vcClient := h.vcClient()
	store := vcStoreAdapter{client: vcClient}

	head, err := store.StoreVC(context.Background(), minimalCredentialBytes(t, wireAggregateIssuerDID, nil), "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}

	factory := newAuditClientFactory(h.signer, h.url, "", h.httpc)
	writer := wireReceiptWriter{resolver: vcClient, factory: factory}
	consumed := []string{addr("c"), addr("b")}
	if err := writer.Put(head.BodyAddress, wireAggregateIssuerDID, consumed); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := h.receipts.Get(head.BodyAddress)
	if err != nil {
		t.Fatalf("receipts.Get: %v", err)
	}
	if len(got) != 2 || got[0] != addr("b") || got[1] != addr("c") {
		t.Errorf("receipt consumed set = %v, want canonical [%s %s]", got, addr("b"), addr("c"))
	}

	env := readReceiptEnvelope(t, h.receiptDir, head.BodyAddress)
	if env.RegistrantDID != wireAggregateIssuerDID {
		t.Errorf("registrant_did = %q, want %q", env.RegistrantDID, wireAggregateIssuerDID)
	}

	cands, err := h.queue.ListNewest(10)
	if err != nil {
		t.Fatalf("ListNewest: %v", err)
	}
	if len(cands) != 1 || cands[0].HeadHash != head.BodyAddress {
		t.Errorf("queue = %+v, want exactly one candidate for %q", cands, head.BodyAddress)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// payloadClientFactory / wirePayloadStore — the D9 fix: RetainPayload
// requires owner_did == the wireauth-proven signer (storehandler's
// errOwnerMismatch), so a node running more than one producing loop (each
// with its OWN output subject) needs one signing client PER owner, not one
// shared node-identity client. This harness proves the fix directly: a real
// storehandler.Handler + wireauth.Verifier + memstore over httptest, driven
// through wirePayloadStore for TWO DIFFERENT owner DIDs sharing ONE
// keystore — both retains must succeed, each recorded under its OWN owner.
// ─────────────────────────────────────────────────────────────────────────

func TestPayloadClientFactory_CachesPerDID(t *testing.T) {
	f := newPayloadClientFactory(nil, "http://example.invalid", "", http.DefaultClient, 0)
	a1 := f.For("did:dplaax:reg:org:acme:pipeline:src1")
	a2 := f.For("did:dplaax:reg:org:acme:pipeline:src1")
	if a1 != a2 {
		t.Error("For(sameDID) returned two different clients, want the cached one")
	}
	b1 := f.For("did:dplaax:reg:org:acme:pipeline:agg")
	if a1 == b1 {
		t.Error("For(differentDID) returned the SAME client as another DID")
	}
}

const (
	payloadOwnerA = "did:dplaax:reg:org:acme:pipeline:src1"
	payloadOwnerB = "did:dplaax:reg:org:acme:pipeline:agg"
)

// payloadRetainHarness stands up a real storehandler.Handler (over a real
// memstore.Store) behind a real wireauth.Verifier, served over httptest —
// mirrors network/pkg/services/payloadresolver/storehandler/retain_e2e_test.
// go's own harness shape, reusing THIS file's fakeDIDResolver/authDoc/jwk
// helpers (defined above for the audit/receipt harness).
type payloadRetainHarness struct {
	store *memstore.Store
	ks    *ksfilestore.Store
	url   string
	httpc *http.Client
}

func newPayloadRetainHarness(t *testing.T, owners ...string) *payloadRetainHarness {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}
	resolver := fakeDIDResolver{}
	for _, owner := range owners {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.SaveKeyPair(owner, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
			t.Fatal(err)
		}
		resolver[owner] = authDoc(owner, kp.PublicKey)
	}

	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Epoch:    time.Now().Add(-time.Hour),
		Window:   wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	store := memstore.New()
	h := storehandler.New(store, v, 1<<20)
	path, hh := payloadpbconnect.NewPayloadStoreServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &payloadRetainHarness{store: store, ks: ks, url: srv.URL, httpc: srv.Client()}
}

// TestWirePayloadStore_SignsEachRetainAsItsOwnOwner is the D9 fix's core
// proof: ONE wirePayloadStore (backed by ONE payloadClientFactory, ONE
// shared keystore) retains payloads for TWO DIFFERENT owner DIDs — the exact
// topology a node running two producing loops with different output
// subjects needs. Before the fix, ONE shared client signed every retain as a
// single node identity, so at most one of these two calls could ever
// satisfy storehandler's owner_did == proven-signer requirement; both must
// now succeed, each recorded under its OWN owner.
func TestWirePayloadStore_SignsEachRetainAsItsOwnOwner(t *testing.T) {
	h := newPayloadRetainHarness(t, payloadOwnerA, payloadOwnerB)
	factory := newPayloadClientFactory(h.ks, h.url, "", h.httpc, 0)
	store := wirePayloadStore{factory: factory}

	payloadA := []byte("bytes produced by src1's output subject")
	addrA, err := store.Store(context.Background(), payloadA, payloadOwnerA)
	if err != nil {
		t.Fatalf("Store(ownerA): %v", err)
	}
	gotA, ownersA, err := h.store.Get(addrA)
	if err != nil {
		t.Fatalf("Get(addrA): %v", err)
	}
	if string(gotA) != string(payloadA) || len(ownersA) != 1 || ownersA[0] != payloadOwnerA {
		t.Errorf("ownerA retain: bytes=%q owners=%v, want %q owned by [%s]", gotA, ownersA, payloadA, payloadOwnerA)
	}

	payloadB := []byte("bytes produced by agg's DIFFERENT output subject")
	addrB, err := store.Store(context.Background(), payloadB, payloadOwnerB)
	if err != nil {
		t.Fatalf("Store(ownerB): %v", err)
	}
	gotB, ownersB, err := h.store.Get(addrB)
	if err != nil {
		t.Fatalf("Get(addrB): %v", err)
	}
	if string(gotB) != string(payloadB) || len(ownersB) != 1 || ownersB[0] != payloadOwnerB {
		t.Errorf("ownerB retain: bytes=%q owners=%v, want %q owned by [%s]", gotB, ownersB, payloadB, payloadOwnerB)
	}

	// The factory must have cached (and reused) a distinct client per owner —
	// never one shared client the way the pre-fix wiring did.
	if factory.For(payloadOwnerA) == factory.For(payloadOwnerB) {
		t.Error("factory returned the SAME client for two different owners")
	}
}

// TestWirePayloadStore_MissingOwnerKey_Errors proves a keystore that never
// held a key for the claimed owner fails the retain (no silent bypass) —
// the exact runtime symptom the D9 boot preflight (main.go) exists to catch
// before it ever reaches this wire call.
func TestWirePayloadStore_MissingOwnerKey_Errors(t *testing.T) {
	h := newPayloadRetainHarness(t, payloadOwnerA) // payloadOwnerB's key is never provisioned
	factory := newPayloadClientFactory(h.ks, h.url, "", h.httpc, 0)
	store := wirePayloadStore{factory: factory}

	if _, err := store.Store(context.Background(), []byte("orphan bytes"), payloadOwnerB); err == nil {
		t.Fatal("Store with no key for the owner: want error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// payloadClientFactory's chunk size (P2 Codex fix, branch review): the
// factory previously always used payloadclient.DefaultRetainChunkSize (256
// KiB) regardless of pipeCfg.MaxRetainChunkSize, so a registry configured
// with a SMALLER cap rejected every frame (ResourceExhausted), aborting the
// whole emission. newPayloadRetainHarnessWithChunkCap reproduces production's
// EXACT server-side mount (internal/netcompose/server.go's retainChunkCap :=
// connect.WithReadMaxBytes(maxRetainChunkSize)) so this is a real end-to-end
// proof, not just a Config struct-literal assertion.
// ─────────────────────────────────────────────────────────────────────────

// newPayloadRetainHarnessWithChunkCap is newPayloadRetainHarness's sibling
// that additionally mounts connect.WithReadMaxBytes(chunkCap) on the
// PayloadStoreService handler — the server-side per-RPC read cap production
// applies from pipeCfg.MaxRetainChunkSize.
func newPayloadRetainHarnessWithChunkCap(t *testing.T, chunkCap int, owners ...string) *payloadRetainHarness {
	t.Helper()
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}
	resolver := fakeDIDResolver{}
	for _, owner := range owners {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.SaveKeyPair(owner, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
			t.Fatal(err)
		}
		resolver[owner] = authDoc(owner, kp.PublicKey)
	}

	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: resolver,
		Crypto:   ed25519.Verifier{},
		Nonces:   wireauth.NewMemoryNonceStore(),
		Epoch:    time.Now().Add(-time.Hour),
		Window:   wireauth.AcceptanceWindow{MaxPast: time.Hour, MaxFuture: time.Minute},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	store := memstore.New()
	h := storehandler.New(store, v, 1<<20)
	path, hh := payloadpbconnect.NewPayloadStoreServiceHandler(h, connect.WithReadMaxBytes(chunkCap))
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &payloadRetainHarness{store: store, ks: ks, url: srv.URL, httpc: srv.Client()}
}

// TestPayloadClientFactory_HonorsConfiguredMaxRetainChunkSize proves the
// fix directly: a factory built with the DEFAULT (unconfigured) chunk size
// sends 256 KiB frames regardless of a small server cap, tripping
// ResourceExhausted on the very first chunk (pinning the PRE-FIX bug); a
// factory built with pipeCfg.MaxRetainChunkSize (here, the same value as the
// server's cap) keeps every frame under it, and the retain succeeds.
func TestPayloadClientFactory_HonorsConfiguredMaxRetainChunkSize(t *testing.T) {
	const chunkCap = 2048 // bytes — far below the client's own 256 KiB DefaultRetainChunkSize
	h := newPayloadRetainHarnessWithChunkCap(t, chunkCap, payloadOwnerA)
	payload := bytes.Repeat([]byte("x"), 10_000) // spans several chunks under chunkCap

	defaultFactory := newPayloadClientFactory(h.ks, h.url, "", h.httpc, 0)
	_, err := (wirePayloadStore{factory: defaultFactory}).Store(context.Background(), payload, payloadOwnerA)
	if err == nil {
		t.Fatal("Store with the default (unconfigured) chunk size against a small server cap: want an error, got nil (this pins the PRE-FIX bug)")
	}
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("Store with oversized default chunks: code = %v, want ResourceExhausted", connect.CodeOf(err))
	}

	configuredFactory := newPayloadClientFactory(h.ks, h.url, "", h.httpc, chunkCap)
	addr, err := (wirePayloadStore{factory: configuredFactory}).Store(context.Background(), payload, payloadOwnerA)
	if err != nil {
		t.Fatalf("Store with configured chunk size: %v", err)
	}
	got, owners, err := h.store.Get(addr)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) || len(owners) != 1 || owners[0] != payloadOwnerA {
		t.Errorf("retained bytes/owners = (%d bytes, %v), want (%d bytes, [%s])", len(got), owners, len(payload), payloadOwnerA)
	}
}

// TestRetainChunkSizeFor pins the headroom derivation directly.
func TestRetainChunkSizeFor(t *testing.T) {
	cases := []struct {
		name string
		max  int
		want int
	}{
		{"typical config value", 1 << 20, (1 << 20) - retainFrameOverhead},
		{"unconfigured (<=0) passes through unchanged", 0, 0},
		{"negative passes through unchanged", -1, 0},
		{"pathologically tiny cap floors at 1, never <=0", 10, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := retainChunkSizeFor(c.max); got != c.want {
				t.Errorf("retainChunkSizeFor(%d) = %d, want %d", c.max, got, c.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────
// preflightPayloadRetainKeys — the D9 boot preflight (main.go's Boot guard
// 5): every producing loop's own output subject must already have a #auth
// key in the keystore BEFORE this binary starts its data plane, since a
// missing key would otherwise only surface as a runtime RetainPayload
// failure that aborts the whole emission (dataplane.go's payloadWiring,
// D-6).
// ─────────────────────────────────────────────────────────────────────────

func TestPreflightPayloadRetainKeys_AllKeysPresent_OK(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}
	for _, subject := range []string{payloadOwnerA, payloadOwnerB} {
		kp, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
			t.Fatal(err)
		}
	}
	loops := []pipelineconfig.LoopConfig{
		{Name: "src1", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: payloadOwnerA}},
		{Name: "agg", Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: payloadOwnerB}},
	}
	if err := preflightPayloadRetainKeys(ks, loops); err != nil {
		t.Fatalf("preflightPayloadRetainKeys: %v", err)
	}
}

func TestPreflightPayloadRetainKeys_MissingKey_NamesTheLoopAndSubject(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	gen := ed25519.Generator{}
	kp, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Only payloadOwnerA gets a key; payloadOwnerB (the "agg" loop) does not.
	if err := ks.SaveKeyPair(payloadOwnerA, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatal(err)
	}
	loops := []pipelineconfig.LoopConfig{
		{Name: "src1", Role: pipelineconfig.RoleSource, Source: pipelineconfig.SourceConfig{OutputSubject: payloadOwnerA}},
		{Name: "agg", Role: pipelineconfig.RoleAggregate, Aggregate: pipelineconfig.AggregateConfig{OutputSubject: payloadOwnerB}},
	}
	err = preflightPayloadRetainKeys(ks, loops)
	if err == nil {
		t.Fatal("preflightPayloadRetainKeys: want error for the loop with no provisioned key, got nil")
	}
	for _, want := range []string{`"agg"`, payloadOwnerB} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("preflightPayloadRetainKeys error = %q, want it to contain %q", err, want)
		}
	}
}

func TestPreflightPayloadRetainKeys_NoProducingLoops_OK(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	loops := []pipelineconfig.LoopConfig{
		{Name: "snk", Role: pipelineconfig.RoleSink, Sink: pipelineconfig.SinkConfig{}},
	}
	if err := preflightPayloadRetainKeys(ks, loops); err != nil {
		t.Fatalf("preflightPayloadRetainKeys: %v (a sink loop needs no retain key)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// preflightWireOnlySignerKeys — the D9 extension (main.go's Boot guard 6,
// branch review Important finding): nodeDID's own key (RegisterAuditHead /
// PayloadResolver) and every DURABLE custody log's checkpoint-signer key,
// both previously discoverable only at first use (see the function's own
// doc for why filelog's checkpoint arming cannot catch this at boot).
// ─────────────────────────────────────────────────────────────────────────

const (
	wireOnlyNodeDID       = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:node"
	wireOnlyCustodySigner = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"
)

func provisionAuthKey(t *testing.T, ks *ksfilestore.Store, subjectDID string) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(subjectDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightWireOnlySignerKeys_AllKeysPresent_OK(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireOnlyNodeDID)
	provisionAuthKey(t, ks, wireOnlyCustodySigner)
	custodyLogs := []pipelineruntime.CustodyLog{
		{LogID: "did:dplaax:reg:org:acme:pipeline:pipe", Signer: pipelineruntime.IssuerConfig{DID: wireOnlyCustodySigner}},
	}
	if err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, custodyLogs); err != nil {
		t.Fatalf("preflightWireOnlySignerKeys: %v", err)
	}
}

func TestPreflightWireOnlySignerKeys_MissingNodeDIDKey_NamesNodeDID(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireOnlyCustodySigner) // nodeDID's own key is deliberately withheld
	custodyLogs := []pipelineruntime.CustodyLog{
		{LogID: "did:dplaax:reg:org:acme:pipeline:pipe", Signer: pipelineruntime.IssuerConfig{DID: wireOnlyCustodySigner}},
	}
	err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, custodyLogs)
	if err == nil {
		t.Fatal("preflightWireOnlySignerKeys: want error for missing nodeDID key, got nil")
	}
	for _, want := range []string{"node identity", wireOnlyNodeDID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

func TestPreflightWireOnlySignerKeys_MissingCustodySignerKey_NamesLogAndSigner(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireOnlyNodeDID) // the custody log's signer key is deliberately withheld
	custodyLogs := []pipelineruntime.CustodyLog{
		{LogID: "did:dplaax:reg:org:acme:pipeline:pipe", Signer: pipelineruntime.IssuerConfig{DID: wireOnlyCustodySigner}},
	}
	err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, custodyLogs)
	if err == nil {
		t.Fatal("preflightWireOnlySignerKeys: want error for missing custody-log signer key, got nil")
	}
	for _, want := range []string{`"did:dplaax:reg:org:acme:pipeline:pipe"`, wireOnlyCustodySigner} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// TestPreflightWireOnlySignerKeys_ChecksEveryCustodyLog proves the guard
// does not stop at the FIRST custody log — it must name whichever one is
// actually missing, even when an earlier one in the slice is fine.
func TestPreflightWireOnlySignerKeys_ChecksEveryCustodyLog(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	const okSigner = "did:dplaax:reg:org:acme:pipeline:pipe1:process:src1"
	provisionAuthKey(t, ks, wireOnlyNodeDID)
	provisionAuthKey(t, ks, okSigner)
	// wireOnlyCustodySigner (the SECOND log) is deliberately left unprovisioned.
	custodyLogs := []pipelineruntime.CustodyLog{
		{LogID: "log-1", Signer: pipelineruntime.IssuerConfig{DID: okSigner}},
		{LogID: "log-2", Signer: pipelineruntime.IssuerConfig{DID: wireOnlyCustodySigner}},
	}
	err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, custodyLogs)
	if err == nil {
		t.Fatal("want error for log-2's missing signer key, got nil")
	}
	if !strings.Contains(err.Error(), `"log-2"`) {
		t.Errorf("error = %q, want it to name log-2 specifically", err)
	}
	if strings.Contains(err.Error(), "log-1") {
		t.Errorf("error = %q, must not name log-1 (its key IS provisioned)", err)
	}
}

// TestPreflightWireOnlySignerKeys_NodeDIDSharedWithCustodySigner_NoDoubleProbeFailure
// proves a custody log whose signer happens to equal nodeDID is checked
// exactly once (via the nodeDID probe) — no double error, no double Sign call
// starving a slower KeyStore backend.
func TestPreflightWireOnlySignerKeys_NodeDIDSharedWithCustodySigner_NoDoubleProbeFailure(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireOnlyNodeDID)
	custodyLogs := []pipelineruntime.CustodyLog{
		{LogID: "shared-log", Signer: pipelineruntime.IssuerConfig{DID: wireOnlyNodeDID}},
	}
	if err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, custodyLogs); err != nil {
		t.Fatalf("preflightWireOnlySignerKeys: %v (nodeDID's key IS provisioned, and the custody log shares that same DID)", err)
	}
}

func TestPreflightWireOnlySignerKeys_NoCustodyLogs_OnlyChecksNodeDID(t *testing.T) {
	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireOnlyNodeDID)
	if err := preflightWireOnlySignerKeys(ks, wireOnlyNodeDID, nil); err != nil {
		t.Fatalf("preflightWireOnlySignerKeys: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Loss-sensitive wiring sites
// wrapped with retryOnUnavailable — wirePayloadStore.Store (RetainPayload),
// wireRetryingPayloadResolver.ResolvePayload, wireAuditRegistrar.Add
// (RegisterAuditHead), and wireReceiptWriter.Put (RegisterEvidence). Each
// harness below is a "stub server" that returns connect.CodeUnavailable
// (simulating cmd/network's boot-window barrier — wireautherr.Code's
// ErrBeforeEpoch mapping, Tasks 1+2 of this branch) for the first N calls to
// the target RPC, then succeeds — proving the wrapped call recovers AND that
// every attempt reached the server with a DISTINCT wireauth nonce (re-signed
// per attempt, never a resent cached proof — the exact recovery mechanism
// the spec requires).
// ─────────────────────────────────────────────────────────────────────────

// assertDistinctNonces fails the test if nonces contains fewer than 2
// entries, an empty entry, or a repeated value — the direct evidence that
// every retry attempt re-signed (a resent cached proof would repeat the same
// nonce).
func assertDistinctNonces(t *testing.T, nonces []string) {
	t.Helper()
	if len(nonces) < 2 {
		t.Fatalf("saw %d attempt(s), want at least 2 (a retry must have happened)", len(nonces))
	}
	seen := make(map[string]bool, len(nonces))
	for i, n := range nonces {
		if n == "" {
			t.Errorf("attempt %d carried an empty nonce", i)
		}
		if seen[n] {
			t.Errorf("nonce %q reused across attempts — re-sign must produce a FRESH nonce per attempt", n)
		}
		seen[n] = true
	}
}

// flakyRetainHandler simulates the boot-window barrier for RetainPayload: the
// first `fail` calls return CodeUnavailable (recording the metadata frame's
// nonce first); later calls drain the stream and succeed with a fake content
// address. It never delegates to a real storehandler — the retry-recovery
// proof needs only the nonce sequence and an eventual success, not real
// persistence (that's already covered by TestWirePayloadStore_* above).
type flakyRetainHandler struct {
	mu     sync.Mutex
	fail   int
	nonces []string
}

func (h *flakyRetainHandler) RetainPayload(ctx context.Context, stream *connect.ClientStream[payloadpb.RetainPayloadRequest]) (*connect.Response[payloadpb.RetainPayloadResponse], error) {
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("flakyRetainHandler: stream closed before the metadata frame")
	}
	meta := stream.Msg().GetMetadata()

	h.mu.Lock()
	h.nonces = append(h.nonces, meta.GetAuthProof().GetNonce())
	shouldFail := h.fail > 0
	if shouldFail {
		h.fail--
	}
	h.mu.Unlock()

	if shouldFail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("boot window (fake)"))
	}

	var size int
	for stream.Receive() {
		size += len(stream.Msg().GetChunk())
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&payloadpb.RetainPayloadResponse{ContentAddress: fmt.Sprintf("sha256:fake-%d", size)}), nil
}

// TestWirePayloadStore_Store_RetriesOnUnavailableAndResigns is the plan's
// Step 5 integration proof (retain site): a stub RetainPayload server
// returns CodeUnavailable twice then succeeds; Store must recover, and the
// server must have seen exactly 3 attempts with 3 DISTINCT nonces.
func TestWirePayloadStore_Store_RetriesOnUnavailableAndResigns(t *testing.T) {
	handler := &flakyRetainHandler{fail: 2}
	path, hh := payloadpbconnect.NewPayloadStoreServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, payloadOwnerA)

	factory := newPayloadClientFactory(ks, srv.URL, "", srv.Client(), 0)
	store := wirePayloadStore{factory: factory}

	contentAddress, err := store.Store(context.Background(), []byte("payload racing the boot window"), payloadOwnerA)
	if err != nil {
		t.Fatalf("Store: %v, want recovery via retry", err)
	}
	if contentAddress == "" {
		t.Error("Store returned an empty content address")
	}
	if len(handler.nonces) != 3 {
		t.Fatalf("server saw %d RetainPayload attempts, want 3 (2 failures + 1 success)", len(handler.nonces))
	}
	assertDistinctNonces(t, handler.nonces)
}

// flakyResolveHandler simulates the boot-window barrier for ResolvePayload:
// the first `fail` calls return CodeUnavailable; later calls stream back a
// fixed payload.
type flakyResolveHandler struct {
	payloadpbconnect.UnimplementedPayloadServiceHandler
	mu     sync.Mutex
	fail   int
	nonces []string
}

const flakyResolvedPayload = "resolved payload bytes"

func (h *flakyResolveHandler) ResolvePayload(ctx context.Context, req *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	h.mu.Lock()
	h.nonces = append(h.nonces, req.Msg.GetAuthProof().GetNonce())
	shouldFail := h.fail > 0
	if shouldFail {
		h.fail--
	}
	h.mu.Unlock()

	if shouldFail {
		return connect.NewError(connect.CodeUnavailable, errors.New("boot window (fake)"))
	}
	return stream.Send(&payloadpb.ResolvePayloadResponse{Chunk: []byte(flakyResolvedPayload)})
}

// TestWireRetryingPayloadResolver_ResolvePayload_RetriesOnUnavailableAndResigns
// proves the resolve (read) side recovers exactly like retain: a stub
// ResolvePayload server fails twice with CodeUnavailable then succeeds.
func TestWireRetryingPayloadResolver_ResolvePayload_RetriesOnUnavailableAndResigns(t *testing.T) {
	handler := &flakyResolveHandler{fail: 2}
	path, hh := payloadpbconnect.NewPayloadServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireNodeDID)

	factory := newPayloadClientFactory(ks, "", "", http.DefaultClient, 0)
	resolver := wireRetryingPayloadResolver{client: factory.For(wireNodeDID)}

	got, err := resolver.ResolvePayload(context.Background(), srv.URL, addr("d"))
	if err != nil {
		t.Fatalf("ResolvePayload: %v, want recovery via retry", err)
	}
	if string(got) != flakyResolvedPayload {
		t.Errorf("ResolvePayload = %q, want %q", got, flakyResolvedPayload)
	}
	if len(handler.nonces) != 3 {
		t.Fatalf("server saw %d ResolvePayload attempts, want 3 (2 failures + 1 success)", len(handler.nonces))
	}
	assertDistinctNonces(t, handler.nonces)
}

// flakyAuditServiceHandler simulates the boot-window barrier independently
// for RegisterEvidence and RegisterAuditHead: the first failEvidence /
// failAuditHead calls to each RPC return CodeUnavailable, then each
// succeeds. Embeds UnimplementedAuditServiceHandler for the read methods
// (GetAuditStatus etc.) neither test below calls.
type flakyAuditServiceHandler struct {
	auditpbconnect.UnimplementedAuditServiceHandler
	mu              sync.Mutex
	failEvidence    int
	failAuditHead   int
	evidenceNonces  []string
	auditHeadNonces []string
}

func (h *flakyAuditServiceHandler) RegisterEvidence(ctx context.Context, req *connect.Request[auditpb.RegisterEvidenceRequest]) (*connect.Response[auditpb.RegisterEvidenceResponse], error) {
	h.mu.Lock()
	h.evidenceNonces = append(h.evidenceNonces, req.Msg.GetAuthProof().GetNonce())
	shouldFail := h.failEvidence > 0
	if shouldFail {
		h.failEvidence--
	}
	h.mu.Unlock()
	if shouldFail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("boot window (fake)"))
	}
	return connect.NewResponse(&auditpb.RegisterEvidenceResponse{}), nil
}

func (h *flakyAuditServiceHandler) RegisterAuditHead(ctx context.Context, req *connect.Request[auditpb.RegisterAuditHeadRequest]) (*connect.Response[auditpb.RegisterAuditHeadResponse], error) {
	h.mu.Lock()
	h.auditHeadNonces = append(h.auditHeadNonces, req.Msg.GetAuthProof().GetNonce())
	shouldFail := h.failAuditHead > 0
	if shouldFail {
		h.failAuditHead--
	}
	h.mu.Unlock()
	if shouldFail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("boot window (fake)"))
	}
	return connect.NewResponse(&auditpb.RegisterAuditHeadResponse{}), nil
}

// TestWireAuditRegistrar_Add_RetriesOnUnavailableAndResigns proves
// RegisterAuditHead recovers via retry, each attempt re-signed.
func TestWireAuditRegistrar_Add_RetriesOnUnavailableAndResigns(t *testing.T) {
	handler := &flakyAuditServiceHandler{failAuditHead: 2}
	path, hh := auditpbconnect.NewAuditServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, hh)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireNodeDID)

	factory := newAuditClientFactory(ks, srv.URL, "", srv.Client())
	registrar := wireAuditRegistrar{client: factory.For(wireNodeDID)}

	if err := registrar.Add(pipelineruntime.StoredHead{WireVariantID: "variant-1"}); err != nil {
		t.Fatalf("Add: %v, want recovery via retry", err)
	}
	if len(handler.auditHeadNonces) != 3 {
		t.Fatalf("server saw %d RegisterAuditHead attempts, want 3 (2 failures + 1 success)", len(handler.auditHeadNonces))
	}
	assertDistinctNonces(t, handler.auditHeadNonces)
}

// TestWireReceiptWriter_Put_RetriesRegisterEvidenceOnUnavailableAndResigns
// proves RegisterEvidence recovers via retry, each attempt re-signed. Put
// also calls ResolveCredential first (over a real VCResolverService,
// unwrapped — not in this task's loss-sensitive matrix), so this harness
// mounts BOTH a real VCResolverService and the flaky AuditService on one mux.
func TestWireReceiptWriter_Put_RetriesRegisterEvidenceOnUnavailableAndResigns(t *testing.T) {
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(vcresolvermemstore.NewBackend()), vcresolvermemstore.NewPool())
	auditHandler := &flakyAuditServiceHandler{failEvidence: 2}

	mux := http.NewServeMux()
	vcPath, vcH := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(vcSvc))
	mux.Handle(vcPath, vcH)
	auditPath, auditH := auditpbconnect.NewAuditServiceHandler(auditHandler)
	mux.Handle(auditPath, auditH)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	vcClient := vcresolverclient.New(vcpbconnect.NewVCResolverServiceClient(srv.Client(), srv.URL))
	store := vcStoreAdapter{client: vcClient}
	head, err := store.StoreVC(context.Background(), minimalCredentialBytes(t, wireAggregateIssuerDID, nil), "", 0)
	if err != nil {
		t.Fatalf("StoreVC: %v", err)
	}

	ks := ksfilestore.New(t.TempDir())
	provisionAuthKey(t, ks, wireAggregateIssuerDID)

	factory := newAuditClientFactory(ks, srv.URL, "", srv.Client())
	writer := wireReceiptWriter{resolver: vcClient, factory: factory}

	if err := writer.Put(head.BodyAddress, wireAggregateIssuerDID, []string{addr("c")}); err != nil {
		t.Fatalf("Put: %v, want recovery via retry", err)
	}
	if len(auditHandler.evidenceNonces) != 3 {
		t.Fatalf("server saw %d RegisterEvidence attempts, want 3 (2 failures + 1 success)", len(auditHandler.evidenceNonces))
	}
	assertDistinctNonces(t, auditHandler.evidenceNonces)
}
