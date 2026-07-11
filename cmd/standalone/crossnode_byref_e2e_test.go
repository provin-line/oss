package main

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	chainhandler "github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadmemstore "github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// This is CAPSTONE A of the export-seam-mode spec (§9-6): the first test to
// prove a STRIPPED envelope crosses a real NATS account export/import
// boundary. It reuses the crossnode capstone's DID lineage (capPipelineDID /
// capIssuerDID / capOwnerDID / capIngress) but drives the subscription
// through the REAL chainmanager peer flow (RegisterSubscription /
// Subscribe) instead of setupCapstone's direct AddExport/AddImport, because
// the thing under test — mode→subject mapping, the subscriber-side rename,
// dual-emit — lives in that flow. Existing capstones (setupCapstone and its
// tests) are NOT modified; this file is additive.

const byrefSubDID = "did:dplaax:poc.dplaax.dev:org:beta"

// inProcessPayloadResolver dereferences payload bytes directly against a
// *payloadresolver.Service in the same process — the sink's PayloadResolver
// seam. It proves the binding gate (sink-side sha256(payload)==outputHash)
// without re-proving the HTTP fetch path, which byref_dataplane_e2e_test.go
// already covers end to end (spec §9-6: capstone A does not re-compose it).
type inProcessPayloadResolver struct{ svc *payloadresolver.Service }

func (r inProcessPayloadResolver) ResolvePayload(ctx context.Context, _ string, contentHash string) ([]byte, error) {
	b, _, err := r.svc.Resolve(ctx, contentHash)
	return b, err
}

// mapDIDResolver resolves publisherDID to a fixed #chain-manager endpoint —
// the subscriber-side chainmanager.DIDResolver seam.
type mapDIDResolver map[string]*did.DIDDocument

func (m mapDIDResolver) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, wireauth.ErrKeyResolution
	}
	return doc, nil
}

// byrefEndpointDoc is capPipelineDID's DID document as the SUBSCRIBER
// resolves it: it advertises the #chain-manager endpoint (the publisher's
// httptest peer server).
func byrefEndpointDoc(endpoint string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: capPipelineDID,
		Service: []did.ServiceEndpoint{{
			ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: endpoint,
		}},
	})
}

// byrefAuthDoc is the SUBSCRIBER's own DID document (what the publisher's
// wireauth verifier resolves to check the L2 signature) — an #auth
// authentication key, distinct from the credential-signing #signing key.
func byrefAuthDoc(pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: byrefSubDID, Controller: byrefSubDID,
		VerificationMethod: []did.VerificationMethod{{
			ID: byrefSubDID + "#auth", Type: "JsonWebKey2020", Controller: byrefSubDID,
			PublicKeyJWK: capJWK(pub),
		}},
		Authentication: []string{byrefSubDID + "#auth"},
	})
}

func capJWK(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

// capSigner generates a fresh Ed25519 #auth key for subject and returns a
// crypto.Signer over it plus the raw public key (for building its DID
// document) — the wireauth signing identity for a chainmanager peer caller.
func capSigner(t *testing.T, subject string) (crypto.Signer, []byte) {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("capSigner: generate: %v", err)
	}
	if err := ks.SaveKeyPair(subject, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("capSigner: save: %v", err)
	}
	return ed25519.NewSigner(ks), kp.PublicKey
}

func capByRefSinkCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "archive",
		Role:           pipelineconfig.RoleSink,
		IngressSubject: capPipelineDID, // unchanged by mode — the rename absorbs it (D-4)
		Sink: pipelineconfig.SinkConfig{
			Kind:                 pipelineconfig.SinkObservationOnly,
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
			PayloadDelivery:      "by-reference",
		},
	}}}
}

// TestCapstone_ByReferenceCrossNodeDelivery is capstone A (export-seam-mode
// spec §9-6): a publisher node with payload serving (PayloadStore wired, so
// its source loop dual-emits) registers a REAL by-reference subscription
// through the chainmanager peer flow — publisher RegisterSubscription maps
// the agreed mode to "byref."+capPipelineDID and exports it; subscriber
// Subscribe imports it and RENAMES it back to the plain capPipelineDID local
// subject (D-4), so the sink loop's ingress-subject config is unchanged. The
// sink runs payload-delivery=by-reference with an in-process PayloadResolver
// returning the publisher-retained bytes.
//
// Positive: the sink receives and DELIVERS the event end to end — the
// stripped envelope crossed the real NATS account export/import boundary and
// the payload was dereferenced + bound.
//
// Negative (confidentiality = grant shape, not a runtime check): the
// by-reference subscriber's account cannot read the PLAIN (inline) subject —
// a probe import of the never-exported plain subject (structurally routable,
// mirroring TestIsolationE2E/TestMultiNodeDelivery's "denied" pattern) stays
// live from before the positive injection begins, so its later "received
// nothing" check is not a timing race: the positive assertion already proves
// N dual-emit cycles (each publishing the primary form on the SAME publisher
// account subject the probe imports) happened before the check runs.
func TestCapstone_ByReferenceCrossNodeDelivery(t *testing.T) {
	ctx := context.Background()

	// --- shared trust root + JWT dir (slice-16 pattern) ---------------------
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	opPub, _ := op.PublicKey()
	sharedDir := t.TempDir()

	pubAcc, _ := nkeys.CreateAccount()
	pubAccSeed, _ := pubAcc.Seed()
	pubAccPub, _ := pubAcc.PublicKey()
	subAcc, _ := nkeys.CreateAccount()
	subAccSeed, _ := subAcc.Seed()

	pubOp := capOperator(t, pubAccSeed, opSeed, sharedDir)
	subOp := capOperator(t, subAccSeed, opSeed, sharedDir)

	// --- publisher-side chainmanager peer server (real wireauth, real nats
	// operator SHARING the publisher data-plane's account, payload serving) --
	subSigner, subAuthPub := capSigner(t, byrefSubDID)
	pubAllows := memstore.NewAllowListStore()
	if err := pubAllows.Save(capPipelineDID, []store.AllowRule{{Pattern: "did:dplaax:*:org:beta"}}); err != nil {
		t.Fatal(err)
	}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: mapDIDResolver{byrefSubDID: byrefAuthDoc(subAuthPub)},
		Crypto:   ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
		Epoch: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	pubChainSvc := chainmanager.New(memstore.NewSubscriptionStore(), pubAllows,
		chainmanager.WithInfraOperator(pubOp), chainmanager.WithPayloadServing())
	_, ph := chainpbconnect.NewChainPeerServiceHandler(chainhandler.NewPeer(pubChainSvc, v))
	pubPeerSrv := httptest.NewServer(ph)
	t.Cleanup(pubPeerSrv.Close)

	// --- subscriber-side chainmanager Service (real nats operator SHARING the
	// subscriber data-plane's account) drives the REAL Subscribe round-trip ---
	guard := core.NewURLGuard(core.WithAllowLoopback(true)) // httptest is 127.0.0.1
	pc := peerclient.New(subSigner, byrefSubDID, guard.HTTPClient())
	subChainSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(subOp),
		chainmanager.WithDIDResolver(mapDIDResolver{capPipelineDID: byrefEndpointDoc(pubPeerSrv.URL)}),
		chainmanager.WithPeerClient(pc),
		chainmanager.WithEndpointGuard(guard),
	)
	if _, err := subChainSvc.Subscribe(ctx, byrefSubDID, capPipelineDID, "by-reference"); err != nil {
		t.Fatalf("Subscribe(by-reference): %v", err)
	}

	// Negative probe: the subscriber account ALSO structurally imports the
	// PLAIN publisher subject onto a distinct local alias — it was never
	// exported for this (by-reference-only) subscription, so nothing should
	// ever arrive on it (mirrors TestIsolationE2E's "denied" subject).
	const probeLocal = "probe.plain"
	if err := subOp.AddImport(capPipelineDID, pubAccPub, probeLocal); err != nil {
		t.Fatalf("AddImport(probe): %v", err)
	}

	// --- cold-account ordering: bridge the operator-written grants into the
	// broker's resolver BEFORE any client connects ---------------------------
	mr := bridgeCapDir(t, sharedDir)
	natsSrv := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(natsSrv.Shutdown)
	url := natsSrv.ClientURL()

	// --- publisher data plane: source loop, payload serving (dual-emit) -----
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(capIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	payloadSvc := payloadresolver.New(payloadmemstore.New())
	pubChainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(pubAccSeed)},
	}
	pubDP, err := buildDataPlane(ctx, pubChainCfg, capSourceCfg(), ks, dataPlaneDeps{PayloadStore: payloadSvc})
	if err != nil {
		t.Fatalf("build publisher data plane: %v", err)
	}

	// --- subscriber data plane: sink loop, by-reference, in-process resolver
	res := local.New()
	res.Add(capProcessDoc(capIssuerDID, capOwnerDID, kp.PublicKey))
	res.Add(capOwnerDoc(capOwnerDID))
	writer := &captureWriter{}
	subChainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(subAccSeed)},
	}
	subDP, err := buildDataPlane(ctx, subChainCfg, capByRefSinkCfg(), filestore.New(t.TempDir()), dataPlaneDeps{
		Resolver:        res,
		SinkWriter:      writer,
		VCStore:         dpVCStore(),
		PayloadResolver: inProcessPayloadResolver{svc: payloadSvc},
	})
	if err != nil {
		t.Fatalf("build subscriber data plane: %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	pubDone := make(chan error, 1)
	subDone := make(chan error, 1)
	go func() { pubDone <- pubDP.Run(runCtx) }()
	go func() { subDone <- subDP.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		<-pubDone
		<-subDone
	})

	// --- injector on the publisher account + a probe observer on the
	// subscriber account (subscribed BEFORE any injection, so the later
	// negative check is deliver-then-check, not a race) -----------------------
	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: string(pubAccSeed)})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	pub := inj.Publisher(capIngress)

	probeConn, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: string(subAccSeed)})
	if err != nil {
		t.Fatalf("probe connect: %v", err)
	}
	t.Cleanup(func() { _ = probeConn.Close() })
	var probeMu sync.Mutex
	var probeHits int
	if err := probeConn.Subscriber(probeLocal).Subscribe(func([]byte) {
		probeMu.Lock()
		probeHits++
		probeMu.Unlock()
	}); err != nil {
		t.Fatalf("probe subscribe: %v", err)
	}

	// --- drive the positive path: retry-inject until the sink delivers ------
	const raw = `{"reading":42}`
	_ = pub.Publish([]byte(raw))
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	var delivered bool
	for !delivered {
		if recs := writer.records(); len(recs) > 0 {
			rec := recs[0]
			if string(rec.Payload) != raw {
				t.Fatalf("payload: got %q want %q", rec.Payload, raw)
			}
			if rec.Verdict == nil || rec.Verdict.Overall != vc.ConfidenceVerified {
				t.Fatalf("verdict: got %+v want ConfidenceVerified", rec.Verdict)
			}
			if rec.Credential == nil || rec.Credential.Issuer() != capIssuerDID {
				t.Fatalf("issuer: got %v want %q", rec.Credential, capIssuerDID)
			}
			delivered = true
			break
		}
		select {
		case <-tick.C:
			_ = pub.Publish([]byte(raw)) // loops subscribe asynchronously; re-push until delivered
		case <-deadline:
			t.Fatal("sink did not receive the by-reference cross-node event")
		}
	}

	// --- negative: deliver-then-check. The positive delivery above proves at
	// least one full dual-emit cycle already published the PRIMARY form on
	// capPipelineDID (the publisher's own account subject) — the SAME subject
	// the probe import targets. probeConn has been live and subscribed the
	// entire time. If the grant were leaking, probeHits would already be > 0.
	probeMu.Lock()
	hits := probeHits
	probeMu.Unlock()
	if hits != 0 {
		t.Fatalf("confidentiality violated: the by-reference subscriber's account received %d message(s) on the never-exported plain subject", hits)
	}
	// Teardown (cancel + drain both data planes) runs via the single
	// t.Cleanup registered above — draining pubDone/subDone a second time
	// here would block forever (the goroutines only send once).
}
