package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	chainhandler "github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadclient "github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	payloadhandler "github.com/provin-line/oss/network/pkg/services/payloadresolver/handler"
	payloadmemstore "github.com/provin-line/oss/network/pkg/services/payloadresolver/memstore"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// This is the by-reference FULL SMOKE composing the two halves the
// export-seam-mode spec (§9-6) explicitly deferred fusing: capstone A
// (TestCapstone_ByReferenceCrossNodeDelivery, crossnode_byref_e2e_test.go) —
// a stripped envelope crossing a REAL NATS account export/import boundary —
// and the by-reference data-path e2e
// (TestByReference_DataPath_SinkFetchesAndDelivers,
// network/pkg/services/payloadresolver/handler/byref_dataplane_e2e_test.go)
// — a sink dereferencing a nil payload over a REAL PayloadService HTTP
// surface. Capstone A's own doc comment on inProcessPayloadResolver named
// this exact composition as future work; gap-backlog L4 tracks it.
//
// It reuses capstone A's DID lineage and scaffolding (capOperator,
// capSigner, bridgeCapDir, mapDIDResolver, byrefEndpointDoc, byrefAuthDoc,
// byrefSubDID, capByRefSinkCfg) rather than duplicating it — here the sink
// config's UpstreamEndpoint points at the publisher's LIVE httptest server
// (mounting BOTH the chain peer surface and the PayloadService, exactly as
// server.go mounts them on one mux), so the sink's PayloadResolver fetch is
// a genuine ConnectRPC HTTP hop rather than capstone A's in-process shortcut.

// TestCapstone_ByReferenceCrossNodeFetchAndDeliver is the combined
// by-reference full smoke: a publisher node (payload serving wired, so its
// source loop dual-emits stripped alongside plain) registers a REAL
// by-reference subscription through the chainmanager peer flow, exactly as
// capstone A does. The subscriber's sink loop receives the stripped envelope
// that crossed the real NATS account boundary and — unlike capstone A —
// dereferences its payload through a REAL payloadclient.Resolver making a
// genuine ConnectRPC call over httptest to the publisher's PayloadService,
// binds the fetched bytes against the credential's outputHash, and DELIVERS.
//
// Teeth:
//  1. Stripped, not plain, crossed the boundary: sink.Processor's
//     acquirePayload fails closed (RejectPayloadDeliveryViolation) if a
//     by-reference-configured sink ever receives an envelope carrying an
//     inline payload (pipeline/sink/sink.go: "by-reference + present →
//     RejectPayloadDeliveryViolation"). A StatusPassed delivery below is
//     therefore only possible if the envelope that crossed was nil-payload.
//  2. The HTTP hop is real and observed: payloadReqs counts requests that
//     actually reached the mounted PayloadService handler. The ONLY writer
//     into payloadSvc's store is the publisher data plane's retain path
//     (PayloadStore: payloadSvc passed to pipelineruntime.Build) — this test never
//     calls payloadSvc.Store directly — so a delivered record with matching
//     bytes plus payloadReqs > 0 together prove the sink actually fetched
//     over the wire rather than short-circuiting.
//  3. Byte-identical payload + ConfidenceVerified binding.
//  4. Negative (deliver-then-check, capstone A's pattern): the probe import
//     of the never-exported PLAIN subject stays empty — the full payload
//     never crossed the boundary in-band, only the by-reference pointer did.
func TestCapstone_ByReferenceCrossNodeFetchAndDeliver(t *testing.T) {
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

	// --- publisher-side chainmanager peer server AND PayloadService, mounted
	// on ONE httptest server exactly as server.go mounts them (real wireauth,
	// real nats operator SHARING the publisher data-plane's account) ---------
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

	// payloadSvc is created here (before the mux) and reused below as the
	// publisher data plane's PayloadStore — the SAME store instance backs
	// both the retain path (producer) and the serving boundary (this
	// handler), which is what makes "successful fetch" proof of a real hop.
	payloadSvc := payloadresolver.New(payloadmemstore.New())

	var payloadReqs int32 // observed hits on the mounted PayloadService — teeth #2
	peerPath, ph := chainpbconnect.NewChainPeerServiceHandler(chainhandler.NewPeer(pubChainSvc, v))
	payloadPath, poh := payloadpbconnect.NewPayloadServiceHandler(payloadhandler.New(payloadresolver.NewServingBoundary(payloadSvc, pubChainSvc), v))
	mux := http.NewServeMux()
	mux.Handle(peerPath, ph)
	mux.Handle(payloadPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&payloadReqs, 1)
		poh.ServeHTTP(w, r)
	}))
	pubPeerSrv := httptest.NewServer(mux)
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
	// ever arrive on it (mirrors capstone A's / TestIsolationE2E's "denied"
	// pattern).
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
	pubChainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(pubAccSeed)},
	}
	pubDP, err := pipelineruntime.Build(ctx, pubChainCfg, capSourceCfg(), ks, pipelineruntime.Deps{PayloadStore: payloadSvc})
	if err != nil {
		t.Fatalf("build publisher data plane: %v", err)
	}

	// --- subscriber data plane: sink loop, by-reference, REAL payloadclient
	// pointed at the publisher's live httptest server ------------------------
	res := local.New()
	res.Add(capProcessDoc(capIssuerDID, capOwnerDID, kp.PublicKey))
	res.Add(capOwnerDoc(capOwnerDID))
	writer := &captureWriter{}
	payloadResolver := payloadclient.New(payloadclient.Config{Signer: subSigner, SignerDID: byrefSubDID, HTTPClient: guard.HTTPClient()})
	subChainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: string(subAccSeed)},
	}
	subDP, err := pipelineruntime.Build(ctx, subChainCfg, capByRefSinkCfg(pubPeerSrv.URL), filestore.New(t.TempDir()), pipelineruntime.Deps{
		Resolver:        res,
		SinkWriter:      writer,
		VCStore:         dpVCStore(),
		PayloadResolver: payloadResolver,
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

	// --- teeth #2: the HTTP hop to the publisher's PayloadService actually
	// happened (not an in-process shortcut). payloadSvc is populated ONLY via
	// the publisher data plane's retain path, so the delivered byte-identical
	// payload above already implies a fetch; this independently OBSERVES it.
	if hits := atomic.LoadInt32(&payloadReqs); hits == 0 {
		t.Fatal("PayloadService received zero requests: the sink did not fetch over the real HTTP surface")
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
