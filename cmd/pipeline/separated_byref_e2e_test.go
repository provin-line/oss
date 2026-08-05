package main

// This is the by-reference CROSS-NODE proof on the separated (cmd/network +
// cmd/pipeline) topology — the coverage that used to live in cmd/standalone's
// crossnode_byref_e2e_test.go / crossnode_byref_fullsmoke_e2e_test.go (PR3c
// retired cmd/standalone; those two files are readable at
// `git show da95e32^:cmd/standalone/crossnode_byref_e2e_test.go` and its
// fullsmoke sibling). Their properties, ported here:
//
//  1. A producer node's source loop DUAL-EMITS: the plain (inline) form on its
//     own account subject, and a STRIPPED (nil-payload) form on the
//     by-reference subject, with the payload retained at the registry's
//     payload-serving boundary (buildDeps always wires PayloadStore — D-6 —
//     so this is automatic, not a scenario-specific opt-in).
//  2. A consumer on a SECOND NATS account negotiates a REAL chainmanager
//     subscription (RegisterSubscription/Subscribe, over a real wire
//     ChainPeerService round trip) that maps "by-reference" to the
//     ByReferenceSubjectPrefix-prefixed subject, exports it on the producer's
//     account, imports-and-renames it back to the plain subject on the
//     consumer's account (D-4) — so the consumer's sink loop's own ingress
//     config is mode-independent.
//  3. The consumer's production sink loop (payload-delivery=by-reference)
//     synchronously appraises the exact selected credential evidence, then dereferences
//     the payload by content address over the registry's REAL PayloadService
//     HTTP surface (a genuine ConnectRPC hop, counted independently below),
//     binds it against the credential's outputHash, and delivers the payload together
//     with its EvidenceView and local decision record.
//  4. Negative: the consumer's account additionally, structurally imports the
//     producer's PLAIN (never-exported-for-this-subscription) subject onto a
//     distinct local alias; it stays empty even though the positive delivery
//     above already proves the plain form was published on that exact
//     subject — a deliver-then-check confidentiality proof, not a race.
//
// What differs from the deleted tests, and why:
//
//   - Topology: the deleted tests ran TWO standalone nodes, each with its OWN
//     embedded chainmanager.Service + ChainPeerService + PayloadService (one
//     monolithic binary serving both control- and data-plane per node). In
//     this repo's current architecture, ONE registry (cmd/network,
//     netcompose.BuildHandler — reused here via buildSepRegistry, extended
//     with two small additive parameters, see its doc) hosts chainmanager,
//     ChainPeerService, and PayloadService for the whole mesh — cmd/pipeline
//     is architecturally barred from linking any of that in-process
//     (depsguard_test.go). So the "producer logical node" here is
//     buildSepRegistry (its own account) + a pipeline runtime; the "consumer
//     logical node" is a directly-constructed chainmanager.Service (a
//     legitimate stand-in for whatever operator tool would drive
//     Subscribe against a real registry — never itself a shipped binary,
//     mirroring network/pkg/services/chainmanager/handler/
//     multinode_e2e_test.go's own subSvc) + a pipeline runtime. Only the
//     producer side needs a full registry: a pure observation sink has no
//     wire dependency (VCStore/AuditQueue/PayloadResolver) that isn't already
//     satisfied by pointing at the SAME one registry every other wire Dep in
//     this binary uses (wiring.go's own "one registry base URL" rule).
//   - Emit-health gating: buildSepRegistry wires NEITHER WithByReferenceHealth
//     nor WithPublisherHealth (the same as its two existing scenarios), so
//     chainmanager.Service.byReferenceHealthy defaults to unconditionally
//     healthy (service_peer.go) — by-reference is offered/negotiated exactly
//     as it always was pre-degradation. cmd/pipeline's own real
//     ReportEmitHealth path (emithealthwiring.go) is therefore NOT exercised
//     here: wiring a report-mode registry (cmd/network's own emitHealth
//     option) plus the producer's health reporter would roughly double this
//     file's setup for a property the fullsmoke capstone itself treated as
//     separable, and this port's brief is the retired coverage (dual-emit +
//     cross-account delivery + fetch + confidentiality), not a new capstone.
//   - No mirror-custody / shipping assertions: the deleted fullsmoke's own
//     scope note already treated the HTTP fetch mechanics as covered
//     elsewhere (network/pkg/services/payloadresolver/handler/
//     byref_dataplane_e2e_test.go, still alive, untouched by the standalone
//     retirement) and this file does not re-prove them in isolation; nor does
//     it exercise custody-log mirror shipping (cmd/pipeline/separated_e2e_test.go's
//     own MirrorCustody_LiveGetMirrorStateAdvances case already proves that,
//     unrelated to by-reference). One assertion here (the PayloadService
//     request counter) stands in for the fullsmoke's own "teeth #2".

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/sink"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const (
	byrefProducerPipeline  = "did:dplaax:reg:org:acme:pipeline:byrefsrc"
	byrefProducerIssuerDID = "did:dplaax:reg:org:acme:pipeline:byrefsrc:process:s1"
	byrefProducerIngress   = "ingest.byref.src"
	byrefConsumerDID       = "did:dplaax:reg:org:byrefsub"
	byrefProbeLocal        = "probe.byref.plain"
)

// byrefDIDMap is the consumer's ad hoc chainmanager.DIDResolver: it resolves
// ONLY the producer's pipeline DID, to a document advertising the producer
// registry's own #chain-manager endpoint (its real, wire-mounted
// ChainPeerService) — mirrors the deleted crossnode_byref tests' own
// mapDIDResolver/byrefEndpointDoc.
type byrefDIDMap map[string]*did.DIDDocument

func (m byrefDIDMap) Resolve(_ context.Context, d string) (*did.DIDDocument, error) {
	doc, ok := m[d]
	if !ok {
		return nil, fmt.Errorf("byref: no DID document mapped for %q", d)
	}
	return doc, nil
}

func byrefEndpointDoc(pipelineDID, endpoint string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: pipelineDID,
		Service: []did.ServiceEndpoint{{
			ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: endpoint,
		}},
	})
}

// byrefCaptureWriter is the consumer sink's Deps.SinkWriter override — the
// test seam dataplane.go's own doc names ("assert on a buffer instead of a
// real surface") — capturing every delivered sink.Record for direct
// assertion, mirroring the deleted tests' own captureWriter /
// byref_dataplane_e2e_test.go's e2eWriter.
type byrefCaptureWriter struct {
	mu   sync.Mutex
	recs []sink.Record
}

func (w *byrefCaptureWriter) Write(_ context.Context, rec sink.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recs = append(w.recs, rec)
	return nil
}

func (w *byrefCaptureWriter) records() []sink.Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]sink.Record, len(w.recs))
	copy(out, w.recs)
	return out
}

// byrefMustOperator builds a nats infra.Operator for accSeed, signed under
// trustSeed, publishing its account-claims JWT into dir — reconstructed from
// network/pkg/services/chainmanager/handler/multinode_e2e_test.go's own
// mustOperator (unexported to a different package, so not importable).
func byrefMustOperator(t *testing.T, accSeed, trustSeed []byte, dir string) *natsop.Operator {
	t.Helper()
	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(trustSeed),
		URL:           "nats://unused-in-e2e:4222",
		Publisher:     natsop.NewDirPublisher(dir),
	})
	if err != nil {
		t.Fatalf("byrefMustOperator: %v", err)
	}
	return o
}

// byrefBridgeDirToResolver copies every <accountPub>.jwt an operator wrote
// into a MemAccResolver, so the embedded broker enforces the SAME grants —
// reconstructed from multinode_e2e_test.go's own bridgeDirToResolver.
func byrefBridgeDirToResolver(t *testing.T, dir string) *server.MemAccResolver {
	t.Helper()
	mr := &server.MemAccResolver{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("byrefBridgeDirToResolver: read dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jwt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		pub := strings.TrimSuffix(e.Name(), ".jwt")
		if err := mr.Store(pub, string(b)); err != nil {
			t.Fatalf("byrefBridgeDirToResolver: store %s: %v", pub, err)
		}
	}
	return mr
}

func TestSeparatedTopology_ByReferenceCrossesNodes(t *testing.T) {
	ctx := context.Background()
	gen := ed25519.Generator{}

	// --- shared operator trust root + resolver dir: bridges the producer
	// registry's OWN chainOp (built inside buildSepRegistry from the chainCfg
	// passed in below) and the consumer's independently-built account
	// operator into ONE broker's grants (cold-account ordering, D-x5). ---
	opKP, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opSeed, err := opKP.Seed()
	if err != nil {
		t.Fatal(err)
	}
	opPub, err := opKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	sharedDir := t.TempDir()

	pubAcc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	pubAccSeed, err := pubAcc.Seed()
	if err != nil {
		t.Fatal(err)
	}
	pubAccPub, err := pubAcc.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	subAcc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	subAccSeed, err := subAcc.Seed()
	if err != nil {
		t.Fatal(err)
	}

	// --- identities: one keystore per logical node, each holding exactly the
	// keys its own runtime needs (D9 preflight scope). ---
	producerKS := ksfilestore.New(t.TempDir())
	producerNodeKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// byrefProducerPipeline is BOTH the source loop's OWN output subject
	// (PayloadStore retain signs as the owning loop's output subject, D9) and
	// this runtime's node identity (AuditQueue/PayloadResolver) — reusing one
	// identity for both is the same choice the existing separated_e2e_test.go
	// main scenario makes ("sepSrc1Pipeline is reused here only because its
	// key already exists").
	if err := producerKS.SaveKeyPair(byrefProducerPipeline, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: producerNodeKP}); err != nil {
		t.Fatal(err)
	}
	producerIssuerKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := producerKS.SaveKeyPair(byrefProducerIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: producerIssuerKP}); err != nil {
		t.Fatal(err)
	}

	consumerKS := ksfilestore.New(t.TempDir())
	consumerKP, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// byrefConsumerDID is BOTH the chainmanager Subscribe's own subscriberDID
	// (the ad hoc chainSvc's peer-client signing identity) and the consumer
	// pipeline runtime's node identity (AuditQueue/PayloadResolver) — the
	// consumer pipeline has no producing loop, so no OutputSubject key is
	// needed beyond this one.
	if err := consumerKS.SaveKeyPair(byrefConsumerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: consumerKP}); err != nil {
		t.Fatal(err)
	}

	// --- shared wireauth DID-resolution server: every identity ANY wireauth
	// caller in this scenario signs as — the producer's node identity
	// (RegisterAuditHead, PayloadStoreService retain, PayloadService serving
	// admission) and the consumer's identity (RegisterSubscription,
	// PayloadService fetch, RegisterAuditHead). One shared server suffices
	// (mirrors separated_e2e_test.go's own newSepFakeDIDServer use). ---
	fakeDIDURL := newSepFakeDIDServer(t, map[string]*did.DIDDocument{
		byrefProducerPipeline: sepIdentityDoc(t, byrefProducerPipeline, producerNodeKP.PublicKey),
		byrefConsumerDID:      sepIdentityDoc(t, byrefConsumerDID, consumerKP.PublicKey),
	})

	// --- producer registry: the SAME netcompose.BuildHandler production mux
	// separated_e2e_test.go's own scenarios use (buildSepRegistry), with its
	// OWN chainOp keyed to pubAccSeed/opSeed/sharedDir (so the AddExport its
	// chainmanager performs when it receives the wire RegisterSubscription
	// below lands in the SAME resolver directory the consumer's
	// independently-built account operator writes to), and the allow-list
	// pre-seeded so RegisterSubscription/PayloadService admit the consumer's
	// identity. The wrap hook counts real PayloadService requests — this
	// file's stand-in for the deleted fullsmoke capstone's own payloadReqs
	// teeth. ---
	producerChainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS: chainconfig.NATSConfig{
			URL: "nats://unused-in-e2e:4222", AccountSeed: string(pubAccSeed),
			TrustRootSeed: string(opSeed), ResolverDir: sharedDir,
			NodeDID: byrefProducerPipeline,
		},
	}
	var payloadReqs int32
	reg := buildSepRegistry(t, fakeDIDURL, nil, map[string][]store.AllowRule{
		byrefProducerPipeline: {{Pattern: byrefConsumerDID}},
	}, producerChainCfg, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/dplaax.payload.v1.PayloadService/") {
				atomic.AddInt32(&payloadReqs, 1)
			}
			next.ServeHTTP(w, r)
		})
	})

	// --- consumer's ad hoc chainmanager.Service: a real subscriber-side
	// control-plane actor driving Subscribe over the REAL wire
	// ChainPeerService the producer registry mounts — mirrors
	// multinode_e2e_test.go's own subSvc. It is a legitimate stand-in for
	// whatever operator tool drives subscription setup against a real
	// registry; cmd/pipeline itself is barred from linking chainmanager's
	// service root in-process (depsguard_test.go), so this is intentionally
	// NOT part of either pipeline runtime built below. ---
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	subOp := byrefMustOperator(t, subAccSeed, opSeed, sharedDir)
	pc := peerclient.New(consumerKS, byrefConsumerDID, guard.HTTPClient())
	subChainSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(subOp),
		chainmanager.WithDIDResolver(byrefDIDMap{byrefProducerPipeline: byrefEndpointDoc(byrefProducerPipeline, reg.url)}),
		chainmanager.WithPeerClient(pc),
		chainmanager.WithEndpointGuard(guard),
	)
	// The registry's peer wireauth verifier (built inside buildSepRegistry,
	// with no Epoch override available from here) defaults its restart-replay
	// epoch to boot+MaxFuture (wireauth.DefaultAcceptanceWindow, 5s) — "peers
	// recover by retrying" is that package's own documented posture for the
	// first few seconds after boot, so Subscribe is retried rather than
	// treated as a hard failure. No partial state survives a failed attempt:
	// GetPublisherInfo (the first wireauth-checked call Subscribe makes) runs
	// before any registration/persist, so a clean retry never risks
	// ErrDuplicateSubscription.
	subDeadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = subChainSvc.Subscribe(ctx, byrefConsumerDID, byrefProducerPipeline, "by-reference"); err == nil {
			break
		}
		if time.Now().After(subDeadline) {
			t.Fatalf("Subscribe(by-reference): %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Negative probe: the consumer's account ALSO structurally imports the
	// PLAIN producer subject onto a distinct local alias — Subscribe above
	// only ever imported the by-reference-prefixed subject, so nothing
	// should ever arrive here (mirrors TestMultiNodeDelivery's "denied"
	// pattern).
	if err := subOp.AddImport(byrefProducerPipeline, pubAccPub, byrefProbeLocal); err != nil {
		t.Fatalf("AddImport(probe): %v", err)
	}

	// --- cold-account ordering: bridge BOTH operators' grants into the
	// broker's resolver BEFORE any client connects. ---
	mr := byrefBridgeDirToResolver(t, sharedDir)
	natsSrv := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(natsSrv.Shutdown)
	natsURL := natsSrv.ClientURL()

	// --- producer pipeline runtime: ONE source loop. buildDeps ALWAYS wires
	// a PayloadStore (D-6), so this loop dual-emits automatically — no
	// separate opt-in needed to prove property 1. ---
	producerPipeCfg := &pipelineconfig.Config{
		VCStoreEndpoint: reg.url, VCStoreBearer: sepBearer, MaxCredentialSize: 1 << 20,
		Loops: []pipelineconfig.LoopConfig{{
			Name: "byrefsrc", Role: pipelineconfig.RoleSource, IngressSubject: byrefProducerIngress,
			Source: pipelineconfig.SourceConfig{
				OutputSubject: byrefProducerPipeline,
				Issuer:        pipelineconfig.IssuerConfig{DID: byrefProducerIssuerDID, KeyID: string(keystore.KeyIDSigning), VerificationMethod: byrefProducerIssuerDID + "#signing"},
				PipelineID:    "byrefsrc", ProcessID: "s1", TransformationClaim: vc.ClaimConvert,
			},
		}},
	}
	producerDataCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: natsURL, AccountSeed: string(pubAccSeed), NodeDID: byrefProducerPipeline},
	}
	producerRTCfg, err := pipelineRuntimeConfigFrom(producerDataCfg, producerPipeCfg, t.TempDir())
	if err != nil {
		t.Fatalf("pipelineRuntimeConfigFrom(producer): %v", err)
	}
	producerDeps := buildDeps(producerPipeCfg, producerKS, guard, nil, byrefProducerPipeline)
	producerDP, err := pipelineruntime.Build(ctx, &producerRTCfg, producerKS, producerDeps)
	if err != nil {
		t.Fatalf("pipelineruntime.Build(producer): %v", err)
	}
	t.Cleanup(func() { _ = producerDP.Close() })

	// --- consumer pipeline runtime: ONE sink loop, payload-delivery =
	// by-reference. IngressSubject stays the PLAIN producer pipeline DID
	// (unchanged by mode — Subscribe's D-4 rename absorbs it). VCStoreEndpoint
	// points at the PRODUCER's registry: a pure observation sink's only wire
	// dependencies (StoreIngressVC/RegisterAuditHead, and the PayloadResolver
	// fetch) all resolve there, and wiring.go's own "one registry base URL"
	// rule is exactly this — whichever registry actually holds what a node
	// needs. ---
	writer := &byrefCaptureWriter{}
	localResolver := local.New()
	localResolver.Add(sepOwnerDocLocal(sepOwnerDID))
	localResolver.Add(sepLocalProcessDoc(t, byrefProducerIssuerDID, sepOwnerDID, producerIssuerKP.PublicKey))
	consumerPipeCfg := &pipelineconfig.Config{
		VCStoreEndpoint: reg.url, VCStoreBearer: sepBearer, MaxCredentialSize: 1 << 20,
		Loops: []pipelineconfig.LoopConfig{{
			Name: "byrefsink", Role: pipelineconfig.RoleSink, IngressSubject: byrefProducerPipeline,
			Sink: pipelineconfig.SinkConfig{
				Kind: pipelineconfig.SinkProduction, VerificationStrategy: pipelineconfig.StrategyAdjacent,
				AllowIssuers: []string{"did:dplaax:reg:org:acme:*"},
				AgentAccess: pipelineconfig.AgentAccessConfig{
					Enabled: true, BoundaryID: "provin-agent-delivery@1",
					DecisionProfileID: "purpose-first-agent-access@1",
					RequiredScopes:    []string{"LINEAR_ATTESTATION@1"},
				},
				// UpstreamEndpoint is NOT decorative for a by-reference sink:
				// sink.go's acquirePayload dials deps.PayloadResolver.
				// ResolvePayload(ctx, UpstreamEndpoint, outputHash) with this
				// EXACT value as the per-call target — the producer registry's
				// own PayloadService serving boundary.
				UpstreamEndpoint: reg.url, PayloadDelivery: "by-reference",
			},
		}},
	}
	consumerDataCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: natsURL, AccountSeed: string(subAccSeed), NodeDID: byrefConsumerDID},
	}
	consumerRTCfg, err := pipelineRuntimeConfigFrom(consumerDataCfg, consumerPipeCfg, t.TempDir())
	if err != nil {
		t.Fatalf("pipelineRuntimeConfigFrom(consumer): %v", err)
	}
	consumerDeps := buildDeps(consumerPipeCfg, consumerKS, guard, localResolver, byrefConsumerDID)
	consumerDeps.SinkWriter = writer
	consumerDP, err := pipelineruntime.Build(ctx, &consumerRTCfg, consumerKS, consumerDeps)
	if err != nil {
		t.Fatalf("pipelineruntime.Build(consumer): %v", err)
	}
	t.Cleanup(func() { _ = consumerDP.Close() })

	runCtx, cancel := context.WithCancel(context.Background())
	producerDone := make(chan error, 1)
	consumerDone := make(chan error, 1)
	go func() { producerDone <- producerDP.Run(runCtx) }()
	go func() { consumerDone <- consumerDP.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		<-producerDone
		<-consumerDone
	})

	// --- injector on the producer's account + a probe observer on the
	// consumer's account (subscribed BEFORE any injection, so the later
	// negative check is deliver-then-check, not a race). ---
	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: natsURL, AccountSeed: string(pubAccSeed)})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	pub := inj.Publisher(byrefProducerIngress)

	probeConn, err := natstransport.Connect(context.Background(), natstransport.Config{URL: natsURL, AccountSeed: string(subAccSeed)})
	if err != nil {
		t.Fatalf("probe connect: %v", err)
	}
	t.Cleanup(func() { _ = probeConn.Close() })
	var probeMu sync.Mutex
	var probeHits int
	if err := probeConn.Subscriber(byrefProbeLocal).Subscribe(func([]byte) {
		probeMu.Lock()
		probeHits++
		probeMu.Unlock()
	}); err != nil {
		t.Fatalf("probe subscribe: %v", err)
	}

	// --- drive the positive path: retry-inject until the sink delivers. ---
	const raw = `{"reading":42}`
	sepRetryUntil(t, 15*time.Second, 150*time.Millisecond, func() { _ = pub.Publish([]byte(raw)) }, func() bool {
		return len(writer.records()) > 0
	})
	recs := writer.records()
	rec := recs[0]
	if string(rec.Payload) != raw {
		t.Fatalf("payload: got %q want %q", rec.Payload, raw)
	}
	if rec.Verdict == nil || rec.Verdict.Overall != vc.ConfidenceVerified {
		t.Fatalf("verdict: got %+v want ConfidenceVerified", rec.Verdict)
	}
	if rec.Credential == nil || rec.Credential.Issuer() != byrefProducerIssuerDID {
		t.Fatalf("issuer: got %v want %q", rec.Credential, byrefProducerIssuerDID)
	}
	if rec.EvidenceView == nil || rec.EvidenceView.PolicyDecision == nil || rec.EvidenceView.PolicyDecision.Decision != "ACCEPT" {
		t.Fatalf("exact appraisal: got %+v", rec.EvidenceView)
	}
	if err := rec.EvidenceView.ValidateID(); err != nil {
		t.Fatalf("EvidenceView identity: %v", err)
	}
	if got := rec.EvidenceView.Manifest.Extensions["selectionPolicyId"]; got != "projected-chain@1" {
		t.Fatalf("selectionPolicyId: got %v", got)
	}
	if rec.Delivery == nil || rec.Delivery.EvidenceViewID != rec.EvidenceView.EvidenceViewID || rec.Delivery.BoundaryID != "provin-agent-delivery@1" {
		t.Fatalf("delivery binding: delivery=%+v view=%+v", rec.Delivery, rec.EvidenceView)
	}

	// --- teeth: the STRIPPED form crossed, not the plain one. A delivered
	// (non-rejected) record from a by-reference-configured sink is only
	// possible if the envelope that crossed carried NO inline payload
	// (pipeline/sink/sink.go's acquirePayload fails closed otherwise: "by-
	// reference + present -> RejectPayloadDeliveryViolation"); this
	// independently OBSERVES that the bytes were fetched over the real wire
	// rather than smuggled inline, mirroring the deleted fullsmoke capstone's
	// own payloadReqs counter (teeth #2 there). ---
	if hits := atomic.LoadInt32(&payloadReqs); hits == 0 {
		t.Fatal("byref: PayloadService received zero requests — the sink did not fetch over the real HTTP surface")
	}

	// --- negative: deliver-then-check. The positive delivery above already
	// proves at least one dual-emit cycle published the PRIMARY (plain) form
	// on byrefProducerPipeline — the producer account subject the probe
	// import targets. probeConn has been live and subscribed the entire
	// time; if the by-reference grant were leaking the plain stream,
	// probeHits would already be > 0. ---
	probeMu.Lock()
	hits := probeHits
	probeMu.Unlock()
	if hits != 0 {
		t.Fatalf("confidentiality violated: the by-reference subscriber's account received %d message(s) on the never-exported plain subject", hits)
	}
}
