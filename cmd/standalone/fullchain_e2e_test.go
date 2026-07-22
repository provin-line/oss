package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/gen/go/dplaax/vc/v1/vcpbconnect"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// fullChainCfg is the two-hop lineage (source → chained → sink) configured for the async
// audit path (slice-17j retired real-time "full"): the sink adjacent-verifies its ingress,
// and the async audit runner walks the WHOLE chain from the local store out of band. The
// AuditRunner/BatchResolver knobs are set so buildAuditRunner constructs (it reads the
// interval/batch/attempts + the max-depth). endpoint is the node-level vc-store-endpoint
// (publication target for the producing loops).
func fullChainCfg(endpoint string) *pipelineconfig.Config {
	cfg := twoHopCfg("{ 'reading': reading, 'relayed': true }", nil)
	cfg.VCStoreEndpoint = endpoint
	cfg.VCStoreBearer = "dummy"
	cfg.AuditRunner = pipelineconfig.AuditRunnerConfig{Interval: 5 * time.Millisecond, BatchSize: 16, MaxAttempts: 5}
	cfg.BatchResolver = pipelineconfig.BatchResolverConfig{Interval: time.Second, BatchSize: 16, MaxRetries: 3, MaxDepth: 1024}
	return cfg
}

// fullChain wires source → chained → sink (sink on full) over an embedded broker AND an
// embedded VCResolverService backed by store. Producing loops publish their issued
// credentials to that store; the full sink resolves predecessors from it.
type fullChain struct {
	inject      func([]byte)
	writer      *captureWriter
	auditStatus *auditor.MemStatusStore
}

func setupFullChain(t *testing.T, store *vcresolver.VariantStore, wrap func(http.Handler) http.Handler) fullChain {
	t.Helper()
	url, accSeed := dpAccountServer(t)

	// Embedded VCResolverService (mounted bare — no authz interceptor in the test, so the
	// client's bearer is accepted trivially). An optional wrap observes the raw requests.
	svc := vcresolver.New(store, memstore.NewPool())
	_, h := vcpbconnect.NewVCResolverServiceHandler(vchandler.New(svc))
	var handler http.Handler = h
	if wrap != nil {
		handler = wrap(h)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// One keystore holds both issuers' signing keys; the resolver serves both lineages.
	ks := filestore.New(t.TempDir())
	res := local.New()
	for _, issuer := range []string{thSrcIssuer, thRelayIssuer} {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		if err := ks.SaveKeyPair(issuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key: %v", err)
		}
		res.Add(capProcessDoc(issuer, thOwnerDID, kp.PublicKey))
	}
	res.Add(capOwnerDoc(thOwnerDID))

	writer := &captureWriter{}
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	// The node's local VC store + audit substrate, shared between the data plane (ingress
	// writes consumed credentials here and registers consumed heads) and the async audit
	// runner (which assembles each head's chain from this store and records a verdict).
	localPool := memstore.NewPool()
	localSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), localPool)
	auditQueue := auditor.NewMemQueue()
	auditStatus := auditor.NewMemStatusStore()
	cfg := fullChainCfg(srv.URL)
	rtCfg, err := runtimeConfigFrom(chainCfg, cfg, "")
	if err != nil {
		t.Fatalf("runtimeConfigFrom: %v", err)
	}
	dp, err := pipelineruntime.Build(context.Background(), &rtCfg, ks, pipelineruntime.Deps{
		Resolver:            res,
		SinkWriter:          writer,
		VCStore:             ingressStoreAdapter{svc: localSvc},
		AuditQueue:          auditQueue,
		CredentialPublisher: credentialPublisherFrom(cfg, srv.Client()),
	})
	if err != nil {
		t.Fatalf("pipelineruntime.Build (full chain): %v", err)
	}
	// The async audit runner walks the full chain from localSvc and records the verdict —
	// the coverage that replaces real-time full (slice-17j). It resolves issuer DIDs via res.
	auditRunner, err := buildAuditRunner(auditQueue, auditStatus, auditor.NewMemReceiptStore(), localSvc, localPool, res, nil, cfg)
	if err != nil || auditRunner == nil {
		t.Fatalf("buildAuditRunner: r=%v err=%v", auditRunner, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	go func() { _ = auditRunner.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	pub := inj.Publisher(thIngress)
	return fullChain{inject: func(p []byte) { _ = pub.Publish(p) }, writer: writer, auditStatus: auditStatus}
}

// awaitRecord injects raw until the sink writes a record (or fails on timeout).
func (fc fullChain) awaitRecord(t *testing.T, raw string) *recordSnapshot {
	t.Helper()
	fc.inject([]byte(raw))
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		if recs := fc.writer.records(); len(recs) > 0 {
			// Let any duplicate the retry-ticker injected finish its publish before the
			// caller's cleanup cancels the context — a producing loop's publication is
			// ctx-aware and fail-closed, so an in-flight event caught mid-publish by the
			// cancel would (correctly) error and log loudly. The settle keeps drain quiet.
			time.Sleep(300 * time.Millisecond)
			return snapshot(t, recs[0])
		}
		select {
		case <-tick.C:
			fc.inject([]byte(raw))
		case <-deadline:
			t.Fatal("sink did not receive a record")
		}
	}
}

// TestFullChain_AsyncAuditRecordsVerified is the slice-17j capstone (re-pointed from the
// retired real-time-full capstone): a real signed two-hop chain (source FirstDrop →
// chained relay → sink) is consumed with an ADJACENT sink, and the async audit runner —
// assembling the WHOLE chain from the local store and running the real vc.VerifyChain over
// the real DID graph — records ConfidenceVerified for the consumed head. This closes the
// Verified-path gap 17h deferred (its runner Verified test used a fake ChainVerifier); the
// batch-resolver fetch path is covered separately by TestBatchResolver_Integration_DrainsFromPeer.
func TestFullChain_AsyncAuditRecordsVerified(t *testing.T) {
	fc := setupFullChain(t, vcresolver.NewVariantStore(memstore.NewBackend()), nil)
	rec := fc.awaitRecord(t, `{"reading":42}`)

	// The relay transformed the payload (proves it is the relayed event, not a passthrough).
	var got map[string]any
	if err := json.Unmarshal(rec.payload, &got); err != nil {
		t.Fatalf("sink payload not JSON: %v (%q)", err, rec.payload)
	}
	if got["relayed"] != true {
		t.Fatalf("payload not transformed: %v", got)
	}
	if rec.prevCredential == "" {
		t.Fatal("chained head has no predecessor link — nothing for the auditor to walk")
	}
	if rec.issuer != thRelayIssuer {
		t.Fatalf("issuer: got %q want %q", rec.issuer, thRelayIssuer)
	}
	if rec.headHash == "" {
		t.Fatal("no head hash captured from the sink record")
	}

	// The async audit runner walks head → source from the local store and records Verified.
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if r, err := fc.auditStatus.Get(rec.headHash); err == nil && r.Overall == vc.ConfidenceVerified {
			if !r.Scope.LinearChain || r.Scope.SourceCommitmentEvaluated {
				t.Fatalf("audit scope = %+v, want linear-only", r.Scope)
			}
			return // the full chain was audited Verified out of band
		}
		select {
		case <-tick.C:
		case <-deadline:
			r, getErr := fc.auditStatus.Get(rec.headHash)
			t.Fatalf("audit runner did not record Verified for head %q (get err=%v rec=%+v)", rec.headHash, getErr, r)
		}
	}
}

// TestFullChain_BearerReachesStore proves the configured vc-store-bearer is presented to
// the store as an Authorization header. The bearer is node config (pipelineconfig.Config),
// so main — which loads and passes that config to pipelineruntime.Build — carries it to the wire
// without a separate composition step. A real L1-protected store would reject every
// publish/resolve without it, so this guards the production token path.
func TestFullChain_BearerReachesStore(t *testing.T) {
	auths := make(chan string, 64)
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case auths <- r.Header.Get("Authorization"):
			default:
			}
			next.ServeHTTP(w, r)
		})
	}
	fc := setupFullChain(t, vcresolver.NewVariantStore(memstore.NewBackend()), wrap)
	fc.awaitRecord(t, `{"reading":42}`) // forces publishes + a full-verify resolve through the wrap

	// At least one request (a publish or the sink's predecessor resolve) carried the bearer.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-auths:
			if got == "Bearer dummy" {
				return // the configured bearer reached the wire
			}
		case <-deadline:
			t.Fatal("no request to the VC store presented the configured bearer (Bearer dummy)")
		}
	}
}
