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
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	vchandler "github.com/provin-line/oss/network/pkg/services/vcresolver/handler"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// fullChainCfg is the two-hop lineage with the sink on verification-strategy = "full":
// the sink walks the chain via the network resolver instead of adjacent-verifying only
// the immediately preceding credential. endpoint is the node-level vc-store-endpoint.
func fullChainCfg(endpoint string) *pipelineconfig.Config {
	cfg := twoHopCfg("{ 'reading': reading, 'relayed': true }", nil)
	cfg.VCStoreEndpoint = endpoint
	cfg.VCStoreBearer = "dummy"
	cfg.Loops[2].Sink.VerificationStrategy = pipelineconfig.StrategyFull
	return cfg
}

// fullChain wires source → chained → sink (sink on full) over an embedded broker AND an
// embedded VCResolverService backed by store. Producing loops publish their issued
// credentials to that store; the full sink resolves predecessors from it.
type fullChain struct {
	inject func([]byte)
	writer *captureWriter
}

func setupFullChain(t *testing.T, store vcresolver.Store, wrap func(http.Handler) http.Handler) fullChain {
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
	dp, err := buildDataPlane(chainCfg, fullChainCfg(srv.URL), ks, dataPlaneDeps{
		Resolver:          res,
		SinkWriter:        writer,
		VCStoreHTTPClient: srv.Client(),
		VCStore:           dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (full chain): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	inj, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	pub := inj.Publisher(thIngress)
	return fullChain{inject: func(p []byte) { _ = pub.Publish(p) }, writer: writer}
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

// TestFullChain_VerifiedByWalk is the slice-17e capstone: the sink on full verification
// resolves the chained credential's predecessor (the source FirstDrop) by content address
// over the network resolver and verifies the WHOLE chain — yielding ConfidenceVerified.
func TestFullChain_VerifiedByWalk(t *testing.T) {
	fc := setupFullChain(t, memstore.NewStore(), nil)
	rec := fc.awaitRecord(t, `{"reading":42}`)

	// The relay transformed the payload (proves it is the relayed event, not a passthrough).
	var got map[string]any
	if err := json.Unmarshal(rec.payload, &got); err != nil {
		t.Fatalf("sink payload not JSON: %v (%q)", err, rec.payload)
	}
	if got["relayed"] != true {
		t.Fatalf("payload not transformed: %v", got)
	}
	// The verdict came from walking the chain: the head (chained) links to a resolved
	// predecessor (source FirstDrop), and the full verifier passed the whole chain.
	if rec.verdict == nil || rec.verdict.Overall != vc.ConfidenceVerified {
		t.Fatalf("verdict: got %+v want ConfidenceVerified", rec.verdict)
	}
	if rec.prevCredential == "" {
		t.Fatal("chained head has no predecessor link — nothing was walked")
	}
	if rec.issuer != thRelayIssuer {
		t.Fatalf("issuer: got %q want %q", rec.issuer, thRelayIssuer)
	}
}

// holeStore wraps a Store but silently drops the source FirstDrop (pipelineId "src"),
// injecting a REAL chain hole: the source still signs+emits over NATS (its publish
// returns the correct hash), the chained head still reaches the sink, but the sink's
// chainwalk cannot resolve the source predecessor. This is NOT "make StoreCredential
// fail" (that would fail-close the source and emit nothing) — the source emits; only the
// predecessor is unresolvable.
type holeStore struct {
	inner vcresolver.Store
}

func (h holeStore) Put(hash string, cred *vc.PipelinePassCredential) error {
	if subj, err := cred.Subject(); err == nil && subj.PipelineID == "src" {
		return nil // accept the write (correct hash returned) but do not retain it
	}
	return h.inner.Put(hash, cred)
}

func (h holeStore) Get(hash string) (*vc.PipelinePassCredential, error) {
	return h.inner.Get(hash)
}

// TestFullChain_HoleIsIndeterminate is the slice-17e negative: with the source FirstDrop
// absent from the store, the full sink's chainwalk hits a hole. The observation-only sink
// writes a ConfidenceIndeterminate verdict — not ConfidenceFailed (a computed rejection)
// and not a pass. The verdict could not be COMPUTED; it was not computed-as-wrong.
func TestFullChain_HoleIsIndeterminate(t *testing.T) {
	fc := setupFullChain(t, holeStore{inner: memstore.NewStore()}, nil)
	rec := fc.awaitRecord(t, `{"reading":42}`)

	if rec.verdict == nil {
		t.Fatal("sink wrote no verdict")
	}
	if rec.verdict.Overall != vc.ConfidenceIndeterminate {
		t.Fatalf("verdict: got %v want ConfidenceIndeterminate (chain hole)", rec.verdict.Overall)
	}
}

// TestFullChain_BearerReachesStore proves the configured vc-store-bearer is presented to
// the store as an Authorization header. The bearer is node config (pipelineconfig.Config),
// so main — which loads and passes that config to buildDataPlane — carries it to the wire
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
	fc := setupFullChain(t, memstore.NewStore(), wrap)
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
