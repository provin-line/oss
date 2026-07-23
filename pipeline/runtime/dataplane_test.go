package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/tlog"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// fakeVCStore is a minimal IngressStorer test double: it derives a
// deterministic body address (sha256 of the credential bytes) and does no
// persistence. It is enough for the assembly-level tests in this file, which
// assert Build/Run succeed and check metrics bookkeeping — not storage
// semantics (predecessor-pool holes, resolvability, out-of-order draining,
// malformed-previousCredential rejection). Those are
// network/pkg/services/vcresolver's own concern and already covered by its
// own test suite (vcresolver_test.go); this package no longer imports
// network/pkg/services/vcresolver at all (network/ and pipeline/ never
// import each other, AGENTS.md rule 2) — cmd/pipeline's vcStoreAdapter
// adapts a wire client to IngressStorer for production and its own
// composition-level e2e tests.
type fakeVCStore struct{}

// StoreVC derives a deterministic body address (sha256 of the credential
// bytes) AND a deterministic, distinguishable wire variant id — distinct
// from the body address so a test asserting on StoredHead.WireVariantID
// cannot pass by accident from a copy-paste of the body address.
func (fakeVCStore) StoreVC(_ context.Context, credential []byte, _ string, _ int) (StoredHead, error) {
	sum := sha256.Sum256(credential)
	body := "sha256:" + hex.EncodeToString(sum[:])
	return StoredHead{BodyAddress: body, WireVariantID: "wire:v1:jcs-rfc8785:" + body}, nil
}

// dpVCStore returns a fresh IngressStorer for data-plane tests that build
// consuming loops (slice-17f: all consuming loops require a VCStore).
func dpVCStore() IngressStorer {
	return fakeVCStore{}
}

// memAuditQueue is a minimal AuditRegistrar test double recording every
// registered head (both StoredHead fields) — enough for these tests, which
// only need audit registration to succeed (no assertions on the queue's own
// drain/list behavior; network/pkg/services/auditor.MemQueue is the
// production-shaped one, wired by cmd/network through an adapter, and reached
// over the wire by cmd/pipeline's own wireAuditRegistrar). A
// package-local fake keeps this package free of any network/ import
// (network/ and pipeline/ never import each other, AGENTS.md rule 2).
type memAuditQueue struct{ heads []StoredHead }

func newMemAuditQueue() *memAuditQueue { return &memAuditQueue{} }

func (q *memAuditQueue) Add(head StoredHead) error {
	q.heads = append(q.heads, head)
	return nil
}

// dpAccountServer embeds a single-account operator-trusted nats-server and returns
// its URL plus the account seed (the node's data-plane identity).
func dpAccountServer(t *testing.T) (url, accountSeed string) {
	t.Helper()
	op, _ := nkeys.CreateOperator()
	opPub, _ := op.PublicKey()
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	accSeed, _ := acc.Seed()
	ac := jwt.NewAccountClaims(accPub)
	ajwt, err := ac.Encode(op)
	if err != nil {
		t.Fatalf("encode account JWT: %v", err)
	}
	mr := &server.MemAccResolver{}
	if err := mr.Store(accPub, ajwt); err != nil {
		t.Fatalf("resolver store: %v", err)
	}
	s := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	t.Cleanup(s.Shutdown)
	return s.ClientURL(), string(accSeed)
}

// withNATS attaches the embedded broker's connection parameters to cfg and
// returns it — the common assembly every Build call in this file needs (cfg
// itself carries only Loops; NATS is wired per-test against the embedded
// broker dpAccountServer starts).
func withNATS(url, accSeed string, cfg *Config) *Config {
	cfg.NATS = NATSConfig{URL: url, AccountSeed: accSeed}
	return cfg
}

const (
	dpPipelineDID = "did:dplaax:reg:org:acme:pipeline:pipe"
	dpIssuerDID   = "did:dplaax:reg:org:acme:pipeline:pipe:process:src"
	dpIngress     = "ingest.src"
)

func dpKeyStore(t *testing.T) keystore.KeyStore {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(dpIssuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	return ks
}

func dpPipelineCfg() *Config {
	return &Config{Loops: []LoopConfig{{
		Name:           "src",
		Role:           RoleSource,
		IngressSubject: dpIngress,
		Source: SourceConfig{
			OutputSubject: dpPipelineDID,
			Issuer: IssuerConfig{
				DID: dpIssuerDID, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpIssuerDID + "#signing",
			},
			PipelineID:          "pipe",
			ProcessID:           "src",
			TransformationClaim: vc.ClaimConvert,
		},
	}}}
}

// TestDataPlane_SourceLoopBoot is the slice-17b capstone: it assembles a
// source loop (nats transport + ingest signer + memlog) and runs it; a raw JSON push
// on the ingress subject yields a signed, correctly-attributed Envelope on the output
// subject; cancelling the context drains the runner.
func TestDataPlane_SourceLoopBoot(t *testing.T) {
	url, accSeed := dpAccountServer(t)

	dp, err := Build(context.Background(), withNATS(url, accSeed, dpPipelineCfg()), dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // drain the runner even if the test fails before the explicit cancel below
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()

	// Observer + injector on a second connection to the same account.
	obs, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	defer obs.Close()
	got := make(chan []byte, 4)
	if err := obs.Subscriber(dpPipelineDID).Subscribe(func(b []byte) { got <- b }); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}
	injector := obs.Publisher(dpIngress)

	// Retry the raw push until the source loop has subscribed and an envelope lands
	// (the loop's Subscribe inside dp.Run has no external ready signal).
	const rawJSON = `{"hello":"world"}`
	var wire []byte
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	_ = injector.Publish([]byte(rawJSON))
loop:
	for {
		select {
		case wire = <-got:
			break loop
		case <-tick.C:
			_ = injector.Publish([]byte(rawJSON))
		case <-deadline:
			t.Fatal("no envelope delivered on the output subject")
		}
	}

	env, err := envelopecodec.New().UnmarshalEnvelope(wire)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.SequenceNo != 1 {
		t.Fatalf("sequence: got %d want 1", env.SequenceNo)
	}
	if string(env.Payload) != rawJSON {
		t.Fatalf("payload: got %q want %q", env.Payload, rawJSON)
	}
	if env.Credential == nil {
		t.Fatal("envelope has no credential")
	}
	if env.Credential.Issuer() != dpIssuerDID {
		t.Fatalf("issuer: got %q want %q", env.Credential.Issuer(), dpIssuerDID)
	}
	if env.Credential.Proof() == nil {
		t.Fatal("credential is unsigned (no proof)")
	}
	subj, err := env.Credential.Subject()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	if subj.PipelineID != "pipe" || subj.ProcessID != "src" {
		t.Fatalf("subject ids: %q / %q", subj.PipelineID, subj.ProcessID)
	}

	// Graceful drain: cancel the context, the runner returns.
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("dp.Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dp.Run did not return after context cancel")
	}
}

// TestDataPlane_FirstLoopErrorCancelsSiblings is the regression guard for the
// early-loop-failure deadlock: when one loop returns an error before the context is
// cancelled (here a Subscribe failure on a malformed subject), Run must cancel its
// siblings and return that error promptly — it must NOT block in wg.Wait until an
// external context cancellation arrives. The context passed in is never cancelled, so
// a Run that returns at all proves the internal child-context cancellation works.
func TestDataPlane_FirstLoopErrorCancelsSiblings(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	conn, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	builder := vc.NewBuilder(dpKeyStore(t))

	// A healthy loop (would otherwise block on <-ctx.Done forever) plus a loop whose
	// ingress subject is malformed, so its Subscribe fails at Run time. buildSourceLoop
	// does not validate the subject (that is the config layer's job), so it builds.
	goodLC := dpPipelineCfg().Loops[0]
	goodLC.Name = "good"
	badLC := goodLC
	badLC.Name = "bad"
	badLC.IngressSubject = "bad subject" // embedded space => nats ErrBadSubject at Subscribe

	good, err := buildSourceLoop(conn.Subscriber(goodLC.IngressSubject), conn, builder, nil, memlog.New(), vc.SchemaRef{}, payloadWiring{}, goodLC)
	if err != nil {
		t.Fatalf("build good loop: %v", err)
	}
	bad, err := buildSourceLoop(conn.Subscriber(badLC.IngressSubject), conn, builder, nil, memlog.New(), vc.SchemaRef{}, payloadWiring{}, badLC)
	if err != nil {
		t.Fatalf("build bad loop: %v", err)
	}
	dp := &Runtime{conn: conn, loops: []*transport.Loop{good, bad}}
	t.Cleanup(func() { _ = dp.Close() })

	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(context.Background()) }()

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("Run returned nil; want the failing loop's Subscribe error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run blocked after a loop failed early — siblings were not cancelled")
	}
}

// TestDataPlane_ZeroLoopsNoDial asserts the no-dial short-circuit: with no loops
// configured, Build must NOT dial nats (a bogus URL must not error), so an
// empty pipeline config never requires a live broker.
func TestDataPlane_ZeroLoopsNoDial(t *testing.T) {
	cfg := &Config{NATS: NATSConfig{URL: "nats://192.0.2.1:4222", AccountSeed: "bogus"}}
	dp, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build (zero loops): %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	if err := dp.Run(context.Background()); err != nil {
		t.Fatalf("zero-loop Run: %v", err)
	}
}

// TestBuildRequiresNATSConfig asserts Build's own NATS-by-construction guard
// (the severed replacement for the old chainCfg.Transport != NATS check,
// which moved out to cmd/pipeline's mapping — see pipelineRuntimeConfigFrom):
// loops configured with an empty NATS URL is a build error naming the
// problem, not a nil-deref or an opaque dial failure from natstransport.
func TestBuildRequiresNATSConfig(t *testing.T) {
	cfg := dpPipelineCfg() // NATS left zero-value: URL == ""
	_, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
	if err == nil {
		t.Fatal("loops configured with an empty NATS URL: want a build error, got nil")
	}
	if !strings.Contains(err.Error(), "nats configuration") {
		t.Errorf("error %q does not name the missing nats configuration (an opaque dial failure instead of the purpose-built guard?)", err)
	}
}

// stubResolver satisfies resolver.Resolver for assembly tests; Resolve is never called
// at build time (only at Run/verify), so its body is irrelevant here.
type stubResolver struct{}

func (stubResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, fmt.Errorf("stub resolver")
}

func dpSinkCfg() *Config {
	return &Config{Loops: []LoopConfig{{
		Name:           "archive",
		Role:           RoleSink,
		IngressSubject: dpPipelineDID,
		Sink: SinkConfig{
			Kind:                 SinkObservationOnly,
			VerificationStrategy: StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
		},
	}}}
}

// TestBuildDataPlane_SinkLoopAssembles asserts the role dispatch builds a terminating
// sink loop (NewLoop accepts it with no Publisher/Codec/Emission) when given a resolver
// and a writer.
func TestBuildDataPlane_SinkLoopAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	dp, err := Build(context.Background(), withNATS(url, accSeed, dpSinkCfg()), dpKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
	})
	if err != nil {
		t.Fatalf("Build (sink): %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	if len(dp.loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(dp.loops))
	}
	// Drain immediately — assembly is what this test asserts.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("sink Run drain: %v", err)
	}
}

// The per-loop metrics bookkeeping follows capability (P1-2): a source loop
// registers emit counting (but no verify, and no stripped counting without a
// payload store); a sink registers verify counting only.
func TestBuildDataPlane_MetricsBookkeepingFollowsRole(t *testing.T) {
	url, accSeed := dpAccountServer(t)

	src, err := Build(context.Background(), withNATS(url, accSeed, dpPipelineCfg()), dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build (source): %v", err)
	}
	if len(src.metrics) != 1 {
		t.Fatalf("source metrics entries: got %d want 1", len(src.metrics))
	}
	lm := src.metrics[0]
	if lm.Name != "src" || lm.Role != RoleSource {
		t.Errorf("source entry = %q/%q, want src/source", lm.Name, lm.Role)
	}
	if lm.Emits == nil {
		t.Error("source loop: emits accessor is nil, want registered")
	}
	if lm.Stripped != nil {
		t.Error("source loop without a payload store: stripped accessor registered, want nil")
	}
	if lm.Verify != nil {
		t.Error("source loop: verify accessor registered, want nil (source verifies nothing)")
	}

	snk, err := Build(context.Background(), withNATS(url, accSeed, dpSinkCfg()), dpKeyStore(t), Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
	})
	if err != nil {
		t.Fatalf("Build (sink): %v", err)
	}
	if len(snk.metrics) != 1 {
		t.Fatalf("sink metrics entries: got %d want 1", len(snk.metrics))
	}
	lm = snk.metrics[0]
	if lm.Role != RoleSink {
		t.Errorf("sink entry role = %q, want sink", lm.Role)
	}
	if lm.Verify == nil {
		t.Error("sink loop: verify accessor is nil, want registered")
	}
	if lm.Emits != nil || lm.Stripped != nil {
		t.Error("sink loop: emit/stripped accessors registered, want nil (a sink emits nothing)")
	}
}

// The remaining bookkeeping branches: a dual-emitting node (payload store
// wired) registers stripped counting on its producing loops, a chained loop
// is both producer and consumer, and the aggregate's early-continue append
// path records exactly one entry with the full producer+consumer set.
func TestBuildDataPlane_MetricsBookkeepingDualEmitChainedAggregate(t *testing.T) {
	url, accSeed := dpAccountServer(t)

	// Source with a payload store: the dual-emit gate registers stripped.
	src, err := Build(context.Background(), withNATS(url, accSeed, dpPipelineCfg()), dpKeyStore(t), Deps{
		PayloadStore: fakePayloadStore{},
	})
	if err != nil {
		t.Fatalf("Build (source+store): %v", err)
	}
	if lm := src.metrics[0]; lm.Stripped == nil {
		t.Error("source loop with a payload store: stripped accessor is nil, want registered (dual-emit)")
	}

	// Chained: producer AND consumer.
	chd, err := Build(context.Background(), withNATS(url, accSeed, dpChainedCfg("{ 'relayed': true }")), dpKeyStore(t), Deps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("Build (chained): %v", err)
	}
	if len(chd.metrics) != 1 {
		t.Fatalf("chained metrics entries: got %d want 1", len(chd.metrics))
	}
	lm := chd.metrics[0]
	if lm.Role != RoleChained || lm.Emits == nil || lm.Verify == nil {
		t.Errorf("chained entry = role %q emits %v verify %v; want chained + both registered", lm.Role, lm.Emits, lm.Verify)
	}
	if lm.Stripped != nil {
		t.Error("chained loop without a payload store: stripped accessor registered, want nil")
	}

	// Aggregate: the early-continue path appends exactly once, producer+consumer.
	aggCfg := &Config{Loops: []LoopConfig{{
		Name: "agg",
		Role: RoleAggregate,
		Aggregate: AggregateConfig{
			OutputSubject: dpRelayDID,
			Issuer: IssuerConfig{
				DID: dpRelayIssr, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpRelayIssr + "#signing",
			},
			PipelineID: "relay",
			ProcessID:  "r1",
			Window:     100 * time.Millisecond,
			Ingresses: []AggregateIngress{
				{Subject: dpPipelineDID, UpstreamEndpoint: "https://acme.example/pipelines/pipe"},
			},
		},
	}}}
	agg, err := Build(context.Background(), withNATS(url, accSeed, aggCfg), dpKeyStore(t), Deps{
		Resolver:     stubResolver{},
		VCStore:      dpVCStore(),
		PayloadStore: fakePayloadStore{},
	})
	if err != nil {
		t.Fatalf("Build (aggregate): %v", err)
	}
	if len(agg.metrics) != 1 {
		t.Fatalf("aggregate metrics entries: got %d want 1 (early-continue path must append exactly once)", len(agg.metrics))
	}
	lm = agg.metrics[0]
	if lm.Role != RoleAggregate || lm.Emits == nil || lm.Verify == nil || lm.Stripped == nil {
		t.Errorf("aggregate entry = role %q emits %v verify %v stripped %v; want aggregate + all three registered",
			lm.Role, lm.Emits, lm.Verify, lm.Stripped)
	}
}

// Sink delivery writers come from per-loop config when no override is injected:
// file outputs share ONE writer per cleaned path (two loops on one file must
// never interleave lines), console is the default, junk types fail closed, and
// an injected deps.SinkWriter (the test seam) overrides everything.
func TestSinkWriters_ProviderSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	sw := newSinkWriters(nil)

	w1, err := sw.writerFor(SinkOutputConfig{Type: SinkOutputFile, Path: path})
	if err != nil {
		t.Fatalf("writerFor(file): %v", err)
	}
	// Same file spelled differently must resolve to the SAME writer instance.
	w2, err := sw.writerFor(SinkOutputConfig{
		Type: SinkOutputFile, Path: filepath.Join(dir, "sub", "..", "out.ndjson")})
	if err != nil {
		t.Fatalf("writerFor(file, uncleaned): %v", err)
	}
	if w1 != w2 {
		t.Error("two loops on one path got distinct writers — lines could interleave")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created at construction (boot): %v", err)
	}

	// Console: the default for a zero-value Output (typed-config construction)
	// and the explicit type; one shared instance.
	c1, err := sw.writerFor(SinkOutputConfig{})
	if err != nil {
		t.Fatalf("writerFor(zero): %v", err)
	}
	c2, err := sw.writerFor(SinkOutputConfig{Type: SinkOutputConsole})
	if err != nil {
		t.Fatalf("writerFor(console): %v", err)
	}
	if c1 != c2 {
		t.Error("console writers not shared")
	}

	if _, err := sw.writerFor(SinkOutputConfig{Type: "warehouse"}); err == nil {
		t.Error("unknown output type: want error (fail closed)")
	}

	// The injection seam wins over any config.
	inj := console.New(io.Discard)
	swo := newSinkWriters(inj)
	if w, err := swo.writerFor(SinkOutputConfig{Type: SinkOutputFile, Path: path}); err != nil || w != sink.Writer(inj) {
		t.Errorf("override: got %v (err %v), want the injected writer", w, err)
	}
}

// A sink loop with a file output assembles with NO injected writer: the surface
// comes from config, and the file exists after boot (fail-closed construction).
func TestBuildDataPlane_SinkFileOutputAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	cfg := dpSinkCfg()
	path := filepath.Join(t.TempDir(), "consumed.ndjson")
	cfg.Loops[0].Sink.Output = SinkOutputConfig{Type: SinkOutputFile, Path: path}

	dp, err := Build(context.Background(), withNATS(url, accSeed, cfg), dpKeyStore(t), Deps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("Build (file sink, no injected writer): %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	if _, err := os.Stat(path); err != nil {
		t.Errorf("output file not created at boot: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

// TestBuildDataPlane_SinkRequiresDeps asserts a sink loop without a resolver is a
// build error (fail closed) rather than a nil-deref at run time. (The writer no
// longer gates assembly: it comes from sink.output config, console by default.)
func TestBuildDataPlane_SinkRequiresDeps(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	if _, err := Build(context.Background(), withNATS(url, accSeed, dpSinkCfg()), dpKeyStore(t), Deps{}); err == nil {
		t.Fatal("sink loop without resolver/writer: want error, got nil")
	}
}

const (
	dpRelayDID  = "did:dplaax:reg:org:beta:pipeline:relay"
	dpRelayIssr = "did:dplaax:reg:org:beta:pipeline:relay:process:r1"
)

func dpChainedCfg(converter string) *Config {
	return &Config{Loops: []LoopConfig{{
		Name:           "relay",
		Role:           RoleChained,
		IngressSubject: dpPipelineDID,
		Chained: ChainedConfig{
			OutputSubject: dpRelayDID,
			Issuer: IssuerConfig{
				DID: dpRelayIssr, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpRelayIssr + "#signing",
			},
			PipelineID:           "relay",
			ProcessID:            "r1",
			TransformationClaim:  vc.ClaimConvert,
			VerificationStrategy: StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
			Converter:            converter,
		},
	}}}
}

// TestBuildDataPlane_ChainedLoopAssembles asserts the role dispatch builds a
// ChainPreserving relay loop (NewLoop accepts Publisher+Codec+Emission) given a resolver;
// a chained loop needs no sink writer.
func TestBuildDataPlane_ChainedLoopAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	dp, err := Build(context.Background(), withNATS(url, accSeed, dpChainedCfg("{ 'reading': reading, 'relayed': true }")), dpKeyStore(t), Deps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("Build (chained): %v", err)
	}
	t.Cleanup(func() { _ = dp.Close() })
	if len(dp.loops) != 1 {
		t.Fatalf("loops: got %d want 1", len(dp.loops))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dp.Run(ctx); err != nil {
		t.Fatalf("chained Run drain: %v", err)
	}
}

// TestBuildDataPlane_ChainedRequiresResolver asserts a chained loop without a DID resolver
// is a build error (fail closed via ensureConsumer) rather than a nil-deref at run time. A
// chained loop needs a resolver (to verify ingress) but no sink writer.
func TestBuildDataPlane_ChainedRequiresResolver(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	if _, err := Build(context.Background(), withNATS(url, accSeed, dpChainedCfg("")), dpKeyStore(t), Deps{}); err == nil {
		t.Fatal("chained loop without resolver: want error, got nil")
	}
}

// TestBuildDataPlane_ChainedMalformedConverterFails asserts a malformed JSONata converter
// expression fails closed at build (compiled at loop-build time), not at first event.
func TestBuildDataPlane_ChainedMalformedConverterFails(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	if _, err := Build(context.Background(), withNATS(url, accSeed, dpChainedCfg("{ unterminated")), dpKeyStore(t), Deps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	}); err == nil {
		t.Fatal("malformed converter expression: want build error, got nil")
	}
}

// The durable node path: with TlogDir set, Build opens a filelog
// per producing loop under sha256(log id), registers it under the OUTPUT
// SUBJECT, and arms it with the loop's issuer key — a signed checkpoint
// must verify as coming from that identity.
func TestDataPlane_DurableEmissionLog(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	tlogDir := t.TempDir()
	cfg := withNATS(url, accSeed, dpPipelineCfg())
	cfg.TlogDir = tlogDir
	dp, err := Build(context.Background(), cfg, dpKeyStore(t), Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = dp.conn.Close() })

	l, ok := dp.tlogs[dpPipelineDID]
	if !ok {
		t.Fatalf("registry keys = %v, want the output subject %s", dp.tlogs, dpPipelineDID)
	}
	sum := sha256.Sum256([]byte(dpPipelineDID))
	if _, err := os.Stat(filepath.Join(tlogDir, hex.EncodeToString(sum[:]), "log.ndjson")); err != nil {
		t.Fatalf("durable log file at the identity-derived path: %v", err)
	}
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatalf("Checkpoint on the armed durable log: %v", err)
	}
	if cp.SignedBy != dpIssuerDID+"#signing" {
		t.Fatalf("checkpoint signed_by = %s, want the loop issuer's verification method", cp.SignedBy)
	}
	if len(dp.tlogClosers) != 1 {
		t.Fatalf("tlogClosers = %d, want 1 (teardown must release the handle)", len(dp.tlogClosers))
	}
}

const dpArchiveReceiptIssr = "did:dplaax:reg:org:acme:pipeline:archive:process:a1"

// dpArchivalSinkCfg is an archival sink loop: Kind = archival, which config
// validation (config.go) already REQUIRES to carry a receipt issuer
// (sink.receipt.issuer) — the same signer identity this task arms the
// reject log's checkpoint with (D-T3).
func dpArchivalSinkCfg() *Config {
	return dpArchivalSinkCfgWithIssuer(dpArchiveReceiptIssr)
}

// dpArchivalSinkCfgWithIssuer is dpArchivalSinkCfg parameterized on the
// receipt issuer DID, so tests can construct two archival sinks that differ
// ONLY in that identity — the axis the reject-log rekeying fix (Task 7) must
// key storage on.
func dpArchivalSinkCfgWithIssuer(issuerDID string) *Config {
	return &Config{Loops: []LoopConfig{{
		Name:           "archive",
		Role:           RoleSink,
		IngressSubject: dpPipelineDID,
		Sink: SinkConfig{
			Kind:                 SinkArchival,
			VerificationStrategy: StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
			AllowIssuers:         []string{"did:dplaax:reg:org:acme:*"},
			Receipt: SinkReceiptConfig{
				Issue: true,
				Issuer: IssuerConfig{
					DID:                issuerDID,
					KeyID:              string(keystore.KeyIDSigning),
					VerificationMethod: issuerDID + "#signing",
				},
				PipelineID: "archive",
				ProcessID:  "a1",
			},
		},
	}}}
}

// TestDataPlane_ArchivalSinkRejectLog_SignedIdentity is the D-T3 sink-reject
// capstone: an archival sink's reject log is armed with the SAME signer as
// its (mandatory) sink-receipt issuer, so its checkpoint carries the stable
// custody identity `sink-reject:<receipt-issuer-process-DID>` — AND (Task 7
// rekeying) the on-disk directory is keyed by sha256(log id), exactly like
// newEmission: identity and storage co-move, so a receipt-DID change across
// a restart resolves to a fresh directory instead of reopening the old DID's
// journal under a new signer.
func TestDataPlane_ArchivalSinkRejectLog_SignedIdentity(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(dpArchiveReceiptIssr, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}

	rejectDir := t.TempDir()
	cfg := withNATS(url, accSeed, dpArchivalSinkCfg())
	cfg.RejectLogDir = rejectDir
	dp, err := Build(context.Background(), cfg, ks, Deps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
		AuditQueue: newMemAuditQueue(),
	})
	if err != nil {
		t.Fatalf("Build (archival sink): %v", err)
	}
	t.Cleanup(func() { _ = dp.conn.Close() })

	// Directory keying MATCHES newEmission: sha256(log id), not the loop name.
	wantRejectLogID := "sink-reject:" + dpArchiveReceiptIssr
	sum := sha256.Sum256([]byte(wantRejectLogID))
	if _, err := os.Stat(filepath.Join(rejectDir, hex.EncodeToString(sum[:]), "log.ndjson")); err != nil {
		t.Fatalf("reject log at the identity-derived path: %v", err)
	}

	// D-T5: the reject log must never be registered into dp.tlogs (custody-only,
	// never served via TlogService reads).
	if _, ok := dp.tlogs[wantRejectLogID]; ok {
		t.Fatalf("reject log registered into dp.tlogs under %q — must stay unregistered (D-T5)", wantRejectLogID)
	}

	// TlogDir is unset here, so the sibling sink-receipt log stays memlog-backed
	// (no closer) — the reject log is the ONLY durable log this loop opens, so
	// it is the only tlogClosers entry. Assert directly on the constructed
	// instance's own Checkpoint (not a reopened/reconstructed one).
	if len(dp.tlogClosers) != 1 {
		t.Fatalf("tlogClosers = %d, want 1 (only the durable reject log)", len(dp.tlogClosers))
	}
	l, ok := dp.tlogClosers[0].(tlog.Log)
	if !ok {
		t.Fatalf("tlogClosers[0] = %T, want a tlog.Log (the reject log)", dp.tlogClosers[0])
	}
	cp, err := l.Checkpoint(context.Background())
	if err != nil {
		t.Fatalf("Checkpoint on the armed reject log: %v", err)
	}
	if cp.Origin != wantRejectLogID {
		t.Errorf("reject log checkpoint Origin = %q, want %q", cp.Origin, wantRejectLogID)
	}
	wantSignedBy := dpArchiveReceiptIssr + "#signing"
	if cp.SignedBy != wantSignedBy {
		t.Errorf("reject log checkpoint SignedBy = %q, want %q", cp.SignedBy, wantSignedBy)
	}
}

// dpArchiveKeyStore returns a filestore keystore holding a fresh signing key
// for issuerDID — the archival sink's receipt issuer identity.
func dpArchiveKeyStore(t *testing.T, issuerDID string) keystore.KeyStore {
	t.Helper()
	ks := filestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("save key: %v", err)
	}
	return ks
}

// TestDataPlane_ArchivalSinkRejectLog_KeyedByIdentity is the Task-7 rekeying
// regression for the P1 custody hole Codex found: with the OLD loop-name
// keying, a receipt-DID change across a restart (volume retained) reopened
// the SAME directory under a NEW signer, and every subsequent checkpoint
// silently re-signed all historical rejects as the new DID's evidence. The
// fix keys the directory by sha256(log id) — the SAME derivation newEmission
// uses — so identity and storage co-move:
//
//   - a receipt-DID CHANGE must resolve to a FRESH, different directory and
//     must never touch the old DID's journal (re-attribution is structurally
//     prevented, not just discouraged);
//   - a SAME-DID restart must resolve to the SAME directory (continuity is
//     preserved for the normal, non-rollover case).
func TestDataPlane_ArchivalSinkRejectLog_KeyedByIdentity(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	rejectDir := t.TempDir()
	const didB = "did:dplaax:reg:org:acme:pipeline:archive:process:a2"

	buildArchive := func(issuerDID string, ks keystore.KeyStore) *Runtime {
		t.Helper()
		cfg := withNATS(url, accSeed, dpArchivalSinkCfgWithIssuer(issuerDID))
		cfg.RejectLogDir = rejectDir
		dp, err := Build(context.Background(), cfg, ks, Deps{
			Resolver:   stubResolver{},
			SinkWriter: console.New(io.Discard),
			VCStore:    dpVCStore(),
			AuditQueue: newMemAuditQueue(),
		})
		if err != nil {
			t.Fatalf("Build (issuer %s): %v", issuerDID, err)
		}
		if len(dp.tlogClosers) != 1 {
			t.Fatalf("tlogClosers = %d, want 1 (issuer %s)", len(dp.tlogClosers), issuerDID)
		}
		return dp
	}
	dirFor := func(issuerDID string) string {
		sum := sha256.Sum256([]byte("sink-reject:" + issuerDID))
		return filepath.Join(rejectDir, hex.EncodeToString(sum[:]))
	}

	// Open under DID-A, append one reject, then release the directory's
	// single-opener lock (filelog flock) so a later reconstruction under the
	// SAME DID can reopen it — a real restart releases the lock too.
	dpA1 := buildArchive(dpArchiveReceiptIssr, dpArchiveKeyStore(t, dpArchiveReceiptIssr))
	rlA1, ok := dpA1.tlogClosers[0].(tlog.Log)
	if !ok {
		t.Fatalf("tlogClosers[0] = %T, want tlog.Log", dpA1.tlogClosers[0])
	}
	if _, err := rlA1.Append(context.Background(), []byte(`{"reason":"allow-list"}`)); err != nil {
		t.Fatalf("append under DID-A: %v", err)
	}
	if n, err := rlA1.Size(context.Background()); err != nil || n != 1 {
		t.Fatalf("DID-A size after append = %d (err %v), want 1", n, err)
	}
	if err := dpA1.tlogClosers[0].Close(); err != nil {
		t.Fatalf("close DID-A reject log: %v", err)
	}
	if err := dpA1.conn.Close(); err != nil {
		t.Fatalf("close DID-A nats conn: %v", err)
	}

	dirA := dirFor(dpArchiveReceiptIssr)
	if _, err := os.Stat(filepath.Join(dirA, "log.ndjson")); err != nil {
		t.Fatalf("DID-A reject log at the identity-derived path: %v", err)
	}

	// Reconstruct under DID-B — a NEW receipt issuer DID, same RejectLogDir.
	// The P1 hole: with loop-name keying this would reopen DID-A's journal
	// under DID-B's signer. With identity keying it must resolve to a
	// DIFFERENT, fresh directory and must NOT touch DID-A's journal.
	dpB := buildArchive(didB, dpArchiveKeyStore(t, didB))
	t.Cleanup(func() { _ = dpB.conn.Close() })
	t.Cleanup(func() { _ = dpB.tlogClosers[0].Close() })

	dirB := dirFor(didB)
	if dirB == dirA {
		t.Fatalf("DID-B resolved to DID-A's directory %q — re-attribution hole", dirB)
	}
	rlB, ok := dpB.tlogClosers[0].(tlog.Log)
	if !ok {
		t.Fatalf("tlogClosers[0] = %T, want tlog.Log", dpB.tlogClosers[0])
	}
	if n, err := rlB.Size(context.Background()); err != nil || n != 0 {
		t.Fatalf("DID-B size = %d (err %v), want 0 (a fresh log, not DID-A's journal)", n, err)
	}
	cpB, err := rlB.Checkpoint(context.Background())
	if err != nil {
		t.Fatalf("Checkpoint on DID-B's reject log: %v", err)
	}
	if want := "sink-reject:" + didB; cpB.Origin != want {
		t.Errorf("DID-B checkpoint Origin = %q, want %q", cpB.Origin, want)
	}

	// DID-A's journal on disk is untouched by DID-B's open: still one record.
	fi, err := os.Stat(filepath.Join(dirA, "log.ndjson"))
	if err != nil {
		t.Fatalf("DID-A journal missing after DID-B open: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatalf("DID-A journal is empty after DID-B open — its append was lost or overwritten")
	}

	// Reconstruct under DID-A again (a same-DID restart): continuity — same
	// directory, and the previously appended reject is still there (size 1,
	// not reset to 0 under a fresh journal).
	dpA2 := buildArchive(dpArchiveReceiptIssr, dpArchiveKeyStore(t, dpArchiveReceiptIssr))
	t.Cleanup(func() { _ = dpA2.conn.Close() })
	t.Cleanup(func() { _ = dpA2.tlogClosers[0].Close() })

	rlA2, ok := dpA2.tlogClosers[0].(tlog.Log)
	if !ok {
		t.Fatalf("tlogClosers[0] = %T, want tlog.Log", dpA2.tlogClosers[0])
	}
	if n, err := rlA2.Size(context.Background()); err != nil || n != 1 {
		t.Fatalf("DID-A reconstruct size = %d (err %v), want 1 (continuity — the earlier reject survives)", n, err)
	}
}
