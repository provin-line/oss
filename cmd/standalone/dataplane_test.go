package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/sink/console"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// dpVCStore returns a fresh in-memory vcresolver.Service for use in data-plane tests
// that build consuming loops (slice-17f: all consuming loops require a VCStore).
func dpVCStore() *vcresolver.Service {
	return vcresolver.New(memstore.NewStore(), memstore.NewPool())
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

func dpPipelineCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "src",
		Role:           pipelineconfig.RoleSource,
		IngressSubject: dpIngress,
		Source: pipelineconfig.SourceConfig{
			OutputSubject: dpPipelineDID,
			Issuer: pipelineconfig.IssuerConfig{
				DID: dpIssuerDID, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpIssuerDID + "#signing",
			},
			PipelineID:          "pipe",
			ProcessID:           "src",
			TransformationClaim: vc.ClaimConvert,
		},
	}}}
}

// TestDataPlane_SourceLoopBoot is the slice-17b capstone: the standalone assembles a
// source loop (nats transport + ingest signer + memlog) and runs it; a raw JSON push
// on the ingress subject yields a signed, correctly-attributed Envelope on the output
// subject; cancelling the context drains the runner.
func TestDataPlane_SourceLoopBoot(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}

	dp, err := buildDataPlane(context.Background(), chainCfg, dpPipelineCfg(), dpKeyStore(t), dataPlaneDeps{})
	if err != nil {
		t.Fatalf("buildDataPlane: %v", err)
	}

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
	builder := vc.NewBuilder(ed25519.NewSigner(dpKeyStore(t)))

	// A healthy loop (would otherwise block on <-ctx.Done forever) plus a loop whose
	// ingress subject is malformed, so its Subscribe fails at Run time. buildSourceLoop
	// does not validate the subject (that is the config layer's job), so it builds.
	goodLC := dpPipelineCfg().Loops[0]
	goodLC.Name = "good"
	badLC := goodLC
	badLC.Name = "bad"
	badLC.IngressSubject = "bad subject" // embedded space => nats ErrBadSubject at Subscribe

	good, err := buildSourceLoop(conn.Subscriber(goodLC.IngressSubject), conn, builder, nil, memlog.New(), vc.SchemaRef{}, goodLC)
	if err != nil {
		t.Fatalf("build good loop: %v", err)
	}
	bad, err := buildSourceLoop(conn.Subscriber(badLC.IngressSubject), conn, builder, nil, memlog.New(), vc.SchemaRef{}, badLC)
	if err != nil {
		t.Fatalf("build bad loop: %v", err)
	}
	dp := &dataPlane{conn: conn, loops: []*transport.Loop{good, bad}}

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
// configured, buildDataPlane must NOT dial nats (a bogus URL must not error), so an
// empty pipeline config never requires a live broker.
func TestDataPlane_ZeroLoopsNoDial(t *testing.T) {
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: "nats://192.0.2.1:4222", AccountSeed: "bogus"},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, &pipelineconfig.Config{}, dpKeyStore(t), dataPlaneDeps{})
	if err != nil {
		t.Fatalf("buildDataPlane (zero loops): %v", err)
	}
	if err := dp.Run(context.Background()); err != nil {
		t.Fatalf("zero-loop Run: %v", err)
	}
}

// stubResolver satisfies resolver.Resolver for assembly tests; Resolve is never called
// at build time (only at Run/verify), so its body is irrelevant here.
type stubResolver struct{}

func (stubResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return nil, fmt.Errorf("stub resolver")
}

func dpSinkCfg() *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "archive",
		Role:           pipelineconfig.RoleSink,
		IngressSubject: dpPipelineDID,
		Sink: pipelineconfig.SinkConfig{
			Kind:                 pipelineconfig.SinkObservationOnly,
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
			UpstreamEndpoint:     "https://acme.example/pipelines/pipe",
		},
	}}}
}

// TestBuildDataPlane_SinkLoopAssembles asserts the role dispatch builds a terminating
// sink loop (NewLoop accepts it with no Publisher/Codec/Emission) when given a resolver
// and a writer.
func TestBuildDataPlane_SinkLoopAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpSinkCfg(), dpKeyStore(t), dataPlaneDeps{
		Resolver:   stubResolver{},
		SinkWriter: console.New(io.Discard),
		VCStore:    dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (sink): %v", err)
	}
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

// Sink delivery writers come from per-loop config when no override is injected:
// file outputs share ONE writer per cleaned path (two loops on one file must
// never interleave lines), console is the default, junk types fail closed, and
// an injected deps.SinkWriter (the test seam) overrides everything.
func TestSinkWriters_ProviderSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.ndjson")
	sw := newSinkWriters(nil)

	w1, err := sw.writerFor(pipelineconfig.SinkOutputConfig{Type: pipelineconfig.SinkOutputFile, Path: path})
	if err != nil {
		t.Fatalf("writerFor(file): %v", err)
	}
	// Same file spelled differently must resolve to the SAME writer instance.
	w2, err := sw.writerFor(pipelineconfig.SinkOutputConfig{
		Type: pipelineconfig.SinkOutputFile, Path: filepath.Join(dir, "sub", "..", "out.ndjson")})
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
	c1, err := sw.writerFor(pipelineconfig.SinkOutputConfig{})
	if err != nil {
		t.Fatalf("writerFor(zero): %v", err)
	}
	c2, err := sw.writerFor(pipelineconfig.SinkOutputConfig{Type: pipelineconfig.SinkOutputConsole})
	if err != nil {
		t.Fatalf("writerFor(console): %v", err)
	}
	if c1 != c2 {
		t.Error("console writers not shared")
	}

	if _, err := sw.writerFor(pipelineconfig.SinkOutputConfig{Type: "warehouse"}); err == nil {
		t.Error("unknown output type: want error (fail closed)")
	}

	// The injection seam wins over any config.
	inj := console.New(io.Discard)
	swo := newSinkWriters(inj)
	if w, err := swo.writerFor(pipelineconfig.SinkOutputConfig{Type: pipelineconfig.SinkOutputFile, Path: path}); err != nil || w != sink.Writer(inj) {
		t.Errorf("override: got %v (err %v), want the injected writer", w, err)
	}
}

// A sink loop with a file output assembles with NO injected writer: the surface
// comes from config, and the file exists after boot (fail-closed construction).
func TestBuildDataPlane_SinkFileOutputAssembles(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	cfg := dpSinkCfg()
	path := filepath.Join(t.TempDir(), "consumed.ndjson")
	cfg.Loops[0].Sink.Output = pipelineconfig.SinkOutputConfig{Type: pipelineconfig.SinkOutputFile, Path: path}

	dp, err := buildDataPlane(context.Background(), chainCfg, cfg, dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (file sink, no injected writer): %v", err)
	}
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
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(context.Background(), chainCfg, dpSinkCfg(), dpKeyStore(t), dataPlaneDeps{}); err == nil {
		t.Fatal("sink loop without resolver/writer: want error, got nil")
	}
}

const (
	dpRelayDID  = "did:dplaax:reg:org:beta:pipeline:relay"
	dpRelayIssr = "did:dplaax:reg:org:beta:pipeline:relay:process:r1"
)

func dpChainedCfg(converter string) *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name:           "relay",
		Role:           pipelineconfig.RoleChained,
		IngressSubject: dpPipelineDID,
		Chained: pipelineconfig.ChainedConfig{
			OutputSubject: dpRelayDID,
			Issuer: pipelineconfig.IssuerConfig{
				DID: dpRelayIssr, KeyID: string(keystore.KeyIDSigning),
				VerificationMethod: dpRelayIssr + "#signing",
			},
			PipelineID:           "relay",
			ProcessID:            "r1",
			TransformationClaim:  vc.ClaimConvert,
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
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
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	dp, err := buildDataPlane(context.Background(), chainCfg, dpChainedCfg("{ 'reading': reading, 'relayed': true }"), dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (chained): %v", err)
	}
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
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(context.Background(), chainCfg, dpChainedCfg(""), dpKeyStore(t), dataPlaneDeps{}); err == nil {
		t.Fatal("chained loop without resolver: want error, got nil")
	}
}

// TestBuildDataPlane_ChainedMalformedConverterFails asserts a malformed JSONata converter
// expression fails closed at build (compiled at loop-build time), not at first event.
func TestBuildDataPlane_ChainedMalformedConverterFails(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	if _, err := buildDataPlane(context.Background(), chainCfg, dpChainedCfg("{ unterminated"), dpKeyStore(t), dataPlaneDeps{
		Resolver: stubResolver{},
		VCStore:  dpVCStore(),
	}); err == nil {
		t.Fatal("malformed converter expression: want build error, got nil")
	}
}

// The durable node path: with TlogDir set, buildDataPlane opens a filelog
// per producing loop under sha256(log id), registers it under the OUTPUT
// SUBJECT, and arms it with the loop's issuer key — a signed checkpoint
// must verify as coming from that identity.
func TestDataPlane_DurableEmissionLog(t *testing.T) {
	url, accSeed := dpAccountServer(t)
	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	tlogDir := t.TempDir()
	dp, err := buildDataPlane(context.Background(), chainCfg, dpPipelineCfg(), dpKeyStore(t), dataPlaneDeps{TlogDir: tlogDir})
	if err != nil {
		t.Fatalf("buildDataPlane: %v", err)
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
