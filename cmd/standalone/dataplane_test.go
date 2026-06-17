package main

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/transport"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/vc"
)

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
		OutputSubject:  dpPipelineDID,
		Issuer: pipelineconfig.IssuerConfig{
			DID: dpIssuerDID, KeyID: string(keystore.KeyIDSigning),
			VerificationMethod: dpIssuerDID + "#signing",
		},
		PipelineID:          "pipe",
		ProcessID:           "src",
		TransformationClaim: vc.ClaimConvert,
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

	dp, err := buildDataPlane(chainCfg, dpPipelineCfg(), dpKeyStore(t))
	if err != nil {
		t.Fatalf("buildDataPlane: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel) // drain the runner even if the test fails before the explicit cancel below
	runDone := make(chan error, 1)
	go func() { runDone <- dp.Run(ctx) }()

	// Observer + injector on a second connection to the same account.
	obs, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: accSeed})
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
	conn, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: accSeed})
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

	good, err := buildSourceLoop(conn, builder, goodLC)
	if err != nil {
		t.Fatalf("build good loop: %v", err)
	}
	bad, err := buildSourceLoop(conn, builder, badLC)
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
	dp, err := buildDataPlane(chainCfg, &pipelineconfig.Config{}, dpKeyStore(t))
	if err != nil {
		t.Fatalf("buildDataPlane (zero loops): %v", err)
	}
	if err := dp.Run(context.Background()); err != nil {
		t.Fatalf("zero-loop Run: %v", err)
	}
}
