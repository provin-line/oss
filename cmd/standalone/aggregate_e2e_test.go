package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// The aggregate capstone lineage: one owner, two independent source pipelines feeding one
// aggregate. The two sources emit FirstDrops on their own pipeline subjects; the aggregate
// pools both and folds them into a single provin:aggregate FirstDrop carrying a two-source
// commitment.
const (
	agOwner    = "did:dplaax:reg:org:acme"
	agSrcAPipe = "did:dplaax:reg:org:acme:pipeline:aggsrca"
	agSrcAIss  = agSrcAPipe + ":process:sa"
	agSrcBPipe = "did:dplaax:reg:org:acme:pipeline:aggsrcb"
	agSrcBIss  = agSrcBPipe + ":process:sb"
	agOutPipe  = "did:dplaax:reg:org:acme:pipeline:aggout"
	agIss      = agOutPipe + ":process:ag"
)

func agHash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// signedSourceEnv signs a real source FirstDrop (issuer's key in builder's keystore) over
// payload and returns the credential plus its inline wire envelope. OutputHash binds to
// payload so the aggregate's payload↔credential gate passes.
func signedSourceEnv(t *testing.T, builder *vc.Builder, issuer, proc string, payload []byte) (*vc.PipelinePassCredential, []byte) {
	t.Helper()
	s, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: issuer, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: issuer + "#signing", PipelineID: proc, ProcessID: proc,
		TransformationClaim: vc.ClaimConvert,
	})
	if err != nil {
		t.Fatalf("source signer %q: %v", issuer, err)
	}
	h := agHash(payload)
	cred, err := s.SignFirstDrop(context.Background(), payload, h, h)
	if err != nil {
		t.Fatalf("SignFirstDrop %q: %v", issuer, err)
	}
	wire, err := envelopecodec.New().MarshalEnvelope(&contract.Envelope{Credential: cred, Payload: payload, SequenceNo: 1})
	if err != nil {
		t.Fatalf("MarshalEnvelope %q: %v", issuer, err)
	}
	return cred, wire
}

// TestAggregate_TwoSource_VerifiedCommitment is the slice-17n capstone (A-3): a config-wired
// aggregate node consumes two real signed source FirstDrops over NATS, folds them on a window
// tick, and emits a provin:aggregate FirstDrop whose two-source SourceCommitment verifies
// Verified over the real DID graph. The aggregate's content-address dedup collapses the retry
// publishes to exactly {srcA, srcB}, so the consumed set is deterministic; a tick that fires
// mid-arrival may emit a transient one-source aggregate first, so we poll for the two-source one.
func TestAggregate_TwoSource_VerifiedCommitment(t *testing.T) {
	url, accSeed := dpAccountServer(t)

	ks := filestore.New(t.TempDir())
	res := local.New()
	for _, iss := range []string{agSrcAIss, agSrcBIss, agIss} {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen %q: %v", iss, err)
		}
		if err := ks.SaveKeyPair(iss, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key %q: %v", iss, err)
		}
		res.Add(capProcessDoc(iss, agOwner, kp.PublicKey))
	}
	res.Add(capOwnerDoc(agOwner))

	builder := vc.NewBuilder(ks)
	srcCredA, envA := signedSourceEnv(t, builder, agSrcAIss, "sa", []byte(`{"reading":1}`))
	srcCredB, envB := signedSourceEnv(t, builder, agSrcBIss, "sb", []byte(`{"reading":2}`))

	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	cfg := &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{{
		Name: "agg",
		Role: pipelineconfig.RoleAggregate,
		Aggregate: pipelineconfig.AggregateConfig{
			OutputSubject: agOutPipe,
			Issuer: pipelineconfig.IssuerConfig{
				DID: agIss, KeyID: string(keystore.KeyIDSigning), VerificationMethod: agIss + "#signing",
			},
			PipelineID:           "aggout",
			ProcessID:            "ag",
			VerificationStrategy: pipelineconfig.StrategyAdjacent,
			Window:               100 * time.Millisecond,
			Ingresses: []pipelineconfig.AggregateIngress{
				{Subject: agSrcAPipe, UpstreamEndpoint: "https://a.example/src-a"},
				{Subject: agSrcBPipe, UpstreamEndpoint: "https://b.example/src-b"},
			},
		},
	}}}
	dp, err := pipelineruntime.Build(context.Background(), chainCfg, cfg, ks, pipelineruntime.Deps{Resolver: res, VCStore: dpVCStore()})
	if err != nil {
		t.Fatalf("pipelineruntime.Build (aggregate): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Observe the aggregate output + publish the two sources to their ingress subjects.
	inj, err := natstransport.Connect(context.Background(), natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	out := make(chan []byte, 16)
	if err := inj.Subscriber(agOutPipe).Subscribe(func(b []byte) {
		select {
		case out <- b:
		default:
		}
	}); err != nil {
		t.Fatalf("observe aggregate output: %v", err)
	}
	pubA := inj.Publisher(agSrcAPipe)
	pubB := inj.Publisher(agSrcBPipe)
	publishBoth := func() { _ = pubA.Publish(envA); _ = pubB.Publish(envB) }

	// Retry-publish (NATS core drops pre-subscription messages); dedup collapses the retries
	// to {srcA, srcB}. Poll for the first aggregate output with a TWO-source commitment.
	codec := envelopecodec.New()
	publishBoth()
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var aggCred *vc.PipelinePassCredential
	var aggPayload []byte
	for aggCred == nil {
		select {
		case wire := <-out:
			env, err := codec.UnmarshalEnvelope(wire)
			if err != nil {
				t.Fatalf("decode aggregate output: %v", err)
			}
			if env.Credential == nil {
				continue
			}
			if sc := env.Credential.SourceCommitment(); sc != nil && len(sc.DerivedFrom) == 2 {
				aggCred = env.Credential
				aggPayload = env.Payload
			}
		case <-tick.C:
			publishBoth()
		case <-deadline:
			t.Fatal("no two-source aggregate FirstDrop was emitted")
		}
	}

	// The emitted credential is a provin:aggregate FirstDrop with InputHash and
	// previousCredential structurally absent.
	subj, err := aggCred.Subject()
	if err != nil {
		t.Fatalf("aggregate subject: %v", err)
	}
	if subj.TransformationClaim != vc.ClaimAggregate {
		t.Errorf("claim = %q, want provin:aggregate", subj.TransformationClaim)
	}
	body := aggCred.Body()
	csub, ok := body["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatal("aggregate FirstDrop body has no credentialSubject object")
	}
	if _, present := csub["inputHash"]; present {
		t.Error("aggregate FirstDrop carries inputHash (must be absent)")
	}
	if _, present := body["previousCredential"]; present {
		t.Error("aggregate FirstDrop body carries previousCredential (must be absent)")
	}
	if aggCred.PreviousCredential() != "" {
		t.Errorf("PreviousCredential()=%q, want empty", aggCred.PreviousCredential())
	}

	// DerivedFrom is the two source issuers, sorted.
	sc := aggCred.SourceCommitment()
	want := []string{agSrcAIss, agSrcBIss}
	sort.Strings(want)
	if len(sc.DerivedFrom) != 2 || sc.DerivedFrom[0] != want[0] || sc.DerivedFrom[1] != want[1] {
		t.Errorf("DerivedFrom = %v, want %v", sc.DerivedFrom, want)
	}

	// The emitted payload is the ManifestFold manifest of the two consumed sources — binding
	// the OUTPUT bytes to the consumed set, complementing the credential-side DerivedFrom.
	var manifest struct {
		Sources []string `json:"sources"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(aggPayload, &manifest); err != nil {
		t.Fatalf("aggregate payload not the fold manifest JSON: %v (%q)", err, aggPayload)
	}
	srcHashA, _ := srcCredA.Hash()
	srcHashB, _ := srcCredB.Hash()
	wantHashes := []string{srcHashA, srcHashB}
	sort.Strings(wantHashes)
	if manifest.Count != 2 || len(manifest.Sources) != 2 || manifest.Sources[0] != wantHashes[0] || manifest.Sources[1] != wantHashes[1] {
		t.Errorf("fold manifest = %+v, want count 2 + sources %v", manifest, wantHashes)
	}

	// The commitment verifies Verified against the two sources as received, over the real
	// DID graph — the capstone assertion.
	verifier := vc.NewVerifier(res, ed25519.Verifier{})
	state, err := verifier.VerifySourceCommitment(context.Background(), aggCred, []*vc.PipelinePassCredential{srcCredA, srcCredB})
	if err != nil {
		t.Fatalf("VerifySourceCommitment: %v", err)
	}
	if state != vc.ConfidenceVerified {
		t.Errorf("VerifySourceCommitment = %v, want Verified", state)
	}
}
