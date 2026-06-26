package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// The two-hop capstone lineage: one owner controlling two pipelines (source + relay),
// each with its own signing process. The source emits a FirstDrop on thSrcPipe; the relay
// (chained) consumes it, transforms, and re-signs a ChainPreserving on thRelayPipe; the
// sink consumes that. All three loops run on one account (the cross-account grant is 17c's
// proven concern; 17d proves the relay transform + chain link).
const (
	thOwnerDID    = "did:dplaax:poc.dplaax.dev:org:acme"
	thSrcPipe     = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:src"
	thSrcIssuer   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:src:process:s1"
	thRelayPipe   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:relay"
	thRelayIssuer = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:relay:process:r1"
	thIngress     = "ingest.src"
)

func twoHopCfg(converter string, filters []string) *pipelineconfig.Config {
	return &pipelineconfig.Config{Loops: []pipelineconfig.LoopConfig{
		{
			Name: "src", Role: pipelineconfig.RoleSource, IngressSubject: thIngress,
			Source: pipelineconfig.SourceConfig{
				OutputSubject: thSrcPipe,
				Issuer: pipelineconfig.IssuerConfig{
					DID: thSrcIssuer, KeyID: string(keystore.KeyIDSigning),
					VerificationMethod: thSrcIssuer + "#signing",
				},
				PipelineID: "src", ProcessID: "s1", TransformationClaim: vc.ClaimConvert,
			},
		},
		{
			Name: "relay", Role: pipelineconfig.RoleChained, IngressSubject: thSrcPipe,
			Chained: pipelineconfig.ChainedConfig{
				OutputSubject: thRelayPipe,
				Issuer: pipelineconfig.IssuerConfig{
					DID: thRelayIssuer, KeyID: string(keystore.KeyIDSigning),
					VerificationMethod: thRelayIssuer + "#signing",
				},
				PipelineID: "relay", ProcessID: "r1", TransformationClaim: vc.ClaimConvert,
				VerificationStrategy: pipelineconfig.StrategyAdjacent,
				UpstreamEndpoint:     "https://acme.example/pipelines/src",
				Converter:            converter,
				Filters:              filters,
			},
		},
		{
			Name: "archive", Role: pipelineconfig.RoleSink, IngressSubject: thRelayPipe,
			Sink: pipelineconfig.SinkConfig{
				Kind:                 pipelineconfig.SinkObservationOnly,
				VerificationStrategy: pipelineconfig.StrategyAdjacent,
				UpstreamEndpoint:     "https://acme.example/pipelines/relay",
			},
		},
	}}
}

type twoHop struct {
	inject      func([]byte)
	writer      *captureWriter
	srcObserved <-chan []byte // raw Envelope bytes the source published (to capture its credential)
}

func setupTwoHop(t *testing.T, converter string, filters []string) twoHop {
	t.Helper()
	url, accSeed := dpAccountServer(t)

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
	dp, err := buildDataPlane(chainCfg, twoHopCfg(converter, filters), ks, dataPlaneDeps{
		Resolver:   res,
		SinkWriter: writer,
		VCStore:    dpVCStore(),
	})
	if err != nil {
		t.Fatalf("buildDataPlane (two-hop): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Injector + a source-output observer (a third subscriber on thSrcPipe, same account)
	// so the test can capture the source's FirstDrop credential for the chain-link assert.
	inj, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: accSeed})
	if err != nil {
		t.Fatalf("injector connect: %v", err)
	}
	t.Cleanup(func() { _ = inj.Close() })
	observed := make(chan []byte, 8)
	if err := inj.Subscriber(thSrcPipe).Subscribe(func(b []byte) {
		select {
		case observed <- b:
		default:
		}
	}); err != nil {
		t.Fatalf("source observe: %v", err)
	}
	pub := inj.Publisher(thIngress)
	return twoHop{inject: func(p []byte) { _ = pub.Publish(p) }, writer: writer, srcObserved: observed}
}

// TestTwoHop_ChainedRelayTransformAndLink is the slice-17d capstone: source → chained →
// sink, each a real loop. The relay transforms the payload (JSONata) and re-signs a
// ChainPreserving credential; the sink verifies it and writes the transformed payload. The
// test asserts the transform happened and the credential chain links back to the source.
func TestTwoHop_ChainedRelayTransformAndLink(t *testing.T) {
	th := setupTwoHop(t, "{ 'reading': reading, 'relayed': true }", nil)
	const raw = `{"reading":42}`

	th.inject([]byte(raw))
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	var sinkRec *recordSnapshot
	for sinkRec == nil {
		if recs := th.writer.records(); len(recs) > 0 {
			sinkRec = snapshot(t, recs[0])
			break
		}
		select {
		case <-tick.C:
			th.inject([]byte(raw))
		case <-deadline:
			t.Fatal("sink did not receive the relayed event")
		}
	}

	// 1. The relay transformed the payload (JSONata added "relayed": true).
	var got map[string]any
	if err := json.Unmarshal(sinkRec.payload, &got); err != nil {
		t.Fatalf("sink payload not JSON: %v (%q)", err, sinkRec.payload)
	}
	if got["reading"] != float64(42) || got["relayed"] != true {
		t.Fatalf("relay did not transform payload: got %v", got)
	}

	// 2. The sink verified the chained credential.
	if sinkRec.verdict == nil || sinkRec.verdict.Overall != vc.ConfidenceVerified {
		t.Fatalf("verdict: got %+v want ConfidenceVerified", sinkRec.verdict)
	}
	if sinkRec.issuer != thRelayIssuer {
		t.Fatalf("issuer: got %q want %q", sinkRec.issuer, thRelayIssuer)
	}

	// 3. The credential chain links back to the source. The chained credential's
	// PreviousCredential() must be the content address of an actually-observed source
	// FirstDrop (search the observed stream — startup retries may emit several, and an
	// early one may not be the event that reached the relay).
	srcCred := matchingSourceCredential(t, th.srcObserved, sinkRec.prevCredential)
	srcSubj, err := srcCred.Subject()
	if err != nil {
		t.Fatalf("source subject: %v", err)
	}
	if srcSubj.OutputHash != sinkRec.inputHash {
		t.Fatalf("data-flow: source OutputHash=%q != chained InputHash=%q", srcSubj.OutputHash, sinkRec.inputHash)
	}
	if want := "sha256:" + hex.EncodeToString(sha256Sum(sinkRec.payload)); want != sinkRec.outputHash {
		t.Fatalf("chained OutputHash=%q want %q (sha256 of transformed payload)", sinkRec.outputHash, want)
	}
}

// TestTwoHop_FilterDropsEvent is the relay-filter negative: a filter that rejects the
// event means the relay publishes nothing, so the sink receives nothing — even though the
// source emitted (observer confirms).
func TestTwoHop_FilterDropsEvent(t *testing.T) {
	th := setupTwoHop(t, "", []string{"reading > 100"}) // 42 fails the predicate → filtered
	const raw = `{"reading":42}`

	th.inject([]byte(raw))
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	emitted := false
	for !emitted {
		select {
		case <-th.srcObserved:
			emitted = true
		case <-tick.C:
			th.inject([]byte(raw))
		case <-deadline:
			t.Fatal("source never emitted (setup issue)")
		}
	}
	time.Sleep(500 * time.Millisecond)
	if recs := th.writer.records(); len(recs) != 0 {
		t.Fatalf("filtered event: sink received %d record(s); the relay should have dropped it", len(recs))
	}
}

// recordSnapshot flattens a sink.Record into the immutable values the asserts need.
type recordSnapshot struct {
	payload        []byte
	verdict        *vc.VerifyResult
	issuer         string
	prevCredential string
	inputHash      string
	outputHash     string
}

func snapshot(t *testing.T, rec sink.Record) *recordSnapshot {
	t.Helper()
	s := &recordSnapshot{payload: rec.Payload, verdict: rec.Verdict}
	if rec.Credential != nil {
		s.issuer = rec.Credential.Issuer()
		s.prevCredential = rec.Credential.PreviousCredential()
		subj, err := rec.Credential.Subject()
		if err != nil {
			t.Fatalf("sink credential subject: %v", err)
		}
		s.inputHash = subj.InputHash
		s.outputHash = subj.OutputHash
	}
	return s
}

// matchingSourceCredential drains the observed source-output stream for the FirstDrop
// whose content address equals wantAddr (the chained credential's PreviousCredential).
// Startup retries may emit several source events and an early one may not be the event
// that reached the relay, so the match — not the first item — is what proves the link.
func matchingSourceCredential(t *testing.T, observed <-chan []byte, wantAddr string) *vc.PipelinePassCredential {
	t.Helper()
	if wantAddr == "" {
		t.Fatal("chained credential has no PreviousCredential link")
	}
	codec := envelopecodec.New()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case wire := <-observed:
			env, err := codec.UnmarshalEnvelope(wire)
			if err != nil {
				t.Fatalf("decode source envelope: %v", err)
			}
			if env.Credential == nil {
				continue
			}
			addr, err := env.Credential.Hash()
			if err != nil {
				t.Fatalf("source hash: %v", err)
			}
			if addr == wantAddr {
				return env.Credential
			}
		case <-deadline:
			t.Fatalf("no observed source credential matched the chain link %q", wantAddr)
			return nil
		}
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
