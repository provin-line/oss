package main

import (
	"context"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	natstransport "github.com/provin-line/oss/pipeline/transport/nats"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// TestAggregate_SelfAudit_RecordsSourceCommitmentVerified is the slice-17p capstone: a
// config-wired aggregate node (built through buildDataPlane WITH the audit substrate —
// AuditQueue + Receipts) consumes two real signed source FirstDrops over embedded NATS, folds
// them on a window tick, emits a provin:aggregate FirstDrop, and SELF-REGISTERS it via the
// composition-root emissionRegistrar (local store + receipt + queue). The node's own audit
// runner then resolves the consumed sources locally and records — for the emitted aggregate
// head — a DISTINCT SourceCommitment=Verified with SourceCommitmentEvaluated=true, over the
// real DID graph. This proves the emit-locus self-audit path end to end through the real
// wiring (17o's integration test drove the registrar directly with a hand-signed credential;
// 17p drives the aggregate runtime + buildDataPlane + the live tick over NATS).
func TestAggregate_SelfAudit_RecordsSourceCommitmentVerified(t *testing.T) {
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

	builder := vc.NewBuilder(ed25519.NewSigner(ks))
	// Only the wire envelopes are needed — the aggregate head is discovered from the emitted
	// output and the verdict asserted on the shared status store (D-17p-1).
	_, envA := signedSourceEnv(t, builder, agSrcAIss, "sa", []byte(`{"reading":1}`))
	_, envB := signedSourceEnv(t, builder, agSrcBIss, "sb", []byte(`{"reading":2}`))

	chainCfg := &chainconfig.Config{
		Transport: chainconfig.TransportNATS,
		NATS:      chainconfig.NATSConfig{URL: url, AccountSeed: accSeed},
	}
	cfg := &pipelineconfig.Config{
		Loops: []pipelineconfig.LoopConfig{{
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
		}},
		// The audit runner reads these; buildAuditRunner rejects non-positive values.
		BatchResolver: pipelineconfig.BatchResolverConfig{Interval: time.Second, BatchSize: 16, MaxRetries: 3, MaxDepth: 1024},
		AuditRunner:   pipelineconfig.AuditRunnerConfig{Interval: 5 * time.Millisecond, BatchSize: 16, MaxAttempts: 20},
	}

	// One local store + audit substrate, shared by the data plane (self-registration) and the
	// audit runner (verdict). This is the emit-locus guarantee: the aggregate stores its
	// consumed sources AND its emitted head into the same store the runner reads.
	localPool := memstore.NewPool()
	localSvc := vcresolver.New(memstore.NewStore(), localPool)
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()
	receipts := auditor.NewMemReceiptStore()

	dp, err := buildDataPlane(chainCfg, cfg, ks, dataPlaneDeps{
		Resolver: res, VCStore: localSvc, AuditQueue: queue, Receipts: receipts,
	})
	if err != nil {
		t.Fatalf("buildDataPlane (aggregate self-audit): %v", err)
	}
	runner, err := buildAuditRunner(queue, status, receipts, localSvc, localPool, res, cfg)
	if err != nil || runner == nil {
		t.Fatalf("buildAuditRunner: r=%v err=%v", runner, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	dpDone := make(chan error, 1)
	runDone := make(chan error, 1)
	go func() { dpDone <- dp.Run(ctx) }()
	go func() { runDone <- runner.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-dpDone; <-runDone })

	// Observe the aggregate output to learn the emitted head content address, and drive the
	// two sources to their ingress subjects on a retry ticker (dedup collapses retries).
	inj, err := natstransport.Connect(natstransport.Config{URL: url, AccountSeed: accSeed})
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

	codec := envelopecodec.New()
	publishBoth()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	// Learn the two-source aggregate head hash from the emitted output (tolerate a transient
	// one-source emit — poll for the two-source commitment, the 17n determinism).
	var aggHead string
	for aggHead == "" {
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
				aggHead, err = env.Credential.Hash()
				if err != nil {
					t.Fatalf("hash aggregate head: %v", err)
				}
			}
		case <-tick.C:
			publishBoth()
		case <-deadline:
			t.Fatal("no two-source aggregate FirstDrop was emitted")
		}
	}

	// The node's own audit runner records a DISTINCT source-commitment Verified for that head.
	// Give this phase its OWN deadline (Codex review P2): a slow-but-successful emit that
	// consumed most of the first deadline must not immediately fail the audit wait before the
	// runner's next tick records the verdict.
	auditDeadline := time.After(10 * time.Second)
	for {
		if rec, err := status.Get(aggHead); err == nil && rec.Scope.SourceCommitmentEvaluated {
			if rec.SourceCommitment != vc.ConfidenceVerified {
				t.Errorf("SourceCommitment = %v, want Verified", rec.SourceCommitment)
			}
			if rec.Overall != vc.ConfidenceVerified {
				t.Errorf("linear Overall = %v, want Verified", rec.Overall)
			}
			if !rec.Scope.LinearChain {
				t.Error("Scope.LinearChain = false, want true")
			}
			// The verdict carries the self-audit locus notation (parity with the 17o
			// integration test) — it is a real source-commitment verdict, not a stray linear one.
			if len(rec.SourceCommitmentNotations) == 0 {
				t.Error("want a source-commitment locus notation")
			}
			return
		}
		select {
		case <-tick.C:
			publishBoth()
		case <-auditDeadline:
			t.Fatalf("audit runner did not record a source-commitment verdict for aggregate head %s", aggHead)
		}
	}
}
