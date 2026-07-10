package main

import (
	"context"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
	"github.com/provin-line/oss/pipeline/contract"
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/pipeline/sink"
	"github.com/provin-line/oss/pipeline/transport/envelopecodec"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/tlog/memlog"
	"github.com/provin-line/oss/vc"
)

// The sink-obligations capstone: a production sink consumes a verified upstream
// credential, writes it externally, and issues a provin:sink-receipt. The receipt
// is registered into the SAME audit substrate the node's audit runner reads
// (local store → tlog → audit queue), so the runner verifies the receipt→consumed
// chain to CONFIDENCE_VERIFIED — proving a receipt is audit-reachable, not just
// stdout. The negative arm proves the local issuer allow-list refuses a verified
// credential whose issuer is off-list before any write or receipt.
//
// This is the process runtime (real signer, store, audit runner) without the NATS
// transport — the receipt's audit-reachability is the claim under test, and it is
// independent of the wire transport.
const (
	srOwner   = "did:dplaax:poc.dplaax.dev:org:acme"
	srSrcIss  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:src:process:s1"
	srSinkIss = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:archive:process:a1"
	srEvilOwn = "did:dplaax:poc.dplaax.dev:org:evil"
	srEvilIss = "did:dplaax:poc.dplaax.dev:org:evil:pipeline:x:process:e1"
)

func TestSinkReceipt_AuditReachableVerified_AndAllowList(t *testing.T) {
	ctx := context.Background()
	ks := filestore.New(t.TempDir())
	res := local.New()
	// Keys + DID docs for the source, the sink's receipt issuer, and an off-list
	// "evil" issuer (whose credential still VERIFIES — so the allow-list, not the
	// verdict, is what refuses it).
	addKey := func(owner, iss string) {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen %q: %v", iss, err)
		}
		if err := ks.SaveKeyPair(iss, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key %q: %v", iss, err)
		}
		res.Add(capProcessDoc(iss, owner, kp.PublicKey))
	}
	addKey(srOwner, srSrcIss)
	addKey(srOwner, srSinkIss)
	addKey(srEvilOwn, srEvilIss)
	res.Add(capOwnerDoc(srOwner))
	res.Add(capOwnerDoc(srEvilOwn))

	builder := vc.NewBuilder(ed25519.NewSigner(ks))

	// Shared audit substrate: one local store + queue + status + receipts, read by
	// both the sink's registrar (write side) and the audit runner (verdict side).
	store := memstore.NewStore()
	pool := memstore.NewPool()
	localSvc := vcresolver.New(store, pool)
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()
	receipts := auditor.NewMemReceiptStore()

	verifier := vc.NewVerifier(res, ed25519.Verifier{})
	ingressStore := &serviceIngressStore{store: localSvc, audit: queue}

	receiptSigner, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: srSinkIss, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: srSinkIss + "#signing", PipelineID: "archive", ProcessID: "a1",
		TransformationClaim: vc.ClaimSinkReceipt,
	})
	if err != nil {
		t.Fatalf("receipt signer: %v", err)
	}
	registrar := &sinkReceiptRegistrar{
		signer: receiptSigner, local: localSvc, receiptLog: memlog.New(), audit: queue, publisher: nil,
	}

	writer := &captureWriter{}
	proc, err := sink.New(sink.Config{
		Strategy: contract.VerificationAdjacent,
		Kind:     contract.SinkProduction,
		Codec:    envelopecodec.New(),
		Verifier: verifier,
		Store:    ingressStore,
		Writer:   writer,
		// admit org:acme issuers; org:evil is off-list.
		AllowIssuers:     []string{"did:dplaax:poc.dplaax.dev:org:acme:*"},
		UpstreamEndpoint: "https://acme.example/pipelines/src",
		Receipts:         registrar,
	})
	if err != nil {
		t.Fatalf("sink New: %v", err)
	}

	// Audit runner over the shared substrate (a minimal consuming-loop cfg so it runs).
	auditCfg := &pipelineconfig.Config{
		Loops:         []pipelineconfig.LoopConfig{{Name: "archive", Role: pipelineconfig.RoleSink}},
		BatchResolver: pipelineconfig.BatchResolverConfig{Interval: time.Second, BatchSize: 16, MaxRetries: 3, MaxDepth: 1024},
		AuditRunner:   pipelineconfig.AuditRunnerConfig{Interval: 5 * time.Millisecond, BatchSize: 16, MaxAttempts: 20},
	}
	runner, err := buildAuditRunner(queue, status, receipts, localSvc, pool, res, auditCfg)
	if err != nil || runner == nil {
		t.Fatalf("buildAuditRunner: r=%v err=%v", runner, err)
	}
	rctx, cancel := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- runner.Run(rctx) }()
	t.Cleanup(func() { cancel(); <-runDone })

	// --- positive: a verified, allow-listed upstream → write + receipt → VERIFIED ---
	_, upstreamWire := signedSourceEnv(t, builder, srSrcIss, "s1", []byte(`{"reading":42}`))
	r, err := proc.Process(ctx, upstreamWire)
	if err != nil {
		t.Fatalf("sink Process (allowed): %v", err)
	}
	if r.Status != contract.StatusPassed {
		t.Fatalf("allowed status = %v (%s), want Passed", r.Status, r.Error)
	}
	if len(writer.records()) != 1 {
		t.Fatalf("writer records = %d, want 1", len(writer.records()))
	}

	// Find the receipt head in the local store (the credential claiming sink-receipt)
	// and wait for the audit runner to record it VERIFIED.
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		receiptHead := findSinkReceiptHead(t, ctx, store, localSvc)
		if receiptHead != "" {
			if rec, gerr := status.Get(receiptHead); gerr == nil {
				if rec.Overall != vc.ConfidenceVerified {
					t.Fatalf("receipt audit Overall = %v, want VERIFIED", rec.Overall)
				}
				break
			}
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("receipt never reached a VERIFIED audit verdict")
		}
	}

	// --- negative: a verified but off-list issuer → rejected before write/receipt ---
	writesBefore := len(writer.records())
	_, evilWire := signedSourceEnv(t, builder, srEvilIss, "e1", []byte(`{"reading":99}`))
	er, err := proc.Process(ctx, evilWire)
	if err != nil {
		t.Fatalf("sink Process (evil): %v", err)
	}
	if er.Status == contract.StatusPassed {
		t.Error("off-list issuer was accepted (want rejected by allow-list)")
	}
	if len(writer.records()) != writesBefore {
		t.Error("off-list issuer produced a write (want none)")
	}
}

// findSinkReceiptHead returns the content address of the stored provin:sink-receipt
// credential, or "" if none is stored yet.
func findSinkReceiptHead(t *testing.T, ctx context.Context, store *memstore.Store, svc *vcresolver.Service) string {
	t.Helper()
	hashes, err := store.ListHashes("", 1000)
	if err != nil {
		t.Fatalf("ListHashes: %v", err)
	}
	for _, h := range hashes {
		cred, rerr := svc.ResolveVC(ctx, h)
		if rerr != nil || cred == nil {
			continue
		}
		subj, serr := cred.Subject()
		if serr != nil {
			continue
		}
		if subj.TransformationClaim == vc.ClaimSinkReceipt {
			return h
		}
	}
	return ""
}
