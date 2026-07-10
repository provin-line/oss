package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/provin-line/oss/pipeline/provenance/vcdid"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// TestSourceCommitmentSelfAudit_Integration_RecordsVerified is the slice-17o integration
// capstone: a real aggregate FirstDrop (signed over two real, independently-signed source
// FirstDrops) is registered for emit-locus self-audit through the composition-root
// emissionRegistrar (local store + receipt + queue), and the REAL audit runner — with the
// consumed-set step (WithSourceCommitment) over the REAL vc.Verifier and DID graph — records
// a DISTINCT SourceCommitment=Verified with SourceCommitmentEvaluated=true. This exercises the
// whole audit half end to end with real crypto (the aggregate runtime's call into the
// registrar is covered by the aggregate unit tests; the full NATS/GetAuditStatus path is the
// follow-on capstone).
func TestSourceCommitmentSelfAudit_Integration_RecordsVerified(t *testing.T) {
	const (
		owner    = "did:dplaax:reg:org:acme"
		srcAPipe = "did:dplaax:reg:org:acme:pipeline:sca"
		srcAIss  = srcAPipe + ":process:sa"
		srcBPipe = "did:dplaax:reg:org:acme:pipeline:scb"
		srcBIss  = srcBPipe + ":process:sb"
		aggPipe  = "did:dplaax:reg:org:acme:pipeline:aggo"
		aggIss   = aggPipe + ":process:ag"
	)
	ctx := context.Background()
	ks := filestore.New(t.TempDir())
	res := local.New()
	for _, iss := range []string{srcAIss, srcBIss, aggIss} {
		kp, err := (ed25519.Generator{}).Generate()
		if err != nil {
			t.Fatalf("keygen %q: %v", iss, err)
		}
		if err := ks.SaveKeyPair(iss, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
			t.Fatalf("save key %q: %v", iss, err)
		}
		res.Add(capProcessDoc(iss, owner, kp.PublicKey))
	}
	res.Add(capOwnerDoc(owner))
	builder := vc.NewBuilder(ed25519.NewSigner(ks))

	scHash := func(b []byte) string {
		s := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(s[:])
	}

	// The node's local store — shared by the registrar (writes) and the runner (reads).
	localPool := memstore.NewPool()
	localSvc := vcresolver.New(memstore.NewStore(), localPool)

	// Two real signed source FirstDrops, stored content-addressed in the local store.
	signSource := func(iss, proc string, payload []byte) *vc.PipelinePassCredential {
		s, err := vcdid.NewSigner(vcdid.Config{
			Builder: builder, IssuerDID: iss, KeyID: string(keystore.KeyIDSigning),
			VerificationMethod: iss + "#signing", PipelineID: proc, ProcessID: proc,
			TransformationClaim: vc.ClaimConvert,
		})
		if err != nil {
			t.Fatalf("source signer %q: %v", iss, err)
		}
		h := scHash(payload)
		cred, err := s.SignFirstDrop(ctx, payload, h, h)
		if err != nil {
			t.Fatalf("SignFirstDrop %q: %v", iss, err)
		}
		b, err := cred.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal source %q: %v", iss, err)
		}
		if _, err := localSvc.StoreVC(ctx, b, "", 0); err != nil {
			t.Fatalf("store source %q: %v", iss, err)
		}
		return cred
	}
	srcA := signSource(srcAIss, "sa", []byte(`{"reading":1}`))
	srcB := signSource(srcBIss, "sb", []byte(`{"reading":2}`))

	// A real aggregate FirstDrop over the two sources (carries the multi-source commitment).
	aggSigner, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: aggIss, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: aggIss + "#signing", PipelineID: "aggo", ProcessID: "ag",
		TransformationClaim: vc.ClaimAggregate, SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		t.Fatalf("aggregate signer: %v", err)
	}
	aggPayload := []byte(`{"agg":true}`)
	aggCred, err := aggSigner.SignAggregateFirstDrop(ctx, aggPayload, scHash(aggPayload),
		[]*vc.PipelinePassCredential{srcA, srcB})
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}

	// Register the emission for self-audit through the composition-root registrar (the exact
	// path the aggregate runtime drives), then build and run the real audit runner.
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()
	receipts := auditor.NewMemReceiptStore()
	reg := &emissionRegistrar{local: localSvc, receipts: receipts, audit: queue}
	srcAHash, _ := srcA.Hash()
	srcBHash, _ := srcB.Hash()
	if err := reg.RegisterEmission(ctx, aggCred, []string{srcAHash, srcBHash}); err != nil {
		t.Fatalf("RegisterEmission: %v", err)
	}
	aggHead, _ := aggCred.Hash()

	runner, err := buildAuditRunner(queue, status, receipts, localSvc, localPool, res, nil,
		auditCfg([]pipelineconfig.LoopConfig{{Role: pipelineconfig.RoleAggregate}}))
	if err != nil || runner == nil {
		t.Fatalf("buildAuditRunner: r=%v err=%v", runner, err)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runner.Run(rctx) }()
	t.Cleanup(func() { cancel(); <-done })

	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if rec, err := status.Get(aggHead); err == nil && rec.Scope.SourceCommitmentEvaluated {
			if rec.Overall != vc.ConfidenceVerified {
				t.Errorf("linear Overall = %v, want Verified", rec.Overall)
			}
			if !rec.Scope.LinearChain {
				t.Error("Scope.LinearChain = false, want true")
			}
			if rec.SourceCommitment != vc.ConfidenceVerified {
				t.Errorf("SourceCommitment = %v, want Verified (real recompute over the two sources)", rec.SourceCommitment)
			}
			if len(rec.SourceCommitmentNotations) == 0 {
				t.Error("want a source-commitment locus notation")
			}
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("audit runner did not record a source-commitment verdict for the aggregate head")
		}
	}
}
