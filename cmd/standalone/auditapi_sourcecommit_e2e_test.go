package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	auditpb "github.com/provin-line/oss/gen/go/dplaax/audit/v1"
	"github.com/provin-line/oss/gen/go/dplaax/audit/v1/auditpbconnect"
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

// TestAuditAPI_ServesSourceCommitmentVerified is the slice-17r wire capstone: a REAL emit-locus
// self-audit (real signed sources + aggregate, the emissionRegistrar, the real audit runner)
// records a source_commitment=Verified verdict, and a GetAuditStatus client reads it back over
// the mounted, L1-gated AuditService RPC as source_commitment present + VERIFIED. Closes the
// gap 17p (asserted on the StatusStore directly) and 17i (served only source_commitment absent)
// left: nothing else proves the RPC serves a PRESENT source_commitment over the authenticated
// wire. No NATS — the emit path is 17p's capstone; 17r's focus is the RPC read.
func TestAuditAPI_ServesSourceCommitmentVerified(t *testing.T) {
	const (
		owner   = "did:dplaax:reg:org:acme"
		srcAIss = "did:dplaax:reg:org:acme:pipeline:apisca:process:sa"
		srcBIss = "did:dplaax:reg:org:acme:pipeline:apiscb:process:sb"
		aggIss  = "did:dplaax:reg:org:acme:pipeline:apiagg:process:ag"
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
	builder := vc.NewBuilder(ks)
	apiHash := func(b []byte) string {
		s := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(s[:])
	}

	localPool := memstore.NewPool()
	localSvc := vcresolver.New(vcresolver.NewVariantStore(memstore.NewBackend()), localPool)
	signSource := func(iss, proc string, payload []byte) (*vc.PipelinePassCredential, string) {
		s, err := vcdid.NewSigner(vcdid.Config{
			Builder: builder, IssuerDID: iss, KeyID: string(keystore.KeyIDSigning),
			VerificationMethod: iss + "#signing", PipelineID: proc, ProcessID: proc,
			TransformationClaim: vc.ClaimConvert,
		})
		if err != nil {
			t.Fatalf("source signer %q: %v", iss, err)
		}
		h := apiHash(payload)
		cred, err := s.SignFirstDrop(ctx, payload, h, h)
		if err != nil {
			t.Fatalf("SignFirstDrop %q: %v", iss, err)
		}
		b, err := cred.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal %q: %v", iss, err)
		}
		stored, err := localSvc.StoreVC(ctx, b, "", 0)
		if err != nil {
			t.Fatalf("store %q: %v", iss, err)
		}
		return cred, stored.BodyAddress
	}
	srcA, hA := signSource(srcAIss, "sa", []byte(`{"reading":1}`))
	srcB, hB := signSource(srcBIss, "sb", []byte(`{"reading":2}`))

	aggSigner, err := vcdid.NewSigner(vcdid.Config{
		Builder: builder, IssuerDID: aggIss, KeyID: string(keystore.KeyIDSigning),
		VerificationMethod: aggIss + "#signing", PipelineID: "apiagg", ProcessID: "ag",
		TransformationClaim: vc.ClaimAggregate, SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		t.Fatalf("aggregate signer: %v", err)
	}
	aggPayload := []byte(`{"agg":true}`)
	aggCred, err := aggSigner.SignAggregateFirstDrop(ctx, aggPayload, apiHash(aggPayload),
		[]*vc.PipelinePassCredential{srcA, srcB})
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}
	aggHead, _ := aggCred.Hash()

	// Register the emission for self-audit, then run the real runner until it records the verdict.
	queue := auditor.NewMemQueue()
	status := auditor.NewMemStatusStore()
	receipts := auditor.NewMemReceiptStore()
	reg := &emissionRegistrar{local: localSvc, receipts: receipts, audit: queue}
	if err := reg.RegisterEmission(ctx, aggCred, []string{hA, hB}); err != nil {
		t.Fatalf("RegisterEmission: %v", err)
	}
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
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if rec, err := status.Get(aggHead); err == nil && rec.Scope.SourceCommitmentEvaluated {
			break
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("runner did not record a source-commitment verdict for the aggregate head")
		}
	}

	// Read it back over the mounted, L1-gated GetAuditStatus RPC — the wire capstone.
	srv := auditServerWith(t, status)
	client := auditpbconnect.NewAuditServiceClient(srv.Client(), srv.URL)
	resp, err := client.GetAuditStatus(ctx, bearer(connect.NewRequest(&auditpb.GetAuditStatusRequest{HeadHash: aggHead})))
	if err != nil {
		t.Fatalf("GetAuditStatus: %v (code %v)", err, connect.CodeOf(err))
	}
	if lc := resp.Msg.GetLinearChain(); lc == nil || lc.GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Errorf("linear_chain = %+v, want present + VERIFIED", lc)
	}
	sc := resp.Msg.GetSourceCommitment()
	if sc == nil {
		t.Fatal("source_commitment is nil, want present + VERIFIED (the 17r coverage)")
	}
	if sc.GetConfidence() != auditpb.Confidence_CONFIDENCE_VERIFIED {
		t.Errorf("source_commitment.confidence = %v, want VERIFIED", sc.GetConfidence())
	}

	// The gate still holds for a source-commitment-bearing record.
	if _, err := client.GetAuditStatus(ctx,
		connect.NewRequest(&auditpb.GetAuditStatusRequest{HeadHash: aggHead})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no bearer: want Unauthenticated, got %v", connect.CodeOf(err))
	}
}
