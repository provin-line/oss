package chain_test

import (
	"context"
	"testing"
	"time"

	"github.com/provin-line/oss/appraisal"
	chainappraisal "github.com/provin-line/oss/appraisal/chain"
	"github.com/provin-line/oss/appraisal/inputcapture"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/vc"
)

type staticDID struct{ doc *did.DIDDocument }

func (s staticDID) Resolve(context.Context, string) (*did.DIDDocument, error) { return s.doc, nil }

type capturingWalker struct {
	resolver inputcapture.DIDResolver
	chain    []*vc.PipelinePassCredential
	result   *vc.VerifyResult
}

func (w capturingWalker) VerifyChainEvidence(ctx context.Context, _ *vc.PipelinePassCredential) ([]*vc.PipelinePassCredential, *vc.VerifyResult, error) {
	if _, err := w.resolver.Resolve(ctx, w.resolver.Next.(staticDID).doc.ID()); err != nil {
		return nil, nil, err
	}
	return w.chain, w.result, nil
}

func TestAppraiseBuildsAcceptedExactView(t *testing.T) {
	credential, err := vc.New(vc.CredentialFields{
		Issuer:    "did:dplaax:example.test:org:a:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID: "p", ProcessID: "x", TransformationClaim: "provin:convert",
			OutputHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := did.New(did.DocumentFields{ID: credential.Issuer()})
	walker := capturingWalker{
		resolver: inputcapture.DIDResolver{Next: staticDID{doc: doc}},
		chain:    []*vc.PipelinePassCredential{credential},
		result:   &vc.VerifyResult{Overall: vc.ConfidenceVerified, SuiteContract: vc.ContractW3CEdDSAJCS2022},
	}
	a, err := chainappraisal.New(walker, inputcapture.Recorder{}, chainappraisal.Config{
		ClaimContractID:   "linear-provenance@1",
		SchemaVersion:     "pipeline-pass-credential@1",
		SelectionPolicyID: chainappraisal.ProjectedChainSelection,
		KnownScopes:       []string{chainappraisal.LinearAttestationScope},
		Profile:           appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{chainappraisal.LinearAttestationScope}},
	})
	if err != nil {
		t.Fatal(err)
	}
	view, result, err := a.Appraise(context.Background(), credential)
	if err != nil {
		t.Fatal(err)
	}
	if result.Overall != vc.ConfidenceVerified || view.PolicyDecision == nil || view.PolicyDecision.Decision != appraisal.DecisionAccept {
		t.Fatalf("result=%+v view=%+v", result, view)
	}
	if err := view.ValidateID(); err != nil {
		t.Fatal(err)
	}
	if len(view.Manifest.InputSnapshotDigests) != 1 {
		t.Fatalf("snapshots=%v", view.Manifest.InputSnapshotDigests)
	}
	if got := view.Manifest.Extensions["selectionPolicyId"]; got != chainappraisal.ProjectedChainSelection {
		t.Fatalf("selectionPolicyId=%v", got)
	}
}

func TestNewRequiresSelectionPolicy(t *testing.T) {
	doc := did.New(did.DocumentFields{ID: "did:example:issuer"})
	_, err := chainappraisal.New(capturingWalker{resolver: inputcapture.DIDResolver{Next: staticDID{doc: doc}}}, inputcapture.Recorder{}, chainappraisal.Config{
		ClaimContractID: "linear-provenance@1",
		SchemaVersion:   "pipeline-pass-credential@1",
		KnownScopes:     []string{chainappraisal.LinearAttestationScope},
		Profile:         appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{chainappraisal.LinearAttestationScope}},
	})
	if err == nil {
		t.Fatal("missing selection policy: want construction error")
	}
}
