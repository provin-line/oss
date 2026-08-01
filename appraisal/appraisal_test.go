package appraisal_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/provin-line/oss/appraisal"
)

const (
	head   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	viewID = "sha256:4382e8875ce5c79e0f053215993f901331003e89d125de78bc610dbdb90b06aa"
)

func manifest() appraisal.Manifest {
	return appraisal.Manifest{
		Head: head,
		Spine: []appraisal.SpineEntry{
			{BodyAddress: "sha256:1111111111111111111111111111111111111111111111111111111111111111", WireVariantID: "wire:v1:jcs-rfc8785:sha256:2222222222222222222222222222222222222222222222222222222222222222"},
			{BodyAddress: head, WireVariantID: "wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		ClaimContractID: "linear-provenance@1",
		CanonicalizerID: appraisal.CanonicalizerRFC8785,
		CryptosuiteID:   "W3C_EDDSA_JCS_2022_REC_20250515@1",
		SchemaVersion:   "pipeline-pass-credential@1",
		InputSnapshotDigests: map[string]string{
			"did:did:dplaax:factory-a": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"lifecycle:factory-a":      "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
	}
}

func truth(v appraisal.TruthState) *appraisal.TruthState { return &v }

func TestManifestIDMatchesIndependentVector(t *testing.T) {
	got, err := manifest().ID()
	if err != nil {
		t.Fatal(err)
	}
	if got != viewID {
		t.Fatalf("ID=%s want %s", got, viewID)
	}
}

func TestManifestIdentityIncludesExtensions(t *testing.T) {
	m := manifest()
	base, _ := m.ID()
	m.Extensions = map[string]any{"futureInput": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
	extended, err := m.ID()
	if err != nil {
		t.Fatal(err)
	}
	if base == extended {
		t.Fatal("extension member did not change EvidenceViewID")
	}
}

func TestManifestJSONRoundTripPreservesExtensions(t *testing.T) {
	raw := []byte(`{"head":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","spine":[{"bodyAddress":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","wireVariantId":"wire:v1:jcs-rfc8785:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],"claimContractId":"linear-provenance@1","canonicalizerId":"jcs-rfc8785","cryptosuiteId":"suite@1","schemaVersion":"credential@1","inputSnapshotDigests":{"did":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"future":{"mode":"strict"}}`)
	var m appraisal.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Extensions["future"]; !ok {
		t.Fatal("extension was dropped")
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["future"]; !ok {
		t.Fatal("extension missing after round trip")
	}
}

func TestValidateIDRejectsMismatch(t *testing.T) {
	v, err := appraisal.NewView(manifest(), []appraisal.ScopeEntry{{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)}})
	if err != nil {
		t.Fatal(err)
	}
	v.EvidenceViewID = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := v.ValidateID(); !errors.Is(err, appraisal.ErrViewIDMismatch) {
		t.Fatalf("ValidateID error=%v", err)
	}
}

func TestValidateVectorCoverageTruthCoupling(t *testing.T) {
	tests := []appraisal.ScopeEntry{
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageNotEvaluated, TruthState: truth(appraisal.TruthVerified)},
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated},
	}
	for _, entry := range tests {
		if err := appraisal.ValidateVector([]appraisal.ScopeEntry{entry}); !errors.Is(err, appraisal.ErrInvalidVector) {
			t.Errorf("entry=%+v error=%v", entry, err)
		}
	}
}

func TestDecideFailClosedTable(t *testing.T) {
	profile := appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1", "SOURCE_SET_BINDING@1"}}
	tests := []struct {
		name   string
		vector []appraisal.ScopeEntry
		want   appraisal.Decision
	}{
		{"all verified", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		}, appraisal.DecisionAccept},
		{"missing", []appraisal.ScopeEntry{{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)}}, appraisal.DecisionQuarantine},
		{"unsupported", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
		}, appraisal.DecisionQuarantine},
		{"indeterminate", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthIndeterminate)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		}, appraisal.DecisionQuarantine},
		{"failed wins", []appraisal.ScopeEntry{
			{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthFailed)},
			{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
		}, appraisal.DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appraisal.Decide(profile, tt.vector)
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision != tt.want {
				t.Fatalf("decision=%s want %s", got.Decision, tt.want)
			}
		})
	}
}

func TestTwoLocalProfilesDifferOverOneEvidenceVector(t *testing.T) {
	vector := []appraisal.ScopeEntry{
		{Scope: "LINEAR_ATTESTATION@1", Coverage: appraisal.CoverageEvaluated, TruthState: truth(appraisal.TruthVerified)},
		{Scope: "SOURCE_SET_BINDING@1", Coverage: appraisal.CoverageUnsupported},
	}
	permissive, err := appraisal.Decide(appraisal.Profile{ID: "purpose-first-agent-access@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1"}}, vector)
	if err != nil {
		t.Fatal(err)
	}
	strict, err := appraisal.Decide(appraisal.Profile{ID: "strict-source-binding@1", RequiredScopes: []string{"LINEAR_ATTESTATION@1", "SOURCE_SET_BINDING@1"}}, vector)
	if err != nil {
		t.Fatal(err)
	}
	if permissive.Decision != appraisal.DecisionAccept || strict.Decision != appraisal.DecisionQuarantine {
		t.Fatalf("same vector: permissive=%s strict=%s", permissive.Decision, strict.Decision)
	}
}
