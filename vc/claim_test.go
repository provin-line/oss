package vc_test

import (
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

// Grammar checks mirror the spec vectors cred-023 (no "+" joins) and
// cred-024 (bare values rejected): a claim is a single <namespace>:<label>
// token (credential.claim.grammar).
func TestTransformationClaimValidateGrammar(t *testing.T) {
	valid := []vc.TransformationClaim{
		vc.ClaimFilter, vc.ClaimConvert, vc.ClaimFilterConvert,
		vc.ClaimAggregate, vc.ClaimEnrich, vc.ClaimGenerate,
		"acme:distill", // foreign namespace, well-formed
	}
	for _, tc := range valid {
		if err := tc.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", tc, err)
		}
	}

	invalid := []struct {
		claim vc.TransformationClaim
		name  string
	}{
		{"", "empty (presence is a MUST)"},
		{"filter", "bare value without namespace prefix (cred-024)"},
		{"provin:filter+provin:convert", "join of two tokens (cred-023)"},
		{"provin:filter+convert", "join surface inside a label"},
		{"provin:", "empty label"},
		{":filter", "empty namespace"},
		{"provin:fil ter", "whitespace in label"},
		{"provin:fil\tter", "control byte in label"},
	}
	for _, tt := range invalid {
		if err := tt.claim.Validate(); err == nil {
			t.Errorf("Validate(%q) = nil, want error: %s", tt.claim, tt.name)
		}
	}
}

func newClaimTestCredential(t *testing.T, claim vc.TransformationClaim) *vc.PipelinePassCredential {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:process:p1",
		ValidFrom: time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "pipe-1",
			ProcessID:           "proc-1",
			TransformationClaim: claim,
			InputHash:           "uEiB0000000000000000000000000000000000000000000",
			OutputHash:          "uEiB1111111111111111111111111111111111111111111",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cred
}

// New emits @context = [credentials-v2, dplaax, provin], so every provin:
// claim is grounded (cred-027) and a foreign prefix without its own
// grounding context must be rejected on the issue path
// (credential.claim.grounding is an issuer MUST).
func TestNewEnforcesClaimGrammarAndGrounding(t *testing.T) {
	for _, claim := range []vc.TransformationClaim{
		vc.ClaimFilter, vc.ClaimGenerate, "dplaax:reserved",
	} {
		cred := newClaimTestCredential(t, claim)
		if err := cred.ValidateTransformationClaim(); err != nil {
			t.Errorf("ValidateTransformationClaim(%q) = %v, want nil", claim, err)
		}
	}

	rejected := []vc.TransformationClaim{
		"",                  // absent (credential.subject.transformation-claim)
		"filter",            // bare (cred-024)
		"provin:filter+provin:convert", // join (cred-023)
		"acme:distill",      // no context grounds "acme" and New emits only known contexts (cred-026 analogue)
	}
	for _, claim := range rejected {
		_, err := vc.New(vc.CredentialFields{
			Issuer:    "did:dplaax:poc.dplaax.io:org:acme:process:p1",
			ValidFrom: time.Date(2026, 6, 11, 0, 0, 0, 0, time.UTC),
			Subject: vc.CredentialSubjectFields{
				PipelineID:          "pipe-1",
				ProcessID:           "proc-1",
				TransformationClaim: claim,
			},
		})
		if err == nil {
			t.Errorf("New with claim %q = nil error, want rejection", claim)
		}
	}
}

// Verifier-side grounding semantics over as-received wire documents:
// cred-025 (unknown namespace + unknown context → open-world accept),
// cred-026 (provin: claim without the provin context → reject),
// cred-027 (grounded conformant form → accept).
func TestValidateTransformationClaimOnWireDocuments(t *testing.T) {
	wire := func(contexts, claim string) string {
		return `{
		  "@context": [` + contexts + `],
		  "type": ["VerifiableCredential", "PipelinePassCredential"],
		  "issuer": "did:dplaax:poc.dplaax.io:org:acme:process:p1",
		  "validFrom": "2026-06-11T00:00:00Z",
		  "credentialSubject": {
		    "pipelineId": "pipe-1",
		    "processId": "proc-1",
		    "transformationClaim": "` + claim + `"
		  }
		}`
	}
	known := `"https://www.w3.org/ns/credentials/v2", "https://poc.dplaax.io/vc/v1"`
	withProvin := known + `, "https://poc.provin.io/vc/v1"`
	withForeign := withProvin + `, "https://acme.example/vc/v1"`

	cases := []struct {
		name     string
		document string
		wantErr  bool
	}{
		{"cred-027 grounded provin claim", wire(withProvin, "provin:filter"), false},
		{"cred-026 provin claim without grounding context", wire(known, "provin:filter"), true},
		{"cred-025 unknown namespace with unknown context", wire(withForeign, "acme:distill"), false},
		{"unknown namespace with only known contexts", wire(withProvin, "acme:distill"), true},
	}
	for _, tt := range cases {
		var cred vc.PipelinePassCredential
		if err := cred.UnmarshalJSON([]byte(tt.document)); err != nil {
			t.Fatalf("%s: unmarshal: %v", tt.name, err)
		}
		err := cred.ValidateTransformationClaim()
		if tt.wantErr && err == nil {
			t.Errorf("%s: want rejection, got nil", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("%s: want accept, got %v", tt.name, err)
		}
	}
}

// An inline @context object (instead of an IRI string) can define arbitrary
// prefix mappings the implementation cannot enumerate — it is an unknown
// grounding source, so the open-world default applies.
func TestValidateTransformationClaimInlineContextIsOpenWorld(t *testing.T) {
	document := `{
	  "@context": ["https://www.w3.org/ns/credentials/v2", "https://poc.dplaax.io/vc/v1", {"acme": "https://acme.example/vocab#"}],
	  "type": ["VerifiableCredential", "PipelinePassCredential"],
	  "issuer": "did:dplaax:poc.dplaax.io:org:acme:process:p1",
	  "validFrom": "2026-06-11T00:00:00Z",
	  "credentialSubject": {
	    "pipelineId": "pipe-1",
	    "processId": "proc-1",
	    "transformationClaim": "acme:distill"
	  }
	}`
	var cred vc.PipelinePassCredential
	if err := cred.UnmarshalJSON([]byte(document)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := cred.ValidateTransformationClaim(); err != nil {
		t.Errorf("inline context must be treated as an unknown grounding source (open-world), got %v", err)
	}
}

// Validation must report which rule failed in a recognizable way so a
// future Verify wires it into the wire-form axis without re-deriving.
func TestValidateTransformationClaimErrorMentionsClaim(t *testing.T) {
	var cred vc.PipelinePassCredential
	if err := cred.UnmarshalJSON([]byte(`{
	  "@context": ["https://www.w3.org/ns/credentials/v2", "https://poc.dplaax.io/vc/v1"],
	  "type": ["VerifiableCredential", "PipelinePassCredential"],
	  "issuer": "did:x:y",
	  "credentialSubject": {"transformationClaim": "filter"}
	}`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	err := cred.ValidateTransformationClaim()
	if err == nil || !strings.Contains(err.Error(), "transformationClaim") {
		t.Errorf("error should name transformationClaim, got %v", err)
	}
}
