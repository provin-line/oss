package conformance_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/provin-line/oss/appraisal"
)

// runEvidenceView drives exact manifest identity, including the independent
// spec implementation's canonical byte and digest fixture.
func runEvidenceView(t *testing.T, v dplaaxVector) {
	var input struct {
		Credential appraisal.View `json:"credential"`
	}
	mustParse(t, v.Input, &input)
	switch vecNum(t, v.ID) {
	case 1:
		var expect struct {
			Canonical      string `json:"canonical"`
			EvidenceViewID string `json:"evidenceViewId"`
		}
		mustParse(t, v.Expect, &expect)
		canonical, err := input.Credential.Manifest.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != expect.Canonical {
			t.Errorf("canonical manifest=%s want %s", canonical, expect.Canonical)
		}
		if err := input.Credential.ValidateID(); err != nil {
			t.Fatal(err)
		}
		if input.Credential.EvidenceViewID != expect.EvidenceViewID {
			t.Errorf("EvidenceViewID=%s want %s", input.Credential.EvidenceViewID, expect.EvidenceViewID)
		}
	case 2:
		if expectString(t, v) != "reject" {
			t.Fatalf("unhandled expect %s", v.Expect)
		}
		if err := input.Credential.ValidateID(); !errors.Is(err, appraisal.ErrViewIDMismatch) {
			t.Errorf("ValidateID error=%v, want mismatch", err)
		}
	default:
		t.Fatalf("unhandled evidence-view vector %s", v.ID)
	}
}

func runClaimsCoverage(t *testing.T, v dplaaxVector) {
	switch vecNum(t, v.ID) {
	case 1, 2, 4:
		var input struct {
			Credential appraisal.View `json:"credential"`
		}
		if err := json.Unmarshal(v.Input, &input); err != nil {
			if vecNum(t, v.ID) == 1 {
				t.Fatalf("decode accept vector: %v", err)
			}
			return
		}
		err := input.Credential.ValidateShape()
		want := expectString(t, v)
		if (err == nil) != (want == "accept") {
			t.Errorf("ValidateShape error=%v want %s", err, want)
		}
	case 3:
		profile, vector := decisionInput(t, v)
		decision, err := appraisal.Decide(profile, vector)
		if err != nil {
			t.Fatal(err)
		}
		var expect struct {
			DecisionNot appraisal.Decision `json:"decisionNot"`
		}
		mustParse(t, v.Expect, &expect)
		if decision.Decision == expect.DecisionNot {
			t.Errorf("decision=%s, forbidden by vector", decision.Decision)
		}
	default:
		t.Fatalf("unhandled claims-coverage vector %s", v.ID)
	}
}

func runClaimsPolicy(t *testing.T, v dplaaxVector) {
	profile, vector := decisionInput(t, v)
	decision, err := appraisal.Decide(profile, vector)
	if err != nil {
		t.Fatal(err)
	}
	var expect struct {
		Decision appraisal.Decision `json:"decision"`
	}
	mustParse(t, v.Expect, &expect)
	if decision.Decision != expect.Decision {
		t.Errorf("decision=%s want %s", decision.Decision, expect.Decision)
	}
}

func decisionInput(t *testing.T, v dplaaxVector) (appraisal.Profile, []appraisal.ScopeEntry) {
	t.Helper()
	var input struct {
		DecisionProfileID string                 `json:"decisionProfileId"`
		RequiredScopes    []string               `json:"requiredScopes"`
		Vector            []appraisal.ScopeEntry `json:"vector"`
	}
	mustParse(t, v.Input, &input)
	return appraisal.Profile{ID: input.DecisionProfileID, RequiredScopes: input.RequiredScopes}, input.Vector
}
