package conformance_test

import (
	"encoding/json"
	"errors"
	"strings"
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

// claimsCoverageRefusals ties each claims-coverage reject vector to the
// sentinel of the refusal its rule names (claims.coverage.three-value: a
// scope's coverage and truth state disagree), so a vector refused with
// another error fails.
var claimsCoverageRefusals = map[string]refusalTie{
	"claims-coverage-002": {err: appraisal.ErrInvalidVector},
	"claims-coverage-004": {err: appraisal.ErrInvalidVector},
}

func runClaimsCoverage(t *testing.T, v dplaaxVector) {
	switch vecNum(t, v.ID) {
	case 1, 2, 4:
		// The view decodes in every vector: a refusal is ValidateShape's.
		var input struct {
			Credential appraisal.View `json:"credential"`
		}
		if err := json.Unmarshal(v.Input, &input); err != nil {
			t.Fatalf("decode the view: %v", err)
		}
		err := input.Credential.ValidateShape()
		want := expectString(t, v)
		if (err == nil) != (want == "accept") {
			t.Errorf("ValidateShape error=%v want %s", err, want)
		}
		if want == "reject" {
			tie, ok := claimsCoverageRefusals[v.ID]
			if !ok {
				t.Fatalf("no refusal tied to %s in claimsCoverageRefusals", v.ID)
			}
			if !tie.holds(err) {
				t.Errorf("ValidateShape refused %s with %v, want %s", v.ID, err, tie)
			}
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

// claimsCoverageRefusals ties exactly the claims-coverage vectors the
// manifest lists as reject (a vector whose expect is not a string names a
// decision, not a refusal).
func TestClaimsCoverageRefusalsTieEveryRejectVector(t *testing.T) {
	listed := map[string]bool{}
	for _, id := range manifestIDs(t) {
		if !strings.HasPrefix(id, "claims-coverage-") {
			continue
		}
		listed[id] = true
		var want string
		_ = json.Unmarshal(loadDplaax(t, id).Expect, &want)
		if _, tied := claimsCoverageRefusals[id]; tied != (want == "reject") {
			t.Errorf("%s expects %q, tied in claimsCoverageRefusals: %t", id, want, tied)
		}
	}
	for id := range claimsCoverageRefusals {
		if !listed[id] {
			t.Errorf("claimsCoverageRefusals ties %s, which the manifest does not list", id)
		}
	}
}
