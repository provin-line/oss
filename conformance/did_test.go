package conformance_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/provin-line/oss/did/dplaax"
)

// runDID drives the did family. did.dplaax.syntax: whether dplaax.Parse
// accepts the DID. did.dplaax.hierarchy: the level the Is* methods give the
// parsed DID, its OwnerDID, and its Pipeline: a Process's, and none for any
// other level (only a Process has a Pipeline, so the vector names one for no
// other level).
//
// A reject vector passes only when Parse refuses it under its rule:
// didRefusals ties the rule to its sentinel.
func runDID(t *testing.T, v dplaaxVector) {
	var input struct {
		DID string `json:"did"`
	}
	mustParse(t, v.Input, &input)
	d, err := dplaax.Parse(input.DID)
	switch v.Rule {
	case "did.dplaax.syntax":
		want := expectString(t, v)
		if (err == nil) != (want == "accept") {
			t.Errorf("Parse(%q) err=%v, want %s", input.DID, err, want)
		}
		if want == "reject" {
			tie, ok := didRefusals[v.Rule]
			if !ok {
				t.Fatalf("no refusal tied to %s in didRefusals", v.Rule)
			}
			if !tie.holds(err) {
				t.Errorf("Parse(%q) refused with %v, want %s", input.DID, err, tie)
			}
		}
		// A DID accepted is taken as it is, never repaired or normalized.
		if err == nil && d.String() != input.DID {
			t.Errorf("Parse(%q) reads %q", input.DID, d.String())
		}
	case "did.dplaax.hierarchy":
		var want struct {
			Level    string  `json:"level"`
			Owner    string  `json:"owner"`
			Pipeline *string `json:"pipeline"`
		}
		mustParse(t, v.Expect, &want)
		if err != nil {
			t.Fatalf("Parse(%q): %v, want a DID to classify", input.DID, err)
		}
		level, levels := "none", 0
		for name, is := range map[string]bool{"owner": d.IsOwner(), "pipeline": d.IsPipeline(), "process": d.IsProcess()} {
			if is {
				level, levels = name, levels+1
			}
		}
		if levels > 1 {
			t.Errorf("%q is at %d levels, want at most one", input.DID, levels)
		}
		if level != want.Level {
			t.Errorf("level of %q: %s, want %s", input.DID, level, want.Level)
		}
		if got := d.OwnerDID().String(); got != want.Owner {
			t.Errorf("OwnerDID of %q: %s, want %s", input.DID, got, want.Owner)
		}
		var pipeline string
		p, ok := d.Pipeline()
		if ok != (p != nil) {
			t.Errorf("Pipeline of %q: %v, %t: a Pipeline exactly when true", input.DID, p, ok)
		}
		if ok {
			pipeline = p.String()
		}
		switch {
		case want.Pipeline == nil && pipeline != "":
			t.Errorf("Pipeline of %q: %s, want none", input.DID, pipeline)
		case want.Pipeline != nil && pipeline != *want.Pipeline:
			t.Errorf("Pipeline of %q: %q, want %s", input.DID, pipeline, *want.Pipeline)
		}
	default:
		t.Fatalf("rule %q: no did driver", v.Rule)
	}
}

// didVectorID is the id form of the did family (did-001), not of another
// family whose name begins with did- (did-resolution-…).
var didVectorID = regexp.MustCompile(`^did-[0-9]+$`)

// Every did vector the manifest lists is driven, and none is left in the
// skip ledger.
func TestDIDVectorsAreDrivenNotSkipped(t *testing.T) {
	n := 0
	for _, id := range manifestIDs(t) {
		if !didVectorID.MatchString(id) {
			continue
		}
		n++
		if _, ok := dplaaxRunners[id]; !ok {
			t.Errorf("%s has no runner", id)
		}
		if reason, ok := dplaaxSkips[id]; ok {
			t.Errorf("%s is still skipped: %s", id, reason)
		}
	}
	if n == 0 {
		t.Error("the manifest lists no did vector")
	}
}

// didRefusals ties each did rule a reject vector names to its sentinel, so a
// vector refused with another error fails. did.dplaax.syntax is one rule with
// one sentinel, so the tie is by rule.
var didRefusals = map[string]refusalTie{
	"did.dplaax.syntax": {err: dplaax.ErrSyntax},
}

// didRefusals ties the rule of every did vector the manifest lists as
// reject, and no rule no such vector names.
func TestDIDRefusalsTieEveryRejectVector(t *testing.T) {
	named := map[string]bool{}
	for _, id := range manifestIDs(t) {
		if !didVectorID.MatchString(id) {
			continue
		}
		v := loadDplaax(t, id)
		var want string
		if json.Unmarshal(v.Expect, &want) != nil || want != "reject" {
			continue
		}
		named[v.Rule] = true
		if _, tied := didRefusals[v.Rule]; !tied {
			t.Errorf("%s expects reject under %s, which didRefusals does not tie", id, v.Rule)
		}
	}
	for rule := range didRefusals {
		if !named[rule] {
			t.Errorf("didRefusals ties %s, which no reject vector names", rule)
		}
	}
}
