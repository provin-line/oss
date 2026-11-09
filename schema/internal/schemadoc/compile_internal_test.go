package schemadoc

import (
	"strings"
	"testing"
)

// The check of a schema against its metaschema runs within a work budget,
// as a payload's validation does, and a schema that needs more is refused in
// the same words.
func TestCompileWithin_ChecksTheSchemaWithinItsBudget(t *testing.T) {
	doc := []byte(`{"allOf":[` + strings.TrimSuffix(strings.Repeat(`{"type":"string"},`, 200), ",") + `]}`)
	if _, err := compileWithin(doc, schemaBudgetBase); err != nil {
		t.Fatalf("within the base budget: %v", err)
	}
	_, err := compileWithin(doc, 100)
	if err == nil || !strings.Contains(err.Error(), "needs more than its work budget of 100 steps") {
		t.Errorf("within 100 steps: %v, want an error naming the work budget", err)
	}
}
