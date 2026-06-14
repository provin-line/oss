package local_test

import (
	"testing"

	"github.com/provin-line/oss/schema/local"
)

// ValidateDocument is the registry-admission check: a document is admitted only
// if it strict-decodes, compiles under Draft 2020-12, and references no external
// $ref. It is the policy schemaregistry reuses so the registry never holds a
// schema a downstream validator would reject.
func TestValidateDocument_AcceptsWellFormedSchema(t *testing.T) {
	if err := local.ValidateDocument(readingSchema); err != nil {
		t.Errorf("ValidateDocument on a well-formed schema: %v", err)
	}
}

func TestValidateDocument_RejectsMalformedJSON(t *testing.T) {
	if err := local.ValidateDocument([]byte(`{not json`)); err == nil {
		t.Error("ValidateDocument on non-JSON: want error")
	}
}

func TestValidateDocument_RejectsDuplicateKey(t *testing.T) {
	// Strict decode rejects the ambiguous duplicate keyword before compilation.
	if err := local.ValidateDocument([]byte(`{"type":"string","type":"number"}`)); err == nil {
		t.Error("ValidateDocument on a duplicate-keyword schema: want error")
	}
}

func TestValidateDocument_RejectsStructurallyInvalidSchema(t *testing.T) {
	// Strict-decodable JSON, but not a valid schema (type must be a string or
	// array of strings, not a number). Compilation must reject it.
	if err := local.ValidateDocument([]byte(`{"type":123}`)); err == nil {
		t.Error("ValidateDocument on a structurally-invalid schema: want error")
	}
}

func TestValidateDocument_RejectsExternalRef(t *testing.T) {
	for name, doc := range map[string]string{
		"file ref": `{"$ref":"file:///etc/passwd"}`,
		"http ref": `{"$ref":"http://evil.example/schema.json"}`,
	} {
		if err := local.ValidateDocument([]byte(doc)); err == nil {
			t.Errorf("%s: ValidateDocument with an external $ref: want error", name)
		}
	}
}
