package schema_test

import (
	"testing"

	"github.com/provin-line/oss/schema"
)

// wellFormedSchema is a minimal, self-contained Draft 2020-12 schema.
var wellFormedSchema = []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {"reading": {"type": "number"}},
  "required": ["reading"]
}`)

// ValidateJSONSchema is the registry-admission check: a document is admitted only
// if it strict-decodes, compiles under Draft 2020-12, and references no external
// $ref. It is the policy schemaregistry reuses so the registry never holds a
// schema a downstream validator would reject.
func TestValidateJSONSchema_AcceptsWellFormedSchema(t *testing.T) {
	if err := schema.ValidateJSONSchema(wellFormedSchema); err != nil {
		t.Errorf("ValidateJSONSchema on a well-formed schema: %v", err)
	}
}

func TestValidateJSONSchema_RejectsMalformedJSON(t *testing.T) {
	if err := schema.ValidateJSONSchema([]byte(`{not json`)); err == nil {
		t.Error("ValidateJSONSchema on non-JSON: want error")
	}
}

func TestValidateJSONSchema_RejectsDuplicateKey(t *testing.T) {
	// Strict decode rejects the ambiguous duplicate keyword before compilation.
	if err := schema.ValidateJSONSchema([]byte(`{"type":"string","type":"number"}`)); err == nil {
		t.Error("ValidateJSONSchema on a duplicate-keyword schema: want error")
	}
}

func TestValidateJSONSchema_RejectsStructurallyInvalidSchema(t *testing.T) {
	// Strict-decodable JSON, but not a valid schema (type must be a string or
	// array of strings, not a number). Compilation must reject it.
	if err := schema.ValidateJSONSchema([]byte(`{"type":123}`)); err == nil {
		t.Error("ValidateJSONSchema on a structurally-invalid schema: want error")
	}
}

func TestValidateJSONSchema_RejectsExternalRef(t *testing.T) {
	for name, doc := range map[string]string{
		"file ref": `{"$ref":"file:///etc/passwd"}`,
		"http ref": `{"$ref":"http://evil.example/schema.json"}`,
	} {
		if err := schema.ValidateJSONSchema([]byte(doc)); err == nil {
			t.Errorf("%s: ValidateJSONSchema with an external $ref: want error", name)
		}
	}
}
