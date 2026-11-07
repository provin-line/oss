package schema_test

import (
	"strings"
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

// boundsSchema puts n where the library reads it as a number at compile.
func boundsSchema(n string) []byte {
	return []byte(`{"type": "number", "minimum": ` + n + `, "maximum": ` + n + `}`)
}

// A number the JSON Schema library would read slowly, or cannot read, is
// refused before it reads the schema: one longer than 256 bytes, or whose
// exponent part (after "e" or "E") lies beyond ±400.
func TestValidateJSONSchema_RefusesANumberBeyondTheBounds(t *testing.T) {
	for _, n := range []string{
		"1e999999", "1e-999999", "0e999999", "-0e401", "1e401", "1E-401", "1e+401",
		"1e0401", "1E-0401", "1e1000001", "1e-1000001", "1e99999999999999999999",
		strings.Repeat("7", 257), "-" + strings.Repeat("7", 256),
		"0." + strings.Repeat("0", 254) + "1",
	} {
		if err := schema.ValidateJSONSchema(boundsSchema(n)); err == nil {
			t.Errorf("%.40s (%d bytes): want error", n, len(n))
		}
	}
}

// Numbers within the bounds are read as before.
func TestValidateJSONSchema_AcceptsANumberWithinTheBounds(t *testing.T) {
	for _, n := range []string{
		"0", "-0", "1.5", "1e400", "1E-400", "1e+400", "1e0400", "-1.7976931348623157e308",
		"5e-324", strings.Repeat("7", 256), "-" + strings.Repeat("7", 255),
		"0." + strings.Repeat("0", 253) + "1",
	} {
		if err := schema.ValidateJSONSchema(boundsSchema(n)); err != nil {
			t.Errorf("%.40s (%d bytes): %v", n, len(n), err)
		}
	}
}
