package local_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/provin-line/oss/schema/local"
	"github.com/provin-line/oss/vc"
)

var readingSchema = []byte(`{
	"type": "object",
	"required": ["reading"],
	"properties": { "reading": { "type": "number" } },
	"additionalProperties": false
}`)

func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ref(id string, doc []byte) vc.SchemaRef {
	return vc.SchemaRef{ID: id, Type: "JsonSchema", ContentHash: contentHash(doc)}
}

func newValidator(t *testing.T) *local.Validator {
	t.Helper()
	v := local.New()
	if err := v.Add("schema:reading", readingSchema); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return v
}

func TestValidate_ConformingPayload(t *testing.T) {
	v := newValidator(t)
	if err := v.Validate(context.Background(), []byte(`{"reading":42}`), ref("schema:reading", readingSchema)); err != nil {
		t.Errorf("Validate on a conforming payload: %v", err)
	}
}

func TestValidate_NonConforming(t *testing.T) {
	v := newValidator(t)
	cases := map[string]string{
		"missing required":    `{}`,
		"wrong type":          `{"reading":"hot"}`,
		"additional property": `{"reading":42,"extra":1}`,
	}
	for name, payload := range cases {
		if err := v.Validate(context.Background(), []byte(payload), ref("schema:reading", readingSchema)); err == nil {
			t.Errorf("%s (%s): want a validation error", name, payload)
		}
	}
}

func TestValidate_ContentHashMismatch(t *testing.T) {
	v := newValidator(t)
	bad := ref("schema:reading", readingSchema)
	bad.ContentHash = "sha256:deadbeef" // not the stored schema's hash
	if err := v.Validate(context.Background(), []byte(`{"reading":42}`), bad); err == nil {
		t.Error("Validate with a mismatched content hash: want error (schema-reference mismatch)")
	}
}

func TestValidate_UnknownSchema(t *testing.T) {
	v := newValidator(t)
	if err := v.Validate(context.Background(), []byte(`{"reading":42}`), ref("schema:absent", readingSchema)); err == nil {
		t.Error("Validate against an unregistered schema id: want error")
	}
}

func TestValidate_UnsupportedType(t *testing.T) {
	v := newValidator(t)
	r := ref("schema:reading", readingSchema)
	r.Type = "Cddl"
	if err := v.Validate(context.Background(), []byte(`{"reading":42}`), r); err == nil {
		t.Error("Validate with a non-JsonSchema type: want error")
	}
}

func TestValidate_MalformedPayload(t *testing.T) {
	v := newValidator(t)
	if err := v.Validate(context.Background(), []byte(`{not json`), ref("schema:reading", readingSchema)); err == nil {
		t.Error("Validate with a non-JSON payload: want error")
	}
}

func TestAdd_RejectsInvalidSchema(t *testing.T) {
	v := local.New()
	if err := v.Add("schema:bad", []byte(`{"type": 123}`)); err == nil {
		t.Error("Add with an invalid JSON Schema: want error")
	}
}

// A schema with an external $ref (file://, http://) must be rejected at Add —
// self-containment is structurally enforced, not assumed (no local-file
// inclusion via a crafted $ref).
func TestAdd_RejectsExternalRef(t *testing.T) {
	v := local.New()
	for name, doc := range map[string]string{
		"file ref": `{"$ref":"file:///etc/passwd"}`,
		"http ref": `{"$ref":"http://evil.example/schema.json"}`,
	} {
		if err := v.Add("schema:"+name, []byte(doc)); err == nil {
			t.Errorf("%s: Add with an external $ref: want error", name)
		}
	}
}

// Duplicate keys are rejected on both protocol paths (strict decode), so the
// validator never disagrees with the rest of the stack's wire semantics.
func TestAdd_RejectsDuplicateKeySchema(t *testing.T) {
	v := local.New()
	if err := v.Add("schema:dup", []byte(`{"type":"string","type":"number"}`)); err == nil {
		t.Error("Add with a duplicate-keyword schema: want error (ambiguous semantics)")
	}
}

func TestValidate_RejectsDuplicateKeyPayload(t *testing.T) {
	v := newValidator(t)
	// The last value (42) would conform, but the duplicate key is ambiguous and
	// strict decoding rejects it before validation.
	if err := v.Validate(context.Background(), []byte(`{"reading":"bad","reading":42}`), ref("schema:reading", readingSchema)); err == nil {
		t.Error("Validate with a duplicate-key payload: want error")
	}
}

// format keywords are annotations only (no assertion) — a format-violating
// payload still validates. Pins the contract against a future library default
// flip.
func TestValidate_FormatIsAnnotationOnly(t *testing.T) {
	v := local.New()
	doc := []byte(`{"type":"object","properties":{"email":{"type":"string","format":"email"}}}`)
	if err := v.Add("schema:email", doc); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := v.Validate(context.Background(), []byte(`{"email":"not-an-email"}`), ref("schema:email", doc)); err != nil {
		t.Errorf("format must be annotation-only (no assertion), got error: %v", err)
	}
}
