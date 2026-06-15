// Package converter_test tests the converter package public API.
package converter_test

import (
	"testing"

	"github.com/provin-line/oss/pipeline/chained/converter"
)

// TestRequireFields_AllPresent verifies that all listed fields being present
// in the document returns nil.
func TestRequireFields_AllPresent(t *testing.T) {
	doc := []byte(`{"name":"Alice","age":30,"active":true}`)
	required := []string{"name", "age", "active"}

	if err := converter.RequireFields(doc, required); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRequireFields_EmptyRequired verifies that an empty required list
// always returns nil.
func TestRequireFields_EmptyRequired(t *testing.T) {
	doc := []byte(`{"name":"Alice"}`)

	if err := converter.RequireFields(doc, nil); err != nil {
		t.Fatalf("unexpected error with nil required: %v", err)
	}
	if err := converter.RequireFields(doc, []string{}); err != nil {
		t.Fatalf("unexpected error with empty required: %v", err)
	}
}

// TestRequireFields_MissingField verifies that a missing required field
// returns an error that names the missing field.
func TestRequireFields_MissingField(t *testing.T) {
	doc := []byte(`{"name":"Alice"}`)
	required := []string{"name", "email"}

	err := converter.RequireFields(doc, required)
	if err == nil {
		t.Fatal("expected error for missing field, got nil")
	}

	// The error must name the missing field.
	if got := err.Error(); got == "" {
		t.Fatal("error message must not be empty")
	}
	// Verify "email" appears in the error (the missing key).
	const missing = "email"
	if e := err.Error(); len(e) == 0 {
		t.Fatal("error must mention the missing field name")
	} else {
		found := false
		for i := 0; i <= len(e)-len(missing); i++ {
			if e[i:i+len(missing)] == missing {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("error %q does not mention missing field %q", e, missing)
		}
	}
}

// TestRequireFields_InvalidJSON verifies that invalid JSON returns an error.
func TestRequireFields_InvalidJSON(t *testing.T) {
	doc := []byte(`not-json`)
	err := converter.RequireFields(doc, []string{"name"})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestRequireFields_ExtraFields verifies that extra fields in the document
// beyond the required list do not cause an error.
func TestRequireFields_ExtraFields(t *testing.T) {
	doc := []byte(`{"name":"Alice","extra1":"x","extra2":99}`)
	required := []string{"name"}

	if err := converter.RequireFields(doc, required); err != nil {
		t.Fatalf("unexpected error with extra fields: %v", err)
	}
}
