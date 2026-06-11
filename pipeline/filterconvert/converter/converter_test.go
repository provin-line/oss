// Package converter_test tests the converter package public API.
package converter_test

import (
	"testing"

	"github.com/provin-line/oss/pipeline/filterconvert/converter"
)

// TestValidateSubset_AllPresent verifies that all listed fields being present
// in the document returns nil.
func TestValidateSubset_AllPresent(t *testing.T) {
	doc := []byte(`{"name":"Alice","age":30,"active":true}`)
	required := []string{"name", "age", "active"}

	if err := converter.ValidateSubset(doc, required); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestValidateSubset_EmptyRequired verifies that an empty required list
// always returns nil.
func TestValidateSubset_EmptyRequired(t *testing.T) {
	doc := []byte(`{"name":"Alice"}`)

	if err := converter.ValidateSubset(doc, nil); err != nil {
		t.Fatalf("unexpected error with nil required: %v", err)
	}
	if err := converter.ValidateSubset(doc, []string{}); err != nil {
		t.Fatalf("unexpected error with empty required: %v", err)
	}
}

// TestValidateSubset_MissingField verifies that a missing required field
// returns an error that names the missing field.
func TestValidateSubset_MissingField(t *testing.T) {
	doc := []byte(`{"name":"Alice"}`)
	required := []string{"name", "email"}

	err := converter.ValidateSubset(doc, required)
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

// TestValidateSubset_InvalidJSON verifies that invalid JSON returns an error.
func TestValidateSubset_InvalidJSON(t *testing.T) {
	doc := []byte(`not-json`)
	err := converter.ValidateSubset(doc, []string{"name"})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestValidateSubset_ExtraFields verifies that extra fields in the document
// beyond the required list do not cause an error.
func TestValidateSubset_ExtraFields(t *testing.T) {
	doc := []byte(`{"name":"Alice","extra1":"x","extra2":99}`)
	required := []string{"name"}

	if err := converter.ValidateSubset(doc, required); err != nil {
		t.Fatalf("unexpected error with extra fields: %v", err)
	}
}
