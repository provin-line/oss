package urdna2015

import (
	"bytes"
	"strings"
	"testing"
)

// An empty object or array Canonicalize accepts is one JSON-LD signs as a
// term: a document holding it and one without it have different canonical
// forms, but for the empty array a property holds, which is signed as no
// quad.
func TestCanonicalize_SignsTheEmptyShapesItAccepts(t *testing.T) {
	c := testContexts(t)
	without, err := c.Canonicalize(subjectWith(map[string]any{"urn:p": "v"}))
	if err != nil {
		t.Fatal(err)
	}
	for name, members := range map[string]map[string]any{
		"an empty object as a property's value":         {"urn:q": map[string]any{}},
		"an empty object in a property's array":         {"urn:q": []any{map[string]any{}, "w"}},
		"an empty object in a list":                     {"urn:q": map[string]any{"@list": []any{map[string]any{}}}},
		"an empty list as a property's value":           {"urn:q": map[string]any{"@list": []any{}}},
		"an empty object as a reverse property's value": {"@reverse": map[string]any{"urn:r": map[string]any{}}},
		"an empty list held through @nest":              {"urn:q": map[string]any{"@nest": map[string]any{"@list": []any{}}}},
		"an empty object in a @nest group":              {"@nest": map[string]any{"urn:q": map[string]any{}}},
	} {
		members["urn:p"] = "v"
		with, err := c.Canonicalize(subjectWith(members))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if bytes.Equal(with, without) {
			t.Errorf("%s: signed as if it were not there", name)
		}
	}
	with, err := c.Canonicalize(subjectWith(map[string]any{"urn:p": "v", "urn:q": []any{}}))
	if err != nil || !bytes.Equal(with, without) {
		t.Errorf("an empty array as a property's value: %v, the same form: %v", err, bytes.Equal(with, without))
	}
}

// A @nest group's members are signed as the members of the object holding it,
// so they are held to the shapes of that object's position.
func TestCanonicalize_ReadsANestGroupAsItsObject(t *testing.T) {
	c := testContexts(t)
	nested, err := c.Canonicalize(subjectWith(map[string]any{"urn:p": "v", "@nest": map[string]any{"urn:q": []any{}}}))
	if err != nil {
		t.Fatalf("an empty array as a property's value in a @nest group: %v", err)
	}
	plain, err := c.Canonicalize(subjectWith(map[string]any{"urn:p": "v", "urn:q": []any{}}))
	if err != nil || !bytes.Equal(nested, plain) {
		t.Errorf("signed otherwise than without the group: %v", err)
	}
	listed := subjectWith(nil)
	listed["@nest"] = map[string]any{"@list": []any{}}
	if _, err := c.Canonicalize(listed); err == nil || !strings.Contains(err.Error(), "a list at") {
		t.Errorf("a list through @nest of the document: %v, want a list where JSON-LD keeps none", err)
	}
}

// A member whose name begins with @ but is no keyword is a property: under a
// @vocab, JSON-LD expands it and signs its value.
func TestCanonicalize_ReadsANameOfAtThatIsNoKeywordAsAProperty(t *testing.T) {
	doc := ownContext(map[string]any{"@vocab": "urn:v:"}, map[string]any{"@1": "w"})
	if _, err := testContexts(t).Canonicalize(doc); err != nil {
		t.Errorf("\"@1\" under a @vocab: %v", err)
	}
}
