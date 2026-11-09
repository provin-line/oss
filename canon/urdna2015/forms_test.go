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

// The count of values only counts: the forms a count could not hold are
// refused before it, by the walk of the document's forms.
func TestDataValues_OnlyCounts(t *testing.T) {
	for _, c := range []struct {
		doc  map[string]any
		want int64
	}{
		{map[string]any{"@id": "urn:s", "urn:p": "v", "@index": "i"}, 3},
		{map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@value": "v", "@type": "urn:T", "urn:q": "w"}}, 3},
	} {
		doc, want := c.doc, c.want
		n, err := newContextRules().dataValues(doc, new(jsonPath))
		if err != nil || n != want {
			t.Errorf("%v: %d, %v; want %d values counted", doc, n, err, want)
		}
	}
}

// The expanded form holds, besides IRIs, only the keywords an expanded node,
// value or list object holds; any other keyword is refused, as toRDF writes no
// quad of it. json-gold writes none of these in the expanded form of a
// document the walk of forms accepts, so the check is given them directly.
func TestRejectDroppableNodes_AcceptsOnlyTheKeywordsOfAnExpandedForm(t *testing.T) {
	for _, kw := range []string{"@explicit", "@default", "@none", "@nest", "@context", "@json"} {
		expanded := []any{map[string]any{"@id": "urn:s", "urn:p": []any{map[string]any{"@value": "v"}}, kw: []any{map[string]any{"@value": "w"}}}}
		if err := rejectDroppableNodes(expanded); err == nil || !strings.Contains(err.Error(), "in the expanded form") {
			t.Errorf("%s: %v", kw, err)
		}
	}
	accepted := []any{map[string]any{
		"@id": "urn:s", "@type": []any{"urn:T"},
		"urn:p":     []any{map[string]any{"@value": "v", "@language": "en"}, map[string]any{"@list": []any{map[string]any{"@value": "w"}}}},
		"@reverse":  map[string]any{"urn:r": []any{map[string]any{"@id": "urn:o"}}},
		"@graph":    []any{map[string]any{"@id": "urn:g", "urn:q": []any{map[string]any{"@value": "x"}}}},
		"@included": []any{map[string]any{"@id": "urn:i", "urn:q": []any{map[string]any{"@value": "y"}}}},
	}}
	if err := rejectDroppableNodes(accepted); err != nil {
		t.Errorf("an expanded form of every keyword it holds: %v", err)
	}
}

// includedBeside is a credential of the W3C VC v2 context alone, with item in
// the @included of its top object, where json-gold drops a value object.
func includedBeside(item any) map[string]any {
	doc := subjectWith(map[string]any{"urn:p": "v"})
	doc["@included"] = []any{item}
	return doc
}

// A value object where JSON-LD keeps none, an item of the document's array,
// of @graph or of @included, is refused: json-gold drops it.
func TestCanonicalize_RefusesAValueObjectWhereJSONLDKeepsNone(t *testing.T) {
	c := testContexts(t)
	value := map[string]any{"@value": "y"}
	credential := subjectWith(map[string]any{"urn:p": "v"})
	for name, doc := range map[string]any{
		"beside the document": []any{credential, value},
		"in @graph": subjectWith(map[string]any{"urn:p": "v", "urn:g": map[string]any{
			"@id": "urn:g", "urn:q": "w", "@graph": []any{map[string]any{"@id": "urn:n", "urn:r": "x"}, value},
		}}),
		"in @included": includedBeside(value),
	} {
		if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "a value object at ") || !strings.Contains(err.Error(), "where JSON-LD keeps none") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A JSON literal is refused, its datatype "@json" alone or in an array,
// wherever it is: as a property's value, or where json-gold drops it and one
// holding no string or boolean would be signed as if it were not there.
func TestCanonicalize_RefusesAJSONLiteral(t *testing.T) {
	c := testContexts(t)
	literal := func(v any) map[string]any { return map[string]any{"@type": []any{"@json"}, "@value": v} }
	credential := subjectWith(map[string]any{"urn:p": "v"})
	for name, doc := range map[string]any{
		"beside the document, holding @index": []any{credential, literal(map[string]any{"@index": []any{}})},
		"beside the document, empty":          []any{credential, literal(map[string]any{})},
		"beside the document, no value":       []any{credential, literal(map[string]any{"a": []any{}})},
		"beside the document, typed alone":    []any{credential, map[string]any{"@type": "@json", "@value": map[string]any{}}},
		"in @graph": subjectWith(map[string]any{"urn:p": "v", "urn:g": map[string]any{
			"@id": "urn:g", "urn:q": "w", "@graph": []any{map[string]any{"@id": "urn:n", "urn:r": "x"}, literal(map[string]any{})},
		}}),
		"a property's value, empty":        subjectWith(map[string]any{"urn:p": "v", "urn:q": literal(map[string]any{})}),
		"a property's value, holding @set": subjectWith(map[string]any{"urn:p": "v", "urn:q": literal(map[string]any{"@set": []any{}})}),
		"in @included, holding @index":     includedBeside(literal(map[string]any{"@index": []any{}})),
	} {
		if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "@json at ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A context term aliasing @json is refused, in whatever scope, used or not:
// the RDFC path accepts no JSON literal, so such an alias has no use it signs.
// A term aliasing @json only in a scope not in use, and an IRI in the scope in
// use, is refused too, though json-gold signs it as a datatype there.
func TestCanonicalize_RefusesAnAliasOfJSON(t *testing.T) {
	c := testContexts(t)
	doc := func(ctx map[string]any, members map[string]any) map[string]any {
		d := map[string]any{"@context": ctx, "@id": "urn:s", "urn:p": "v"}
		for k, v := range members {
			d[k] = v
		}
		return d
	}
	typed := map[string]any{"urn:q": map[string]any{"@value": "x", "@type": "J"}}
	for name, d := range map[string]any{
		"typing a JSON literal in @graph": doc(map[string]any{"J": "@json"}, map[string]any{"urn:g": map[string]any{
			"@id": "urn:g", "urn:q": "w", "@graph": []any{map[string]any{"@id": "urn:n", "urn:r": "x"}, map[string]any{"@type": "J", "@value": map[string]any{"@direction": []any{}}}},
		}}),
		"typing a JSON literal in an array":    doc(map[string]any{"J": "@json"}, map[string]any{"urn:q": map[string]any{"@type": []any{"J"}, "@value": map[string]any{}}}),
		"through @id":                          doc(map[string]any{"J": map[string]any{"@id": "@json"}}, nil),
		"in a scope not in use, an IRI in use": doc(map[string]any{"J": "urn:J", "Unused": map[string]any{"@id": "urn:Unused", "@context": map[string]any{"J": "@json"}}}, typed),
		"a term of an IRI's form, in a scope not in use": doc(map[string]any{"Unused": map[string]any{"@id": "urn:Unused", "@context": map[string]any{"urn:J": "@json"}}},
			map[string]any{"urn:q": map[string]any{"@value": "x", "@type": "urn:J"}}),
		"in the scope of a type not used": doc(map[string]any{"J": "urn:J", "T": map[string]any{"@id": "urn:T", "@context": map[string]any{"J": "@json"}}}, typed),
	} {
		if _, err := c.Canonicalize(d); err == nil || !strings.Contains(err.Error(), "an alias of @json") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A context term aliasing @context is refused, in whatever scope, used or
// not: JSON-LD 1.1 makes it an invalid keyword alias, and json-gold, which
// refuses one in a context it processes, reads the term as a property in a
// scope it never processes.
func TestCanonicalize_RefusesAnAliasOfContext(t *testing.T) {
	c := testContexts(t)
	unused := func(members map[string]any) map[string]any {
		doc := map[string]any{"@context": map[string]any{"Unused": map[string]any{"@id": "urn:Unused", "@context": map[string]any{"urn:c": "@context"}}}, "@id": "urn:s", "urn:p": "v"}
		for k, v := range members {
			doc[k] = v
		}
		return doc
	}
	for name, doc := range map[string]any{
		"holding a language tag not of ASCII": unused(map[string]any{"urn:c": map[string]any{"@value": "x", "@language": "\u0130t"}}),
		"holding a value object":              unused(map[string]any{"urn:c": map[string]any{"@value": "x", "@language": "it"}}),
		"holding @set":                        unused(map[string]any{"urn:c": map[string]any{"@set": []any{"a"}}}),
		"holding an array in an array":        unused(map[string]any{"urn:c": []any{[]any{"a"}}}),
		"holding an empty list":               unused(map[string]any{"urn:c": map[string]any{"@list": []any{}}}),
		"in the context in use":               map[string]any{"@context": map[string]any{"c": "@context"}, "@id": "urn:s", "urn:p": "v"},
	} {
		if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "an alias of @context") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
