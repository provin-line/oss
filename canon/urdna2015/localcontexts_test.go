package urdna2015_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/urdna2015"
)

// localContext is a context written in a document: JSON-LD's local context.
var localContext = map[string]any{"q": "https://e.x/q"}

// By default, Canonicalize refuses a document holding, at any depth, a
// @context other than the IRI of a context it serves or a list of them,
// before JSON-LD processing reads it, and before the input's grammar, so a
// context with a number or null is refused as what it is. The refusal names
// where the @context is, an item of a list by its index.
func TestCanonicalize_RefusesALocalContextByDefault(t *testing.T) {
	c := w3cCanonicalizer(t)
	for name, tc := range map[string]struct {
		doc  any
		want string
	}{
		"at the top":           {map[string]any{"@context": localContext, "@id": "https://e.x/s", "q": "v"}, `at "/@context" is a context written in the document`},
		"an empty one":         {map[string]any{"@context": map[string]any{}, "@id": "https://e.x/s", "https://e.x/p": "v"}, "a context written in the document"},
		"beside a served IRI":  {map[string]any{"@context": []any{ctxCredentialsV2, localContext}, "id": "https://e.x/s", "q": "v"}, `at "/@context/1" is a context written in the document`},
		"in a node":            {map[string]any{"@context": ctxCredentialsV2, "id": "https://e.x/s", "credentialSubject": map[string]any{"@context": localContext, "id": "https://e.x/o", "q": "v"}}, `at "/credentialSubject/@context" is a context written`},
		"in @graph":            {map[string]any{"@context": ctxCredentialsV2, "@graph": []any{map[string]any{"@context": localContext, "id": "https://e.x/s", "q": "v"}}}, `at "/@graph/0/@context" is a context written`},
		"in the document list": {[]any{map[string]any{"@context": localContext, "@id": "https://e.x/s", "q": "v"}}, `at "/0/@context" is a context written`},
		"holding a number":     {map[string]any{"@context": []any{ctxCredentialsV2, map[string]any{"@version": 1.1, "q": "https://e.x/q"}}, "id": "https://e.x/s", "q": "v"}, "a context written in the document"},
		"a list in a list":     {map[string]any{"@context": []any{[]any{ctxCredentialsV2}}, "id": "https://e.x/s"}, `at "/@context/0" holds a list, not the IRI of a context`},
		"a boolean":            {map[string]any{"@context": true, "@id": "https://e.x/s", "https://e.x/p": "v"}, "holds a boolean, not the IRI of a context"},
		"null":                 {map[string]any{"@context": nil, "@id": "https://e.x/s", "https://e.x/p": "v"}, "holds null, not the IRI of a context"},
		"an IRI not served":    {map[string]any{"@context": []any{ctxCredentialsV2, "https://e.x/unserved"}, "id": "https://e.x/s"}, `at "/@context/1" names "https://e.x/unserved", a context this Canonicalizer does not serve`},
	} {
		if _, err := c.Canonicalize(tc.doc); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
}

// By default, Canonicalize reads the IRI of a context it serves wherever it
// is, and signs such a document as it does with WithLocalContexts.
func TestCanonicalize_ReadsAServedContextAtAnyDepthByDefault(t *testing.T) {
	c := w3cCanonicalizer(t)
	opened := urdna2015.NewCanonicalizer(map[string][]byte{
		ctxCredentialsV2: read(t, "credentials-v2.jsonld"),
		ctxExamplesV2:    read(t, "examples-v2.jsonld"),
	}, urdna2015.WithLocalContexts())
	inSubject := readJSON(t, "w3c-ex8-credential.json")
	inSubject["credentialSubject"].(map[string]any)["@context"] = ctxCredentialsV2
	listInSubject := readJSON(t, "w3c-ex8-credential.json")
	listInSubject["credentialSubject"].(map[string]any)["@context"] = []any{ctxCredentialsV2, ctxExamplesV2}
	inGraph := readJSON(t, "w3c-ex8-credential.json")
	for name, doc := range map[string]any{
		"an IRI in a node":     inSubject,
		"a list in a node":     listInSubject,
		"a list in @graph":     map[string]any{"@context": ctxCredentialsV2, "@graph": []any{inGraph}},
		"in the document list": []any{readJSON(t, "w3c-ex8-credential.json")},
	} {
		got, err := c.Canonicalize(doc)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want, err := opened.Canonicalize(doc)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: with WithLocalContexts, %v, the same bytes: %v", name, err, bytes.Equal(got, want))
		}
	}
}

// WithLocalContexts opens what the default refuses: Canonicalize reads a
// context written in the document, held to the forms the package doc lists.
func TestCanonicalize_ReadsALocalContextWithLocalContexts(t *testing.T) {
	c := urdna2015.NewCanonicalizer(map[string][]byte{ctxCredentialsV2: read(t, "credentials-v2.jsonld")}, urdna2015.WithLocalContexts())
	for name, doc := range map[string]any{
		"at the top":          map[string]any{"@context": localContext, "@id": "https://e.x/s", "q": "v"},
		"beside a served IRI": map[string]any{"@context": []any{ctxCredentialsV2, localContext}, "id": "https://e.x/s", "q": "v"},
	} {
		if _, err := c.Canonicalize(doc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	held := map[string]any{"@context": map[string]any{"q": "https://e.x/q", "ix": "@index"}, "@id": "https://e.x/s", "q": map[string]any{"@id": "https://e.x/o", "ix": "i"}}
	if _, err := c.Canonicalize(held); err == nil || !strings.Contains(err.Error(), "@index at") {
		t.Errorf("a local context's alias of @index: %v, want it refused by the forms", err)
	}
}

// The zero Option changes nothing: a Canonicalizer given it refuses a local
// context as the default does.
func TestNewCanonicalizer_TheZeroOptionChangesNothing(t *testing.T) {
	c := urdna2015.NewCanonicalizer(map[string][]byte{ctxCredentialsV2: read(t, "credentials-v2.jsonld")}, urdna2015.Option{})
	doc := map[string]any{"@context": localContext, "@id": "https://e.x/s", "q": "v"}
	if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "a context written in the document") {
		t.Errorf("%v, want it refused as a context written in the document", err)
	}
}
