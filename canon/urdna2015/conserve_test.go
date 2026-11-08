package urdna2015

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
)

// ownContext is a document of its own context, the terms q and those given,
// whose node https://e.x/s holds the given members.
func ownContext(terms map[string]any, members map[string]any) map[string]any {
	ctx := map[string]any{"q": "https://e.x/q"}
	for k, v := range terms {
		ctx[k] = v
	}
	doc := map[string]any{"@context": ctx, "@id": "https://e.x/s"}
	for k, v := range members {
		doc[k] = v
	}
	return doc
}

// graphTerm is the definition of a term whose container is a graph, with the
// further entries given.
func graphTerm(container any, entries map[string]any) map[string]any {
	d := map[string]any{"@id": "https://e.x/g", "@container": container}
	for k, v := range entries {
		d[k] = v
	}
	return d
}

// credentialV2 is a credential of the W3C VC v2 contexts alone.
func credentialV2(subject map[string]any) map[string]any {
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
}

var aNode = map[string]any{"@id": "https://e.x/n", "q": "v"}

// differentValues are pairs of documents that differ in one value, m: "a" in
// one and "b" in the other. Each is a form in which JSON-LD processing could
// leave that value out of the dataset.
var differentValues = map[string]func(m string) any{
	"a string in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": m})
	},
	"strings in a graph and set container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm([]any{"@graph", "@set"}, nil)}, map[string]any{"g": []any{m, "x"}})
	},
	"a string in a graph and id container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm([]any{"@graph", "@id"}, nil)}, map[string]any{"g": map[string]any{"https://e.x/gid": m}})
	},
	"a node of only @id in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@id": "https://e.x/" + m}})
	},
	"an IRI in a graph container of @type @id": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", map[string]any{"@type": "@id"})}, map[string]any{"g": "https://e.x/" + m})
	},
	"a list in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@list": []any{m}}})
	},
	"a value with a language in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"@value": m, "@language": "en"}})
	},
	"a value object in a top-level @graph": func(m string) any {
		return map[string]any{"@context": map[string]any{"q": "https://e.x/q"}, "@graph": []any{map[string]any{"@value": m}, aNode}}
	},
	"a node of only @id in a top-level @graph": func(m string) any {
		return map[string]any{"@context": map[string]any{"q": "https://e.x/q"}, "@graph": []any{map[string]any{"@id": "https://e.x/" + m}, aNode}}
	},
	"a value object in a top-level array": func(m string) any {
		ctx := map[string]any{"q": "https://e.x/q"}
		return []any{map[string]any{"@context": ctx, "@value": m}, map[string]any{"@context": ctx, "@id": "https://e.x/n", "q": "v"}}
	},
	"a string under an alias of @graph": func(m string) any {
		return ownContext(map[string]any{"gg": "@graph"}, map[string]any{"gg": []any{m, aNode}})
	},
	"a string under @graph": func(m string) any {
		return ownContext(nil, map[string]any{"@graph": []any{m, aNode}})
	},
	"a credential's proof as an IRI": func(m string) any {
		d := credentialV2(map[string]any{"id": "did:example:s", "name": "x"})
		d["proof"] = "https://e.x/" + m
		return d
	},
	"a credential's proof as a node of only id": func(m string) any {
		d := credentialV2(map[string]any{"id": "did:example:s", "name": "x"})
		d["proof"] = map[string]any{"id": "https://e.x/" + m}
		return d
	},
	"a proof as an IRI in a subject typed VerifiableCredential": func(m string) any {
		return credentialV2(map[string]any{"id": "did:example:s", "name": "x", "type": "VerifiableCredential", "proof": "https://e.x/" + m})
	},
	"a graph and type container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm([]any{"@graph", "@type"}, nil)}, map[string]any{"g": map[string]any{"https://e.x/T": m}})
	},
	"a string in a graph container of an included node": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/i", "g": m}}})
	},
	"a reverse term of a graph container": func(m string) any {
		return ownContext(map[string]any{"rg": map[string]any{"@reverse": "https://e.x/g", "@container": "@graph"}}, map[string]any{"rg": map[string]any{"@id": "https://e.x/" + m}})
	},
	"a string in a graph container under @nest": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil), "n": "@nest"}, map[string]any{"q": "x", "n": map[string]any{"g": m}})
	},
	"a JSON literal in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", map[string]any{"@type": "@json"})}, map[string]any{"g": map[string]any{"k": m}})
	},
	"a node of only @id in @included": func(m string) any {
		return ownContext(nil, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/" + m}}})
	},
	"a key of an id map whose item has its own @id": func(m string) any {
		return ownContext(map[string]any{"im": map[string]any{"@id": "https://e.x/im", "@container": "@id"}}, map[string]any{"im": map[string]any{"https://e.x/k" + m: map[string]any{"@id": "https://e.x/x", "q": "v"}}})
	},
	"the @index of a set object": func(m string) any {
		return ownContext(nil, map[string]any{"q": map[string]any{"@set": []any{"v"}, "@index": m}})
	},
	"an object of only @language": func(m string) any {
		return ownContext(nil, map[string]any{"q": []any{"x", map[string]any{"@language": map[string]string{"a": "en", "b": "fr"}[m]}}})
	},
	"a value repeated": func(m string) any {
		values := []any{"x", "d"}
		if m == "b" {
			values = append(values, "d")
		}
		return ownContext(nil, map[string]any{"q": values})
	},
	"a second datatype of a value object": func(m string) any {
		return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": "v", "@type": []any{"https://e.x/T", "https://e.x/" + m}}}
	},
	"a string hidden by an alias from a scope not in use": func(m string) any {
		return map[string]any{
			"@context": []any{
				map[string]any{"v": "https://e.x/v", "t": "@graph"},
				map[string]any{"Unused": map[string]any{"@id": "https://e.x/Unused", "@context": map[string]any{"v": "@value", "t": "@type"}}},
			},
			"@id": "https://e.x/s", "v": "kept", "t": m,
		}
	},
	"a value of type rdf:JSON": func(m string) any {
		value := map[string]string{"a": `{"a":true}`, "b": `{ "a":true}`}[m]
		return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": value, "@type": "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON"}}
	},
	"a boolean or a string of one datatype": func(m string) any {
		value := map[string]any{"a": true, "b": "true"}[m]
		return map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@value": value, "@type": "http://www.w3.org/2001/XMLSchema#string"}}
	},
	"a node of only an IRI the document names, in @included": func(m string) any {
		iri := map[string]string{"a": "https://e.x/s", "b": "https://e.x/o"}[m]
		return ownContext(nil, map[string]any{"q": map[string]any{"@id": "https://e.x/o"}, "@included": []any{map[string]any{"@id": iri}}})
	},
	"a proof naming an IRI the credential names": func(m string) any {
		iri := map[string]string{"a": "did:example:s", "b": "did:example:issuer"}[m]
		return credentialV2(map[string]any{"id": "did:example:s", "name": "x", "type": "VerifiableCredential", "proof": iri})
	},
	"a node of only @id named as a type": func(m string) any {
		types := map[string][]any{"a": {"https://e.x/T", "https://e.x/U"}, "b": {"https://e.x/U", "https://e.x/T"}}[m]
		node := map[string]string{"a": "https://e.x/T", "b": "https://e.x/U"}[m]
		return []any{map[string]any{"@id": "https://e.x/s", "@type": types}, map[string]any{"@id": node, "https://e.x/p": []any{}}}
	},
	"the node of a graph that holds only another graph": func(m string) any {
		return map[string]any{"@id": "urn:" + m, "@graph": []any{map[string]any{"@id": "urn:b", "@graph": []any{map[string]any{"@id": "urn:c", "urn:p": "v"}}}}}
	},
	"a value dropped beside a map key of a wrapped context": func(m string) any {
		return map[string]any{
			"@context": map[string]any{"@context": map[string]any{"m": map[string]any{"@id": "urn:m", "@container": "@id"}, "q": "urn:q"}},
			"@id":      "urn:s", "@graph": m, "m": map[string]any{"urn:o": map[string]any{"q": "kept"}},
		}
	},
	"a blank node's label": func(m string) any {
		return credentialV2(map[string]any{"id": "_:" + m, "name": "x"})
	},
	"a blank node's label in a reference": func(m string) any {
		return ownContext(nil, map[string]any{"q": []any{map[string]any{"@id": "_:" + m, "q": "v"}, map[string]any{"@id": "_:" + m}}})
	},
	"a node of only @id beside a node in a graph container": func(m string) any {
		return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": []any{aNode, map[string]any{"@id": "https://e.x/" + m}}})
	},
	"a relative @id with dot segments, against @base": func(m string) any {
		return map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "pay-" + m + "/../s", "https://e.x/p": "v"}
	},
	"a relative value of a term typed @id, against @base": func(m string) any {
		return ownContext(map[string]any{"@base": "https://e.x/", "r": map[string]any{"@id": "https://e.x/r", "@type": "@id"}}, map[string]any{"r": "x" + m + "/../y"})
	},
	"a relative type, against @base": func(m string) any {
		return map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "https://e.x/s", "@type": m + "/../T"}
	},
	"a relative @id against a type-scoped @base": func(m string) any {
		return ownContext(map[string]any{"T": map[string]any{"@id": "https://e.x/T", "@context": map[string]any{"@base": "https://e.x/"}}}, map[string]any{"@type": "T", "q": map[string]any{"@id": "pay-" + m + "/../n", "q": "v"}})
	},
	"an absolute @id with dot segments": func(m string) any {
		return map[string]any{"@id": "https://e.x/" + m + "/../s", "https://e.x/p": "v"}
	},
	"a value object's key, a term of a term of @none": func(m string) any {
		return map[string]any{"@context": noneThroughATerm, "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": m}}
	},
	"a value object's key, a term of a term of @none, a boolean": func(m string) any {
		return map[string]any{"@context": noneThroughATerm, "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": m == "a"}}
	},
	"a language tag Unicode lowercases to ASCII": func(m string) any {
		return map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@value": "v", "@language": map[string]string{"a": "\u0130t", "b": "it"}[m]}}
	},
	"a default language Unicode lowercases to ASCII": func(m string) any {
		return map[string]any{"@context": map[string]any{"@language": map[string]string{"a": "\u212Ar", "b": "kr"}[m], "q": "urn:q"}, "@id": "urn:s", "q": "v"}
	},
	"a term's language Unicode lowercases to ASCII": func(m string) any {
		return map[string]any{"@context": map[string]any{"q": map[string]any{"@id": "urn:q", "@language": map[string]string{"a": "\u0130t", "b": "it"}[m]}}, "@id": "urn:s", "q": "v"}
	},
}

// noneThroughATerm makes k a term of n, which is @none, while a scope not in
// use makes k @type.
var noneThroughATerm = map[string]any{
	"n":      "@none",
	"k":      "n",
	"Unused": map[string]any{"@id": "urn:Unused", "@context": map[string]any{"k": "@type"}},
}

// Two documents that differ in a value have different canonical forms, or
// are refused: no value of a document Canonicalize accepts is outside what it
// signs.
func TestCanonicalize_SignsEveryValueOrRefuses(t *testing.T) {
	c := testContexts(t)
	for name, doc := range differentValues {
		a, errA := c.Canonicalize(doc("a"))
		b, errB := c.Canonicalize(doc("b"))
		if errA == nil && errB == nil && bytes.Equal(a, b) {
			t.Errorf("%s: two documents differing in a value have one canonical form", name)
		}
	}
}

// Documents near those forms that hold every value are accepted, and their
// differing values make different canonical forms.
func TestCanonicalize_AcceptsTheFormsThatHoldEveryValue(t *testing.T) {
	c := testContexts(t)
	for name, doc := range map[string]func(m string) any{
		"a node with a property in a graph container": func(m string) any {
			return ownContext(map[string]any{"g": graphTerm("@graph", nil)}, map[string]any{"g": map[string]any{"https://e.x/q": m}})
		},
		"a presentation's credential as an IRI": func(m string) any {
			return map[string]any{"@context": []any{"https://www.w3.org/ns/credentials/v2"}, "type": []any{"VerifiablePresentation"}, "verifiableCredential": "urn:uuid:" + m}
		},
		"a value with a language, a value of a type": func(m string) any {
			return ownContext(nil, map[string]any{"q": []any{map[string]any{"@value": m, "@language": "en"}, map[string]any{"@value": "x", "@type": "https://e.x/T"}}})
		},
		"@nest": func(m string) any {
			return ownContext(map[string]any{"n": "@nest"}, map[string]any{"n": map[string]any{"q": m}})
		},
		"@included": func(m string) any {
			return ownContext(nil, map[string]any{"q": "x", "@included": []any{map[string]any{"@id": "https://e.x/i", "q": m}}})
		},
		"a boolean under a term typed xsd:boolean": func(m string) any {
			return ownContext(map[string]any{"f": map[string]any{"@id": "https://e.x/f", "@type": "http://www.w3.org/2001/XMLSchema#boolean"}}, map[string]any{"f": m == "a"})
		},
	} {
		a, errA := c.Canonicalize(doc("a"))
		b, errB := c.Canonicalize(doc("b"))
		if errA != nil || errB != nil || bytes.Equal(a, b) {
			t.Errorf("%s: %v, %v, the same form: %v", name, errA, errB, bytes.Equal(a, b))
		}
	}
}

// Each way a value could leave the dataset is refused with its reason.
func TestCanonicalize_RefusesWhatItWouldNotSign(t *testing.T) {
	c := testContexts(t)
	for name, tc := range map[string]struct {
		doc  any
		want string
	}{
		"@index in the document":         {differentValues["the @index of a set object"]("a"), "@index at"},
		"@direction in the document":     {ownContext(nil, map[string]any{"q": map[string]any{"@value": "x", "@direction": "rtl"}}), "@direction at"},
		"@language outside a value":      {differentValues["an object of only @language"]("a"), "outside a value object"},
		"a map container":                {differentValues["a key of an id map whose item has its own @id"]("a"), "container"},
		"a value expansion drops":        {differentValues["a value object in a top-level @graph"]("a"), "its expanded form"},
		"a value in no node's property":  {differentValues["a string in a graph container"]("a"), "outside any node's property"},
		"a node in no quad":              {differentValues["a proof as an IRI in a subject typed VerifiableCredential"]("a"), "in no quad"},
		"a value twice":                  {differentValues["a value repeated"]("b"), "one value twice"},
		"a node written out twice":       {map[string]any{"@id": "https://e.x/s", "https://e.x/p": map[string]any{"@id": "https://e.x/n", "https://e.x/q": "v"}, "https://e.x/r": map[string]any{"@id": "https://e.x/n", "https://e.x/q": "v"}}, "refer to it elsewhere by its @id"},
		"an alias of @value":             {ownContext(map[string]any{"val": "@value"}, map[string]any{"q": map[string]any{"val": "x"}}), "alias of @value"},
		"a term aliasing two keywords":   {ownContext(map[string]any{"A": map[string]any{"@id": "https://e.x/A", "@context": map[string]any{"k": "@id"}}, "B": map[string]any{"@id": "https://e.x/B", "@context": map[string]any{"k": "@type"}}}, map[string]any{"q": "x"}), "aliases"},
		"two datatypes":                  {differentValues["a second datatype of a value object"]("a"), "one datatype"},
		"a datatype of rdf:JSON":         {differentValues["a value of type rdf:JSON"]("a"), "JSON"},
		"a boolean with a datatype":      {differentValues["a boolean or a string of one datatype"]("a"), "boolean"},
		"a blank node label":             {differentValues["a blank node's label"]("a"), "blank node label"},
		"a wrapped context's container":  {map[string]any{"@context": map[string]any{"@context": map[string]any{"m": map[string]any{"@id": "urn:m", "@container": "@index"}}}, "@id": "urn:s", "urn:q": "x"}, "container"},
		"a JSON literal written":         {ownContext(nil, map[string]any{"q": map[string]any{"@value": map[string]any{"k": "v"}, "@type": "@json"}}), "@json at"},
		"a language tag not ASCII":       {map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@value": "v", "@language": "\u0130t"}}, "@language"},
		"a default language not ASCII":   {map[string]any{"@context": map[string]any{"@language": "\u212Ar", "q": "urn:q"}, "@id": "urn:s", "q": "v"}, "@language"},
		"a term's language not ASCII":    {map[string]any{"@context": map[string]any{"q": map[string]any{"@id": "urn:q", "@language": "\u0130t"}}, "@id": "urn:s", "q": "v"}, "@language"},
		"a @base":                        {map[string]any{"@context": map[string]any{"@base": "https://e.x/"}, "@id": "https://e.x/s", "https://e.x/p": "v"}, "@base"},
		"one RDF value in two spellings": {ownContext(nil, map[string]any{"q": []any{"x", map[string]any{"@value": "x", "@type": "http://www.w3.org/2001/XMLSchema#string"}}}), "one value twice"},
		"a boolean in two spellings":     {ownContext(nil, map[string]any{"q": []any{true, map[string]any{"@value": "true", "@type": "http://www.w3.org/2001/XMLSchema#boolean"}}}), "one value twice"},
		"an alias in a value object":     {ownContext(map[string]any{"t": "@type"}, map[string]any{"q": map[string]any{"@value": "x", "t": "https://e.x/T"}}), "keywords written out"},
		"a term of @none in a value":     {differentValues["a value object's key, a term of a term of @none"]("a"), "keywords written out"},
		"a @vocab of @value":             {map[string]any{"@context": map[string]any{"@vocab": "@value", "v": map[string]any{"@id": ""}}, "@id": "urn:s", "urn:p": map[string]any{"v": "kept"}}, "@vocab"},
		"a @vocab of @":                  {map[string]any{"@context": map[string]any{"@vocab": "@"}, "@id": "urn:s", "urn:p": map[string]any{"value": "kept"}}, "@vocab"},
		"a JSON literal by a term":       {credentialV2(map[string]any{"id": "did:example:s", "name": "x", "credentialSchema": map[string]any{"id": "https://e.x/schema", "type": "JsonSchema", "jsonSchema": map[string]any{"k": "v"}}}), "@json"},
	} {
		if _, err := c.Canonicalize(tc.doc); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
}

// The dataset must hold a quad for every value the walk counts: one missing
// is refused.
func TestNodeMapWork_RefusesADatasetMissingAQuad(t *testing.T) {
	c := testContexts(t)
	full := ownContext(nil, map[string]any{"q": []any{"x", "y"}})
	w := newNodeMapWork()
	expanded, err := ld.NewJsonLdProcessor().Expand(full, c.options())
	if err != nil {
		t.Fatal(err)
	}
	w.walk(expanded)
	if err := w.holds(documentDataset(t, c, full)); err != nil {
		t.Errorf("the dataset of the same document: %v", err)
	}
	if err := w.holds(documentDataset(t, c, ownContext(nil, map[string]any{"q": "x"}))); err == nil {
		t.Error("a dataset missing a quad: accepted")
	}
}

// A context the Canonicalizer serves is held to the rules a document's own
// context is: one defining a map container refuses every document; its
// keyword aliases, scoped ones included, are read (a scoped alias of @index:
// unread, the counts would refuse it, but not by name); and a value object's
// key it makes a term of a term of @none is refused.
func TestCanonicalize_HoldsServedContextsToTheSameRules(t *testing.T) {
	scoped := []byte(`{"@context": {"q": "https://e.x/q", "T": {"@id": "https://e.x/T", "@context": {"idx": "@index"}}}}`)
	doc := map[string]any{"@context": "https://e.x/ctx", "@id": "https://e.x/s", "q": map[string]any{"@type": "T", "q": map[string]any{"@id": "https://e.x/o", "idx": "i", "q": "v"}}}
	withMap := NewCanonicalizer(map[string][]byte{
		"https://e.x/ctx": scoped,
		"https://e.x/map": []byte(`{"@context": {"m": {"@id": "https://e.x/m", "@container": "@language"}}}`),
	})
	if _, err := withMap.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "container") {
		t.Errorf("a served context defines a map container: %v, want an error naming the container", err)
	}
	if _, err := NewCanonicalizer(map[string][]byte{"https://e.x/ctx": scoped}).Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "@index at") {
		t.Errorf("a served context's scoped alias of @index: %v, want an error naming @index", err)
	}
	none := NewCanonicalizer(map[string][]byte{"https://e.x/none": []byte(`{"@context": {"n": "@none", "k": "n", "Unused": {"@id": "urn:Unused", "@context": {"k": "@type"}}}}`)})
	a, errA := none.Canonicalize(map[string]any{"@context": "https://e.x/none", "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": "a"}})
	b, errB := none.Canonicalize(map[string]any{"@context": "https://e.x/none", "@id": "urn:s", "urn:p": map[string]any{"@value": "kept", "k": "b"}})
	if errA == nil && errB == nil && bytes.Equal(a, b) {
		t.Error("a served term of a term of @none in a value object: two documents differing in a value have one canonical form")
	}
}

// Every document the package's tests canonicalized before the values were
// counted, and that holds no value twice, keeps its canonical form.
func TestCanonicalize_KeepsTheFormsOfDocumentsItAccepted(t *testing.T) {
	c := testContexts(t)
	want := map[string]string{
		"20 distinct line items":                                "cb7a09bdf3cccc0c68778b84bf89f11c2bd59d6b88bb195224567c3a113643b6",
		"200 identical anonymous tags":                          "90c027346e435b25cd657d146420c839e844949e0de1f47622cd912b92eaf8c5",
		"50 identical line items, each with an anonymous price": "536a381fd05b141bb02f65fb4550259723969e61f4aced4faa4797a86b2146e5",
		"W3C vc-di-eddsa Example 8":                             "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017",
		"a chain of 12 identical anonymous objects":             "d74187674abf29a9dcbf2f46962f177ef5a0acb9be52f625c3d17dcb3346fc34",
		"a list of 16 identical strings":                        "db87fee6035080899b4b1dc2d5622c7341bde3db5c5462cc068e7d71360d5766",
		"a list of 40 identical strings":                        "15c22e1e90212cde702ec5f01799182ab0290522c1b1eb09b6a7b7d534051dbc",
		"a presentation of a credential with a proof":           "dbf9d8cc7f61ce6462a5194c8e9f241401a2aeb1d1ee17e7c240579100d4610f",
		"graph @included":                                       "624b1d0aa511cc63693472653bafd71b8e6b472ce8b9737c4c99d5431ce51e04",
		"graph a @graph container":                              "adea30a899cf15ace6ddfe45f40f711f81efc160a930ef0e986393b4b90bffe9",
		"graph a top-level @graph with an @id":                  "8091aa66e2e8712db57900e0450a079c1389aad3c7fb464e8a3378c0115b2e65",
		"graph list items naming nodes by @reverse":             "63edfca6ad16ae64d1b211c3fabedb4b18996b0539468fc90a6589f96a2f699c",
		"shape IRIs":               "a80306cfea698f5c57d33f3cc10731f32de06be9e86f2c9c425acb0395b0ec03",
		"shape aliases":            "ee43d8dc765ce228ba58c0e9c80577a69e939ee393ef98fb165da8d7c137b0bd",
		"shape blank nodes":        "089a6db41455ddb65c6d3996c118a7d9346d0b45aa74f7cd0a6447143d3e03ea",
		"shape lists":              "a09ca3f519d29c8b61ea5af0c817ca467550056620bd24efeccc80dc1c6da944",
		"shape literals":           "ee43d8dc765ce228ba58c0e9c80577a69e939ee393ef98fb165da8d7c137b0bd",
		"shape reverse properties": "273d7f17beff014568bd7df9e9aea612e34c67b7ec7c7709d1aee36106d00667",
		"shape types":              "fdd13a00dfe0286b91985aa32219b9247338b5cbf8bb40a1256629adffe860fd",
		"two identical anonymous evidence entries with nested parts":               "306c78e6b35587457082f965a042311f38a7b55906f4f459f530b5d385fce637",
		"two identical anonymous evidence entries, each listing 6 identical parts": "a59472c3db8374718b5ff26ec1aab29de4a40ae41201a8c6f07f507f59d8a981",
	}
	docs := ordinaryDocuments(t)
	for name, shape := range shapes {
		docs["shape "+name] = shape(30)
	}
	for name, doc := range graphShapes(30) {
		docs["graph "+name] = doc
	}
	docs["a presentation of a credential with a proof"] = map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiablePresentation"},
		"verifiableCredential": []any{map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:issuer",
			"validFrom":         "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]any{"id": "did:example:s", "name": "x"},
			"proof":             map[string]any{"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022", "proofPurpose": "assertionMethod", "verificationMethod": "did:example:issuer#k", "proofValue": "z123"},
		}},
	}
	for name, sum := range want {
		doc, ok := docs[name]
		if !ok {
			t.Errorf("%s: no such document", name)
			continue
		}
		out, err := c.Canonicalize(doc)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if h := sha256.Sum256(out); hex.EncodeToString(h[:]) != sum {
			t.Errorf("%s: the canonical form changed", name)
		}
	}
}

// Reading the contexts gives one answer whatever the order Go visits them in:
// a term two scopes alias to different keywords is refused every time.
func TestCanonicalize_ReadsAliasesTheSameEveryTime(t *testing.T) {
	c := testContexts(t)
	doc := ownContext(map[string]any{
		"A": map[string]any{"@id": "https://e.x/A", "@context": map[string]any{"k": "@id"}},
		"B": map[string]any{"@id": "https://e.x/B", "@context": map[string]any{"k": "@language"}},
	}, map[string]any{"q": map[string]any{"@type": "A", "k": "https://e.x/o"}})
	for range 50 {
		if _, err := c.Canonicalize(doc); err == nil {
			t.Fatal("a term aliasing two keywords: accepted")
		}
	}
}

// Reading contexts nested d deep takes time in d, not d squared: each
// context is read once. The two depths are timed in turn, the best of each
// kept, so a change in the machine's load falls on both; a ratio past the
// bound three times over fails (reading each context again takes about 64).
func TestContextRules_ReadEachContextOnce(t *testing.T) {
	nested := func(depth int) map[string]any {
		var ctx any = map[string]any{"leaf": "https://e.x/leaf"}
		for i := range depth {
			ctx = map[string]any{fmt.Sprintf("t%d", i): map[string]any{"@id": "https://e.x/t", "@context": ctx}}
		}
		return map[string]any{"@context": ctx, "@id": "https://e.x/s"}
	}
	shortDoc, longDoc := nested(500), nested(4000)
	timeOf := func(doc map[string]any) time.Duration {
		start := time.Now()
		if err := newContextRules().readDocument(doc); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	var ratio float64
	var short, long time.Duration
	for range 3 {
		short, long = time.Hour, time.Hour
		for range 5 {
			short = min(short, timeOf(shortDoc))
			long = min(long, timeOf(longDoc))
		}
		if ratio = float64(long) / float64(max(short, time.Microsecond)); ratio <= 24 {
			return
		}
	}
	t.Errorf("contexts 8 times as deep took %.0f times as long (%v, %v); reading each once takes about 8", ratio, short, long)
}

// acceptedCorpus is documents Canonicalize accepts: the package's ordinary
// credentials, the node map's shapes, documents of several graphs, and a
// presentation of a credential with a proof.
func acceptedCorpus(t *testing.T) map[string]any {
	docs := map[string]any{}
	for name, doc := range ordinaryDocuments(t) {
		docs[name] = doc
	}
	for name, shape := range shapes {
		docs["shape "+name] = shape(5)
	}
	for name, doc := range graphShapes(5) {
		docs["graph "+name] = doc
	}
	docs["a presentation of a credential with a proof"] = map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiablePresentation"},
		"verifiableCredential": []any{map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:issuer",
			"validFrom":         "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]any{"id": "did:example:s", "name": "x"},
			"proof":             map[string]any{"type": "DataIntegrityProof", "cryptosuite": "eddsa-rdfc-2022", "proofPurpose": "assertionMethod", "verificationMethod": "did:example:issuer#k", "proofValue": "z123"},
		}},
	}
	return docs
}

// jsonCopy is a deep copy of a JSON document.
func jsonCopy(t *testing.T, v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// leaves calls f with a getter and a setter for each string or boolean of v
// outside its contexts.
func leaves(v any, f func(get func() any, set func(any))) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if k == "@context" {
				continue
			}
			switch x.(type) {
			case string, bool:
				f(func() any { return t[k] }, func(y any) { t[k] = y })
			default:
				leaves(x, f)
			}
		}
	case []any:
		for i, x := range t {
			switch x.(type) {
			case string, bool:
				f(func() any { return t[i] }, func(y any) { t[i] = y })
			default:
				leaves(x, f)
			}
		}
	}
}

// For every document Canonicalize accepts, changing any one of its values
// changes the canonical form or makes the document refused; and a node of
// only an IRI the document names, added in a graph to any of its node
// objects, gives a form that tells which IRI, or is refused. This tests the
// closed property itself, not a list of forms.
func TestCanonicalize_ChangesWithEveryValueOfADocumentItAccepts(t *testing.T) {
	c := testContexts(t)
	for name, doc := range acceptedCorpus(t) {
		want, err := c.Canonicalize(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		changed := jsonCopy(t, doc)
		n := 0
		leaves(changed, func(get func() any, set func(any)) {
			n++
			was := get()
			var changes []any
			switch v := was.(type) {
			case string:
				// A dot segment in front changes an IRI's spelling but not
				// what it resolves to.
				changes = []any{v + "z", "z/../" + v}
			case bool:
				changes = []any{!v}
			}
			for _, to := range changes {
				set(to)
				if got, err := c.Canonicalize(changed); err == nil && bytes.Equal(got, want) {
					t.Errorf("%s: changing %v to %v keeps the canonical form", name, was, to)
				}
			}
			set(was)
		})
		if n == 0 {
			t.Errorf("%s: no value changed", name)
		}
		iris := map[string]bool{}
		leaves(doc, func(get func() any, _ func(any)) {
			if s, ok := get().(string); ok && (strings.HasPrefix(s, "https:") || strings.HasPrefix(s, "did:") || strings.HasPrefix(s, "urn:")) {
				iris[s] = true
			}
		})
		var named []string
		for iri := range iris {
			named = append(named, iri)
		}
		sort.Strings(named)
		top, ok := doc.(map[string]any)
		if len(named) < 2 || !ok {
			continue
		}
		withNode := func(i int, iri string) any {
			added := jsonCopy(t, top).(map[string]any)
			ctx, ok := added["@context"].([]any)
			if !ok {
				ctx = []any{added["@context"]}
			}
			added["@context"] = append(ctx, map[string]any{"zgc": map[string]any{"@id": "https://e.x/zgc", "@container": "@graph"}})
			nodeObjects(added)[i]["zgc"] = map[string]any{"@id": iri}
			return added
		}
		for i := range nodeObjects(top) {
			a, errA := c.Canonicalize(withNode(i, named[0]))
			b, errB := c.Canonicalize(withNode(i, named[1]))
			if errA == nil && errB == nil && bytes.Equal(a, b) {
				t.Errorf("%s: a node of only %s or of only %s, in a graph, gives one canonical form", name, named[0], named[1])
			}
		}
	}
}

// nodeObjects is the node objects of v outside its contexts, in an order
// fixed by their keys.
func nodeObjects(v any) []map[string]any {
	var out []map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, x := range t {
				walk(x)
			}
		case map[string]any:
			_, value := t["@value"]
			_, list := t["@list"]
			_, set := t["@set"]
			if !value && !list && !set {
				out = append(out, t)
			}
			for _, k := range sortedKeys(t) {
				if k != "@context" {
					walk(t[k])
				}
			}
		}
	}
	walk(v)
	return out
}

// Which of a document's faults Canonicalize reports does not depend on Go's
// map order: each of these documents, with two faults under different keys,
// gives the same error every time.
func TestCanonicalize_ReportsTheSameFaultEveryTime(t *testing.T) {
	c := testContexts(t)
	for name, doc := range map[string]string{
		"two nulls": `{"@id":"https://e.x/s","https://e.x/a":null,"https://e.x/b":null}`,
		"@index and @direction in one value object": `{"@id":"https://e.x/s","https://e.x/p":{"@value":"v","@index":"i","@direction":"ltr"}}`,
		"two keys a value object does not have":     `{"@id":"https://e.x/s","https://e.x/p":{"@value":"v","https://e.x/x":"1","https://e.x/y":"2"}}`,
		"@language outside a value object, twice":   `{"@id":"https://e.x/s","https://e.x/a":{"@language":"en"},"https://e.x/b":{"@language":"fr"}}`,
		"two context keywords it does not read":     `{"@context":{"@foo":"x","@bar":"y"},"@id":"https://e.x/s","https://e.x/p":"v"}`,
		"a term aliased in two scoped contexts":     `{"@context":{"a":{"@id":"https://e.x/a","@context":{"x":"@id"}},"b":{"@id":"https://e.x/b","@context":{"x":"@type"}}},"@id":"https://e.x/s","https://e.x/p":"v"}`,
		"two map containers":                        `{"@context":{"a":{"@id":"https://e.x/a","@container":"@index"},"b":{"@id":"https://e.x/b","@container":"@language"}},"@id":"https://e.x/s","https://e.x/p":"v"}`,
		"two node objects in no quad":               `{"@context":{"g1":{"@id":"https://e.x/g1","@container":"@graph","@type":"@id"},"g2":{"@id":"https://e.x/g2","@container":"@graph","@type":"@id"}},"@id":"https://e.x/s","g1":"https://e.x/a","g2":"https://e.x/b"}`,
		"two blank node labels":                     `{"@id":"https://e.x/s","https://e.x/a":{"@id":"_:x"},"https://e.x/b":{"@id":"_:y"}}`,
		"two predicates toRDF drops":                `{"@id":"https://e.x/s","_:a":"v","_:b":"w"}`,
	} {
		var v any
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatal(err)
		}
		var first string
		for i := range 30 {
			_, err := c.Canonicalize(v)
			if err == nil {
				t.Fatalf("%s: accepted", name)
			}
			if i == 0 {
				first = err.Error()
			} else if err.Error() != first {
				t.Errorf("%s: %q, then %q", name, first, err)
				break
			}
		}
	}
}

// A credential that writes a value twice is refused, with the way to write it
// once: a self-issued one whose issuer and subject, one id, both carry the
// same name, and one that lists a type twice.
func TestCanonicalize_RefusesACredentialThatWritesAValueTwice(t *testing.T) {
	c := testContexts(t)
	selfIssued := credentialV2(map[string]any{"id": "did:example:s", "name": "x"})
	selfIssued["issuer"] = map[string]any{"id": "did:example:s", "name": "x"}
	typedTwice := credentialV2(map[string]any{"id": "did:example:s", "name": "x"})
	typedTwice["type"] = []any{"VerifiableCredential", "VerifiableCredential"}
	for name, doc := range map[string]any{"self-issued": selfIssued, "typed twice": typedTwice} {
		if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "refer to it elsewhere by its @id") {
			t.Errorf("%s: %v, want it refused with the way to write it once", name, err)
		}
	}
}

// The RDF collection vocabulary written out (rdf:first and rdf:rest as
// properties, rdf:nil as an IRI) would be signed as the list @list makes,
// though a JSON reader sees another shape, so it is refused: a list comes
// only from @list. The lists themselves are accepted.
func TestCanonicalize_RefusesTheCollectionVocabularyWrittenOut(t *testing.T) {
	const rdf = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	c := testContexts(t)
	nilRef := map[string]any{"@id": rdf + "nil"}
	for name, tc := range map[string]struct{ writtenOut, list any }{
		"an empty list": {
			map[string]any{"@id": "urn:s", "urn:p": nilRef},
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@list": []any{}}},
		},
		"a list of one": {
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{rdf + "first": "a", rdf + "rest": nilRef}},
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@list": []any{"a"}}},
		},
		"a list of two": {
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{rdf + "first": "a", rdf + "rest": map[string]any{rdf + "first": "b", rdf + "rest": nilRef}}},
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@list": []any{"a", "b"}}},
		},
		"rdf:rest under @reverse": {
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@reverse": map[string]any{rdf + "rest": map[string]any{rdf + "first": "a"}}, rdf + "first": "b", rdf + "rest": nilRef}},
			map[string]any{"@id": "urn:s", "urn:p": map[string]any{"@list": []any{"b"}}},
		},
	} {
		want, err := c.Canonicalize(tc.list)
		if err != nil {
			t.Fatalf("%s: the list refused: %v", name, err)
		}
		got, err := c.Canonicalize(tc.writtenOut)
		if err == nil {
			t.Errorf("%s: written out, accepted; its canonical form is the list's: %v", name, bytes.Equal(got, want))
		} else if !strings.Contains(err.Error(), "rdf:") {
			t.Errorf("%s: %v, want the collection vocabulary refused by name", name, err)
		}
	}
	for name, doc := range map[string]any{
		"rdf:nil as a type":    map[string]any{"@id": "urn:s", "@type": rdf + "nil"},
		"rdf:nil as a subject": map[string]any{"@id": rdf + "nil", "urn:p": "v"},
	} {
		if _, err := c.Canonicalize(doc); err == nil || !strings.Contains(err.Error(), "rdf:nil") {
			t.Errorf("%s: %v, want it refused", name, err)
		}
	}
}
