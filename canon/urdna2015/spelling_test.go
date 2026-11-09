package urdna2015_test

import (
	"fmt"
	"strings"
	"testing"
)

// spellingDocs holds one document per place an IRI takes in a quad, each with
// s in that IRI.
func spellingDocs(s string) map[string]map[string]any {
	ctx := []any{ctxCredentialsV2}
	return map[string]map[string]any{
		"subject": {
			"@context": ctx, "@id": "urn:example:s" + s,
			"https://example.org/p": "v",
		},
		"predicate": {
			"@context": ctx, "@id": "urn:example:s",
			"urn:example:p" + s: "v",
		},
		"object": {
			"@context": ctx, "@id": "urn:example:s",
			"https://example.org/p": map[string]any{"@id": "urn:example:o" + s},
		},
		"type": {
			"@context": ctx, "@id": "urn:example:s",
			"@type": "urn:example:t" + s,
		},
		"datatype": {
			"@context": ctx, "@id": "urn:example:s",
			"https://example.org/p": map[string]any{"@value": "v", "@type": "urn:example:d" + s},
		},
		"graph": {
			"@context": ctx, "@id": "urn:example:g" + s,
			"@graph": []any{map[string]any{"@id": "urn:example:s", "https://example.org/p": "v"}},
		},
	}
}

// An IRI holding a character an N-Quads IRI cannot hold is refused, wherever
// it sits in a quad.
func TestCanonicalize_RefusesAnIRIThatNQuadsCannotHold(t *testing.T) {
	c := w3cCanonicalizer(t)
	for _, s := range []string{
		" ", "<", ">", `"`, "{", "}", "|", "^", "`", `\`,
		"\x00", "\x1f", "\t", "\n", "\r",
		"\xff", // not UTF-8
	} {
		for place, doc := range spellingDocs(s) {
			if out, err := c.Canonicalize(doc); err == nil {
				t.Errorf("%s IRI holding %q: want error, got\n%s", place, s, out)
			}
		}
	}
}

// The characters an N-Quads IRI may hold are written as they are.
func TestCanonicalize_WritesAnIRIItMayHoldAsItIs(t *testing.T) {
	c := w3cCanonicalizer(t)
	const s = "é%20?q=1&r#f~!$'()*+,;=:@/-._\u00a0\U00010000"
	for place, doc := range spellingDocs(s) {
		out, err := c.Canonicalize(doc)
		if err != nil {
			t.Errorf("%s IRI holding %q: %v", place, s, err)
			continue
		}
		if !containsIRI(string(out), s) {
			t.Errorf("%s IRI holding %q: not written as it is:\n%s", place, s, out)
		}
	}
}

func containsIRI(nq, s string) bool {
	for _, prefix := range []string{"s", "p", "o", "t", "d", "g"} {
		if strings.Contains(nq, "<urn:example:"+prefix+s+">") {
			return true
		}
	}
	return false
}

// literalDoc holds one plain literal.
func literalDoc(v string) map[string]any {
	return map[string]any{
		"@context": []any{ctxCredentialsV2}, "@id": "urn:example:s",
		"https://example.org/p": v,
	}
}

// A literal holding a character that RDFC-1.0 writes escaped and URDNA2015
// writes as it is, or that is not UTF-8, is refused: its canonical forms
// under the two would differ.
func TestCanonicalize_RefusesALiteralTheTwoCanonicalFormsWriteDifferently(t *testing.T) {
	c := w3cCanonicalizer(t)
	for _, s := range []string{
		"\b", "\f", "\v", "\x00", "\x01", "\x07", "\x0e", "\x1f", "\x7f",
		"\ufffe", "\uffff",
		"\xff", // not UTF-8
	} {
		if out, err := c.Canonicalize(literalDoc("a" + s + "b")); err == nil {
			t.Errorf("literal holding %q: want error, got\n%s", s, out)
		}
	}
}

// Every other character of a literal is written as both canonical forms write
// it: HT, LF, CR, quotation mark and backslash escaped, the rest as they are.
func TestCanonicalize_WritesALiteralAsBothCanonicalFormsWriteIt(t *testing.T) {
	c := w3cCanonicalizer(t)
	for v, want := range map[string]string{
		"a\tb\nc\rd\"e\\f":          `a\tb\nc\rd\"e\\f`,
		"é\u0080\u00a0\u2028\ufffd": "é\u0080\u00a0\u2028\ufffd",
		"\U00010000\U0010ffff":      "\U00010000\U0010ffff",
		"a b~c":                     "a b~c",
		"":                          "",
	} {
		out, err := c.Canonicalize(literalDoc(v))
		if err != nil {
			t.Errorf("literal %q: %v", v, err)
			continue
		}
		line := fmt.Sprintf("<urn:example:s> <https://example.org/p> \"%s\" .\n", want)
		if string(out) != line {
			t.Errorf("literal %q:\n got %q\nwant %q", v, out, line)
		}
	}
}

// A literal typed rdf:langString is written with its language tag, which must
// follow the N-Quads LANGTAG grammar: one with no tag is refused.
func TestCanonicalize_RefusesALangStringWithoutALanguage(t *testing.T) {
	c := w3cCanonicalizer(t)
	for _, v := range []any{"v", true} {
		doc := map[string]any{
			"@context": []any{ctxCredentialsV2}, "@id": "urn:example:s",
			"https://example.org/p": map[string]any{
				"@value": v, "@type": "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString",
			},
		}
		if out, err := c.Canonicalize(doc); err == nil {
			t.Errorf("rdf:langString %v without a language: want error, got\n%s", v, out)
		}
	}
}
