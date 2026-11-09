package urdna2015

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
)

// longIRIShapes builds, for n quads and an IRI of length bytes, documents
// whose canonical form writes that IRI in every quad: as the subject, as a
// predicate from a term of the document's own context, and as the name of a
// graph.
var longIRIShapes = map[string]func(n, length int) map[string]any{
	"the subject of every quad": func(n, length int) map[string]any {
		subject := map[string]any{"id": "urn:x:" + strings.Repeat("a", length)}
		for i := range n {
			subject[fmt.Sprintf("urn:p:%d", i)] = "v"
		}
		return credential(subject, nil)
	},
	"a term's predicate in every quad": func(n, length int) map[string]any {
		return credential(map[string]any{
			"p": each(n, func(i int) any { return map[string]any{"t": fmt.Sprintf("v%d", i)} }),
		}, map[string]any{"t": map[string]any{"@id": "urn:t:" + strings.Repeat("a", length)}})
	},
	"the graph of every quad": func(n, length int) map[string]any {
		return map[string]any{
			"@context": []any{map[string]any{"p": map[string]any{"@id": "urn:p"}}},
			"@id":      "urn:g:" + strings.Repeat("a", length),
			"@graph":   each(n, func(i int) any { return map[string]any{"@id": fmt.Sprintf("urn:n:%d", i), "p": "v"} }),
		}
	},
}

// A document whose canonical form would be more than a bound linear in the
// document's size is refused with ErrTooComplex before it is labelled or
// written; one within it is canonicalized.
func TestCanonicalize_BoundsTheSizeOfTheCanonicalForm(t *testing.T) {
	c := testContexts(t)
	for name, shape := range longIRIShapes {
		if _, err := c.Canonicalize(shape(100, 1000)); err != nil {
			t.Errorf("%s, 100 quads, an IRI of 1 KB: %v", name, err)
		}
		out, err := c.Canonicalize(shape(1000, 100_000))
		if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "canonical form:") {
			t.Errorf("%s, 1,000 quads, an IRI of 100 KB: %.200v, want urdna2015.ErrTooComplex, naming the canonical form", name, err)
		}
		if out != nil {
			t.Errorf("%s: %d bytes returned with the refusal", name, len(out))
		}
	}
}

// documentBytes is the length of the document written as compact JSON, its
// strings counted as they are, unescaped.
func TestDocumentBytes_IsTheLengthOfTheDocumentAsJSON(t *testing.T) {
	docs := ordinaryDocuments(t)
	for name, shape := range shapes {
		docs[name] = shape(30)
	}
	docs["values of every kind Canonicalize admits"] = map[string]any{"a": []any{"s", true, false, map[string]any{}, []any{}}}
	for name, doc := range docs {
		b, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if got := documentBytes(doc); got != int64(len(b)) {
			t.Errorf("%s: %d bytes, json.Marshal writes %d", name, got, len(b))
		}
	}
}

// canonicalSize is an upper bound of the canonical form's length, exact for a
// dataset without blank nodes, whose labels it counts at their longest.
func TestCanonicalSize_IsAnUpperBoundOfTheCanonicalForm(t *testing.T) {
	c := testContexts(t)
	docs := ordinaryDocuments(t)
	for name, shape := range shapes {
		docs[name] = shape(30)
	}
	for name, doc := range graphShapes(30) {
		docs[name] = doc
	}
	for name, shape := range longIRIShapes {
		docs[name] = shape(10, 100)
	}
	docs["literals to escape"] = credential(map[string]any{
		"id": "urn:s", "p": []any{"a \"quoted\" \\ back\nslash\r\t", "x"},
	}, nil)
	docs["no blank nodes: escapes, a language, a datatype"] = map[string]any{
		"@id":   "urn:s",
		"urn:p": []any{"a \"quoted\" \\ back\nslash\r\t", "x"},
		"urn:l": map[string]any{"@value": "x", "@language": "en"},
		"urn:t": map[string]any{"@value": "y", "@type": "urn:dt"},
		"urn:g": map[string]any{"@id": "urn:o"},
	}
	for name, doc := range docs {
		ds := documentDataset(t, c, doc)
		blanks := false
		for _, quads := range ds.Graphs {
			for _, q := range quads {
				for _, n := range []ld.Node{q.Subject, q.Object, q.Graph} {
					blanks = blanks || n != nil && ld.IsBlankNode(n)
				}
			}
		}
		for g := range ds.Graphs {
			blanks = blanks || strings.HasPrefix(g, "_:")
		}
		size := canonicalSize(ds)
		out, err := canonicalNQuads(ds)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if size < int64(len(out)) || !blanks && size != int64(len(out)) {
			t.Errorf("%s: canonicalSize %d, the canonical form %d bytes (blank nodes: %v)", name, size, len(out), blanks)
		}
	}
}

// Ordinary credentials, anonymous repeats included, take at most 3% of the
// bound on the canonical form, as canonicalBase's doc says.
func TestCanonicalSize_OrdinaryDocumentsStayWellWithinTheBound(t *testing.T) {
	c := testContexts(t)
	for name, doc := range ordinaryDocuments(t) {
		in := documentBytes(doc)
		size, limit := canonicalSize(documentDataset(t, c, doc)), canonicalLimit(in)
		t.Logf("%-75s document %6d  canonical %7d  bound %8d  share %5.2f%%", name, in, size, limit, 100*float64(size)/float64(limit))
		if 100*size > 3*limit {
			t.Errorf("%s: a canonical form of %d bytes is more than 3%% of the bound %d", name, size, limit)
		}
	}
}

// Large documents of the shapes the node map's tests use have canonical forms
// at most 16 times their size, half of canonicalPerDocumentByte.
func TestCanonicalSize_LargeDocumentsStayWithinHalfThePerByteBound(t *testing.T) {
	c := testContexts(t)
	docs := map[string]map[string]any{}
	for name, shape := range shapes {
		docs[name] = shape(1000)
	}
	for name, doc := range graphShapes(1000) {
		docs[name] = doc
	}
	for name, doc := range docs {
		in, size := documentBytes(doc), canonicalSize(documentDataset(t, c, doc))
		t.Logf("%-40s document %7d  canonical %7d  %5.2f per byte", name, in, size, float64(size)/float64(in))
		if size > canonicalPerDocumentByte/2*in {
			t.Errorf("%s: a canonical form of %d bytes for a document of %d", name, size, in)
		}
	}
}

// The canonical form is counted before the quads are read for their IRIs: a
// dataset past the bound whose IRIs canonical N-Quads could not write is
// refused for its size, and one within it for its IRI.
func TestCanonicalize_CountsTheFormBeforeReadingTheIRIs(t *testing.T) {
	c := testContexts(t)
	unwritable := func(n, length int) map[string]any {
		subject := map[string]any{"id": "urn:x:" + strings.Repeat("a", length) + "^"}
		for i := range n {
			subject[fmt.Sprintf("urn:p:%d", i)] = "v"
		}
		return credential(subject, nil)
	}
	if _, err := c.Canonicalize(unwritable(1000, 100_000)); !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "canonical form:") {
		t.Errorf("past the bound: %.200v, want urdna2015.ErrTooComplex, naming the canonical form", err)
	}
	if _, err := c.Canonicalize(unwritable(10, 100)); err == nil || errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "U+005E") {
		t.Errorf("within the bound: %.200v, want the IRI refused", err)
	}
}

// canonicalSize takes time in the quads, not in the length of the IRIs they
// name: a dataset whose quads name an IRI 16 times as long takes about as
// long to count (at most 4 times; reading the IRIs would take about 16).
func TestCanonicalSize_TakesTimeInTheQuads(t *testing.T) {
	c := testContexts(t)
	for name, shape := range longIRIShapes {
		timeOf := func(length int) time.Duration {
			ds := documentDataset(t, c, shape(4000, length))
			best := time.Hour
			for range 5 {
				start := time.Now()
				for range 100 {
					canonicalSize(ds)
				}
				best = min(best, time.Since(start))
			}
			return best
		}
		short, long := timeOf(25_000), timeOf(400_000)
		if ratio := float64(long) / float64(max(short, time.Microsecond)); ratio > 4 {
			t.Errorf("%s: an IRI 16 times as long took %.1f times as long to count (%v, %v)", name, ratio, short, long)
		}
	}
}

// The bound takes a canonical form of exactly its length, and refuses one a
// byte longer.
func TestBoundCanonicalSize_TakesTheBoundAndRefusesAByteMore(t *testing.T) {
	dataset := func(value int) *ld.RDFDataset {
		ds := ld.NewRDFDataset()
		ds.Graphs["@default"] = []*ld.Quad{ld.NewQuad(ld.NewIRI("urn:s"), ld.NewIRI("urn:p"), ld.NewLiteral(strings.Repeat("a", value), ld.XSDString, ""), "@default")}
		return ds
	}
	const documentBytes = 1000
	limit := canonicalLimit(documentBytes)
	value := int(limit - canonicalSize(dataset(0)))
	if got := canonicalSize(dataset(value)); got != limit {
		t.Fatalf("canonicalSize %d, want %d", got, limit)
	}
	if err := boundCanonicalSize(dataset(value), documentBytes); err != nil {
		t.Errorf("a form of the bound's length: %v", err)
	}
	if err := boundCanonicalSize(dataset(value+1), documentBytes); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a form a byte longer: %v, want urdna2015.ErrTooComplex", err)
	}
}
