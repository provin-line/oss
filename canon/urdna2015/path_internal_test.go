package urdna2015

import (
	"runtime"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/excerpt"
)

// deep nests n objects and arrays, alternately, around a string.
func deep(n int) any {
	var v any = "leaf"
	for i := range n {
		if i%2 == 0 {
			v = map[string]any{"https://example.org/p": v}
		} else {
			v = []any{v}
		}
	}
	return v
}

// The walk spells the path to a value only into an error: walking a document
// nested 10 000 deep costs at most 256 bytes a level, and refusing one quotes
// the path within pathQuoteLimit: its head and its length.
func TestRejectSilentDrops_SpellsThePathOnlyOnError(t *testing.T) {
	const depth = 10000
	ok := deep(depth)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if err := rejectSilentDrops(ok, new(jsonPath), false); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 256*depth {
		t.Errorf("walking %d levels allocated %d bytes, want at most %d", depth, got, 256*depth)
	}

	var refused any = nil
	for range depth {
		refused = map[string]any{"k": refused}
	}
	err := rejectSilentDrops(refused, new(jsonPath), false)
	if err == nil {
		t.Fatal("null 10000 deep: want error")
	}
	if want := " at " + excerpt.Quoted(strings.Repeat("/k", depth), pathQuoteLimit) + ":"; !strings.Contains(err.Error(), want) {
		t.Errorf("error does not quote the path to the null within %d bytes, its head and its length:\n%.400s", pathQuoteLimit, err)
	}
}

// The path is spelled as before: "/"-separated keys and indexes.
func TestRejectSilentDrops_SpellsThePath(t *testing.T) {
	doc := map[string]any{"a": []any{"x", map[string]any{"b": nil}}}
	err := rejectSilentDrops(doc, new(jsonPath), false)
	if err == nil || !strings.Contains(err.Error(), `"/a/1/b"`) {
		t.Errorf("err = %v, want the path \"/a/1/b\"", err)
	}
	graph := map[string]any{"@graph": []any{map[string]any{}, "rider"}}
	err = rejectSilentDrops(graph, new(jsonPath), false)
	if err == nil || !strings.Contains(err.Error(), `element 1 of "/@graph"`) {
		t.Errorf("err = %v, want element 1 of \"/@graph\"", err)
	}
}

// A container wide at any depth costs no more per value than a narrow one:
// d single-member objects around an array of 64 strings, for every d up to
// 2048, cost at most 256 bytes a value.
func TestRejectSilentDrops_CostsTheSameAtEveryDepth(t *testing.T) {
	leaves := make([]any, 64)
	for i := range leaves {
		leaves[i] = "x"
	}
	for d := 1; d <= 2048; d++ {
		var v any = leaves
		for range d {
			v = map[string]any{"a": v}
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if err := rejectSilentDrops(v, new(jsonPath), false); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		values := uint64(d + 1 + len(leaves))
		if got := after.TotalAlloc - before.TotalAlloc; got > 256*values {
			t.Fatalf("depth %d: %d bytes for %d values (%d a value), want at most 256 a value", d, got, values, got/values)
		}
	}
}

// Every refusal that names where a form is quotes the path within
// pathQuoteLimit, however long the path: here a key of 10 000 bytes holds the
// form, and each form reaches the refusal named.
func TestCanonicalize_QuotesThePathOfARefusalWithinTheBound(t *testing.T) {
	c := testContexts(t)
	long := "urn:" + strings.Repeat("k", 10000)
	for name, f := range map[string]struct {
		form   any
		reason string
	}{
		"null":                            {map[string]any{"urn:q": nil}, "refusing null at "},
		"a number":                        {map[string]any{"urn:q": 1.5}, "refusing value of type float64 at "},
		"a member named \"\"":             {map[string]any{"": "v"}, `a member named "" at `},
		"a scalar in @graph":              {map[string]any{"@id": "urn:g", "@graph": []any{map[string]any{"@id": "urn:n", "urn:q": "v"}, "x"}}, "element 1 of "},
		"@index":                          {map[string]any{"@value": "v", "@index": "i"}, "@index at "},
		"@direction":                      {map[string]any{"@value": "v", "@direction": "rtl"}, "@direction at "},
		"@set":                            {map[string]any{"@set": []any{"v"}}, "@set at "},
		"a framing keyword":               {map[string]any{"urn:q": "v", "@explicit": true}, "@explicit at "},
		"@language outside a value":       {map[string]any{"@language": "en"}, "@language at "},
		"@json":                           {map[string]any{"@value": "v", "@type": "@json"}, "@json at "},
		"a value object's other key":      {map[string]any{"@value": "v", "urn:q": "w"}, "a value object at "},
		"an empty array":                  {map[string]any{"urn:q": "v", "@type": []any{}}, "an empty array at "},
		"an empty array in @nest":         {map[string]any{"urn:q": "v", "@nest": []any{}}, "an empty array at "},
		"an array in an array":            {[]any{"v", []any{"w"}}, "an array in an array at "},
		"an array in an array in @nest":   {map[string]any{"urn:q": "v", "@nest": []any{[]any{map[string]any{"urn:r": "w"}}}}, "an array in an array at "},
		"an empty object":                 {map[string]any{"urn:q": "v", "@included": []any{map[string]any{}}}, "an empty object at "},
		"an empty object in @nest":        {map[string]any{"urn:q": "v", "@nest": map[string]any{}}, "an empty object at "},
		"a keyword JSON-LD does not read": {map[string]any{"urn:q": "v", "@none": map[string]any{"urn:r": []any{}}}, `"@none" at `},
		"a list where JSON-LD keeps none": {map[string]any{"@graph": []any{map[string]any{"@list": []any{}}}, "@id": "urn:g", "urn:q": "v"}, "a list at "},
	} {
		_, err := c.Canonicalize(map[string]any{"@id": "urn:s", long: f.form})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), f.reason+`"/urn:kkk`) || !strings.Contains(err.Error(), " bytes)") || len(err.Error()) > 512 {
			t.Errorf("%s: %d bytes, want %q and the path within %d bytes: %.300s", name, len(err.Error()), f.reason, pathQuoteLimit, err)
		}
	}
}

// An error of json-gold's is quoted within goldErrorQuoteLimit: json-gold
// writes into its error the value it refuses, here a term defined as an array
// of 10 000 strings in a document's own context.
func TestCanonicalize_QuotesJSONGoldsErrorWithinTheBound(t *testing.T) {
	values := make([]any, 10000)
	for i := range values {
		values[i] = "urn:v"
	}
	doc := map[string]any{"@context": map[string]any{"t": values, "q": "urn:q"}, "@id": "urn:s", "q": "v"}
	_, err := testContexts(t).Canonicalize(doc)
	if err == nil || !strings.HasPrefix(err.Error(), "urdna2015: expand: ") {
		t.Fatalf("%.200v", err)
	}
	if len(err.Error()) > 512 {
		t.Errorf("the refusal is %d bytes", len(err.Error()))
	}
}
