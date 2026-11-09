package urdna2015

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
)

// credential is a credential whose subject is subject, with the extra term
// definitions terms in its own context.
func credential(subject map[string]any, terms map[string]any) map[string]any {
	ctx := map[string]any{
		"p": map[string]any{"@id": "https://example.org/p"},
		"q": map[string]any{"@id": "https://example.org/q"},
		"l": map[string]any{"@id": "https://example.org/l", "@container": "@list"},
	}
	for k, v := range terms {
		ctx[k] = v
	}
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2", ctx},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
}

// shapes builds, for n values, documents whose node map gathers the n values
// on one node and property in each way the node map gathers them: an array
// of literals, of blank nodes, of IRIs, of lists; nodes of one id spread over
// an array; terms that are aliases of one property; types; reverse
// properties.
var shapes = map[string]func(n int) map[string]any{
	"literals": func(n int) map[string]any {
		return credential(map[string]any{"p": each(n, func(i int) any { return fmt.Sprintf("v%d", i) })}, nil)
	},
	"blank nodes": func(n int) map[string]any {
		return credential(map[string]any{"p": each(n, func(i int) any { return map[string]any{"q": fmt.Sprintf("v%d", i)} })}, nil)
	},
	"IRIs": func(n int) map[string]any {
		return credential(map[string]any{"p": each(n, func(i int) any { return map[string]any{"id": fmt.Sprintf("https://example.org/o%d", i)} })}, nil)
	},
	"lists": func(n int) map[string]any {
		return credential(map[string]any{"p": each(n, func(i int) any { return map[string]any{"@list": []any{fmt.Sprintf("v%d", i)}} })}, nil)
	},
	"one id spread": func(n int) map[string]any {
		return credential(map[string]any{"p": map[string]any{"id": "https://example.org/s"}, "@included": each(n, func(i int) any {
			return map[string]any{"id": "https://example.org/s", "q": fmt.Sprintf("v%d", i)}
		})}, nil)
	},
	"aliases": func(n int) map[string]any {
		subject, terms := map[string]any{}, map[string]any{}
		for i := 0; i < n; i++ {
			a := fmt.Sprintf("a%d", i)
			terms[a] = map[string]any{"@id": "https://example.org/p"}
			subject[a] = fmt.Sprintf("v%d", i)
		}
		return credential(subject, terms)
	},
	"types": func(n int) map[string]any {
		return credential(map[string]any{"type": each(n, func(i int) any { return fmt.Sprintf("https://example.org/T%d", i) })}, nil)
	},
	"reverse properties": func(n int) map[string]any {
		return credential(map[string]any{"p": each(n, func(i int) any {
			return map[string]any{
				"id":       fmt.Sprintf("https://example.org/s%d", i),
				"@reverse": map[string]any{"https://example.org/r": map[string]any{"id": "https://example.org/o"}},
			}
		})}, nil)
	},
}

func each(n int, f func(int) any) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

// Values the node map gathers on one node and property, in whichever way
// they are gathered, are compared each with those before it: a document whose
// node map would compare more pairs than the bound allows is refused with
// ErrTooComplex before json-gold builds it; one with few is canonicalized.
func TestCanonicalize_BoundsTheComparisonsOfTheNodeMap(t *testing.T) {
	c := testContexts(t)
	for name, shape := range shapes {
		if _, err := c.Canonicalize(shape(20)); err != nil {
			t.Errorf("%s, 20 values: %v", name, err)
		}
		out, err := c.Canonicalize(shape(3000))
		if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "node map:") {
			t.Errorf("%s, 3,000 values: %v, want urdna2015.ErrTooComplex, naming the node map", name, err)
		}
		if out != nil {
			t.Errorf("%s: %d bytes returned with the refusal", name, len(out))
		}
	}
}

// Equal values are compared once each and gathered once: many copies of one
// value are within the node map's bound. (Canonicalize refuses a value held
// twice for what it would not sign; see conserve_test.go.)
func TestNodeMapWork_EqualValuesAreWithinTheBound(t *testing.T) {
	doc := credential(map[string]any{"p": each(3000, func(int) any { return "same" })}, nil)
	c := testContexts(t)
	expanded, err := ld.NewJsonLdProcessor().Expand(doc, c.options())
	if err != nil {
		t.Fatal(err)
	}
	w := newNodeMapWork()
	w.walk(expanded)
	if err := w.bound(); err != nil {
		t.Errorf("3,000 equal values: %v", err)
	}
}

// groupSizes is, for each node's property in each graph, the number of
// distinct values it holds: by name where the graph and the node are named by
// IRIs, and as a sorted list where either is a blank node, which json-gold
// and the walk label differently.
type groupSizes struct {
	named map[string]int64
	blank []int64
}

func (s *groupSizes) put(graph, node, property string, n int64) {
	if n == 0 {
		return
	}
	if isBlank(graph) || isBlank(node) {
		s.blank = append(s.blank, n)
		return
	}
	s.named[graph+" "+node+" "+property] = n
}

func isBlank(id string) bool { return strings.HasPrefix(id, "_:") || strings.HasPrefix(id, "\x00") }

// gathered is what json-gold's node map gathers from an expanded document.
func gathered(t *testing.T, expanded any) groupSizes {
	t.Helper()
	graphs := map[string]any{"@default": map[string]any{}}
	if _, err := ld.NewJsonLdApi().GenerateNodeMap(expanded, graphs, "@default", ld.NewIdentifierIssuer("_:b"), nil, "", nil); err != nil {
		t.Fatal(err)
	}
	s := groupSizes{named: map[string]int64{}}
	for graph, nodes := range graphs {
		for node, props := range nodes.(map[string]any) {
			for p, v := range props.(map[string]any) {
				if values, ok := v.([]any); ok && p != "@id" && p != "@index" {
					s.put(graph, node, p, int64(len(values)))
				}
			}
		}
	}
	sort.Slice(s.blank, func(i, j int) bool { return s.blank[i] < s.blank[j] })
	return s
}

// counted is what the walk counts of an expanded document.
func counted(expanded any) groupSizes {
	w := newNodeMapWork()
	w.walk(expanded)
	s := groupSizes{named: map[string]int64{}}
	for k, g := range w.groups {
		s.put(w.names[k.graph], w.names[k.node], w.names[k.property], g.distinct)
	}
	sort.Slice(s.blank, func(i, j int) bool { return s.blank[i] < s.blank[j] })
	return s
}

// graphShapes are documents whose values the node map gathers across graphs
// and from places other than a node's own properties: a named graph from a
// @graph container and from a top-level @graph with an @id, @included nodes,
// and items of a list naming other nodes by @reverse.
func graphShapes(n int) map[string]map[string]any {
	values := func(prefix string) []any {
		return each(n, func(i int) any { return fmt.Sprintf("%s%d", prefix, i) })
	}
	return map[string]map[string]any{
		"a @graph container": credential(map[string]any{
			"g": []any{
				map[string]any{"id": "https://example.org/x", "p": values("a")},
				map[string]any{"id": "https://example.org/x", "p": values("a")},
			},
		}, map[string]any{"g": map[string]any{"@id": "https://example.org/g", "@container": "@graph"}}),
		"a top-level @graph with an @id": {
			"@context": []any{map[string]any{"p": map[string]any{"@id": "https://example.org/p"}}},
			"@id":      "https://example.org/G",
			"@graph": []any{
				map[string]any{"@id": "https://example.org/a", "p": values("v")},
				map[string]any{"@id": "https://example.org/a", "p": values("w")},
				map[string]any{"@id": "https://example.org/b", "p": values("v")},
			},
		},
		"@included": credential(map[string]any{
			"id": "https://example.org/s",
			"p":  values("v"),
			"@included": []any{
				map[string]any{"id": "https://example.org/s", "p": values("w")},
				map[string]any{"id": "https://example.org/i", "q": values("v")},
			},
		}, nil),
		"list items naming nodes by @reverse": credential(map[string]any{
			"l": each(n, func(i int) any {
				return map[string]any{
					"id":       fmt.Sprintf("https://example.org/li%d", i),
					"@reverse": map[string]any{"https://example.org/r": map[string]any{"id": "https://example.org/o"}},
				}
			}),
		}, nil),
	}
}

// The walk gathers values as json-gold's node map does: for every shape and
// every ordinary credential, each node's property holds as many values in
// json-gold's node map as the walk counts distinct ones. Each side expands
// the document itself, since GenerateNodeMap changes what it is given.
func TestNodeMapWork_GathersAsJsonGoldDoes(t *testing.T) {
	c := testContexts(t)
	docs := ordinaryDocuments(t)
	for name, shape := range shapes {
		docs[name] = shape(30)
	}
	for name, doc := range graphShapes(30) {
		docs[name] = doc
	}
	expand := func(name string, doc map[string]any) any {
		expanded, err := ld.NewJsonLdProcessor().Expand(doc, c.options())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return expanded
	}
	for name, doc := range docs {
		got := counted(expand(name, doc))
		want := gathered(t, expand(name, doc))
		if len(want.named)+len(want.blank) == 0 {
			t.Errorf("%s: json-gold's node map gathers no values", name)
		}
		if fmt.Sprint(got.named) != fmt.Sprint(want.named) {
			t.Errorf("%s: by node, the walk counts %v; json-gold's node map holds %v", name, got.named, want.named)
		}
		if fmt.Sprint(got.blank) != fmt.Sprint(want.blank) {
			t.Errorf("%s: on blank nodes, the walk counts %v; json-gold's node map holds %v", name, got.blank, want.blank)
		}
	}
}

// Ordinary credentials, anonymous repeats included, take at most 2% of the
// bound, as nodeMapBase's doc says.
func TestNodeMapWork_OrdinaryDocumentsStayWellWithinTheBound(t *testing.T) {
	c := testContexts(t)
	for name, doc := range ordinaryDocuments(t) {
		expanded, err := ld.NewJsonLdProcessor().Expand(doc, c.options())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		w := newNodeMapWork()
		w.walk(expanded)
		pairs, limit := w.comparisons(), nodeMapBase+nodeMapPerValue*w.added
		t.Logf("%-75s values %5d  pairs %6d  bound %7d  share %5.2f%%", name, w.added, pairs, limit, 100*float64(pairs)/float64(limit))
		if 100*pairs > 2*limit {
			t.Errorf("%s: %d pairs is more than 2%% of the bound %d", name, pairs, limit)
		}
	}
}

// oneGroupFromTwoKeys is an expanded document in which one node's property
// gathers values from two keys of one node object: its own values, and, from
// a node under another property, a reverse property naming it, which repeats
// one of those values. Go visits a map's keys in no fixed order, so the walk
// meets the repeat first in some runs and last in others.
func oneGroupFromTwoKeys(n int) []any {
	p := make([]any, n)
	for i := range p {
		p[i] = map[string]any{"@id": fmt.Sprintf("https://example.org/u%d", i)}
	}
	p[0] = map[string]any{"@id": "https://example.org/t"}
	return []any{map[string]any{
		"@id":                   "https://example.org/s",
		"https://example.org/p": p,
		"https://example.org/q": []any{map[string]any{
			"@id":      "https://example.org/t",
			"@reverse": map[string]any{"https://example.org/p": []any{map[string]any{"@id": "https://example.org/s"}}},
		}},
	}}
}

// The count does not depend on the order the walk meets the values in: a
// document is counted the same in every run.
func TestNodeMapWork_CountsADocumentTheSameEveryRun(t *testing.T) {
	doc := oneGroupFromTwoKeys(10)
	counts := map[int64]bool{}
	for range 200 {
		w := newNodeMapWork()
		w.walk(doc)
		counts[w.comparisons()] = true
	}
	if len(counts) != 1 {
		t.Errorf("one document counted as %v comparisons in different runs", counts)
	}
}

// A node's property is counted as the most comparisons any order of its
// values takes: each of its D distinct values compared with every one before
// it, and each of its A - D repeats with all D, D(D-1)/2 + (A-D)D. A list is
// equal to no other value, so each is a distinct one.
func TestNodeMapWork_CountsTheMostAnyOrderOfTheValuesTakes(t *testing.T) {
	type value struct {
		key  string
		list bool
	}
	a, b, c, list := value{key: "a"}, value{key: "b"}, value{key: "c"}, value{list: true}
	for _, tc := range []struct {
		values []value
		want   int64
	}{
		{[]value{a}, 0},
		{[]value{a, a}, 1},
		{[]value{a, b, c}, 3},
		{[]value{a, b, c, a, a}, 3 + 2*3},
		{[]value{a, a, a, b, c}, 3 + 2*3},
		{[]value{c, a, b, a, a}, 3 + 2*3},
		{[]value{list, list, a, a}, 3 + 1*3},
	} {
		w := newNodeMapWork()
		for _, v := range tc.values {
			w.add(w.id("@default"), w.id("s"), w.id("p"), valueID{value: v.key}, v.list, -1, -1)
		}
		if got := w.comparisons(); got != tc.want {
			t.Errorf("%v: %d comparisons, want %d", tc.values, got, tc.want)
		}
	}
}

// Values on different nodes, properties or graphs are not compared: each
// node's property is counted alone, and the counts are added.
func TestNodeMapWork_CountsEachNodesPropertyAlone(t *testing.T) {
	w := newNodeMapWork()
	for _, g := range []struct{ graph, node, property string }{{"@default", "s", "p"}, {"@default", "s", "q"}, {"@default", "t", "p"}, {"g", "s", "p"}} {
		for _, v := range []string{"a", "b", "c"} {
			w.add(w.id(g.graph), w.id(g.node), w.id(g.property), valueID{value: v}, false, -1, -1)
		}
	}
	if got := w.comparisons(); got != 4*3 {
		t.Errorf("%d comparisons, want %d", got, 4*3)
	}
	if w.added != 12 {
		t.Errorf("%d values added, want 12", w.added)
	}
}

// A document of more values than any fits in memory is counted as past every
// bound, rather than overflowing: past 2^31 values, the count is the largest
// int64.
func TestNodeMapWork_PastTwoToThe31ValuesIsPastEveryBound(t *testing.T) {
	w := newNodeMapWork()
	w.add(w.id("@default"), w.id("s"), w.id("p"), valueID{value: "a"}, false, -1, -1)
	w.added = 1<<31 + 1
	if got := w.comparisons(); got != math.MaxInt64 {
		t.Errorf("%d comparisons, want math.MaxInt64", got)
	}
}

// manyReferencesToALongIRI is an expanded document of n short nodes, each
// naming one node of a long IRI: by a property of theirs, and by @reverse
// from it.
func manyReferencesToALongIRI(n, length int) []any {
	long := "urn:x:" + strings.Repeat("a", length)
	targets := make([]any, n)
	nodes := make([]any, n)
	for i := range n {
		id := fmt.Sprintf("urn:t:%d", i)
		targets[i] = map[string]any{"@id": id}
		nodes[i] = map[string]any{"@id": id, "urn:p": []any{map[string]any{"@id": long}}}
	}
	return append(nodes, map[string]any{"@id": long, "@reverse": map[string]any{"urn:q": targets}})
}

// The walk keeps what it reads without copying it: its memory does not grow
// with the length of an IRI many values name.
func TestNodeMapWork_DoesNotCopyTheIRIsItCounts(t *testing.T) {
	doc := manyReferencesToALongIRI(1000, 100_000)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	w := newNodeMapWork()
	w.walk(doc)
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
		t.Errorf("the walk allocated %d MB for 2,000 references to one IRI of 100 KB", got>>20)
	}
	if w.added != 2000 {
		t.Errorf("%d values added, want 2,000", w.added)
	}
}

// Two value objects have one valueID only when json-gold's CompareValues
// finds them equal, so the walk never counts fewer distinct values than
// json-gold holds; and values it finds equal have one valueID, but for 0 and
// -0, and values valueOf counts as equal to none (NaN, a @type that is not a
// string): the walk counts those apart, more, never fewer.
func TestValueOf_IsOneOnlyForValuesJsonGoldFindsEqual(t *testing.T) {
	values := []map[string]any{
		{"@value": "a"},
		{"@value": "a", "@language": "en"},
		{"@value": "a", "@language": "fr"},
		{"@value": "a", "@type": "urn:t"},
		{"@value": "a", "@index": ""},
		{"@value": "a", "@index": "i"},
		{"@value": "a", "@type": "urn:t", "@index": "i"},
		{"@value": "true"},
		{"@value": true},
		{"@value": false},
		{"@value": "1"},
		{"@value": float64(1)},
		{"@value": 1.5},
		{"@value": 0.0},
		{"@value": math.Copysign(0, -1)},
		{"@value": math.NaN()},
		{"@value": "a", "@type": 1.0},
	}
	// json-gold compares @value with ==, which panics on an array or an
	// object; expansion and rejectSilentDrops keep them from it. valueOf
	// counts such a value as equal to none.
	for _, v := range []map[string]any{{"@value": []any{"a"}}, {"@value": map[string]any{"a": "b"}}} {
		if _, ok := valueOf(v); ok {
			t.Errorf("%v: valueOf finds a valueID", v)
		}
	}
	for i, a := range values {
		for j, b := range values {
			idA, okA := valueOf(a)
			idB, okB := valueOf(b)
			same := okA && okB && idA == idB
			equal := ld.CompareValues(a, b)
			if same && !equal {
				t.Errorf("%v and %v: one valueID, but json-gold finds them unequal", a, b)
			}
			zeros := i >= 13 && i <= 14 && j >= 13 && j <= 14
			if equal && okA && okB && !same && !zeros {
				t.Errorf("%v and %v: json-gold finds them equal, but they have two valueIDs ", a, b)
			}
		}
	}
}

// The walk takes time in the values it counts, not in the length of the IRIs
// they name: it reads a node's or a graph's @id, and a property, once where
// the document writes it, not at every value added to it, so an IRI 16 times as long
// takes about as long (at most 4 times; reading it at every value would take
// about 16).
func TestNodeMapWork_TakesTimeInTheValuesNotInTheIRIs(t *testing.T) {
	timeOf := func(doc []any) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			newNodeMapWork().walk(doc)
			best = min(best, time.Since(start))
		}
		return best
	}
	inGraph := func(n, length int) []any {
		return []any{map[string]any{
			"@id": "urn:g:" + strings.Repeat("a", length),
			"@graph": each(n, func(i int) any {
				return map[string]any{"@id": fmt.Sprintf("urn:n:%d", i), "urn:p": []any{map[string]any{"@value": "v"}}}
			}),
		}}
	}
	namingMany := func(n, length int) []any {
		targets := each(n, func(i int) any { return map[string]any{"@id": fmt.Sprintf("urn:t:%d", i)} })
		return []any{map[string]any{
			"@id":      "urn:x:" + strings.Repeat("a", length),
			"urn:p":    targets,
			"@reverse": map[string]any{"urn:q": targets},
		}}
	}
	longPredicate := func(n, length int) []any {
		return []any{map[string]any{
			"@id":                                  "urn:s",
			"urn:p:" + strings.Repeat("a", length): each(n, func(i int) any { return map[string]any{"@value": fmt.Sprintf("v%d", i)} }),
		}}
	}
	for name, shape := range map[string]func(n, length int) []any{
		"a node of a long IRI naming many, and named by them": namingMany,
		"nodes in a graph of a long IRI":                      inGraph,
		"many values of a long predicate":                     longPredicate,
	} {
		short, long := timeOf(shape(4000, 25_000)), timeOf(shape(4000, 400_000))
		if ratio := float64(long) / float64(max(short, time.Microsecond)); ratio > 4 {
			t.Errorf("%s: an IRI 16 times as long took %.1f times as long (%v, %v)", name, ratio, short, long)
		}
	}
}
