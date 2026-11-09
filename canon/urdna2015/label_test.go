package urdna2015

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/piprate/json-gold/ld"
)

// jsonGoldNQuads is the reference: json-gold's own URDNA2015 over N-Quads.
func jsonGoldNQuads(t testing.TB, nq string) string {
	t.Helper()
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.InputFormat = "application/n-quads"
	opts.Format = "application/n-quads"
	out, err := ld.NewJsonLdProcessor().Normalize(nq, opts)
	if err != nil {
		t.Fatalf("json-gold: %v", err)
	}
	return out.(string)
}

func labelNQuads(t testing.TB, nq string, base, perQuad int) (string, int, error) {
	t.Helper()
	ds, err := ld.ParseNQuads(nq)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return label(ds, base, perQuad)
}

// unbounded is a budget no test dataset reaches.
const unbounded = math.MaxInt

// checkAgainstJSONGold compares the labelling with json-gold's. Where two
// blank nodes no hash tells apart are not interchangeable, json-gold's answer
// depends on map order, so the labelling must be one of its answers.
func checkAgainstJSONGold(t *testing.T, nq string) {
	t.Helper()
	got, _, err := labelNQuads(t, nq, unbounded, 0)
	if err != nil {
		t.Fatalf("label: %v", err)
	}
	seen := map[string]bool{}
	for range 32 {
		want := jsonGoldNQuads(t, nq)
		if got == want {
			return
		}
		seen[want] = true
	}
	for want := range seen {
		t.Errorf("labelling differs from every json-gold answer for\n%s--- got ---\n%s--- json-gold ---\n%s", nq, got, want)
		return
	}
}

func clique(k int, prefix string) string {
	var b strings.Builder
	for i := range k {
		for j := range k {
			if i != j {
				fmt.Fprintf(&b, "_:%s%d <http://ex/p> _:%s%d .\n", prefix, i, prefix, j)
			}
		}
	}
	return b.String()
}

func ring(k int, prefix string) string {
	var b strings.Builder
	for i := range k {
		fmt.Fprintf(&b, "_:%s%d <http://ex/p> _:%s%d .\n", prefix, i, prefix, (i+1)%k)
	}
	return b.String()
}

func copies(n int, shape func(int, string) string, k int) string {
	var b strings.Builder
	for c := range n {
		b.WriteString(shape(k, fmt.Sprintf("c%dx", c)))
	}
	return b.String()
}

// The labelling is json-gold's on datasets of every shape the algorithm
// branches on: unique and shared first-degree hashes, cliques and rings,
// named and blank graphs, the same triple in two graphs, and literals with
// escapes, languages and datatypes.
func TestLabel_MatchesJSONGold(t *testing.T) {
	cases := []string{
		"",
		"<http://ex/s> <http://ex/p> \"v\" .\n",
		"_:a <http://ex/p> _:b .\n_:b <http://ex/q> \"x\" .\n",
		clique(2, "b"), clique(3, "b"), clique(4, "b"), clique(5, "b"),
		ring(3, "b"), ring(7, "b"), ring(16, "b"),
		list(2, "b"), list(9, "b"), hubs(3, "b"),
		copies(3, clique, 3), copies(4, ring, 5),
		"_:a <http://ex/p> _:b <http://ex/g> .\n_:a <http://ex/p> _:b <http://ex/h> .\n",
		"_:a <http://ex/p> _:b _:g .\n_:b <http://ex/p> _:a _:g .\n_:g <http://ex/p> \"g\" .\n",
		"_:a <http://ex/p> \"tab\\there \\\"q\\\" back\\\\slash\\nline\\r\" .\n_:b <http://ex/p> \"x\"@en-GB .\n_:c <http://ex/p> \"1\"^^<http://www.w3.org/2001/XMLSchema#integer> .\n",
		"<http://ex/s> <http://ex/items> _:i1 .\n<http://ex/s> <http://ex/items> _:i2 .\n_:i1 <http://ex/price> _:p1 .\n_:i2 <http://ex/price> _:p2 .\n_:p1 <http://ex/amount> \"1\" .\n_:p2 <http://ex/amount> \"1\" .\n",
	}
	for _, nq := range cases {
		checkAgainstJSONGold(t, nq)
	}
}

// A blank node whose label already looks canonical is relabelled like any
// other. json-gold leaves it, so its canonical label can collide with an
// issued one, and its output then depends on map order.
func TestLabel_RelabelsALabelThatLooksCanonical(t *testing.T) {
	got, _, err := labelNQuads(t, "_:c14n0 <http://ex/p> _:x .\n_:x <http://ex/p> _:c14n0 .\n", unbounded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "_:c14n0 <http://ex/p> _:c14n1 .\n_:c14n1 <http://ex/p> _:c14n0 .\n"; got != want {
		t.Errorf("got\n%swant\n%s", got, want)
	}
}

// hubs is two indistinguishable blank nodes, each the subject of k
// indistinguishable leaves.
func hubs(k int, prefix string) string {
	var b strings.Builder
	for h := range 2 {
		for i := range k {
			fmt.Fprintf(&b, "_:%sh%d <http://ex/p> _:%sl%d_%d .\n", prefix, h, prefix, h, i)
		}
	}
	return b.String()
}

// list is an RDF list of k equal values: its middle nodes are
// indistinguishable by their own quads.
func list(k int, prefix string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<http://ex/s> <http://ex/list> _:%s0 .\n", prefix)
	for i := range k {
		fmt.Fprintf(&b, "_:%s%d <http://ex/first> \"a\" .\n", prefix, i)
		if i+1 < k {
			fmt.Fprintf(&b, "_:%s%d <http://ex/rest> _:%s%d .\n", prefix, i, prefix, i+1)
		} else {
			fmt.Fprintf(&b, "_:%s%d <http://ex/rest> <http://ex/nil> .\n", prefix, i)
		}
	}
	return b.String()
}

// fuzzDataset spells bytes as a small dataset: up to 6 blank nodes, so that
// json-gold, which has no bound, stays quick.
func fuzzDataset(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	blanks := int(data[0]%6) + 1
	node := func(b byte) string {
		switch b % 8 {
		case 5:
			return fmt.Sprintf("_:g%d", int(b/8)%2)
		case 6:
			return "<http://ex/n>"
		case 7:
			return "<http://ex/m>"
		}
		return fmt.Sprintf("_:b%d", int(b)%blanks)
	}
	objects := []string{`"v"`, `"v"@en`, `"1"^^<http://ex/t>`, "\"a\\tb\\\"c\\\\\"", `""`}
	var b strings.Builder
	for i := 1; i+3 < len(data) && i < 4*40; i += 4 {
		s, p, o, g := data[i], data[i+1], data[i+2], data[i+3]
		subject := node(s)
		if strings.HasPrefix(subject, "<") && s%2 == 0 {
			subject = "_:b0"
		}
		object := node(o)
		if o%5 == 4 {
			object = objects[int(o/5)%len(objects)]
		}
		graph := ""
		switch g % 4 {
		case 1:
			graph = " <http://ex/g>"
		case 2:
			graph = fmt.Sprintf(" _:g%d", int(g/4)%2)
		}
		fmt.Fprintf(&b, "%s <http://ex/p%d> %s%s .\n", subject, p%3, object, graph)
	}
	return b.String()
}

func FuzzLabelMatchesJSONGold(f *testing.F) {
	f.Add([]byte{5, 0, 0, 1, 0, 1, 0, 2, 0, 2, 0, 3, 0, 3, 0, 0, 0})
	f.Add([]byte{3, 0, 1, 1, 2, 1, 1, 2, 2, 2, 1, 0, 1, 0, 2, 4, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		nq := fuzzDataset(data)
		if _, err := ld.ParseNQuads(nq); err != nil {
			t.Skip()
		}
		checkAgainstJSONGold(t, nq)
	})
}

// A sweep of generated datasets, the fuzz target's shapes, labels as json-gold
// labels them on every run of the tests.
func TestLabel_MatchesJSONGoldOnGeneratedDatasets(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 400 {
		data := make([]byte, 8+r.IntN(120))
		for i := range data {
			data[i] = byte(r.Uint32())
		}
		nq := fuzzDataset(data)
		if _, err := ld.ParseNQuads(nq); err != nil {
			continue
		}
		checkAgainstJSONGold(t, nq)
	}
}

// Datasets of indistinguishable blank nodes, which json-gold takes tens of
// milliseconds to seconds to label or does not finish, are refused within
// the bound; so is a small clique whose predicate is long, as hashing it is
// work too.
func TestLabel_RefusesDatasetsTooComplexToLabel(t *testing.T) {
	for name, nq := range map[string]string{
		"clique of 8":      clique(8, "b"),
		"clique of 12":     clique(12, "b"),
		"ring of 256":      ring(256, "b"),
		"50 cliques of 5":  copies(50, clique, 5),
		"200 cliques of 4": copies(200, clique, 4),
		"20 rings of 64":   copies(20, ring, 64),
	} {
		_, work, err := labelNQuads(t, nq, labelWorkBase, labelWorkPerQuad)
		if !errors.Is(err, ErrTooComplex) {
			t.Errorf("%s: err = %v, want ErrTooComplex (work %d)", name, err, work)
		}
	}
}

// ordinaryDocuments are credentials a relying party meets, including the
// shapes in which anonymous objects repeat.
func ordinaryDocuments(t testing.TB) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/w3c-ex8-credential.json")
	if err != nil {
		t.Fatal(err)
	}
	var w3c map[string]any
	if err := json.Unmarshal(raw, &w3c); err != nil {
		t.Fatal(err)
	}
	credential := func(subject map[string]any) map[string]any {
		return map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            "did:example:issuer",
			"validFrom":         "2026-01-01T00:00:00Z",
			"credentialSubject": subject,
		}
	}
	repeat := func(n int, v func(int) any) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = v(i)
		}
		return out
	}
	item := func(int) any {
		return map[string]any{"name": "Widget", "price": map[string]any{"amount": "1", "currency": "EUR"}}
	}
	return map[string]map[string]any{
		"W3C vc-di-eddsa Example 8": w3c,
		"20 distinct line items": credential(map[string]any{"items": repeat(20, func(i int) any {
			return map[string]any{"name": fmt.Sprintf("Widget %d", i), "price": map[string]any{"amount": fmt.Sprint(i)}}
		})}),
		"50 identical line items, each with an anonymous price": credential(map[string]any{"items": repeat(50, item)}),
		"200 identical anonymous tags":                          credential(map[string]any{"tags": repeat(200, func(int) any { return map[string]any{"label": "x"} })}),
		"a chain of 12 identical anonymous objects": credential(func() map[string]any {
			v := map[string]any{"label": "end"}
			for range 12 {
				v = map[string]any{"next": v}
			}
			return v
		}()),
		"a list of 16 identical strings": func() map[string]any {
			doc := credential(map[string]any{"steps": repeat(16, func(int) any { return "pass" })})
			doc["@context"] = append(doc["@context"].([]any), map[string]any{
				"steps": map[string]any{"@id": "https://example.org/steps", "@container": "@list"},
			})
			return doc
		}(),
		"two identical anonymous evidence entries with nested parts": credential(map[string]any{"evidence": repeat(2, func(int) any {
			return map[string]any{"kind": "inspection", "part": map[string]any{"serial": "unknown"}, "site": map[string]any{"country": "JP"}}
		})}),
		"two identical anonymous evidence entries, each listing 6 identical parts": credential(map[string]any{"evidence": repeat(2, func(int) any {
			return map[string]any{"kind": "inspection", "parts": repeat(6, func(int) any { return map[string]any{"serial": "unknown"} })}
		})}),
		"a list of 40 identical strings": func() map[string]any {
			doc := credential(map[string]any{"steps": repeat(40, func(int) any { return "pass" })})
			doc["@context"] = append(doc["@context"].([]any), map[string]any{
				"steps": map[string]any{"@id": "https://example.org/steps", "@container": "@list"},
			})
			return doc
		}(),
	}
}

func documentDataset(t testing.TB, c *Canonicalizer, doc map[string]any) *ld.RDFDataset {
	t.Helper()
	proc := ld.NewJsonLdProcessor()
	opts := c.options()
	expanded, err := proc.Expand(doc, opts)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	ds, err := datasetOf(proc, expanded, opts)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// testContexts serves the W3C contexts and reads a document's own, as the
// corpus writes many: the forms are held the same either way, and the
// default's refusal of a document's own context is tested on its own
// (localcontexts_test.go).
func testContexts(t testing.TB) *Canonicalizer {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return NewCanonicalizer(map[string][]byte{
		"https://www.w3.org/ns/credentials/v2":          read("credentials-v2.jsonld"),
		"https://www.w3.org/ns/credentials/examples/v2": read("examples-v2.jsonld"),
	}, WithLocalContexts())
}

// Ordinary credentials, anonymous repeats included, take at most half of the
// bound, and label as json-gold labels them.
func TestLabel_OrdinaryDocumentsStayWellWithinTheBound(t *testing.T) {
	c := testContexts(t)
	for name, doc := range ordinaryDocuments(t) {
		ds := documentDataset(t, c, doc)
		quads := 0
		for _, g := range ds.Graphs {
			quads += len(g)
		}
		out, work, err := label(ds, unbounded, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		budget := labelWorkBase + labelWorkPerQuad*quads
		t.Logf("%s: %d quads, work %d, bound %d", name, quads, work, budget)
		if 2*work > budget {
			t.Errorf("%s: work %d is more than half of the bound %d", name, work, budget)
		}
		if want := jsonGoldDocument(t, c, doc); out != want {
			t.Errorf("%s: labelling differs from json-gold:\n--- got ---\n%s--- json-gold ---\n%s", name, out, want)
		}
	}
}

// jsonGoldDocument is the reference for a JSON-LD document: json-gold's
// Normalize over the expanded document, with the canonicalizer's options.
func jsonGoldDocument(t testing.TB, c *Canonicalizer, doc map[string]any) string {
	t.Helper()
	proc := ld.NewJsonLdProcessor()
	opts := c.options()
	expanded, err := proc.Expand(doc, opts)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"
	out, err := proc.Normalize(expanded, opts)
	if err != nil {
		t.Fatalf("json-gold: %v", err)
	}
	return out.(string)
}

// A dataset too complex to label is refused at a cost that grows with its
// size, not with how alike its blank nodes are: the time per quad stays flat
// from 400 to 40000 quads, where json-gold does not finish the smallest.
func BenchmarkLabel_RefusesWithinTheBound(b *testing.B) {
	for _, k := range []int{200, 2000, 20000} {
		nq := hubs(k, "b")
		b.Run(fmt.Sprintf("hubs/%d", k), func(b *testing.B) {
			for b.Loop() {
				if _, _, err := labelNQuads(b, nq, labelWorkBase, labelWorkPerQuad); !errors.Is(err, ErrTooComplex) {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(2*k), "ns/quad")
		})
	}
	for name, nq := range map[string]string{
		"clique/8":                 clique(8, "b"),
		"ring/256":                 ring(256, "b"),
		"clique/6/predicate/100KB": strings.ReplaceAll(clique(6, "b"), "http://ex/p", "urn:x:"+strings.Repeat("p", 100_000)),
	} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, _, err := labelNQuads(b, nq, labelWorkBase, labelWorkPerQuad); !errors.Is(err, ErrTooComplex) {
					b.Fatal(err)
				}
			}
		})
	}
}
