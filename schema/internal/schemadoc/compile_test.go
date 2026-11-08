package schemadoc_test

import (
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/schema/internal/schemadoc"
)

func nested(depth int, leaf string) string {
	return strings.Repeat(`{"not":`, depth-1) + leaf + strings.Repeat(`}`, depth-1)
}

func allOf(n int, item string) string {
	return `{"allOf":[` + strings.TrimSuffix(strings.Repeat(item+",", n), ",") + `]}`
}

// A schema is compiled only when it is nested at most 64 deep: the
// library's work per subschema grows with its depth. SchemaStore's schemas
// nest at most 23 deep.
func TestCompile_RefusesASchemaNestedPastTheBound(t *testing.T) {
	if _, err := schemadoc.Compile([]byte(nested(64, `{}`))); err != nil {
		t.Errorf("64 deep: %v", err)
	}
	if _, err := schemadoc.Compile([]byte(nested(65, `{}`))); err == nil || !strings.Contains(err.Error(), "64") {
		t.Errorf("65 deep: %v, want an error naming the bound of 64", err)
	}
}

// The library keeps each subschema's JSON pointer, so a schema's pointers
// together are bounded by its size: a long name above many subschemas is
// refused, whose pointers would each repeat the name.
func TestCompile_RefusesPointersPastTheBound(t *testing.T) {
	long := `{"properties":{"` + strings.Repeat("k", 10000) + `":` + allOf(2000, `{}`) + `}}`
	if _, err := schemadoc.Compile([]byte(long)); err == nil || !strings.Contains(err.Error(), "pointer") {
		t.Errorf("a 10 KB name above 2,000 subschemas: %v, want an error naming the bound on pointers", err)
	}
	short := `{"properties":{"` + strings.Repeat("k", 10) + `":` + allOf(2000, `{}`) + `}}`
	if _, err := schemadoc.Compile([]byte(short)); err != nil {
		t.Errorf("a 10-byte name above 2,000 subschemas: %v", err)
	}
	// The library keeps a subschema's location escaped for a URL too, where
	// a byte outside a URL path's characters takes three: such names count
	// as escaped.
	for _, name := range []string{strings.Repeat("%", 20), strings.Repeat("あ", 7)} {
		escaped := `{"properties":{"` + name + `":` + allOf(2000, `{}`) + `}}`
		if _, err := schemadoc.Compile([]byte(escaped)); err == nil || !strings.Contains(err.Error(), "pointer") {
			t.Errorf("a name of about 20 bytes, each escaped as three, above 2,000 subschemas: %v, want an error naming the bound on pointers", err)
		}
		plain := `{"properties":{"` + strings.Repeat("k", len(name)) + `":` + allOf(2000, `{}`) + `}}`
		if _, err := schemadoc.Compile([]byte(plain)); err != nil {
			t.Errorf("the same with a name of as many letters: %v", err)
		}
	}
}

// The library keeps a subschema of about 1 KB for each object or boolean it
// compiles, so a schema holds at most 4,096 of them and one per 8 bytes:
// SchemaStore's schemas hold at most one value of any kind per 17.5 bytes.
// Numbers, strings and arrays are not counted: an enum's entries, for one,
// are not subschemas.
func TestCompile_RefusesMoreValuesThanTheBound(t *testing.T) {
	if _, err := schemadoc.Compile([]byte(allOf(10000, `{}`))); err == nil || !strings.Contains(err.Error(), "objects and booleans") {
		t.Errorf("10,000 empty subschemas in 30 KB: %v, want an error naming the bound on objects and booleans", err)
	}
	numbers := make([]string, 20000)
	for i := range numbers {
		numbers[i] = fmt.Sprint(i)
	}
	for name, doc := range map[string]string{
		"4,000 empty subschemas":                 allOf(4000, `{}`),
		"10,000 subschemas of a type, in 190 KB": allOf(10000, `{"type":"string"}`),
		"an enum of 20,000 numbers, in 109 KB":   `{"enum":[` + strings.Join(numbers, ",") + `]}`,
	} {
		if _, err := schemadoc.Compile([]byte(doc)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The library keeps the URL each $id resolves to, resolves each $ref
// against its base, and finds each subschema's resource by its base, so a
// long base above many relative $id or $ref, or many subschemas, is refused:
// each would be built or hashed at the base's length. The same under a short
// base compile.
func TestCompile_RefusesURLsPastTheBound(t *testing.T) {
	long := "https://e.x/" + strings.Repeat("a", 100000) + "/"
	for name, item := range map[string]func(i int) string{
		"relative $id":  func(i int) string { return fmt.Sprintf(`{"$id":"r%d"}`, i) },
		"relative $ref": func(i int) string { return fmt.Sprintf(`{"$ref":"#/$defs/d%d"}`, i%2) },
		// The library finds each subschema's resource by its base URL.
		"a subschema": func(int) string { return `{}` },
	} {
		items := make([]string, 2000)
		for i := range items {
			items[i] = item(i)
		}
		for base, refused := range map[string]bool{long: true, "https://e.x/": false} {
			doc := `{"$id":"` + base + `","$defs":{"d0":{},"d1":{}},"allOf":[` + strings.Join(items, ",") + `]}`
			_, err := schemadoc.Compile([]byte(doc))
			if refused && (err == nil || !strings.Contains(err.Error(), "pointers and URLs")) {
				t.Errorf("%s under a base of %d bytes: %v, want an error naming the bound on pointers and URLs", name, len(base), err)
			}
			if !refused && err != nil {
				t.Errorf("%s under a short base: %v", name, err)
			}
		}
	}
}

// The bound on URLs holds whichever keyword a draft resolves a URL by, and
// at the length the library writes the URL in: draft-04's id, draft
// 2019-09's $recursiveRef, a base the library escapes (each byte of あ as
// nine), and an $id a draft before 2019-09 ignores beside a $ref, which
// resolves against the base outside it.
func TestCompile_RefusesURLsPastTheBoundInEveryDraft(t *testing.T) {
	long := "https://e.x/" + strings.Repeat("a", 100000) + "/"
	items := func(item func(i int) string) string {
		parts := make([]string, 2000)
		for i := range parts {
			parts[i] = item(i)
		}
		return strings.Join(parts, ",")
	}
	for name, doc := range map[string]string{
		"draft-04 id":                       `{"$schema":"http://json-schema.org/draft-04/schema#","id":"` + long + `","allOf":[` + items(func(i int) string { return fmt.Sprintf(`{"id":"r%d"}`, i) }) + `]}`,
		"$recursiveRef":                     `{"$schema":"https://json-schema.org/draft/2019-09/schema","$id":"` + long + `","$recursiveAnchor":true,"allOf":[` + items(func(int) string { return `{"$recursiveRef":"#"}` }) + `]}`,
		"an escaped base":                   `{"$id":"https://e.x/` + strings.Repeat("あ", 50) + `/","allOf":[` + items(func(i int) string { return fmt.Sprintf(`{"$id":"r%d"}`, i) }) + `]}`,
		"an $id beside a $ref, in draft-07": `{"$schema":"http://json-schema.org/draft-07/schema#","$id":"` + long + `","definitions":{"d":{}},"allOf":[` + items(func(int) string { return `{"$id":"urn:x","$ref":"#/definitions/d"}` }) + `]}`,
	} {
		if _, err := schemadoc.Compile([]byte(doc)); err == nil || !strings.Contains(err.Error(), "pointers and URLs") {
			t.Errorf("%s: %v, want an error naming the bound on pointers and URLs", name, err)
		}
	}
}

// Compiling takes time about linear in the schema's size, for each shape whose
// work the library could make grow faster: many subschemas, embedded resources
// and references to them, references to values not otherwise compiled, dynamic
// anchors, arrays whose items hash alike under uniqueItems, and resources
// whose metaschema is the document itself, with a long $vocabulary. Some
// shapes grow two sizes at once, so that work in their product shows:
// references to a resource or an anchor at a long location, subschemas under a
// long base, a reference by an array index spelled long above a subtree as
// large, and object names sharing a prefix as long as there are names, which
// uniqueItems sorts and hashes (up to a factor of log n more, as
// ValidateWithBudget states). (Where that work is only hashing, as for the
// anchor and the base, it is too fast to show here: the bound on pointers and
// URLs counts the base for each subschema, and the library resolves each
// reference's URL once.) Each compiles but those refused by the metaschema,
// the bound on pointers and URLs, or a pointer that does not resolve. (Sixteen
// times the size takes about sixteen times as long; work in the square of the
// size, about 256 times.)
func TestCompile_IsLinear(t *testing.T) {
	timeOf := func(doc string, valid bool) time.Duration {
		best := time.Hour
		for range 3 {
			start := time.Now()
			_, err := schemadoc.Compile([]byte(doc))
			best = min(best, time.Since(start))
			if valid && err != nil {
				t.Fatalf("%.60s…: %v", doc, err)
			}
		}
		return best
	}
	items := func(n int, item func(i int) string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = item(i)
		}
		return strings.Join(parts, ",")
	}
	signs := func(i int) string {
		v := make([]string, 13)
		for b := range v {
			v[b] = map[bool]string{true: "1", false: "-1"}[i>>b&1 == 1]
		}
		return "[" + strings.Join(v, ",") + "]"
	}
	for name, c := range map[string]struct {
		shape func(n int) string
		valid bool
	}{
		"subschemas":         {func(n int) string { return allOf(n, `{"type":"string"}`) }, true},
		"subschemas 12 deep": {func(n int) string { return nested(12, allOf(n, `{"type":"string"}`)) }, true},
		"embedded resources": {func(n int) string {
			return `{"allOf":[` + items(n, func(i int) string { return fmt.Sprintf(`{"$id":"urn:x:%d"}`, i) }) + `]}`
		}, true},
		"references to them": {func(n int) string {
			return `{"$defs":{` + items(n, func(i int) string { return fmt.Sprintf(`"d%d":{"$id":"urn:x:%d"}`, i, i) }) + `},"allOf":[` + items(n, func(i int) string { return fmt.Sprintf(`{"$ref":"urn:x:%d"}`, i) }) + `]}`
		}, true},
		"references to values": {func(n int) string {
			return `{"x":{` + items(n, func(i int) string { return fmt.Sprintf(`"a%d":{}`, i) }) + `},"allOf":[` + items(n, func(i int) string { return fmt.Sprintf(`{"$ref":"#/x/a%d"}`, i) }) + `]}`
		}, true},
		"dynamic anchors": {func(n int) string {
			return `{"allOf":[` + items(n, func(i int) string { return fmt.Sprintf(`{"$dynamicAnchor":"a%d"}`, i) }) + `]}`
		}, true},
		"items that hash alike": {func(n int) string { return `{"required":[` + items(n/4, signs) + `]}` }, false},
		"references by id to a resource at a long location": {func(n int) string {
			return `{"$defs":{"` + strings.Repeat("a", 16*n) + `":{"$id":"urn:x","$defs":{"d":{}}}},"allOf":[` + items(n, func(i int) string { return []string{`{"$ref":"urn:x"}`, `{"$ref":"urn:x#/$defs/d"}`}[i%2] }) + `]}`
		}, true},
		"references to an anchor at a long location": {func(n int) string {
			return `{"$defs":{"` + strings.Repeat("a", 4*n) + `":{"$anchor":"a"}},"allOf":[` + items(n, func(int) string { return `{"$ref":"#a"}` }) + `]}`
		}, true},
		"subschemas under a long base": {func(n int) string {
			return `{"$id":"https://e.x/` + strings.Repeat("a", 4*n) + `/","$defs":{` + items(16, func(i int) string { return fmt.Sprintf(`"i%d":{"$id":"urn:i:%d"}`, i, i) }) + `},"allOf":[` + items(n, func(int) string { return `{}` }) + `]}`
		}, false},
		"a reference by a long index above a subtree": {func(n int) string {
			return `{"allOf":[` + allOf(n, `{"type":"string"}`) + `],"anyOf":[{"$ref":"#/allOf/` + strings.Repeat("0", 4*n) + `"}]}`
		}, false},
		"object names sharing a long prefix, hashed by uniqueItems": {func(n int) string {
			k := max(16, int(math.Sqrt(float64(n))*4))
			return `{"$schema":"http://json-schema.org/draft-04/schema#","enum":[{` + items(k, func(i int) string { return fmt.Sprintf(`"%s%06d":0`, strings.Repeat("a", k), i) }) + `},` + items(20, func(i int) string { return fmt.Sprint(i) }) + `]}`
		}, true},
		"a vocabulary, read for each resource": {func(n int) string {
			return `{"$schema":"https://json-schema.org/draft/2020-12/schema","$vocabulary":{"https://json-schema.org/draft/2020-12/vocab/core":true,` + items(n, func(i int) string { return fmt.Sprintf(`"urn:v:%d":false`, i) }) + `},"allOf":[` + items(n/2, func(i int) string {
				return fmt.Sprintf(`{"$id":"urn:r:%d","$schema":"urn:dplaax:schema-doc:document"}`, i)
			}) + `]}`
		}, true},
	} {
		t.Run(strings.ReplaceAll(name, " ", "_"), func(t *testing.T) {
			short, long := timeOf(c.shape(2000), c.valid), timeOf(c.shape(32000), c.valid)
			if ratio := float64(long) / float64(max(short, time.Millisecond)); ratio > 48 {
				t.Errorf("16 times the size took %.0f times as long (%v, %v)", ratio, short, long)
			}
		})
	}
}

// A schema the metaschema refuses is refused with its first failure, stated
// within the bound on failure text, however many failures it holds and
// however deep: the library's text lists every failure, indented per level.
func TestCompile_StatesAFailureWithinTheBound(t *testing.T) {
	for name, doc := range map[string]string{
		"deep":          nested(60, `{"type":5}`),
		"wide":          allOf(5000, `{"type":5}`),
		"deep and wide": nested(20, allOf(500, `{"type":5}`)),
		"a long name":   `{"properties":{"` + strings.Repeat("k", 2000) + `":{"type":5}}}`,
	} {
		_, err := schemadoc.Compile([]byte(doc))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if len(err.Error()) > 1024 || !strings.Contains(err.Error(), "fails enum") {
			t.Errorf("%s: %d bytes of error text (%.80s…), want at most 1,024 naming the keyword", name, len(err.Error()), err.Error())
		}
	}
}

// An array item is reached by one pointer: a $ref spelled with an index
// RFC 6901 does not write ("00", "+0", "-0", "01") is refused, where the
// library would compile the item's subtree again under each spelling, with
// its location as long as the spelling. The indices RFC 6901 writes resolve.
func TestCompile_RefusesAnArrayIndexRFC6901DoesNotWrite(t *testing.T) {
	for index, refused := range map[string]bool{"0": false, "1": false, "00": true, "01": true, "+0": true, "-0": true} {
		doc := `{"allOf":[` + nested(10, `{"type":"string"}`) + `,{}],"anyOf":[{"$ref":"#/allOf/` + index + `"}]}`
		_, err := schemadoc.Compile([]byte(doc))
		if refused && (err == nil || !strings.Contains(err.Error(), "not found")) {
			t.Errorf("%q: %v, want the pointer refused as not found", index, err)
		}
		if !refused && err != nil {
			t.Errorf("%q: %v", index, err)
		}
	}
}

// A compiled schema keeps at most what the bounds allow, about 170 MB for a
// schema of 1 MiB and as much per byte at any size (about 1 KB for each
// object or boolean, one per 8 bytes, and the pointers and locations within
// the bound on pointers and URLs), for the shapes that keep the most and
// those that would keep more than the bounds count: subschemas at the bound
// on objects, long names above subschemas, references by id or by an anchor
// to a long location, and references by spellings of an array index. Each
// is compiled or refused.
func TestCompile_KeepsAtMostWhatTheBoundsAllow(t *testing.T) {
	const size = 256 << 10
	pad := func(item string, width int) string { return item + strings.Repeat(" ", width-len(item)) }
	repeat := func(item string, n int) string { return strings.TrimSuffix(strings.Repeat(item+",", n), ",") }
	names := make([]string, 250)
	for i := range names {
		names[i] = fmt.Sprintf(`"%s%d":`, strings.Repeat("k", 900), i) + allOf(14, `{}`)
	}
	aliases := []string{}
	for _, a := range []string{"0", "00", "+0", "-0"} {
		for _, b := range []string{"0", "00", "+0", "-0"} {
			aliases = append(aliases, `{"$ref":"#/allOf/`+a+`/allOf/`+b+`"}`)
		}
	}
	for name, doc := range map[string]string{
		"subschemas at the bound on objects":     `{"allOf":[` + repeat(pad(`{}`, 7), size/8-16) + `]}`,
		"long names above subschemas":            `{"properties":{` + strings.Join(names, ",") + `}}`,
		"references by id to a long location":    `{"$defs":{"` + strings.Repeat("a", size/3) + `":{"$id":"urn:x"}},"allOf":[` + repeat(`{"$ref":"urn:x"}`, size*2/3/17-16) + `]}`,
		"references to an anchor, long location": `{"$defs":{"` + strings.Repeat("a", size/3) + `":{"$anchor":"a"}},"allOf":[` + repeat(`{"$ref":"#a"}`, size*2/3/14-16) + `]}`,
		"references by spellings of an index":    `{"allOf":[{"allOf":[` + allOf(size/40, `{"type":"string"}`) + `]}],"anyOf":[` + strings.Join(aliases, ",") + `]}`,
		"a reference by a long index":            `{"allOf":[` + allOf(size/40, `{"type":"string"}`) + `],"anyOf":[{"$ref":"#/allOf/` + strings.Repeat("0", size/2) + `"}]}`,
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		compiled, err := schemadoc.Compile([]byte(doc))
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(compiled)
		kept := int64(after.HeapAlloc) - int64(before.HeapAlloc)
		if limit := int64(170e6) * int64(len(doc)) >> 20; kept > limit {
			t.Errorf("%s: %d bytes keep %d bytes compiled (refused: %v), beyond %d", name, len(doc), kept, err != nil, limit)
		}
	}
}

// A compile error carries no character that is not printable, from the
// library's text or from the schema it quotes: an external reference, an
// anchor not found, and a pointer not found, each holding U+202E, which
// would reorder the text after it, are written escaped.
func TestCompile_EscapesWhatItQuotesInAnError(t *testing.T) {
	for name, ref := range map[string]string{
		"an external reference": `urn:x‮y`,
		"an anchor not found":   `#a‮b`,
		"a pointer not found":   `#/a‮b`,
	} {
		_, err := schemadoc.Compile([]byte(`{"$ref":"` + ref + `"}`))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if strings.ContainsRune(err.Error(), '‮') {
			t.Errorf("%s: %q holds U+202E as it is", name, err)
		}
	}
}
