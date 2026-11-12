// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema_test

// Tests of the local patches to how v6.0.3 compiles a schema (README.md).

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/jsonschema"
)

// A subschema is admitted whole or not at all: one a reference reaches
// outside the schema's keywords is read when the reference is compiled, and
// is refused by the metaschema there; had that read stayed in the compiler,
// compiling the schema again would skip the subschema's check. Compiling
// again fails the same way.
func TestCompile_AdmitsASubschemaWholeOrNotAtAll(t *testing.T) {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"$ref":"#/x/bad","x":{"bad":{"type":5}}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	_, first := c.Compile("schema.json")
	if first == nil {
		t.Fatal("a reference to a subschema the metaschema refuses compiled")
	}
	if _, again := c.Compile("schema.json"); again == nil || again.Error() != first.Error() {
		t.Errorf("compiled again: %v, want %v", again, first)
	}
}

func compiler(t *testing.T, schema string) *jsonschema.Compiler {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	return c
}

// CompileWithBudget checks a schema against its metaschema within its
// budget: the same schema compiles within a budget that pays for the check
// and is refused, with a *BudgetExceededError, within one that does not.
func TestCompileWithBudget_ChecksTheSchemaWithinItsBudget(t *testing.T) {
	schema := `{"allOf":[` + strings.TrimSuffix(strings.Repeat(`{"type":"string"},`, 200), ",") + `]}`
	if _, err := compiler(t, schema).CompileWithBudget("schema.json", 1<<30); err != nil {
		t.Fatalf("a budget of 2^30: %v", err)
	}
	_, err := compiler(t, schema).CompileWithBudget("schema.json", 100)
	var be *jsonschema.BudgetExceededError
	if !errors.As(err, &be) || be.Budget != 100 {
		t.Errorf("a budget of 100 steps: %v, want a *BudgetExceededError of 100", err)
	}
	if _, err := compiler(t, schema).Compile("schema.json"); err != nil {
		t.Errorf("Compile, without a budget: %v", err)
	}
}

func compileString(t *testing.T, schema string) (*jsonschema.Schema, error) {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	return c.Compile("schema.json")
}

// A JSON pointer reads an array index only as RFC 6901 §4 writes one, "0"
// or digits not beginning with 0, so an item has one pointer: read as a
// number, "00", "+0" and "-0" would each reach the first item, and a
// reference by each would compile its subtree again.
func TestCompile_ReadsAnArrayIndexAsRFC6901WritesIt(t *testing.T) {
	for index, found := range map[string]bool{
		"0": true, "1": true, "10": true,
		"00": false, "01": false, "+0": false, "-0": false, "+1": false, " 1": false, "1 ": false,
	} {
		items := make([]string, 11)
		for i := range items {
			items[i] = `{"type":"string"}`
		}
		_, err := compileString(t, `{"anyOf":[{"$ref":"#/allOf/`+index+`"}],"allOf":[`+strings.Join(items, ",")+`]}`)
		var notFound *jsonschema.JSONPointerNotFoundError
		if found && err != nil {
			t.Errorf("%q: %v", index, err)
		}
		if !found && !errors.As(err, &notFound) {
			t.Errorf("%q: %v, want a JSONPointerNotFoundError", index, err)
		}
	}
}

// A reference is resolved once for each URL it resolves to, not once for
// each reference: n references to a resource at a location 4n bytes long
// allocate about n times as much as one, not n squared, where resolving each
// would build the resource's location again.
func TestCompile_ResolvesEachURLOnce(t *testing.T) {
	refs := func(n int, ref string) string {
		items := make([]string, n)
		for i := range items {
			items[i] = fmt.Sprintf(`{"$ref":%q}`, ref)
		}
		return strings.Join(items, ",")
	}
	for name, shape := range map[string]func(n int) string{
		"by id": func(n int) string {
			return `{"$defs":{"` + strings.Repeat("a", 4*n) + `":{"$id":"urn:x"}},"allOf":[` + refs(n, "urn:x") + `]}`
		},
		"by id and a pointer": func(n int) string {
			return `{"$defs":{"` + strings.Repeat("a", 4*n) + `":{"$id":"urn:x","$defs":{"d":{}}}},"allOf":[` + refs(n, "urn:x#/$defs/d") + `]}`
		},
	} {
		allocated := func(n int) uint64 {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			if _, err := compileString(t, shape(n)); err != nil {
				t.Fatalf("%s, %d: %v", name, n, err)
			}
			runtime.ReadMemStats(&after)
			return after.TotalAlloc - before.TotalAlloc
		}
		short, long := allocated(2000), allocated(16000)
		if ratio := float64(long) / float64(short); ratio > 16 {
			t.Errorf("%s: 8 times the references and the location allocated %.0f times as much (%d, %d)", name, ratio, short, long)
		}
	}
}

// A number keyword whose number the compiler cannot read fails the compile
// with a *LargeNumberError at the keyword, under draft 2020-12 and under draft
// 4 (where exclusiveMinimum and exclusiveMaximum are booleans that make
// minimum and maximum exclusive): it is not compiled as if the keyword were
// absent. A number it can read is still a bound.
func TestCompile_RefusesANumberKeywordItCannotRead(t *testing.T) {
	const draft4 = `"$schema": "http://json-schema.org/draft-04/schema#", `
	refused := func(t *testing.T, label string, err error, keyword string) {
		t.Helper()
		var lne *jsonschema.LargeNumberError
		if !errors.As(err, &lne) || !strings.HasSuffix(lne.URL, "#"+keyword) {
			t.Errorf("%s: %v, want a *LargeNumberError at %s", label, err, keyword)
		}
	}
	for _, c := range []struct{ schema, keyword string }{
		{`{"minimum": ` + large + `}`, "/minimum"},
		{`{"maximum": -` + large + `}`, "/maximum"},
		{`{"exclusiveMinimum": ` + large + `}`, "/exclusiveMinimum"},
		{`{"exclusiveMaximum": -` + large + `}`, "/exclusiveMaximum"},
		{`{"properties": {"a": {"minimum": ` + large + `}}}`, "/properties/a/minimum"},
		{`{` + draft4 + `"minimum": ` + large + `}`, "/minimum"},
		{`{` + draft4 + `"maximum": -` + large + `}`, "/maximum"},
		{`{` + draft4 + `"minimum": ` + large + `, "exclusiveMinimum": true}`, "/minimum"},
		{`{` + draft4 + `"maximum": -` + large + `, "exclusiveMaximum": true}`, "/maximum"},
	} {
		_, err := compile(c.schema)
		refused(t, c.schema, err, c.keyword)
	}

	// The metaschema refuses such a multipleOf, but the library does not check
	// a schema located below json-schema.org against it: there the compiler
	// alone refuses it.
	const loc = "https://json-schema.org/number-keyword.json"
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"multipleOf": ` + large + `}`))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(loc, doc); err != nil {
		t.Fatal(err)
	}
	_, err = c.Compile(loc)
	refused(t, "multipleOf below json-schema.org", err, "/multipleOf")

	sch, err := compile(`{"minimum": 1e1000000}`)
	if err != nil {
		t.Fatal(err)
	}
	if sch.Validate(5) == nil {
		t.Error(`{"minimum": 1e1000000} accepts 5`)
	}
}

// An integer keyword reads an integer above math.MaxInt as math.MaxInt, and
// one below math.MinInt as math.MinInt, under every draft that has it; a
// number big.Rat cannot read is a *LargeNumberError at the keyword, and a
// value that is not an integer a *NonIntegerError.
func TestCompile_ReadsAnIntegerKeywordBeyondIntAsTheNearestInt(t *testing.T) {
	const above, below = "18446744073709551616", "-18446744073709551616" // ±2^64
	for _, c := range []struct {
		schema string
		field  func(*jsonschema.Schema) *int
		want   int
	}{
		{`{"minLength": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MinLength }, math.MaxInt},
		{`{"minLength": 9223372036854775808}`, func(s *jsonschema.Schema) *int { return s.MinLength }, math.MaxInt},
		{`{"maxLength": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MaxLength }, math.MaxInt},
		{`{"minItems": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MinItems }, math.MaxInt},
		{`{"maxItems": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MaxItems }, math.MaxInt},
		{`{"minProperties": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MinProperties }, math.MaxInt},
		{`{"maxProperties": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MaxProperties }, math.MaxInt},
		{`{"contains": {}, "minContains": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MinContains }, math.MaxInt},
		{`{"contains": {}, "maxContains": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MaxContains }, math.MaxInt},
		{`{"$schema": "http://json-schema.org/draft-04/schema#", "minLength": ` + above + `}`, func(s *jsonschema.Schema) *int { return s.MinLength }, math.MaxInt},
		{`{"minLength": 3}`, func(s *jsonschema.Schema) *int { return s.MinLength }, 3},
		// 2^32 lies within int64 and above a 32-bit int.
		{`{"minLength": 4294967296}`, func(s *jsonschema.Schema) *int { return s.MinLength }, int(min(int64(1)<<32, int64(math.MaxInt)))},
	} {
		sch, err := compile(c.schema)
		if err != nil {
			t.Errorf("%s: %v", c.schema, err)
			continue
		}
		if got := c.field(sch); got == nil || *got != c.want {
			t.Errorf("%s: read as %s, want %d", c.schema, intText(got), c.want)
		}
	}

	// The metaschema refuses an integer keyword below zero and a number it
	// cannot read, but the library does not check a schema located below
	// json-schema.org against it: there the compiler alone reads them.
	compileAt := func(schema string) (*jsonschema.Schema, error) {
		const loc = "https://json-schema.org/integer-keyword.json"
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
		if err != nil {
			return nil, err
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(loc, doc); err != nil {
			return nil, err
		}
		return c.Compile(loc)
	}
	for _, c := range []struct {
		value string
		want  int
	}{
		{below, math.MinInt},
		// -2^32 lies within int64 and below a 32-bit int.
		{"-4294967296", int(max(-int64(1)<<32, int64(math.MinInt)))},
	} {
		if sch, err := compileAt(`{"maxLength": ` + c.value + `}`); err != nil || sch.MaxLength == nil || *sch.MaxLength != c.want {
			t.Errorf("maxLength %s below json-schema.org: %v, read as %s, want %d", c.value, err, intText(maxLengthOf(sch)), c.want)
		}
	}
	for _, keyword := range []string{"minLength", "maxItems", "minProperties"} {
		_, err := compileAt(`{"` + keyword + `": ` + large + `}`)
		var lne *jsonschema.LargeNumberError
		if !errors.As(err, &lne) || !strings.HasSuffix(lne.URL, "#/"+keyword) {
			t.Errorf("%s %s below json-schema.org: %v, want a *LargeNumberError at /%s", keyword, large, err, keyword)
		}
	}

	// The metaschema refuses an integer keyword whose value is not an
	// integer; below json-schema.org the compiler alone refuses it, with a
	// *NonIntegerError at the keyword, rather than reading it as absent. A
	// number with no fraction is an integer.
	for _, c := range []struct{ keyword, value string }{
		{"minLength", "1.5"},
		{"maxLength", "-0.5"},
		{"minItems", "2.5"},
		{"maxItems", `"5"`},
		{"minProperties", "true"},
		{"maxProperties", "null"},
		{"minContains", "[1]"},
		{"maxContains", `{"a": 1}`},
	} {
		schema := `{"` + c.keyword + `": ` + c.value + `}`
		if c.keyword == "minContains" || c.keyword == "maxContains" {
			schema = `{"contains": {}, "` + c.keyword + `": ` + c.value + `}`
		}
		_, err := compileAt(schema)
		var nie *jsonschema.NonIntegerError
		if !errors.As(err, &nie) || !strings.HasSuffix(nie.URL, "#/"+c.keyword) {
			t.Errorf("%s below json-schema.org: %v, want a *NonIntegerError at /%s", schema, err, c.keyword)
		}
	}
	if sch, err := compileAt(`{"minLength": 2.0}`); err != nil || sch.MinLength == nil || *sch.MinLength != 2 {
		t.Errorf(`{"minLength": 2.0} below json-schema.org: %v, want it read as 2`, err)
	}
	// Under draft 4 and draft 2019-09 too.
	for _, schema := range []string{
		`{"$schema": "http://json-schema.org/draft-04/schema#", "minLength": 1.5}`,
		`{"$schema": "https://json-schema.org/draft/2019-09/schema", "contains": {}, "minContains": 1.5}`,
	} {
		var nie *jsonschema.NonIntegerError
		if _, err := compileAt(schema); !errors.As(err, &nie) {
			t.Errorf("%s below json-schema.org: %v, want a *NonIntegerError", schema, err)
		}
	}
	// A document made of Go values: a float64 with a fraction is refused.
	c := jsonschema.NewCompiler()
	const loc = "https://json-schema.org/integer-keyword-go.json"
	if err := c.AddResource(loc, map[string]any{"minLength": 1.5}); err != nil {
		t.Fatal(err)
	}
	var nie *jsonschema.NonIntegerError
	if _, err := c.Compile(loc); !errors.As(err, &nie) {
		t.Errorf("a float64 1.5 below json-schema.org: %v, want a *NonIntegerError", err)
	}
	// The error writes the value as JSON writes it, so a string reads as one.
	if _, err := compileAt(`{"maxItems": "5"}`); err == nil || !strings.Contains(err.Error(), `"5"`) {
		t.Errorf(`{"maxItems": "5"}: %v, want the value written as the string "5"`, err)
	}
	// Elsewhere, the metaschema refuses such a value before the compiler
	// reads the keyword.
	if _, err := compile(`{"minLength": 1.5}`); err == nil || errors.As(err, &nie) {
		t.Errorf(`{"minLength": 1.5}: %v, want the metaschema's refusal`, err)
	}
}

// intText is *p, or "nil".
func intText(p *int) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

// maxLengthOf is s.MaxLength, or nil for no schema.
func maxLengthOf(s *jsonschema.Schema) *int {
	if s == nil {
		return nil
	}
	return s.MaxLength
}
