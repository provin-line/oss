// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema_test

// Work budget: tests of the local patch to v6.0.3 (see budget.go).

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/jsonschema"
	"golang.org/x/text/message"
)

func compileBudget(t *testing.T, schema string, content bool) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if content {
		c.AssertContent()
	}
	if err := c.AddResource("schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func instance(t *testing.T, s string) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func exceeded(err error) bool {
	var be *jsonschema.BudgetExceededError
	return errors.As(err, &be)
}

// least returns the smallest budget within which ValidateWithBudget finishes:
// the steps a validation takes do not depend on its budget.
func least(t *testing.T, sch *jsonschema.Schema, v any) int64 {
	t.Helper()
	lo, hi := int64(0), int64(1)<<40
	if exceeded(sch.ValidateWithBudget(v, hi)) {
		t.Fatal("no budget below 2^40 suffices")
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if exceeded(sch.ValidateWithBudget(v, mid)) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// Within its budget, ValidateWithBudget gives Validate's answer; one step
// less is a *BudgetExceededError, never an answer.
func TestValidateWithBudget_AnswersAsValidateOrNotAtAll(t *testing.T) {
	for _, tc := range []struct{ schema, value string }{
		{`true`, `1`},
		{`false`, `1`},
		{`{"type":"array","items":{"type":"integer"}}`, `[1,2,3]`},
		{`{"type":"array","items":{"type":"integer"}}`, `[1,"2",3]`},
		{`{"properties":{"a":{"enum":[{"x":[1,2]},{"x":[1,3]}]}}}`, `{"a":{"x":[1,3]}}`},
		{`{"const":{"x":[1,2]}}`, `{"x":[1,2,3]}`},
		{`{"uniqueItems":true}`, `[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,1]`},
		{`{"uniqueItems":true}`, `[[1],[2],[3]]`},
		{`{"not":{"type":"array","items":{"type":"string"}}}`, `[1,2,3]`},
		{`{"anyOf":[{"items":{"type":"string"}},{"items":{"type":"integer"}}]}`, `[1,2,3]`},
		{`{"propertyNames":{"maxLength":3}}`, `{"abc":1,"abcd":2}`},
		{`{"patternProperties":{"^a":{"type":"integer"}},"additionalProperties":false}`, `{"aa":1,"ab":2}`},
		{`{"type":"string","pattern":"^a+$"}`, `"aaaa"`},
	} {
		sch := compileBudget(t, tc.schema, false)
		v := instance(t, tc.value)
		want := sch.Validate(v)
		n := least(t, sch, v)
		got := sch.ValidateWithBudget(v, n)
		if (got == nil) != (want == nil) {
			t.Errorf("%s on %s: within %d steps %v, Validate %v", tc.schema, tc.value, n, got, want)
		}
		if n > 0 {
			if err := sch.ValidateWithBudget(v, n-1); !exceeded(err) {
				t.Errorf("%s on %s: within %d steps %v, want a *BudgetExceededError", tc.schema, tc.value, n-1, err)
			}
		}
	}
}

// A budget that runs out inside not, anyOf or oneOf is reported as such,
// not read as a failed branch.
func TestValidateWithBudget_ExhaustionIsNotABranchResult(t *testing.T) {
	long := `[` + strings.Repeat(`1,`, 50) + `1]`
	for _, schema := range []string{
		`{"not":{"items":{"type":"integer"}}}`,
		`{"not":{"items":{"type":"string"}}}`,
		`{"anyOf":[{"items":{"type":"string"}},true]}`,
		`{"oneOf":[{"items":{"type":"string"}},true]}`,
		`{"if":{"items":{"type":"integer"}},"then":true,"else":false}`,
	} {
		sch := compileBudget(t, schema, false)
		if err := sch.ValidateWithBudget(instance(t, long), 10); !exceeded(err) {
			t.Errorf("%s: %v, want a *BudgetExceededError", schema, err)
		}
	}
}

// The budget is shared with a schema applied to decoded content.
func TestValidateWithBudget_CountsContentSchema(t *testing.T) {
	sch := compileBudget(t, `{"contentMediaType":"application/json","contentSchema":{"items":{"type":"integer"}}}`, true)
	v := instance(t, `"[`+strings.Repeat(`1,`, 50)+`1]"`)
	if err := sch.Validate(v); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := sch.ValidateWithBudget(v, 110); !exceeded(err) {
		t.Errorf("within 110 steps: %v, want a *BudgetExceededError", err)
	}
	if err := sch.ValidateWithBudget(v, 1000); err != nil {
		t.Errorf("within 1000 steps: %v", err)
	}
}

// A budget of 0 or less admits no work, and the error names the budget.
func TestValidateWithBudget_NoBudget(t *testing.T) {
	sch := compileBudget(t, `true`, false)
	for _, n := range []int64{0, -1} {
		err := sch.ValidateWithBudget(instance(t, `1`), n)
		var be *jsonschema.BudgetExceededError
		if !errors.As(err, &be) || be.Budget != n {
			t.Errorf("budget %d: %v, want a *BudgetExceededError of %d", n, err, n)
		}
	}
}

// The steps of a validation, as ValidateWithBudget documents them.
func TestValidateWithBudget_Steps(t *testing.T) {
	items := make([]string, 21)
	for i := range items {
		items[i] = strings.Repeat("9", i+1)
	}
	ints := "[" + strings.Join(items, ",") + "]"
	strs := make([]string, 21)
	objs := make([]string, 21)
	for i := range strs {
		strs[i] = `"` + strings.Repeat("a", i+1) + `"`
		objs[i] = fmt.Sprintf(`{"k":%d}`, i)
	}
	strArr := "[" + strings.Join(strs, ",") + "]"
	objArr := "[" + strings.Join(objs, ",") + "]"
	for _, tc := range []struct {
		schema, value string
		steps         int64
	}{
		{`true`, `1`, 1},
		// each enum value compared: a value, and the 2 bytes of number text
		{`{"enum":[1,2,3]}`, `3`, 1 + 3*(1+2)},
		// a number compared: a value, its text and its exponent, twice
		{`{"enum":[1e2]}`, `1e2`, 1 + 1 + 2*(3+2)},
		// a number read to see whether it is an integer: its text
		{`{"type":"integer"}`, `1.0`, 1 + 3},
		// a number read for a bound (1), then compared with the bound: two,
		// and one per 16 bits of the two (its 1 step taken as 8 bits, and
		// 0/1's 1 bit)
		{`{"minimum":0}`, `5`, 1 + 1 + 2},
		// a number with an exponent: its text and exponent (44); compared:
		// two, and its 44 steps taken as 8 bits each, with 0/1's 1 bit
		{`{"minimum":0}`, `1e40`, 1 + (4 + 40) + (2 + (8*44+1)/16)},
		// each schema applied in place, and the scope its cycle check walks;
		// the number read for type integer (1), and for minimum (1) and
		// compared with it (2)
		{`{"allOf":[{"type":"integer"},{"minimum":0}]}`, `1`, 1 + 2*(1+1) + 1 + 1 + 2},
		// two levels in place: the inner one's cycle check walks two scopes;
		// the number read for type integer
		{`{"allOf":[{"allOf":[{"type":"integer"}]}]}`, `1`, 1 + (1 + 1) + (1 + 2) + 1},
		// the array, and its items with the scope each one's cycle check
		// walks and the number read for type integer
		{`{"type":"array","items":{"type":"integer"}}`, `[1,2,3]`, 4 + 3*(1+1+1)},
		// a failing item also copies its location (one token) into its error
		{`{"items":{"type":"string"}}`, `[1]`, 2 + (1 + 1) + 1},
		// the array (2); its item (1) and the scope its cycle check walks (1);
		// the two scopes $dynamicRef walks; the schema it resolves to,
		// applied in place (1), and the two scopes its cycle check walks
		{`{"$dynamicAnchor":"node","items":{"$dynamicRef":"#node"}}`, `[1]`, 2 + (1 + 1) + 2 + (1 + 2)},
		// each required name looked up, and its bytes
		{`{"required":["a","bb","ccc"]}`, `{}`, 1 + (1 + 1) + (1 + 2) + (1 + 3)},
		// the object, the dependentRequired entry and its name's byte, and
		// its names looked up with their bytes
		{`{"dependentRequired":{"a":["b","cc"]}}`, `{"a":1}`, 3 + (1 + 1) + (1 + 1) + (1 + 2)},
		// the object, and the dependentSchemas entry with its name's bytes
		{`{"dependentSchemas":{"ab":{}}}`, `{}`, 1 + (1 + 2)},
		// the object, and the dependencies entry with its name's bytes
		{`{"$schema":"http://json-schema.org/draft-07/schema#","dependencies":{"abc":["d"]}}`, `{}`, 1 + (1 + 3)},
		// the object and each name
		{`{"propertyNames":{"maxLength":3}}`, `{"abc":1,"abcd":2}`, 10 + 4 + 5},
		// the object (3), its values compared: the object (1), the sort of
		// its one name (3) and the name looked up (1), the array (1), and
		// each number with its text (3 each)
		{`{"const":{"x":[1,2]}}`, `{"x":[1,2]}`, 3 + 1 + 3 + 1 + 1 + 3 + 3},
		// the string, and the string compared with its bytes
		{`{"const":"abc"}`, `"abc"`, 4 + 4},
		// the object, each pattern tried and each byte of the name it is
		// matched against, each value
		{`{"patternProperties":{"^a":{}}}`, `{"aa":1,"ab":2}`, 7 + 3 + 3 + 2},
		// 3 pairs, each an array and a number with its text
		{`{"uniqueItems":true}`, `[[1],[2],[3]]`, 4 + 3*(1+3)},
		// past 20 items: each item, its hash, and its number text
		{`{"uniqueItems":true}`, ints, 22 + 21*2 + (21*22)/2},
		// past 20 items: each item, its hash, and its string's bytes
		{`{"uniqueItems":true}`, strArr, 22 + 21*2 + (21*22)/2},
		// past 20 items: each item; its hash: the object, its name and the
		// sort of its one name (3), the name with its byte (2), the number
		// with its text (1 + 1 or 2)
		{`{"uniqueItems":true}`, objArr, 22 + 21*(1+1+3+2+1) + 10*1 + 11*2},
	} {
		sch := compileBudget(t, tc.schema, false)
		if got := least(t, sch, instance(t, tc.value)); got != tc.steps {
			t.Errorf("%s on %.20s: %d steps, want %d", tc.schema, tc.value, got, tc.steps)
		}
	}
}

// probe is a custom keyword that asks its ValidatorContext to validate a
// nested value and to compare values.
type probe struct{ sub *jsonschema.Schema }

func (p *probe) Validate(ctx *jsonschema.ValidatorContext, v any) {
	obj, ok := v.(map[string]any)
	if !ok {
		return
	}
	if a, ok := obj["a"].(map[string]any); ok {
		ctx.AddErr(ctx.Validate(p.sub, a["b"], []string{"a", "b"}))
	}
	if _, err := ctx.Equals(v, v); err != nil {
		ctx.AddErr(err)
	}
	if _, _, err := ctx.Duplicates([]any{v, v}); err != nil {
		ctx.AddErr(err)
	}
}

type probeKind struct{}

func (probeKind) KeywordPath() []string                   { return []string{"probe"} }
func (probeKind) LocalizedString(*message.Printer) string { return "probe" }

// The budget counts what a custom vocabulary asks of its ValidatorContext.
func TestValidateWithBudget_CountsVocabularyRequests(t *testing.T) {
	sub := compileBudget(t, `true`, false)
	meta := compileBudget(t, `{"properties":{"probe":{"type":"boolean"}}}`, false)
	c := jsonschema.NewCompiler()
	c.AssertVocabs()
	c.RegisterVocabulary(&jsonschema.Vocabulary{
		URL:    "http://example.com/meta/probe",
		Schema: meta,
		Compile: func(_ *jsonschema.CompilerContext, obj map[string]any) (jsonschema.SchemaExt, error) {
			if _, ok := obj["probe"]; !ok {
				return nil, nil
			}
			return &probe{sub: sub}, nil
		},
	})
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"probe":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("probe.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("probe.json")
	if err != nil {
		t.Fatal(err)
	}
	// The object (3), the nested value (1), and what Equals and Duplicates
	// each compare: two objects, each visited (1) with its one name sorted
	// (3) and looked up (1), and a number with its text (3).
	if got := least(t, sch, instance(t, `{"a":{"b":1}}`)); got != 3+1+13+13 {
		t.Errorf("%d steps, want %d", got, 3+1+13+13)
	}
}

// Schemas applied within one another deeper than MaxNesting stop the
// validation, whatever its budget: each level holds stack.
func TestValidateWithBudget_BoundsTheNesting(t *testing.T) {
	sch := compileBudget(t, `{"items":{"$ref":"#"}}`, false)
	nested := func(depth int) any {
		return instance(t, strings.Repeat("[", depth)+strings.Repeat("]", depth))
	}
	// Each array within another applies two schemas: items, then the $ref,
	// so d arrays nest 2(d-1) deep.
	if err := sch.ValidateWithBudget(nested(jsonschema.MaxNesting/2+1), 1<<40); err != nil {
		t.Errorf("at MaxNesting: %v", err)
	}
	err := sch.ValidateWithBudget(nested(jsonschema.MaxNesting/2+2), 1<<40)
	var be *jsonschema.BudgetExceededError
	if !errors.As(err, &be) || !be.Nested {
		t.Errorf("beyond MaxNesting: %v, want a *BudgetExceededError that is Nested", err)
	}
	if err := sch.Validate(nested(jsonschema.MaxNesting/2 + 2)); err != nil {
		t.Errorf("Validate is not bounded: %v", err)
	}
}

// BenchmarkValidateWithBudget measures, for two ordinary schemas over 20 000
// records, the steps a validation takes per byte of the instance and the time
// a step takes: the figures a caller sets a budget from.
func BenchmarkValidateWithBudget(b *testing.B) {
	for _, bc := range []struct {
		name, schema string
		item         func(i int) string
	}{
		{"record", `{"type":"array","items":{"type":"object","required":["name","age"],"properties":{"name":{"type":"string","maxLength":64},"age":{"type":"integer","minimum":0},"tags":{"type":"array","items":{"type":"string"},"uniqueItems":true},"kind":{"enum":["a","b","c"]}},"additionalProperties":false}}`,
			func(i int) string {
				return fmt.Sprintf(`{"name":"person-%d","age":%d,"tags":["x%d","y","z"],"kind":"b"}`, i, i%90, i)
			}},
		{"credential", `{"type":"array","items":{"$ref":"#/$defs/vc"},"$defs":{"vc":{"type":"object","required":["type","issuer","credentialSubject"],"properties":{"type":{"type":"array","contains":{"const":"VerifiableCredential"}},"issuer":{"type":"string","pattern":"^did:"},"credentialSubject":{"allOf":[{"type":"object"},{"properties":{"id":{"type":"string"},"score":{"type":"number","minimum":0,"maximum":100}}}]}}}}}`,
			func(i int) string {
				return fmt.Sprintf(`{"type":["VerifiableCredential","X"],"issuer":"did:example:%d","credentialSubject":{"id":"did:example:s%d","score":%d.5}}`, i, i, i%100)
			}},
	} {
		b.Run(bc.name, func(b *testing.B) {
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(bc.schema))
			if err != nil {
				b.Fatal(err)
			}
			c := jsonschema.NewCompiler()
			if err := c.AddResource("s.json", doc); err != nil {
				b.Fatal(err)
			}
			sch, err := c.Compile("s.json")
			if err != nil {
				b.Fatal(err)
			}
			items := make([]string, 20_000)
			for i := range items {
				items[i] = bc.item(i)
			}
			raw := "[" + strings.Join(items, ",") + "]"
			v, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
			if err != nil {
				b.Fatal(err)
			}
			lo, hi := int64(0), int64(1)<<40
			for lo < hi {
				mid := lo + (hi-lo)/2
				if exceeded(sch.ValidateWithBudget(v, mid)) {
					lo = mid + 1
				} else {
					hi = mid
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := sch.ValidateWithBudget(v, lo); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(lo)/float64(len(raw)), "steps/byte")
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(lo), "ns/step")
		})
	}
}

// Each pattern tried against a property name costs a step, whatever the
// name's length: a property named "" is matched against every pattern too.
func TestValidateWithBudget_ChargesEachPatternTried(t *testing.T) {
	patterns := func(n int) string {
		ps := make([]string, n)
		for i := range ps {
			ps[i] = fmt.Sprintf(`"^p%d$":{}`, i)
		}
		return `{"patternProperties":{` + strings.Join(ps, ",") + `}}`
	}
	v := instance(t, `{"":0}`)
	one := least(t, compileBudget(t, patterns(1), false), v)
	many := least(t, compileBudget(t, patterns(100), false), v)
	if many-one != 99 {
		t.Errorf("1 pattern: %d steps; 100 patterns: %d steps; want 99 more", one, many)
	}
}

// The nesting a propertyNames validation starts counts on from the schema
// that starts it: schemas applied around it and within it together pass
// MaxNesting, though each alone is within it.
func TestValidateWithBudget_NestingCountsOnIntoPropertyNames(t *testing.T) {
	const inner = jsonschema.MaxNesting / 2
	defs := make([]string, 0, inner+1)
	for i := 0; i < inner; i++ {
		defs = append(defs, fmt.Sprintf(`"e%d":{"$ref":"#/$defs/e%d"}`, i, i+1))
	}
	defs = append(defs, fmt.Sprintf(`"e%d":{"type":"string"}`, inner))
	sch := compileBudget(t, `{"items":{"$ref":"#"},"propertyNames":{"$ref":"#/$defs/e0"},"$defs":{`+strings.Join(defs, ",")+`}}`, false)
	nested := func(levels int) any {
		return instance(t, strings.Repeat("[", levels)+`{"a":0}`+strings.Repeat("]", levels))
	}
	// Two scopes per array level (items, then $ref): 1,200 levels (2,400
	// scopes) around and 5,000 within stay under MaxNesting; 2,600 levels
	// (5,200 scopes) around and 5,000 within pass it.
	if err := sch.ValidateWithBudget(nested(1200), 1<<40); err != nil {
		t.Errorf("within MaxNesting: %v", err)
	}
	var be *jsonschema.BudgetExceededError
	if err := sch.ValidateWithBudget(nested(2600), 1<<40); !errors.As(err, &be) || !be.Nested {
		t.Errorf("past MaxNesting: %v, want a *BudgetExceededError for nesting", err)
	}
}

// counter is a custom vocabulary's keyword that counts the values it is asked
// to validate.
type counter struct{ calls *int }

func (c counter) Validate(*jsonschema.ValidatorContext, any) { *c.calls++ }

// Once the budget is spent, no custom vocabulary is asked to validate: its
// own work is not counted, so it would run on unbounded.
func TestValidateWithBudget_AsksNoVocabularyOnceSpent(t *testing.T) {
	calls := 0
	meta := compileBudget(t, `{"properties":{"counter":{"type":"boolean"}}}`, false)
	c := jsonschema.NewCompiler()
	c.AssertVocabs()
	c.RegisterVocabulary(&jsonschema.Vocabulary{
		URL:    "http://example.com/meta/counter",
		Schema: meta,
		Compile: func(_ *jsonschema.CompilerContext, obj map[string]any) (jsonschema.SchemaExt, error) {
			if _, ok := obj["counter"]; !ok {
				return nil, nil
			}
			return counter{&calls}, nil
		},
	})
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"counter":true,"items":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("counter.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("counter.json")
	if err != nil {
		t.Fatal(err)
	}
	// The array costs 1 + 10 steps and each item 1: a budget of 15 runs out
	// among the items, before the vocabulary's turn.
	v := instance(t, `[0,1,2,3,4,5,6,7,8,9]`)
	if err := sch.ValidateWithBudget(v, 15); !exceeded(err) {
		t.Fatalf("budget 15: %v, want it exceeded", err)
	}
	if calls != 0 {
		t.Errorf("the vocabulary was asked %d times after the budget was spent", calls)
	}
	if err := sch.ValidateWithBudget(v, 1<<20); err != nil || calls != 1 {
		t.Errorf("within budget: %v, %d calls; want nil, 1", err, calls)
	}
}

// The locations a $ref cycle's error names are charged by their length: a
// location holds text the schema has (a pattern of patternProperties, here),
// so a cycle met many times would otherwise build text in the schema's size
// each time.
func TestValidateWithBudget_ChargesTheTextOfACyclesLocations(t *testing.T) {
	schema := func(pattern int) string {
		return `{"patternProperties":{"^(?:` + strings.Repeat("x", pattern) + `|b)$":{"items":{"$ref":"#/$defs/c"}}},"$defs":{"c":{"$ref":"#/$defs/c"}}}`
	}
	v := instance(t, `{"b":[0]}`)
	short := least(t, compileBudget(t, schema(10), false), v)
	long := least(t, compileBudget(t, schema(1010), false), v)
	if long-short < 2*1000 {
		t.Errorf("pattern of 10: %d steps; of 1010: %d steps; want at least %d more", short, long, 2*1000)
	}
}

// The nesting a contentSchema validation starts counts on from the schema
// that starts it, as propertyNames' does.
func TestValidateWithBudget_NestingCountsOnIntoContentSchema(t *testing.T) {
	const inner = jsonschema.MaxNesting / 2
	defs := make([]string, 0, inner+1)
	for i := 0; i < inner; i++ {
		defs = append(defs, fmt.Sprintf(`"e%d":{"$ref":"#/$defs/e%d"}`, i, i+1))
	}
	defs = append(defs, fmt.Sprintf(`"e%d":{"type":"string"}`, inner))
	sch := compileBudget(t, `{"items":{"$ref":"#"},"contentMediaType":"application/json","contentSchema":{"$ref":"#/$defs/e0"},"$defs":{`+strings.Join(defs, ",")+`}}`, true)
	nested := func(levels int) any {
		return instance(t, strings.Repeat("[", levels)+`"\"x\""`+strings.Repeat("]", levels))
	}
	if err := sch.ValidateWithBudget(nested(1200), 1<<40); err != nil {
		t.Errorf("within MaxNesting: %v", err)
	}
	var be *jsonschema.BudgetExceededError
	if err := sch.ValidateWithBudget(nested(2600), 1<<40); !errors.As(err, &be) || !be.Nested {
		t.Errorf("past MaxNesting: %v, want a *BudgetExceededError for nesting", err)
	}
}

// sized is a Regexp whose program the engine says has size instructions.
type sized struct {
	*regexp.Regexp
	size int
}

func (r sized) Size() int { return r.size }

// compileSized compiles schema with an engine whose every Regexp has the
// given size, asserting formats or not.
func compileSized(t *testing.T, schema string, size int, assertFormat bool) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, err
		}
		return sized{re, size}, nil
	})
	if assertFormat {
		c.AssertFormat()
	}
	if err := c.AddResource("sized.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sized.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

// Matching a string against a pattern costs, besides the string's bytes, a
// step per position (each byte, and the end) for each
// PatternInstructionsPerStep instructions of the pattern's program, an empty
// string included; a pattern whose engine gives no size costs no more.
func TestValidateWithBudget_ChargesAPatternBySize(t *testing.T) {
	per := jsonschema.PatternInstructionsPerStep
	for value, positions := range map[string]int64{`"aaaa"`: 5, `""`: 1} {
		v := instance(t, value)
		none := least(t, compileSized(t, `{"pattern":"^a*$"}`, 0, false), v)
		big := least(t, compileSized(t, `{"pattern":"^a*$"}`, 10*per, false), v)
		if big-none != positions*10 {
			t.Errorf("%s: size 0: %d steps; size %d: %d steps; want %d more", value, none, 10*per, big, positions*10)
		}
	}
}

// A patternProperties pattern tried against a name costs, per position of
// the name (each byte, and the end), 1 plus a step for each
// PatternInstructionsPerStep instructions of its program, an empty name
// included.
func TestValidateWithBudget_ChargesAPatternPropertyBySize(t *testing.T) {
	per := jsonschema.PatternInstructionsPerStep
	for value, positions := range map[string]int64{`{"aa":1}`: 3, `{"":1}`: 1} {
		v := instance(t, value)
		none := least(t, compileSized(t, `{"patternProperties":{"^a":{}}}`, 0, false), v)
		big := least(t, compileSized(t, `{"patternProperties":{"^a":{}}}`, 10*per, false), v)
		if big-none != positions*10 {
			t.Errorf("%s: size 0: %d steps; size %d: %d steps; want %d more", value, none, 10*per, big, positions*10)
		}
	}
}

// Checking format "regex" compiles the value: it costs
// PatternCompileStepsPerInstruction steps per instruction of the program
// compiled.
func TestValidateWithBudget_ChargesARegexFormatBySize(t *testing.T) {
	v := instance(t, `"a+"`)
	want := int64(500 * jsonschema.PatternCompileStepsPerInstruction)
	none := least(t, compileSized(t, `{"format":"regex"}`, 0, true), v)
	big := least(t, compileSized(t, `{"format":"regex"}`, 500, true), v)
	if big-none != want {
		t.Errorf("size 0: %d steps; size 500: %d steps; want %d more", none, big, want)
	}
}

// Checking format "regex" costs, before the value is compiled,
// PatternParseStepsPerByte steps per byte of it, whatever the size of the
// program it compiles to: parsing takes time in its length. A budget that
// cannot pay them is exceeded before the engine runs.
func TestValidateWithBudget_ChargesARegexFormatByLengthBeforeCompiling(t *testing.T) {
	short, long := instance(t, `"a"`), instance(t, `"aaaaaaaaaaa"`)
	more := func(schema string) int64 {
		sch := compileSized(t, schema, 0, true)
		return least(t, sch, long) - least(t, sch, short)
	}
	if got, want := more(`{"format":"regex"}`)-more(`{"type":"string"}`), int64(10*jsonschema.PatternParseStepsPerByte); got != want {
		t.Errorf("10 bytes more cost %d more steps checked as format \"regex\", want %d", got, want)
	}

	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"format":"regex"}`))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	calls := 0
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		calls++
		return regexp.Compile(s)
	})
	c.AssertFormat()
	if err := c.AddResource("counted.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("counted.json")
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	budget := least(t, compileSized(t, `{"type":"string"}`, 0, true), long)
	var be *jsonschema.BudgetExceededError
	if err := sch.ValidateWithBudget(long, budget); !errors.As(err, &be) || calls != 0 {
		t.Errorf("a budget that pays only the value's bytes: %v, the engine ran %d times; want a *BudgetExceededError, and no run", err, calls)
	}
}

// Comparing two objects takes the same steps every time, whatever order Go
// ranges over their names in: so a budget near them answers the same each
// time.
func TestValidateWithBudget_ComparesObjectsInOneOrder(t *testing.T) {
	long := strings.Repeat("a", 1000)
	sch := compileBudget(t, `{"const":{"a":"`+long+`","b":"x"}}`, false)
	v := instance(t, `{"a":"`+long+`","b":"y"}`)
	want := least(t, sch, v)
	for i := 0; i < 30; i++ {
		if got := least(t, sch, v); got != want {
			t.Fatalf("comparing two objects took %d steps, then %d", want, got)
		}
	}
}
