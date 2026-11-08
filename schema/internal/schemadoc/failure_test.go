package schemadoc_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/schema/internal/schemadoc"
)

// failure validates payload against schema and returns the error's text.
func failure(t *testing.T, schema, payload string) string {
	t.Helper()
	s, err := schemadoc.Compile([]byte(schema))
	if err != nil {
		t.Fatalf("compile %.60s…: %v", schema, err)
	}
	err = s.Validate([]byte(payload))
	if err == nil {
		t.Fatalf("%.60s… accepted %s", schema, payload)
	}
	return err.Error()
}

// A failure is stated by where it is in the payload and the keyword it
// fails, without the values the schema holds (a required list, enum or const
// values, a pattern): their text would grow with the schema, on every
// validation that fails.
func TestValidate_StatesAFailureWithoutWhatTheSchemaHolds(t *testing.T) {
	names := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf(`"n%04d"`, i)
	}
	list := strings.Join(names, ",")
	for _, c := range []struct{ schema, payload, keyword string }{
		{`{"required":[` + list + `]}`, `{}`, "required"},
		{`{"properties":{"a":{"enum":[` + list + `]}}}`, `{"a":"x"}`, "enum"},
		{`{"const":"` + strings.Repeat("c", 5000) + `"}`, `"x"`, "const"},
		{`{"pattern":"^` + strings.Repeat("p", 5000) + `$"}`, `"x"`, "pattern"},
	} {
		text := failure(t, c.schema, c.payload)
		if !strings.Contains(text, c.keyword) {
			t.Errorf("%s: %q does not name the keyword", c.keyword, text)
		}
		for _, held := range []string{"n0001", "ccc", "ppp"} {
			if strings.Contains(text, held) {
				t.Errorf("%s: %.200q quotes what the schema holds", c.keyword, text)
			}
		}
	}
	if text := failure(t, `{"properties":{"a":{"required":["b"]}}}`, `{"a":{}}`); !strings.Contains(text, "/a") {
		t.Errorf("%q does not say where the failure is", text)
	}
}

// A failure whose description grows only with the payload, or with numbers
// within the bounds every schema keeps, is described.
func TestValidate_DescribesAFailureBoundedByThePayload(t *testing.T) {
	for _, c := range []struct{ schema, payload, want string }{
		{`{"type":"string"}`, `1`, "want string"},
		{`{"minimum":5}`, `1`, "5"},
		{`{"maxLength":2}`, `"abc"`, "2"},
	} {
		if text := failure(t, c.schema, c.payload); !strings.Contains(text, c.want) {
			t.Errorf("%s on %s: %q does not hold %q", c.schema, c.payload, text, c.want)
		}
	}
}

// A name in the payload or the schema is written with its control
// characters escaped, so a failure cannot carry a line break or a terminal
// sequence into a log.
func TestValidate_EscapesControlCharactersInAFailure(t *testing.T) {
	for _, c := range []struct{ schema, payload string }{
		{`{"additionalProperties":{"type":"string"}}`, `{"\u001b[2J\n":1}`},
		{`{"dependentRequired":{"a\u001b\n":["b"]}}`, `{"a\u001b\n":1}`},
		{`{"$schema":"http://json-schema.org/draft-07/schema#","format":"regex"}`, `"\u001b("`},
	} {
		text := failure(t, c.schema, c.payload)
		if strings.ContainsAny(text, "\x1b\n") || !strings.Contains(text, `\x1b`) {
			t.Errorf("%s on %s: %q", c.schema, c.payload, text)
		}
	}
}

// A failure the library describes in fixed words is described; one it does
// not, such as a $ref cycle, is named in words, not by a Go type.
func TestValidate_NamesEveryFailureInWords(t *testing.T) {
	for _, c := range []struct{ schema, payload, want string }{
		{`{"not":{}}`, `1`, "'not' failed"},
		{`{"$defs":{"c":{"$ref":"#/$defs/c"}},"$ref":"#/$defs/c"}`, `1`, "$ref cycle"},
	} {
		text := failure(t, c.schema, c.payload)
		if !strings.Contains(text, c.want) || strings.Contains(text, "*kind.") {
			t.Errorf("%s on %s: %q, want it to hold %q", c.schema, c.payload, text, c.want)
		}
	}
}

// repeats is a regular expression of n bounded repeats of a small class:
// each has a size (patternSize) of about 4,000.
func repeats(n int) string { return "^" + strings.Repeat("[a-c]{0,1000}", n) + "$" }

// A schema whose pattern, or patternProperties name, expands to more than
// 8,192 instructions is refused when it is compiled; one within it is not.
func TestCompile_RefusesAPatternLargerThanTheBound(t *testing.T) {
	for schema, ok := range map[string]bool{
		`{"pattern":"` + repeats(2) + `"}`:                      true,
		`{"pattern":"` + repeats(3) + `"}`:                      false,
		`{"patternProperties":{"` + repeats(3) + `":{}}}`:       false,
		`{"properties":{"a":{"pattern":"` + repeats(3) + `"}}}`: false,
	} {
		_, err := schemadoc.Compile([]byte(schema))
		if (err == nil) != ok {
			t.Errorf("%.60s…: %v, want accepted %v", schema, err, ok)
		}
	}
}

// A payload value checked as format "regex" that expands to more than 8,192
// instructions is not a valid regex here.
func TestValidate_RefusesARegexValueLargerThanTheBound(t *testing.T) {
	s, err := schemadoc.Compile([]byte(`{"$schema":"http://json-schema.org/draft-07/schema#","format":"regex"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`"` + repeats(2) + `"`)); err != nil {
		t.Errorf("a regex within the bound: %v", err)
	}
	if err := s.Validate([]byte(`"` + repeats(3) + `"`)); err == nil || !strings.Contains(err.Error(), "regex") {
		t.Errorf("a regex past the bound: %v, want a format failure", err)
	}
}

// Matching a string against a pattern is charged by the pattern's size: a
// string of a few kilobytes against a pattern near the bound needs more than
// the payload's budget.
func TestValidate_ChargesMatchingByThePatternsSize(t *testing.T) {
	s, err := schemadoc.Compile([]byte(`{"pattern":"` + repeats(2) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`"` + strings.Repeat("a", 4096) + `"`)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("4 KiB against a pattern of a size of about 8,000: %v, want the budget refusal", err)
	}
	if err := s.Validate([]byte(`"` + strings.Repeat("a", 100) + `"`)); err != nil {
		t.Errorf("100 bytes: %v", err)
	}
}

// A schema of many short patterns, each within maxPatternSize, is refused
// when it is compiled: together they pass what a schema of its size may
// compile. Two are not (each is compiled twice, once where the metaschema
// checks it as format "regex", and has a size of about 3,000).
func TestCompile_RefusesManyShortPatternsTogether(t *testing.T) {
	schema := func(n int) string {
		props := make([]string, n)
		for i := range props {
			props[i] = fmt.Sprintf(`"p%d":{"pattern":"a{1000}"}`, i)
		}
		return `{"properties":{` + strings.Join(props, ",") + `}}`
	}
	if _, err := schemadoc.Compile([]byte(schema(2))); err != nil {
		t.Errorf("2 patterns: %v", err)
	}
	if _, err := schemadoc.Compile([]byte(schema(40))); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("40 patterns: %v, want the total refused", err)
	}
}

// An inline flag group, which JSON Schema's regular expressions do not have,
// is refused before it is parsed: in a schema's pattern when the schema is
// compiled, and in a payload value checked as format "regex".
func TestCompileAndValidate_RefuseInlineFlags(t *testing.T) {
	if _, err := schemadoc.Compile([]byte(`{"pattern":"(?i)abc"}`)); err == nil || !strings.Contains(err.Error(), "inline flags") {
		t.Errorf("schema: %v, want the inline flags refused", err)
	}
	s, err := schemadoc.Compile([]byte(`{"$schema":"http://json-schema.org/draft-07/schema#","format":"regex"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`"(?i)abc"`)); err == nil || !strings.Contains(err.Error(), "inline flags") {
		t.Errorf("payload: %v, want the inline flags refused", err)
	}
	if err := s.Validate([]byte(`"(?:abc)"`)); err != nil {
		t.Errorf("a non-capturing group: %v", err)
	}
}

// A number is charged by what reading and dividing it costs: a schema that
// applies a multipleOf of about 2,900 bits to one small number 6,561 times
// (through $ref) needs more than the budget of a short payload. Charged one
// step an application, it would fit, at microseconds each.
func TestValidate_ChargesTheNumbersItReads(t *testing.T) {
	defs := []string{`"d0":{"multipleOf":0.` + strings.Repeat("7", 240) + `e-400}`}
	for i := 1; i <= 4; i++ {
		refs := strings.TrimSuffix(strings.Repeat(fmt.Sprintf(`{"$ref":"#/$defs/d%d"},`, i-1), 9), ",")
		defs = append(defs, fmt.Sprintf(`"d%d":{"allOf":[%s]}`, i, refs))
	}
	s, err := schemadoc.Compile([]byte(`{"$ref":"#/$defs/d4","$defs":{` + strings.Join(defs, ",") + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate([]byte(`1.5`)); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("a multipleOf of about 2,900 bits applied 6,561 times: %v, want the budget refusal", err)
	}
}

// A validation that would nest schemas deeper than the library's bound
// within its budget is refused by naming the nesting, not the budget: 25
// schemas in place at each of 450 levels of the payload nest about 12,000
// deep.
func TestValidate_NamesTheNestingBound(t *testing.T) {
	inner := `{"items":{"$ref":"#"}}`
	for range 25 {
		inner = `{"allOf":[` + inner + `]}`
	}
	s, err := schemadoc.Compile([]byte(inner))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("[", 450) + strings.Repeat("]", 450)
	if err := s.Validate([]byte(payload)); err == nil || !strings.Contains(err.Error(), "nests") || strings.Contains(err.Error(), "budget") {
		t.Errorf("%v, want an error naming the nesting bound", err)
	}
}
