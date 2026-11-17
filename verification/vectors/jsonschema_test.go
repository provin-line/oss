package vectors_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/provin-line/oss/schema/local"
	"github.com/provin-line/oss/vc"
)

// suiteCase is one case of a JSON-Schema-Test-Suite file: a schema and the
// tests of data against it. The schema and the data stay as the bytes the
// file holds, so their numbers are not rewritten.
type suiteCase struct {
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Tests       []struct {
		Description string          `json:"description"`
		Data        json.RawMessage `json:"data"`
		Valid       bool            `json:"valid"`
	} `json:"tests"`
}

const suiteDir = "testdata/json-schema-test-suite/tests/draft2020-12"

// suiteID is the id each schema is registered under; addHead and
// validateHead are the wrappers schema/local puts around Add's and
// Validate's errors for it.
const suiteID = "suite"

var (
	addHead      = "schema/local: schema " + strconv.Quote(suiteID) + ": "
	validateHead = "schema/local: payload against " + strconv.Quote(suiteID) + ": "
)

func loadSuite(t *testing.T) map[string][]suiteCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(suiteDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]suiteCase{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var cases []suiteCase
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[filepath.Base(p)] = cases
	}
	return out
}

// outcomeClass names an error by the head of schemadoc's message, under
// schema/local's wrapper, and by a phrase where one head starts more than one
// class: in the rest of the message (inRest), or at the start of the reason
// of a pattern the metaschema check refuses (patternReason). A metaschema
// refusal that is not a pattern's is notPattern. Text from the schema or the
// payload comes only after a head, and a pattern refusal is read by position,
// so neither can change the class.
type outcomeClass struct {
	class, head, phrase string
	part                messagePart
}

// messagePart is where an outcomeClass's phrase is read.
type messagePart int

const (
	inRest messagePart = iota
	inPatternReason
	notPattern
)

// metaschemaHead begins the message of a schema its metaschema check
// refuses.
const metaschemaHead = "schemadoc: compile: the schema does not conform to its metaschema: "

// patternReason reads a metaschema refusal (the message after metaschemaHead)
// by position: "at '<location>': '<pattern>' is not valid regex: <reason>",
// where the location and the pattern write ' and \ as \' and \\. It reports
// the reason, and whether the refusal is a pattern's.
func patternReason(rest string) (string, bool) {
	r, ok := strings.CutPrefix(rest, "at '")
	if !ok {
		return "", false
	}
	if i := quoteEnd(r); i < 0 {
		return "", false
	} else if r, ok = strings.CutPrefix(r[i+1:], ": '"); !ok {
		return "", false
	}
	i := quoteEnd(r)
	if i < 0 {
		return "", false
	}
	return strings.CutPrefix(r[i+1:], " is not valid regex: ")
}

// quoteEnd is the index of the first ' in s that no backslash escapes, or -1.
func quoteEnd(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			return i
		}
	}
	return -1
}

// The classes of an outcome. Add's refusals: schema-budget (the bounds and
// budgets of compiling a schema, a pattern's among them), refused-pattern-
// dialect (a pattern the product does not read: outside its regular-
// expression dialect, or one Go's parser refuses), schema-invalid (a schema
// its metaschema does not admit) and refused-external-ref (a schema that
// refers outside itself). A pattern's bounds come before its dialect, which
// takes any other reason, and the metaschema rows before the external-ref
// row, whose head they share. Validate's outcomes: valid, invalid,
// payload-budget, payload-nesting and refused-payload (the payload's decode
// and its bounds).
var (
	addClasses = []outcomeClass{
		{"schema-budget", "schemadoc: schema nested ", "", inRest},
		{"schema-budget", "schemadoc: the schema holds ", "", inRest},
		{"schema-budget", "schemadoc: the schema's JSON pointers and URLs ", "", inRest},
		{"schema-budget", "schemadoc: checking the schema against its metaschema nests schemas deeper than ", "", inRest},
		{"schema-budget", "schemadoc: checking the schema against its metaschema needs more than its work budget ", "", inRest},
		{"schema-budget", metaschemaHead, "regexp: its program has more than ", inPatternReason},
		{"schema-budget", metaschemaHead, "regexp: the schema's regular expressions, together, have more instructions than it is allowed", inPatternReason},
		{"schema-budget", metaschemaHead, "regexp: its Unicode classes hold more than ", inPatternReason},
		{"schema-budget", metaschemaHead, "regexp: its groups nest more than ", inPatternReason},
		{"refused-pattern-dialect", metaschemaHead, "", inPatternReason},
		{"schema-invalid", metaschemaHead, "", notPattern},
		{"refused-external-ref", "schemadoc: compile: ", "schemadoc: external $ref is not allowed: ", inRest},
	}
	validateClasses = []outcomeClass{
		{"invalid", "schemadoc: does not conform: ", "", inRest},
		{"payload-budget", "schemadoc: validating the payload needs more than its work budget ", "", inRest},
		{"payload-nesting", "schemadoc: validating the payload nests schemas deeper than ", "", inRest},
		{"refused-payload", "schemadoc: not strict-decodable JSON: ", "", inRest},
		{"refused-payload", "schemadoc: payload nested ", "", inRest},
		{"refused-payload", "schemadoc: a number of ", "", inRest},
		{"refused-payload", "schemadoc: number ", ": exponent beyond ±", inRest},
	}
)

// classify names the outcome of Add (addErr) and, when Add succeeded, of
// Validate (validateErr). It reports false for an error no class names,
// including one without schema/local's wrapper, so a refusal nobody declared
// is never taken for one.
func classify(addErr, validateErr error) (string, bool) {
	match := func(err error, wrapper string, classes []outcomeClass) (string, bool) {
		msg, ok := strings.CutPrefix(err.Error(), wrapper)
		if !ok {
			return "", false
		}
		// A metaschema refusal cut short ("…") may have lost what decides it.
		if strings.HasPrefix(msg, metaschemaHead) && strings.HasSuffix(msg, "…") {
			return "", false
		}
		for _, c := range classes {
			rest, ok := strings.CutPrefix(msg, c.head)
			if !ok {
				continue
			}
			reason, isPattern := patternReason(rest)
			switch {
			case c.part == inRest && strings.Contains(rest, c.phrase),
				c.part == inPatternReason && isPattern && strings.HasPrefix(reason, c.phrase),
				c.part == notPattern && !isPattern:
				return c.class, true
			}
		}
		return "", false
	}
	switch {
	case addErr != nil:
		return match(addErr, addHead, addClasses)
	case validateErr != nil:
		return match(validateErr, validateHead, validateClasses)
	default:
		return "valid", true
	}
}

// A pattern refusal whose message is cut before its reason names no class:
// the reason decides it.
func TestClassifyCutPatternRefusalFails(t *testing.T) {
	for name, schema := range map[string]string{
		"a long pattern outside the dialect": `{"pattern":"` + strings.Repeat("a", 1100) + `(?i)"}`,
		"a long pattern over its program":    `{"pattern":"` + strings.Repeat(`a{1000}`, 9) + strings.Repeat("b", 1100) + `"}`,
	} {
		err := local.New().Add(suiteID, []byte(schema))
		if err == nil || !strings.HasSuffix(err.Error(), "…") {
			t.Fatalf("%s: %v, want a refusal cut before its reason", name, err)
		}
		if class, ok := classify(err, nil); ok {
			t.Errorf("%s: classed %q", name, class)
		}
	}
}

func TestClassifyUnknownErrorFails(t *testing.T) {
	if class, ok := classify(errors.New(addHead+"schemadoc: compile: something new"), nil); ok {
		t.Errorf("an unknown compile error was classed %q", class)
	}
	if class, ok := classify(nil, errors.New("schema/local: no schema registered")); ok {
		t.Errorf("an unknown validate error was classed %q", class)
	}
	if class, ok := classify(nil, errors.New("schemadoc: does not conform: x")); ok {
		t.Errorf("an error without schema/local's wrapper was classed %q", class)
	}
	if class, ok := classify(nil, nil); !ok || class != "valid" {
		t.Errorf("no error: %q %v, want valid", class, ok)
	}
}

// Every class is checked against the refusal that names it, through the
// local.Validator the suite runs. A refusal that is costly to reach is the
// text schemadoc writes, under the wrapper schema/local puts around it. A
// pattern's groups nest 33 deep, past every bound
// PROVIN_SCHEMA_REGEXP_MAX_GROUP_DEPTH may set (1 to 32).
func TestClassifyProductRefusals(t *testing.T) {
	// schemadoc reads the setting as it is initialized, before go test
	// records what a test reads; reading it here keys go test's cache on it.
	os.LookupEnv("PROVIN_SCHEMA_REGEXP_MAX_GROUP_DEPTH")
	nested := func(open, inner, close string, n int) string {
		return strings.Repeat(open, n) + inner + strings.Repeat(close, n)
	}
	for _, c := range []struct {
		name, schema, payload, want string
	}{
		{"external ref", `{"$ref":"http://example.com/x"}`, "", "refused-external-ref"},
		{"metaschema", `{"type":5}`, "", "schema-invalid"},
		{"pattern dialect", `{"pattern":"\\p{Foo}"}`, "", "refused-pattern-dialect"},
		{"pattern inline flag", `{"pattern":"(?i)a"}`, "", "refused-pattern-dialect"},
		{"pattern \\Q", `{"pattern":"\\Qa\\E"}`, "", "refused-pattern-dialect"},
		{"pattern count with a leading zero", `{"pattern":"a{01}"}`, "", "refused-pattern-dialect"},
		{"pattern Go's parser refuses", `{"pattern":"(?:a{1000}){1000}"}`, "", "refused-pattern-dialect"},
		{"pattern program", `{"pattern":"` + strings.Repeat(`a{1000}`, 9) + `"}`, "", "schema-budget"},
		{"pattern Unicode classes", `{"pattern":"` + strings.Repeat(`\\p{L}`, 30) + `"}`, "", "schema-budget"},
		{"pattern groups nested", `{"pattern":"` + nested(`(`, `a`, `)`, 33) + `"}`, "", "schema-budget"},
		{"patterns together", `{"allOf":[` + strings.Repeat(`{"pattern":"a{900}"},`, 60) + `{}]}`, "", "schema-budget"},
		{"a pattern quoting a bound's text", `{"pattern":"(?i)' is not valid regex: regexp: its program has more than "}`, "", "refused-pattern-dialect"},
		{"a category name quoting a bound's text", `{"pattern":"\\p{' is not valid regex: regexp: its program has more than }"}`, "", "refused-pattern-dialect"},
		{"a location quoting the regex text", `{"properties":{"' is not valid regex: ":{"type":5}}}`, "", "schema-invalid"},
		{"schema depth", nested(`{"not":`, `{}`, `}`, 64), "", "schema-budget"},
		{"schema objects", `{"allOf":[` + strings.Repeat(`{},`, 7000) + `{}]}`, "", "schema-budget"},
		{"valid", `{"type":"string"}`, `"a"`, "valid"},
		{"invalid", `{"type":"string"}`, `1`, "invalid"},
		{"duplicate name", `{}`, `{"a":1,"a":2}`, "refused-payload"},
		{"duplicate name quoting the invalid text", `{}`, `{"schemadoc: does not conform: x":1,"schemadoc: does not conform: x":2}`, "refused-payload"},
		{"payload depth", `{}`, nested(`[`, ``, `]`, 513), "refused-payload"},
		{"number size", `{}`, strings.Repeat("1", 257), "refused-payload"},
		{"exponent", `{}`, `1e401`, "refused-payload"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := local.New()
			addErr := v.Add(suiteID, []byte(c.schema))
			var validateErr error
			if addErr == nil && c.payload != "" {
				sum := sha256.Sum256([]byte(c.schema))
				ref := vc.SchemaRef{ID: suiteID, Type: "JsonSchema", ContentHash: "sha256:" + hex.EncodeToString(sum[:])}
				validateErr = v.Validate(context.Background(), []byte(c.payload), ref)
			}
			if got, ok := classify(addErr, validateErr); !ok || got != c.want {
				t.Errorf("%q %v, want %s (add %v, validate %v)", got, ok, c.want, addErr, validateErr)
			}
		})
	}
	for _, c := range []struct {
		name          string
		add, validate string
		want          string
	}{
		{"schema pointers", addHead + "schemadoc: the schema's JSON pointers and URLs (its values' pointers, and what its $id and $ref resolve to) come to 90000 bytes, beyond the bound of 80000 (65536, and 16 per byte of the schema)", "", "schema-budget"},
		{"metaschema nesting", addHead + "schemadoc: checking the schema against its metaschema nests schemas deeper than 10000", "", "schema-budget"},
		{"metaschema budget", addHead + "schemadoc: checking the schema against its metaschema needs more than its work budget of 1048592 steps (1048576, and 16 per byte of the schema)", "", "schema-budget"},
		{"payload nesting", "", validateHead + "schemadoc: validating the payload nests schemas deeper than 10000", "payload-nesting"},
		{"payload budget", "", validateHead + "schemadoc: validating the payload needs more than its work budget of 1048592 steps (1048576, and 16 per byte of payload)", "payload-budget"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var addErr, validateErr error
			if c.add != "" {
				addErr = errors.New(c.add)
			}
			if c.validate != "" {
				validateErr = errors.New(c.validate)
			}
			if got, ok := classify(addErr, validateErr); !ok || got != c.want {
				t.Errorf("%q %v, want %s", got, ok, c.want)
			}
		})
	}
}

// suiteExpected is jsonschema.expected.tsv, keyed by file, case and test
// ("*" for every test of the case).
type suiteRow struct{ class, fragment string }

func loadSuiteExpected(t *testing.T) map[[3]string]suiteRow {
	t.Helper()
	out, err := suiteExpected(readExpected(t, "jsonschema.expected.tsv", 6))
	if err != nil {
		t.Fatalf("jsonschema.expected.tsv: %v", err)
	}
	return out
}

// suiteExpected keys the table's rows by file, case and test. A row with no
// error fragment, or a key listed twice, is an error.
func suiteExpected(rows [][]string) (map[[3]string]suiteRow, error) {
	out := map[[3]string]suiteRow{}
	for _, r := range rows {
		k := [3]string{r[0], r[1], r[2]}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%q listed twice", k)
		}
		if r[4] == "" {
			return nil, fmt.Errorf("%q names no error fragment", k)
		}
		out[k] = suiteRow{class: r[3], fragment: r[4]}
	}
	return out, nil
}

// A row names the error it expects; one with no fragment would match any
// error, and one listed twice is ambiguous: both are refused.
func TestSuiteExpectedRefusesAmbiguousRows(t *testing.T) {
	row := []string{"ref.json", "a case", "*", "refused-external-ref", "external $ref is not allowed", "why"}
	if _, err := suiteExpected([][]string{row}); err != nil {
		t.Fatalf("a well-formed row: %v", err)
	}
	empty := slices.Clone(row)
	empty[4] = ""
	if _, err := suiteExpected([][]string{empty}); err == nil {
		t.Error("a row with no error fragment was taken")
	}
	if _, err := suiteExpected([][]string{row, row}); err == nil {
		t.Error("a row listed twice was taken")
	}
}

func TestJSONSchemaSuiteKeysAreUnique(t *testing.T) {
	for file, cases := range loadSuite(t) {
		seen := map[string]bool{}
		for _, c := range cases {
			if seen[c.Description] {
				t.Errorf("%s: case %q twice", file, c.Description)
			}
			seen[c.Description] = true
			tests := map[string]bool{}
			for _, tc := range c.Tests {
				if tests[tc.Description] {
					t.Errorf("%s: case %q: test %q twice", file, c.Description, tc.Description)
				}
				tests[tc.Description] = true
			}
		}
	}
}

// Every case of the suite goes through schema/local: Add compiles its schema
// under the product's policy, and Validate checks each test's data. The
// expected outcome is the table's row, else the test's own valid/invalid.
// A row's error fragment must be in the error, and a row that no case uses,
// or that says what the default says, fails.
func TestJSONSchemaTestSuite(t *testing.T) {
	suite := loadSuite(t)
	rows := loadSuiteExpected(t)
	used := map[[3]string]bool{}
	var files, cases, tests int
	ctx := context.Background()
	for file, cs := range suite {
		files++
		for _, c := range cs {
			cases++
			v := local.New()
			addErr := v.Add(suiteID, c.Schema)
			sum := sha256.Sum256(c.Schema)
			ref := vc.SchemaRef{ID: suiteID, Type: "JsonSchema", ContentHash: "sha256:" + hex.EncodeToString(sum[:])}
			for _, tc := range c.Tests {
				tests++
				var validateErr error
				if addErr == nil {
					validateErr = v.Validate(ctx, tc.Data, ref)
				}
				got, ok := classify(addErr, validateErr)
				where := file + ": " + c.Description + ": " + tc.Description
				if !ok {
					t.Errorf("%s: an error no class names: add %v, validate %v", where, addErr, validateErr)
					continue
				}
				want := map[bool]string{true: "valid", false: "invalid"}[tc.Valid]
				for _, k := range [][3]string{{file, c.Description, tc.Description}, {file, c.Description, "*"}} {
					row, listed := rows[k]
					if !listed {
						continue
					}
					used[k] = true
					if row.class == want {
						t.Errorf("%s: the table says %s, which the test says already", where, row.class)
					}
					want = row.class
					err := addErr
					if err == nil {
						err = validateErr
					}
					if got == row.class && (err == nil || !strings.Contains(err.Error(), row.fragment)) {
						t.Errorf("%s: %s, but not for the listed reason %q: %v", where, got, row.fragment, err)
					}
					break
				}
				if got != want {
					t.Errorf("%s: %s, want %s (add %v, validate %v)", where, got, want, addErr, validateErr)
				}
			}
		}
	}
	for k := range rows {
		if !used[k] {
			t.Errorf("jsonschema.expected.tsv: no case for %q", k)
		}
	}
	if files != 46 || cases != 385 || tests != 1300 {
		t.Errorf("ran %d files, %d cases, %d tests; recorded 46, 385, 1300", files, cases, tests)
	}
	t.Logf("%d files, %d cases, %d tests; %d table rows", files, cases, tests, len(rows))
}
