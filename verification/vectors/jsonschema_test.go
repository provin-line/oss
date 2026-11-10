package vectors_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
// schema/local's wrapper, and by a phrase in the rest of it where one head
// starts more than one class. Text from the schema or the payload comes only
// after a head, so it cannot change the class.
type outcomeClass struct{ class, head, phrase string }

// The classes of an outcome. Add's refusals: schema-budget (the bounds and
// budgets of compiling a schema), refused-pattern-dialect (a pattern outside
// the product's regular-expression dialect, which the metaschema check
// reports), schema-invalid (a schema its metaschema does not admit) and
// refused-external-ref (a schema that refers outside itself). The metaschema
// rows come before the external-ref row, whose head they share. Validate's
// outcomes: valid, invalid, payload-budget, payload-nesting and
// refused-payload (the payload's decode and its bounds).
var (
	addClasses = []outcomeClass{
		{"schema-budget", "schemadoc: schema nested ", ""},
		{"schema-budget", "schemadoc: the schema holds ", ""},
		{"schema-budget", "schemadoc: the schema's JSON pointers and URLs ", ""},
		{"schema-budget", "schemadoc: checking the schema against its metaschema nests schemas deeper than ", ""},
		{"schema-budget", "schemadoc: checking the schema against its metaschema needs more than its work budget ", ""},
		{"refused-pattern-dialect", "schemadoc: compile: the schema does not conform to its metaschema: ", "is not a general category this package accepts"},
		{"schema-invalid", "schemadoc: compile: the schema does not conform to its metaschema: ", ""},
		{"refused-external-ref", "schemadoc: compile: ", "schemadoc: external $ref is not allowed: "},
	}
	validateClasses = []outcomeClass{
		{"invalid", "schemadoc: does not conform: ", ""},
		{"payload-budget", "schemadoc: validating the payload needs more than its work budget ", ""},
		{"payload-nesting", "schemadoc: validating the payload nests schemas deeper than ", ""},
		{"refused-payload", "schemadoc: not strict-decodable JSON: ", ""},
		{"refused-payload", "schemadoc: payload nested ", ""},
		{"refused-payload", "schemadoc: a number of ", ""},
		{"refused-payload", "schemadoc: number ", ": exponent beyond ±"},
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
		for _, c := range classes {
			if rest, ok := strings.CutPrefix(msg, c.head); ok && strings.Contains(rest, c.phrase) {
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
// text schemadoc writes, under the wrapper schema/local puts around it.
func TestClassifyProductRefusals(t *testing.T) {
	nested := func(open, inner, close string, n int) string {
		return strings.Repeat(open, n) + inner + strings.Repeat(close, n)
	}
	for _, c := range []struct {
		name, schema, payload, want string
	}{
		{"external ref", `{"$ref":"http://example.com/x"}`, "", "refused-external-ref"},
		{"metaschema", `{"type":5}`, "", "schema-invalid"},
		{"pattern dialect", `{"pattern":"\\p{Letter}"}`, "", "refused-pattern-dialect"},
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
	out := map[[3]string]suiteRow{}
	for _, r := range readExpected(t, "jsonschema.expected.tsv", 6) {
		k := [3]string{r[0], r[1], r[2]}
		if _, dup := out[k]; dup {
			t.Fatalf("jsonschema.expected.tsv: %q listed twice", k)
		}
		out[k] = suiteRow{class: r[3], fragment: r[4]}
	}
	return out
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
