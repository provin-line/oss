// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema_test

// Tests of the local patches to how v6.0.3 compiles a schema (README.md).

import (
	"errors"
	"fmt"
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
