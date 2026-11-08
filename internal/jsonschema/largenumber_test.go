// Added by 1o1 Co. Ltd. for github.com/provin-line/oss; not upstream code.
// See README.md in this directory.

package jsonschema_test

// Large number: tests of the local patch to v6.0.3 (see README.md). A number
// big.Rat cannot read, such as 1e1000001, is reported as a kind.LargeNumber
// error by the number keywords, by the comparison enum, const and uniqueItems
// use, and by the hash uniqueItems uses past 20 items: instead of a nil
// big.Rat, or of taking the number as unequal to every number.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/internal/jsonschema"
	"github.com/provin-line/oss/internal/jsonschema/kind"
)

// large is a number big.Rat cannot read: its exponent is past what
// big.Rat.SetString accepts.
const large = "1e1000001"

// hasLargeNumber reports whether err, or an error it holds, is of kind
// LargeNumber.
func hasLargeNumber(err error) bool {
	var sve *jsonschema.SchemaValidationError
	if errors.As(err, &sve) {
		err = sve.Err
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return false
	}
	var walk func(*jsonschema.ValidationError) bool
	walk = func(e *jsonschema.ValidationError) bool {
		if _, ok := e.ErrorKind.(*kind.LargeNumber); ok {
			return true
		}
		for _, c := range e.Causes {
			if walk(c) {
				return true
			}
		}
		return false
	}
	return walk(ve)
}

// upTo20 is the numbers 0 to 20, joined by commas: past 20 items,
// uniqueItems hashes the items instead of comparing each pair.
func upTo20(each func(int) string) string {
	items := make([]string, 21)
	for i := range items {
		items[i] = each(i)
	}
	return strings.Join(items, ",")
}

// compile compiles schema under draft 2020-12, recovering a panic as an error
// so that one failing case does not stop the others.
func compile(schema string) (sch *jsonschema.Schema, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("schema.json")
}

// validate validates v against sch, unbounded and within a budget, recovering
// a panic as an error.
func validate(sch *jsonschema.Schema, v any, budget bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	if budget {
		return sch.ValidateWithBudget(v, 1<<40)
	}
	return sch.Validate(v)
}

// The number keywords refuse a number they cannot read as a LargeNumber, and
// still admit a number within their bound.
func TestValidate_ANumberKeywordRefusesALargeNumber(t *testing.T) {
	for kw, within := range map[string]string{"minimum": "1", "maximum": "1", "exclusiveMinimum": "2", "exclusiveMaximum": "0", "multipleOf": "3"} {
		sch, err := compile(fmt.Sprintf(`{%q: 1}`, kw))
		if err != nil {
			t.Fatalf("%s: %v", kw, err)
		}
		for _, budget := range []bool{false, true} {
			if err := validate(sch, instance(t, large), budget); !hasLargeNumber(err) {
				t.Errorf("%s (budget %v): %v, want a LargeNumber error", kw, budget, err)
			}
			if err := validate(sch, instance(t, within), budget); err != nil {
				t.Errorf("%s (budget %v): %s is refused: %v", kw, budget, within, err)
			}
		}
	}
}

// uniqueItems refuses an array holding a number it cannot read, however deep
// in an item, as a LargeNumber; it still tells unique items from duplicates.
func TestValidate_UniqueItemsRefusesALargeNumber(t *testing.T) {
	sch, err := compile(`{"uniqueItems": true}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, arr := range []string{
		"[" + upTo20(func(i int) string { return fmt.Sprint(i) }) + "," + large + "]",
		"[" + upTo20(func(i int) string { return fmt.Sprintf("[%d]", i) }) + ",[" + large + "]]",
		"[" + upTo20(func(i int) string { return fmt.Sprintf(`{"a":%d}`, i) }) + `,{"a":` + large + "}]",
	} {
		for _, budget := range []bool{false, true} {
			if err := validate(sch, instance(t, arr), budget); !hasLargeNumber(err) {
				t.Errorf("%.40s… (budget %v): %v, want a LargeNumber error", arr, budget, err)
			}
		}
	}
	unique := "[" + upTo20(func(i int) string { return fmt.Sprint(i) }) + ",21]"
	duplicate := "[" + upTo20(func(i int) string { return fmt.Sprint(i) }) + ",20.0]"
	for _, budget := range []bool{false, true} {
		if err := validate(sch, instance(t, unique), budget); err != nil {
			t.Errorf("unique items (budget %v) refused: %v", budget, err)
		}
		if err := validate(sch, instance(t, duplicate), budget); err == nil || hasLargeNumber(err) {
			t.Errorf("duplicate items (budget %v): %v, want a uniqueItems error", budget, err)
		}
	}
}

// Up to 20 items, uniqueItems compares each pair; a number it cannot read is
// a LargeNumber there too, so the answer does not depend on the array's
// length.
func TestValidate_UniqueItemsUpTo20RefusesALargeNumber(t *testing.T) {
	sch, err := compile(`{"uniqueItems": true}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, arr := range []string{"[" + large + "," + large + "]", "[0," + large + "]", "[[0],[" + large + "]]"} {
		for _, budget := range []bool{false, true} {
			if err := validate(sch, instance(t, arr), budget); !hasLargeNumber(err) {
				t.Errorf("%s (budget %v): %v, want a LargeNumber error", arr, budget, err)
			}
		}
	}
}

// enum and const refuse a number they cannot read as a LargeNumber, and still
// admit a number they hold.
func TestValidate_EnumAndConstRefuseALargeNumber(t *testing.T) {
	for schema, within := range map[string]string{`{"enum": [1, 2]}`: "2", `{"const": 1}`: "1", `{"enum": [[1], [2]]}`: "[2]"} {
		sch, err := compile(schema)
		if err != nil {
			t.Fatalf("%s: %v", schema, err)
		}
		v := large
		if strings.HasPrefix(within, "[") {
			v = "[" + large + "]"
		}
		for _, budget := range []bool{false, true} {
			if err := validate(sch, instance(t, v), budget); !hasLargeNumber(err) {
				t.Errorf("%s, %s (budget %v): %v, want a LargeNumber error", schema, v, budget, err)
			}
			if err := validate(sch, instance(t, within), budget); err != nil {
				t.Errorf("%s, %s (budget %v): %v", schema, within, budget, err)
			}
		}
	}
}

// A schema document is validated against the metaschema: its type and
// required carry uniqueItems, and its multipleOf carries exclusiveMinimum. A
// number the library cannot read there makes the compile fail as a
// LargeNumber.
func TestCompile_RefusesALargeNumberTheMetaschemaReads(t *testing.T) {
	numbers := upTo20(func(i int) string { return fmt.Sprint(i) })
	for _, schema := range []string{
		`{"type": [` + numbers + "," + large + "]}",
		`{"required": [` + numbers + "," + large + "]}",
		`{"multipleOf": ` + large + "}",
		`{"properties": {"a": {"multipleOf": ` + large + "}}}",
	} {
		if _, err := compile(schema); !hasLargeNumber(err) {
			t.Errorf("%.40s…: %v, want a LargeNumber error", schema, err)
		}
	}
}
