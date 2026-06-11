// Package jsonata_test tests the jsonata Converter implementation.
package jsonata_test

import (
	"context"
	"strings"
	"testing"

	"github.com/provin-line/oss/pipeline/filterconvert/converter"
	"github.com/provin-line/oss/pipeline/filterconvert/converter/jsonata"
)

// interfaceCheck ensures *Converter satisfies converter.Converter at compile
// time. Both New and NewSteps return *Converter, so one check covers both
// modes.
var _ converter.Converter = (*jsonata.Converter)(nil)

// TestNew_WholeDoc_Reshape tests whole-document mode with a real JSONata
// expression that reshapes an object.
func TestNew_WholeDoc_Reshape(t *testing.T) {
	c, err := jsonata.New(`{"name": $.firstName & " " & $.lastName}`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"firstName":"John","lastName":"Doe"}`)
	got, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	want := `{"name":"John Doe"}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestNewSteps_SequentialComposition pins that per-field steps compose
// sequentially: step 2 reads from the document produced by step 1.
func TestNewSteps_SequentialComposition(t *testing.T) {
	// Step 1 adds "full" by concatenating two fields.
	// Step 2 adds "greeting" by reading "full" from step 1's output.
	steps := []jsonata.FieldStep{
		{Field: "full", Expr: `$.firstName & " " & $.lastName`},
		{Field: "greeting", Expr: `"Hello, " & $.full`},
	}
	c, err := jsonata.NewSteps(steps)
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	input := []byte(`{"firstName":"Jane","lastName":"Smith"}`)
	got, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if !strings.Contains(string(got), `"full":"Jane Smith"`) {
		t.Errorf("expected full field in output, got %s", got)
	}
	if !strings.Contains(string(got), `"greeting":"Hello, Jane Smith"`) {
		t.Errorf("expected greeting field in output, got %s", got)
	}
}

// TestNewSteps_UndefinedResult verifies that a per-field step whose expression
// returns undefined produces an error.
func TestNewSteps_UndefinedResult(t *testing.T) {
	steps := []jsonata.FieldStep{
		{Field: "missing", Expr: `$.fieldThatDoesNotExist`},
	}
	c, err := jsonata.NewSteps(steps)
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	_, err = c.Convert(context.Background(), []byte(`{"other":"value"}`))
	if err == nil {
		t.Fatal("expected error for undefined result, got nil")
	}
}

// TestNew_WholeDoc_Undefined verifies that a whole-document expression that
// returns undefined produces an error.
func TestNew_WholeDoc_Undefined(t *testing.T) {
	c, err := jsonata.New(`$.fieldThatDoesNotExist`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.Convert(context.Background(), []byte(`{"other":"value"}`))
	if err == nil {
		t.Fatal("expected error for undefined result, got nil")
	}
}

// TestNew_CompileError verifies that invalid JSONata syntax returns an error
// from New.
func TestNew_CompileError(t *testing.T) {
	_, err := jsonata.New(`{invalid syntax %%%`)
	if err == nil {
		t.Fatal("expected compile error for invalid syntax, got nil")
	}
}

// TestNew_EmptyExpr verifies that an empty expression returns a construction
// error from New.
func TestNew_EmptyExpr(t *testing.T) {
	_, err := jsonata.New(``)
	if err == nil {
		t.Fatal("expected error for empty expression, got nil")
	}
}

// TestNewSteps_EmptySteps verifies that an empty steps slice returns a
// construction error.
func TestNewSteps_EmptySteps(t *testing.T) {
	_, err := jsonata.NewSteps([]jsonata.FieldStep{})
	if err == nil {
		t.Fatal("expected error for empty steps slice, got nil")
	}
}

// TestConvert_InvalidInputJSON verifies that invalid JSON input returns an
// error at Convert time.
func TestConvert_InvalidInputJSON(t *testing.T) {
	c, err := jsonata.New(`$`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = c.Convert(context.Background(), []byte(`not-json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON input, got nil")
	}
}

// TestConvert_IntegerPrecision_Golden is a golden test for 2^53+1 (9007199254740993).
// Using json.Number-based decoding preserves integer precision; the identity
// expression $ must return the value unchanged.
//
// Golden output: {"n":9007199254740993}
// (With standard json.Unmarshal / float64, precision is lost and the output
// would be {"n":9007199254740992}.)
func TestConvert_IntegerPrecision_Golden(t *testing.T) {
	c, err := jsonata.New(`$`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"n": 9007199254740993}`)
	got, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	// Golden: UseNumber preserves precision; 2^53+1 round-trips exactly.
	const golden = `{"n":9007199254740993}`
	if string(got) != golden {
		t.Errorf("integer precision golden test failed:\n  got:  %s\n  want: %s", got, golden)
	}
}

// TestConvert_ValidateSubset_Integration verifies that after a transformation
// the output can be validated for expected fields using ValidateSubset.
func TestConvert_ValidateSubset_Integration(t *testing.T) {
	c, err := jsonata.New(`{"name": $.firstName & " " & $.lastName, "age": $.age}`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"firstName":"Alice","lastName":"Wong","age":25}`)
	out, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	if err := converter.ValidateSubset(out, []string{"name", "age"}); err != nil {
		t.Errorf("ValidateSubset: %v", err)
	}
}

// TestNewSteps_StepExprCompileError verifies that a step with invalid JSONata
// syntax returns an error from NewSteps.
func TestNewSteps_StepExprCompileError(t *testing.T) {
	steps := []jsonata.FieldStep{
		{Field: "ok", Expr: `$.name`},
		{Field: "bad", Expr: `{invalid %%%`},
	}
	_, err := jsonata.NewSteps(steps)
	if err == nil {
		t.Fatal("expected compile error for invalid step expression, got nil")
	}
}

// ----- Regression: strict input decode (Finding 1) -----

// TestConvert_TrailingData_Error is a regression test for Finding 1.
// A plain json.Decoder silently accepts trailing data after the first JSON
// value. StrictDecoder must reject it so that input bytes are not laundered
// before being hashed into the signed outputHash.
func TestConvert_TrailingData_Error(t *testing.T) {
	c, err := jsonata.New(`$`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Two concatenated JSON objects — trailing data must be rejected.
	input := []byte(`{"a":1} {"b":2}`)
	_, err = c.Convert(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for trailing data after JSON value, got nil")
	}
}

// TestConvert_DuplicateKeys_Error is a regression test for Finding 1.
// A plain json.Decoder (and standard json.Unmarshal) silently accepts
// duplicate keys, keeping the last value. StrictDecoder must reject them.
func TestConvert_DuplicateKeys_Error(t *testing.T) {
	c, err := jsonata.New(`$`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"a":1,"a":2}`)
	_, err = c.Convert(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate JSON keys, got nil")
	}
}

// TestConvertSteps_TrailingData_Error checks trailing-data rejection in steps mode.
func TestConvertSteps_TrailingData_Error(t *testing.T) {
	c, err := jsonata.NewSteps([]jsonata.FieldStep{
		{Field: "out", Expr: `$.a`},
	})
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	input := []byte(`{"a":1} {"b":2}`)
	_, err = c.Convert(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for trailing data in steps mode, got nil")
	}
}

// TestConvertSteps_DuplicateKeys_Error checks duplicate-key rejection in steps mode.
func TestConvertSteps_DuplicateKeys_Error(t *testing.T) {
	c, err := jsonata.NewSteps([]jsonata.FieldStep{
		{Field: "out", Expr: `$.a`},
	})
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	input := []byte(`{"a":1,"a":2}`)
	_, err = c.Convert(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate keys in steps mode, got nil")
	}
}

// ----- Regression: json.Number numeric operators (Finding 2) -----

// TestConvert_NumericArithmetic_Addition is a regression test for Finding 2.
// After StrictDecoder (UseNumber), numbers must be normalized to int64/float64
// so that JSONata arithmetic operators work. {"next": $.age + 1} on
// {"age": 41} must produce {"next": 42}.
func TestConvert_NumericArithmetic_Addition(t *testing.T) {
	c, err := jsonata.New(`{"next": $.age + 1}`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"age": 41}`)
	got, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	want := `{"next":42}`
	if string(got) != want {
		t.Errorf("numeric addition: got %s, want %s", got, want)
	}
}

// TestConvert_NumericComparison is a regression test for Finding 2.
// Numeric comparison ($.age > 18) must work correctly after normalization.
func TestConvert_NumericComparison(t *testing.T) {
	c, err := jsonata.New(`{"adult": $.age > 18}`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	input := []byte(`{"age": 25}`)
	got, err := c.Convert(context.Background(), input)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}

	want := `{"adult":true}`
	if string(got) != want {
		t.Errorf("numeric comparison: got %s, want %s", got, want)
	}
}

// ----- Regression: NewSteps empty Field validation (Finding 4) -----

// TestNewSteps_EmptyFieldName is a regression test for Finding 4.
// An empty Field name must be rejected at construction time to prevent
// silently writing a "" key into the output document.
func TestNewSteps_EmptyFieldName(t *testing.T) {
	_, err := jsonata.NewSteps([]jsonata.FieldStep{
		{Field: "", Expr: `$.name`},
	})
	if err == nil {
		t.Fatal("expected error for empty Field name in FieldStep, got nil")
	}
}

// TestConvertSteps_NonObjectInput is a regression test for Finding 4 (missing
// error-path test). Steps mode requires a JSON object input; an array must
// trigger the toStringMap error path.
func TestConvertSteps_NonObjectInput(t *testing.T) {
	c, err := jsonata.NewSteps([]jsonata.FieldStep{
		{Field: "out", Expr: `$[0]`},
	})
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	input := []byte(`[1, 2, 3]`)
	_, err = c.Convert(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for non-object input in steps mode, got nil")
	}
}

// ----- Concurrency (Finding 6) -----

// TestConvertConcurrency exercises concurrent Convert calls to verify thread-
// safety. Mirrors the filter package's concurrency test shape. Run with -race.
func TestConvertConcurrency(t *testing.T) {
	cWhole, err := jsonata.New(`{"next": $.age + 1}`)
	if err != nil {
		t.Fatalf("New (whole-doc): %v", err)
	}

	cSteps, err := jsonata.NewSteps([]jsonata.FieldStep{
		{Field: "full", Expr: `$.first & " " & $.last`},
	})
	if err != nil {
		t.Fatalf("NewSteps: %v", err)
	}

	ctx := context.Background()
	const goroutines = 50

	type result struct{ err error }
	errs := make(chan result, goroutines*2)

	// Whole-doc mode goroutines.
	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := cWhole.Convert(ctx, []byte(`{"age":41}`))
			errs <- result{err}
		}()
	}

	// Steps mode goroutines.
	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := cSteps.Convert(ctx, []byte(`{"first":"A","last":"B"}`))
			errs <- result{err}
		}()
	}

	for i := 0; i < goroutines*2; i++ {
		if r := <-errs; r.err != nil {
			t.Errorf("concurrent Convert error: %v", r.err)
		}
	}
}
