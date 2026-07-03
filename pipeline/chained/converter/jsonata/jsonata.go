// Package jsonata implements converter.Converter using JSONata expressions
// (github.com/blues/jsonata-go).
//
// Two construction modes are provided:
//
//   - New(expr): whole-document mode. The expression receives the full input
//     document as its evaluation context and its result becomes the output
//     document.
//
//   - NewSteps(steps): per-field steps mode. Each step evaluates its
//     expression against the document produced by the previous step (the input
//     document for step 0) and writes the result into the named field of that
//     document. Steps compose sequentially: step N reads from the output of
//     step N-1, enabling derived fields.
//
// Both modes pre-compile all expressions at construction time. Construction
// fails if the expression list is empty or any expression fails to compile.
//
// Undefined handling:
//   - Whole-document mode: if the expression returns undefined, Convert returns
//     an error "expression produced no output".
//   - Per-field steps mode: if a step expression returns undefined, Convert
//     returns an error naming the step index and field.
//
// Input decode: Convert uses canon.StrictDecoder on the raw input bytes.
// StrictDecoder enforces: trailing-data rejection (a document must be exactly
// one JSON value), duplicate-key rejection (RFC 8785 §3.2.5), and numeric
// precision preservation via json.Number. Expressions that only pass through
// fields (identity paths) preserve integers exactly. Expressions that perform
// arithmetic operate in float64 internally via jsonata-go, which loses
// precision for integers above 2^53.
//
// Numeric model: after strict decode the json.Number values in the decoded
// tree are normalized — integral values that fit int64 become int64, all
// others become float64. This normalization is required because jsonata-go
// treats json.Number as a string kind and rejects it in arithmetic and
// comparison operators. Integer identity is preserved up to the int64 range
// (2^63-1); arithmetic and comparisons on integers above 2^53 may lose
// precision (float64 boundary). Golden test: input {"n":9007199254740993},
// expression $, output {"n":9007199254740993} — int64 marshals exactly.
//
// Concurrency: jsonata-go's Expr.Eval creates a fresh environment per call.
// Concurrent Convert calls on the same *Converter are safe without additional
// locking.
package jsonata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	libjsonata "github.com/blues/jsonata-go"
	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/chained/converter"
)

// FieldStep describes a single per-field transformation step.
// Field is the top-level key to write into the document; Expr is a JSONata
// expression evaluated against the current document state.
// Field must not be empty; NewSteps returns an error if it is.
type FieldStep struct {
	// Field is the top-level key to assign in the output document. Must not be empty.
	Field string
	// Expr is the JSONata expression evaluated against the current document.
	Expr string
}

// Converter is a stateless JSON→JSON transformer. Construct it with New (whole-
// document mode) or NewSteps (per-field steps mode). It satisfies
// converter.Converter.
type Converter struct {
	// mode selects between whole-document and per-field evaluation.
	mode modeKind

	// expr holds the pre-compiled expression for whole-document mode.
	expr *libjsonata.Expr

	// steps holds pre-compiled per-field steps for steps mode.
	steps []compiledStep
}

type modeKind int

const (
	modeWholeDoc modeKind = iota
	modeSteps
)

type compiledStep struct {
	field string
	expr  *libjsonata.Expr
}

// compile-time interface check.
var _ converter.Converter = (*Converter)(nil)

// New constructs a Converter in whole-document mode. The expression is
// evaluated against the full input document; its result becomes the output
// document. Returns an error if expr is empty or fails to compile.
func New(expr string) (*Converter, error) {
	if expr == "" {
		return nil, errors.New("jsonata converter: expression must not be empty")
	}

	compiled, err := libjsonata.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("jsonata converter: compile %q: %w", expr, err)
	}

	return &Converter{
		mode: modeWholeDoc,
		expr: compiled,
	}, nil
}

// NewSteps constructs a Converter in per-field steps mode. Each step is
// pre-compiled at construction time; evaluation runs sequentially at Convert
// time. Returns an error if steps is empty, if any step has an empty Field
// name, or if any step expression fails to compile.
func NewSteps(steps []FieldStep) (*Converter, error) {
	if len(steps) == 0 {
		return nil, errors.New("jsonata converter: steps must not be empty")
	}

	compiled := make([]compiledStep, 0, len(steps))
	for i, s := range steps {
		if s.Field == "" {
			return nil, fmt.Errorf("jsonata converter: step %d: Field must not be empty", i)
		}
		e, err := libjsonata.Compile(s.Expr)
		if err != nil {
			return nil, fmt.Errorf("jsonata converter: compile step %d (field %q): %w", i, s.Field, err)
		}
		compiled = append(compiled, compiledStep{field: s.Field, expr: e})
	}

	return &Converter{
		mode:  modeSteps,
		steps: compiled,
	}, nil
}

// Convert applies the pre-compiled expression(s) to data and returns the
// transformed JSON document.
//
// The input is decoded with canon.StrictDecoder, which rejects trailing data,
// duplicate keys, and preserves numeric precision via json.Number. After
// strict decode the tree is normalized: json.Number values become int64 (when
// integral and fitting int64) or float64, so that JSONata arithmetic and
// comparison operators work correctly.
//
// Returns an error if data is not valid JSON (including trailing data or
// duplicate keys), if a JSONata expression returns undefined, or if any other
// evaluation error occurs.
func (c *Converter) Convert(_ context.Context, data []byte) ([]byte, error) {
	var v interface{}
	if err := canon.NewStrictDecoder(data).Decode(&v); err != nil {
		return nil, fmt.Errorf("jsonata converter: invalid JSON input: %w", err)
	}

	// Normalize json.Number → int64/float64 so jsonata-go operators work.
	v = normalizeNumbers(v)

	switch c.mode {
	case modeWholeDoc:
		return c.convertWholeDoc(v)
	case modeSteps:
		return c.convertSteps(v)
	default:
		return nil, fmt.Errorf("jsonata converter: unknown mode %d", c.mode)
	}
}

// convertWholeDoc evaluates the whole-document expression and marshals the
// result.
func (c *Converter) convertWholeDoc(v interface{}) ([]byte, error) {
	result, err := c.expr.Eval(v)
	if err != nil {
		if errors.Is(err, libjsonata.ErrUndefined) {
			return nil, errors.New("jsonata converter: expression produced no output")
		}
		return nil, fmt.Errorf("jsonata converter: evaluation error: %w", err)
	}

	// canonicalizer-hygiene-exempt: converted payload bytes, not a signing scope.
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("jsonata converter: marshal result: %w", err)
	}

	return out, nil
}

// convertSteps evaluates each step sequentially, writing the result of each
// step into the named field of the current document, then marshals the final
// document.
func (c *Converter) convertSteps(v interface{}) ([]byte, error) {
	doc, ok := toStringMap(v)
	if !ok {
		return nil, errors.New("jsonata converter: steps mode requires a JSON object input")
	}

	for i, step := range c.steps {
		result, err := step.expr.Eval(doc)
		if err != nil {
			if errors.Is(err, libjsonata.ErrUndefined) {
				return nil, fmt.Errorf("jsonata converter: step %d (field %q): expression produced no output", i, step.field)
			}
			return nil, fmt.Errorf("jsonata converter: step %d (field %q): evaluation error: %w", i, step.field, err)
		}
		doc[step.field] = result
	}

	// canonicalizer-hygiene-exempt: converted payload bytes, not a signing scope.
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("jsonata converter: marshal result: %w", err)
	}

	return out, nil
}

// toStringMap type-asserts v to map[string]interface{}. Returns (nil, false)
// if v is not an object.
func toStringMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// normalizeNumbers walks the decoded JSON tree replacing every json.Number
// with a native Go numeric type so that jsonata-go arithmetic and comparison
// operators work correctly.
//
// Conversion rules:
//   - If the number has no decimal point or exponent, attempt int64 parsing.
//     On success the value becomes int64, preserving integer identity exactly
//     up to the int64 range (2^63-1). json.Marshal encodes int64 as an exact
//     decimal integer, so 9007199254740993 (2^53+1) round-trips without loss.
//   - All other numbers (fractions, exponents, or integers that overflow
//     int64) become float64. Arithmetic on integers above 2^53 loses precision
//     at the float64 boundary — this is documented in the package comment.
func normalizeNumbers(v interface{}) interface{} {
	switch val := v.(type) {
	case json.Number:
		s := string(val)
		// Try integral parse first (no '.' or 'e'/'E').
		if !containsAny(s, '.', 'e', 'E') {
			if i, err := strconv.ParseInt(s, 10, 64); err == nil {
				return i
			}
		}
		// Fall back to float64.
		f, _ := val.Float64()
		return f
	case map[string]interface{}:
		for k, elem := range val {
			val[k] = normalizeNumbers(elem)
		}
		return val
	case []interface{}:
		for i, elem := range val {
			val[i] = normalizeNumbers(elem)
		}
		return val
	default:
		return v
	}
}

// containsAny reports whether s contains any of the given bytes.
func containsAny(s string, chars ...byte) bool {
	for i := 0; i < len(s); i++ {
		for _, c := range chars {
			if s[i] == c {
				return true
			}
		}
	}
	return false
}
