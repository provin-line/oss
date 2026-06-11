// Package jsonata implements filter.Filter using JSONata expressions
// (github.com/blues/jsonata-go).
//
// Construction pre-compiles all expressions. An empty expression list or any
// compile error fails construction — filters degrade at runtime are never
// permitted (repo convention: fail at startup).
//
// Apply semantics:
//   - All expressions must be truthy for Pass=true.
//   - Evaluation stops at the first falsy result (short-circuit).
//   - A missing/undefined field (ErrUndefined) is falsy, not an error.
//   - Any other evaluation error propagates as an Apply error (step failure).
//
// Truthiness delegates to github.com/blues/jsonata-go/jlib.Boolean, which
// implements JSONata $boolean() semantics by construction:
//   - bool: false → falsy, true → truthy
//   - number: 0 → falsy, any other number → truthy
//   - string: "" → falsy, non-empty → truthy
//   - array: empty → falsy; any element truthy → truthy
//   - object: empty → falsy, non-empty → truthy
//   - null/undefined: falsy
//
// Input decode: Apply uses canon.StrictDecoder — the only JSON decode path
// permitted on protocol boundaries. Duplicate keys and trailing data are
// rejected as errors. Numbers are preserved as json.Number by StrictDecoder,
// then normalized before passing to JSONata.
//
// Numeric model: json.Number values are normalized to int64 when integral and
// fitting int64, else to float64. This preserves integer identity through the
// Go tree. Inside JSONata expressions, arithmetic and comparison operate in
// float64 (jsonata-go's internal representation). Integers above 2^53 are
// represented exactly in the decoded Go tree but lose precision once they
// enter JSONata arithmetic or comparison — equality comparisons near 2^53 may
// be unreliable (both sides round to the same float64 only if the expression
// literal rounds identically). Pin behavior in tests using the golden-test
// pattern; do not rely on exact integer semantics for values > 2^53.
//
// Concurrency: jsonata-go's Expr.Eval creates a fresh environment per call and
// reads compiled state (node + registry) without mutation. Concurrent Apply
// calls on the same *Filter are safe without additional locking.
package jsonata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	libjsonata "github.com/blues/jsonata-go"
	"github.com/blues/jsonata-go/jlib"
	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/pipeline/chained/filter"
)

// Filter evaluates a fixed list of pre-compiled JSONata expressions against
// each event payload. It implements filter.Filter.
type Filter struct {
	exprs []*libjsonata.Expr
}

// New compiles all expressions and returns a ready-to-use Filter.
// Construction fails if exprs is empty or any expression fails to compile.
// An empty expression list is a misconfiguration: a filter with nothing to
// evaluate cannot express a meaningful pass/drop policy.
func New(exprs []string) (*Filter, error) {
	if len(exprs) == 0 {
		return nil, errors.New("jsonata filter: expression list must not be empty")
	}

	compiled := make([]*libjsonata.Expr, 0, len(exprs))
	for i, expr := range exprs {
		e, err := libjsonata.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("jsonata filter: compile expression[%d] %q: %w", i, expr, err)
		}
		compiled = append(compiled, e)
	}

	return &Filter{exprs: compiled}, nil
}

// Apply evaluates all expressions against data in order. Returns Pass=true
// only if all expressions yield a truthy result. Short-circuits on the first
// falsy result. Returns an error if data is not valid JSON (including duplicate
// keys and trailing data), or if any expression raises an evaluation error
// (distinct from undefined/no-match, which is treated as falsy).
func (f *Filter) Apply(_ context.Context, data []byte) (*filter.Result, error) {
	// Decode via StrictDecoder: duplicate keys, trailing data, and invalid
	// Unicode are rejected. Numbers decode as json.Number for precision.
	var v interface{}
	if err := canon.NewStrictDecoder(data).Decode(&v); err != nil {
		return nil, fmt.Errorf("jsonata filter: invalid JSON input: %w", err)
	}

	// Normalize json.Number values in the decoded tree before handing to
	// jsonata-go. StrictDecoder uses UseNumber(), so all JSON numbers arrive
	// as json.Number. jsonata-go's reflect-based type inspection treats
	// json.Number as a string kind, breaking numeric comparisons. Normalizing
	// converts each json.Number to int64 (when integral and fitting int64) or
	// float64, matching what json.Unmarshal would produce while preserving
	// integer identity up to int64 range.
	v = normalizeNumbers(v)

	for _, expr := range f.exprs {
		result, err := expr.Eval(v)
		if err != nil {
			// ErrUndefined means the expression matched nothing — falsy, not
			// an error (e.g. a field reference that does not exist in data).
			if errors.Is(err, libjsonata.ErrUndefined) {
				return &filter.Result{Pass: false}, nil
			}
			return nil, fmt.Errorf("jsonata filter: evaluation error: %w", err)
		}
		if !jlib.Boolean(reflect.ValueOf(result)) {
			return &filter.Result{Pass: false}, nil
		}
	}

	return &filter.Result{Pass: true}, nil
}

// normalizeNumbers walks a decoded JSON value tree and converts every
// json.Number to int64 (when the value is integral and fits int64) or float64
// (otherwise). This is required because StrictDecoder uses UseNumber(), and
// jsonata-go's reflect-based type system treats json.Number as a string kind,
// causing numeric comparisons and $boolean() to misbehave.
func normalizeNumbers(v interface{}) interface{} {
	switch val := v.(type) {
	case json.Number:
		// Try int64 first to preserve integer identity.
		if i, err := val.Int64(); err == nil {
			return i
		}
		// Fall back to float64 for fractional or out-of-range values.
		if f, err := val.Float64(); err == nil {
			return f
		}
		// Malformed json.Number: leave as-is; jsonata-go will error on eval.
		return val
	case map[string]interface{}:
		for k, child := range val {
			val[k] = normalizeNumbers(child)
		}
		return val
	case []interface{}:
		for i, child := range val {
			val[i] = normalizeNumbers(child)
		}
		return val
	default:
		return v
	}
}
