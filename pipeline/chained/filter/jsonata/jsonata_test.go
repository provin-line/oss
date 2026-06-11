package jsonata_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/provin-line/oss/pipeline/chained/filter"
	"github.com/provin-line/oss/pipeline/chained/filter/jsonata"
)

// Compile-time interface compliance check.
var _ filter.Filter = (*jsonata.Filter)(nil)

// TestNew covers construction-time validation.
func TestNew(t *testing.T) {
	t.Run("empty expression list is a construction error", func(t *testing.T) {
		_, err := jsonata.New([]string{})
		if err == nil {
			t.Fatal("expected error for empty expression list, got nil")
		}
	})

	t.Run("nil expression list is a construction error", func(t *testing.T) {
		_, err := jsonata.New(nil)
		if err == nil {
			t.Fatal("expected error for nil expression list, got nil")
		}
	})

	t.Run("invalid JSONata syntax is a construction error", func(t *testing.T) {
		_, err := jsonata.New([]string{"payload.value >>"})
		if err == nil {
			t.Fatal("expected compile error for invalid syntax, got nil")
		}
	})

	t.Run("valid expressions compile without error", func(t *testing.T) {
		f, err := jsonata.New([]string{"payload.value > 10"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f == nil {
			t.Fatal("expected non-nil Filter")
		}
	})
}

// TestApply covers Apply semantics.
func TestApply(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		exprs    []string
		input    string
		wantErr  bool
		wantPass bool
	}{
		{
			name:     "all-truthy single expression → Pass=true",
			exprs:    []string{"payload.value > 10"},
			input:    `{"payload":{"value":20}}`,
			wantPass: true,
		},
		{
			name:     "all-truthy multiple expressions → Pass=true",
			exprs:    []string{"payload.value > 10", "payload.status = \"active\""},
			input:    `{"payload":{"value":20,"status":"active"}}`,
			wantPass: true,
		},
		{
			name:     "one falsy among several → Pass=false",
			exprs:    []string{"payload.value > 10", "payload.status = \"active\""},
			input:    `{"payload":{"value":20,"status":"inactive"}}`,
			wantPass: false,
		},
		{
			name:     "first expression falsy → Pass=false without evaluating rest",
			exprs:    []string{"payload.value > 100", "payload.status = \"active\""},
			input:    `{"payload":{"value":5,"status":"active"}}`,
			wantPass: false,
		},
		{
			name:     "JSONata no-match / undefined field → Pass=false, no error",
			exprs:    []string{"payload.nonexistent"},
			input:    `{"payload":{"value":20}}`,
			wantPass: false,
			wantErr:  false,
		},
		{
			name:     "expression returns false literal → Pass=false",
			exprs:    []string{"false"},
			input:    `{"payload":{"value":20}}`,
			wantPass: false,
		},
		{
			name:     "expression returns true literal → Pass=true",
			exprs:    []string{"true"},
			input:    `{}`,
			wantPass: true,
		},
		{
			name:     "nested field access → truthy result",
			exprs:    []string{"order.items[0].qty > 2"},
			input:    `{"order":{"items":[{"qty":5,"sku":"ABC"}]}}`,
			wantPass: true,
		},
		{
			name:     "nested field access → falsy result",
			exprs:    []string{"order.items[0].qty > 10"},
			input:    `{"order":{"items":[{"qty":5,"sku":"ABC"}]}}`,
			wantPass: false,
		},
		{
			name:     "numeric zero → falsy (JSONata $boolean(0)=false)",
			exprs:    []string{"payload.count"},
			input:    `{"payload":{"count":0}}`,
			wantPass: false,
		},
		{
			name:     "empty string → falsy (JSONata $boolean(\"\")=false)",
			exprs:    []string{"payload.label"},
			input:    `{"payload":{"label":""}}`,
			wantPass: false,
		},
		{
			name:     "non-zero number → truthy",
			exprs:    []string{"payload.count"},
			input:    `{"payload":{"count":42}}`,
			wantPass: true,
		},
		{
			name:     "non-empty string → truthy",
			exprs:    []string{"payload.label"},
			input:    `{"payload":{"label":"hello"}}`,
			wantPass: true,
		},
		{
			name:     "empty array → falsy",
			exprs:    []string{"payload.items"},
			input:    `{"payload":{"items":[]}}`,
			wantPass: false,
		},
		{
			name:    "invalid JSON input → Apply returns error",
			exprs:   []string{"payload.value > 10"},
			input:   `not-json`,
			wantErr: true,
		},
		// Finding #1: $count returns Go int — must be truthy when non-zero.
		{
			name:     "$count(items) on non-empty array → Pass=true (int-typed result)",
			exprs:    []string{"$count(items)"},
			input:    `{"items":[1,2,3]}`,
			wantPass: true,
		},
		// Finding #1: $length returns Go int — must be truthy when non-zero.
		{
			name:     "$length(name) on non-empty string → Pass=true (int-typed result)",
			exprs:    []string{"$length(name)"},
			input:    `{"name":"abc"}`,
			wantPass: true,
		},
		// Finding #2: duplicate-key input must be rejected as an error.
		{
			name:    "duplicate-key JSON input → Apply returns error",
			exprs:   []string{"payload.value > 10"},
			input:   `{"payload":{"value":0,"value":20}}`,
			wantErr: true,
		},
		// Finding #2: trailing-data input must be rejected as an error.
		{
			name:    "trailing-data JSON input → Apply returns error",
			exprs:   []string{"a"},
			input:   `{"a":1} {"b":2}`,
			wantErr: true,
		},
		// Finding #3: numeric comparison after strict decode (json.Number normalization).
		{
			name:     "payload.value > 10 with value=20 after strict decode → Pass=true",
			exprs:    []string{"payload.value > 10"},
			input:    `{"payload":{"value":20}}`,
			wantPass: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f, err := jsonata.New(tc.exprs)
			if err != nil {
				t.Fatalf("New(%v): unexpected error: %v", tc.exprs, err)
			}

			result, err := f.Apply(ctx, []byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("Apply returned nil result with nil error")
			}
			if result.Pass != tc.wantPass {
				t.Errorf("Pass=%v, want %v", result.Pass, tc.wantPass)
			}
		})
	}
}

// TestApplyIntegerPrecision pins the library's behavior for integers > 2^53.
// After strict decode, json.Number values are normalized: integral values
// fitting int64 become int64, others become float64. JSONata arithmetic
// operates in float64 internally, so integers > 2^53 lose precision once they
// enter JSONata expression evaluation. This test documents (golden) what the
// library does so behavioral drift is caught.
//
// Numeric model: integer identity is preserved up to int64 in the decoded Go
// tree (via normalization). Inside JSONata expressions, arithmetic and
// comparison are float64. Integers above 2^53 may lose precision during
// expression evaluation even though the input was decoded exactly.
func TestApplyIntegerPrecision(t *testing.T) {
	ctx := context.Background()

	// 2^53+1 = 9007199254740993; as float64 it becomes 9007199254740992.
	// The input is decoded exactly as int64 (9007199254740993) by normalization,
	// but jsonata-go converts it to float64 internally for comparison.
	// val > 9007199254740991: float64(9007199254740993) = 9007199254740992 > 9007199254740991.
	// Golden: Pass=true.
	f, err := jsonata.New([]string{"val > 9007199254740991"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := f.Apply(ctx, []byte(`{"val":9007199254740993}`))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Pin observed behavior: normalized int64 enters jsonata-go as float64,
	// rounds 2^53+1 → 2^53, but 2^53 > 2^53-1 still holds.
	if !result.Pass {
		t.Errorf("golden: expected Pass=true for val(2^53+1) > 2^53-1, got false")
	}

	// Precision loss check: compare 2^53+1 to itself using the expression literal.
	// Both sides undergo float64 rounding, so they may or may not be equal.
	// Golden: pin what actually happens.
	f2, err := jsonata.New([]string{"val = 9007199254740993"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result2, err := f2.Apply(ctx, []byte(`{"val":9007199254740993}`))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Golden: both sides round to 9007199254740992 → equal → Pass=true.
	// If this test breaks, the library's numeric handling changed.
	if !result2.Pass {
		t.Logf("NOTICE: 2^53+1 precision golden changed: val=9007199254740993 returned Pass=false. "+
			"Both input (after normalization) and expression literal undergo float64 rounding "+
			"inside jsonata-go; if they round to different values the comparison is false. "+
			"This indicates a change in jsonata-go numeric handling. result2.Pass=%v", result2.Pass)
		// Do not fatal — log and pin; caller can decide to update.
		t.Errorf("golden broken: expected Pass=true for val=9007199254740993, got false")
	}
}

// TestApplyConcurrency exercises concurrent Apply calls to verify thread-safety.
func TestApplyConcurrency(t *testing.T) {
	f, err := jsonata.New([]string{"value > 0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	input := []byte(`{"value":1}`)

	const goroutines = 50
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			result, err := f.Apply(ctx, input)
			if err != nil {
				errs <- err
				return
			}
			if !result.Pass {
				// Finding #5 fix: send a real error, not nil, when Pass is unexpected.
				errs <- fmt.Errorf("Apply returned Pass=false, want true")
				return
			}
			errs <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		if e := <-errs; e != nil {
			t.Errorf("concurrent Apply error: %v", e)
		}
	}
}
