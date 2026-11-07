package canon_test

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon"
)

// AdmitSafeNumbers is the artifact admission gate (canon.number.safe-integer /
// canon.number.raw-token-guard). It runs at the raw-token stage, BEFORE
// canonicalization, so an unsafe integer is rejected while its literal is still
// exact — never inferred from a value a lossy parser already rounded.
//
// It is deliberately not part of the canonicalizer: a serializer that rejected
// these could not be byte-for-byte RFC 8785 (the RFC's own example carries
// 1E30). The serializer keeps emitting; admission is what says no.

func TestAdmitSafeNumbers_AdmitsSafeValues(t *testing.T) {
	tests := []struct {
		name string
		in   any
	}{
		{"safe max literal", json.Number("9007199254740991")},
		{"safe min literal", json.Number("-9007199254740991")},
		{"zero", json.Number("0")},
		{"negative zero", json.Number("-0")},
		{"exponent integer in range", json.Number("1e3")},
		{"typed int", 1},
		{"typed int64 in range", int64(9007199254740991)},
		{"typed uint64 in range", uint64(9007199254740991)},
		{"non-integer is not the gate's business", json.Number("4.50")},
		{"non-integer exponent", json.Number("2e-3")},
		{"long fraction", json.Number("333333333.33333329")},
		{"tiny fraction", json.Number("0.000000000000000000000000001")},
		{"nested safe", map[string]any{"a": []any{json.Number("1"), map[string]any{"b": json.Number("-5")}}}},
		{"no numbers at all", map[string]any{"s": "x", "b": true, "z": nil}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := canon.AdmitSafeNumbers(tc.in); err != nil {
				t.Errorf("AdmitSafeNumbers rejected a safe value: %v", err)
			}
		})
	}
}

func TestAdmitSafeNumbers_RejectsUnsafeIntegersInEverySpelling(t *testing.T) {
	// The gate keys on the VALUE being integral and out of range, not on the
	// spelling. A spelling-sensitive gate would be trivially bypassed by
	// writing the same integer as an exponent or with a .0 tail.
	tests := []struct {
		name string
		in   any
	}{
		{"plain above safe range", json.Number("9007199254740993")},
		{"plain below safe range", json.Number("-9007199254740993")},
		{"exactly 2^53", json.Number("9007199254740992")},
		{"exponent spelling", json.Number("1e21")},
		{"exponent spelling of an unsafe integer", json.Number("9007199254740993e0")},
		{"RFC example 1E30 is an unsafe integer", json.Number("1E30")},
		{"fraction spelling of an unsafe integer", json.Number("9007199254740992.0")},
		{"max int64 literal", json.Number("9223372036854775807")},
		{"typed int64 above range", int64(9007199254740993)},
		{"typed uint64 above range", uint64(9007199254740993)},
		{"nested unsafe", map[string]any{"a": []any{json.Number("1"), map[string]any{"b": json.Number("1e30")}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := canon.AdmitSafeNumbers(tc.in)
			if err == nil {
				t.Fatalf("AdmitSafeNumbers admitted an unsafe integer")
			}
			var unsafeErr *canon.UnsafeNumberError
			if !errors.As(err, &unsafeErr) {
				t.Errorf("error is not *UnsafeNumberError: %T (%v)", err, err)
			}
		})
	}
}

func TestAdmitSafeNumbers_RejectsNaNAndInfinity(t *testing.T) {
	for _, in := range []any{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if err := canon.AdmitSafeNumbers(in); err == nil {
			t.Errorf("AdmitSafeNumbers admitted %v", in)
		}
	}
}

func TestAdmitSafeNumbers_ReportsPath(t *testing.T) {
	// A rejection an operator cannot locate is a rejection they will route
	// around. The error names where the offending number lives.
	err := canon.AdmitSafeNumbers(map[string]any{
		"credentialSubject": map[string]any{"counts": []any{json.Number("1"), json.Number("1e30")}},
	})
	if err == nil {
		t.Fatal("expected rejection")
	}
	var unsafeErr *canon.UnsafeNumberError
	if !errors.As(err, &unsafeErr) {
		t.Fatalf("error is not *UnsafeNumberError: %T", err)
	}
	if unsafeErr.Literal != "1e30" {
		t.Errorf("Literal = %q, want 1e30", unsafeErr.Literal)
	}
	wantPath := "credentialSubject.counts[1]"
	if got := unsafeErr.Path; got != wantPath {
		t.Errorf("Path = %q, want %q", got, wantPath)
	}
}

func TestAdmitSafeNumbers_RawTokenGuard(t *testing.T) {
	// The guard's whole point: 9007199254740993 rounds to 9007199254740992 in
	// float64. A gate that parsed first and range-checked the result would see a
	// safe-looking value and admit a corrupted one. Decoding through the strict
	// decoder keeps the literal exact, and the gate must reject it.
	var v any
	if err := canon.NewStrictDecoder([]byte(`{"n":9007199254740993}`)).Decode(&v); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if err := canon.AdmitSafeNumbers(v); err == nil {
		t.Error("gate inferred safety from a rounded value — the raw-token guard is not effective")
	}
}

// The path to a refused number is spelled the same in every shape: members
// joined by ".", indexes as "[i]", an empty member name contributing no
// segment of its own at the root and an empty one after a dot elsewhere.
func TestAdmitSafeNumbers_SpellsThePathInEveryShape(t *testing.T) {
	unsafe := json.Number("1e30")
	for _, c := range []struct {
		in   any
		path string
	}{
		{unsafe, ""},
		{[]any{unsafe}, "[0]"},
		{[]any{json.Number("1"), []any{json.Number("2"), unsafe}}, "[1][1]"},
		{map[string]any{"a": []any{1, map[string]any{"b": []any{json.Number("1"), unsafe}}}}, "a[1].b[1]"},
		{map[string]any{"": map[string]any{"x": unsafe}}, "x"},
		{[]any{map[string]any{"": []any{unsafe}}}, "[0].[0]"},
		{map[string]any{"n": uint64(1) << 60}, "n"},
		{map[string]any{"f": []any{math.Inf(1)}}, "f[0]"},
		{map[string]any{"i": []any{0, int64(-1) << 60}}, "i[1]"},
	} {
		var u *canon.UnsafeNumberError
		if err := canon.AdmitSafeNumbers(c.in); !errors.As(err, &u) {
			t.Errorf("AdmitSafeNumbers(%v) = %v, want *UnsafeNumberError", c.in, err)
		} else if u.Path != c.path {
			t.Errorf("AdmitSafeNumbers(%v): Path = %q, want %q", c.in, u.Path, c.path)
		}
	}
}

func nestedArray(depth int, leaf any) any {
	v := leaf
	for range depth {
		v = []any{v}
	}
	return v
}

// The walk keeps one path for the whole value: depth costs no allocation per
// level, and a refusal deep down still names its path.
func TestAdmitSafeNumbers_DepthCostsNoAllocationPerLevel(t *testing.T) {
	const depth = 10000
	deep := nestedArray(depth, json.Number("1"))
	if a := testing.AllocsPerRun(5, func() {
		if err := canon.AdmitSafeNumbers(deep); err != nil {
			t.Fatal(err)
		}
	}); a > 64 {
		t.Errorf("AdmitSafeNumbers on %d nested arrays allocates %.0f times", depth, a)
	}
	var u *canon.UnsafeNumberError
	if err := canon.AdmitSafeNumbers(nestedArray(depth, json.Number("1e30"))); !errors.As(err, &u) {
		t.Fatalf("AdmitSafeNumbers admitted 1e30 nested %d deep: %v", depth, err)
	}
	if want := strings.Repeat("[0]", depth); u.Path != want {
		t.Errorf("Path has %d bytes, want %d", len(u.Path), len(want))
	}
}
