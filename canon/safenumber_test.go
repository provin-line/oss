package canon_test

import (
	"encoding/json"
	"errors"
	"math"
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
