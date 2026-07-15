package jcs

import (
	"encoding/json"
	"testing"
)

// The RFC8785 canonicalizer is a PURE RFC 8785 serializer: it rounds every
// number through binary64 per ES6 Number::toString, including the integers the
// legacy path emits verbatim. It does NOT reject unsafe integers — that is the
// artifact admission gate's job (canon.AdmitSafeNumbers), which runs at the
// raw-token stage before canonicalization. Keeping the two apart is what lets
// this type stay byte-for-byte conformant (canon.jcs.base) while new artifacts
// still get the safe-integer gate (canon.number.safe-integer).

func TestRFC8785_OfficialExampleNumbers(t *testing.T) {
	// The RFC 8785 spec example: a pure serializer emits these, never rejects.
	in := map[string]any{
		"numbers": []any{
			json.Number("333333333.33333329"),
			json.Number("1E30"),
			json.Number("4.50"),
			json.Number("2e-3"),
			json.Number("0.000000000000000000000000001"),
		},
	}
	// Expected values are the RFC's own canonical output (jcs_test.go pins the
	// same example for the legacy path): ES6 emits the SHORTEST decimal that
	// round-trips, so the 17-digit input collapses to 333333333.3333333.
	want := `{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}`
	got, err := CanonicalizeRFC8785(in)
	if err != nil {
		t.Fatalf("CanonicalizeRFC8785: unexpected error: %v", err)
	}
	if string(got) != want {
		t.Errorf("CanonicalizeRFC8785:\n got %s\nwant %s", got, want)
	}
}

func TestRFC8785_RoundsIntegersThroughBinary64(t *testing.T) {
	// The one deviation of the legacy path, removed here: an integer above 2^53
	// is emitted as its binary64 round-trip, exactly as a strict-ES6 JCS
	// implementation would. The serializer does not reject it; admission does.
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"unsafe int64 literal rounds", json.Number("9007199254740993"), "9007199254740992"},
		// ES6 emits the shortest round-tripping decimal for the binary64 (2^63),
		// which is 9223372036854776000 — not the exact value 9223372036854775808.
		{"max int64 literal rounds", json.Number("9223372036854775807"), "9223372036854776000"},
		{"safe integer literal is exact", json.Number("9007199254740991"), "9007199254740991"},
		{"typed int64 above 2^53 rounds", int64(9007199254740993), "9007199254740992"},
		{"typed uint64 above 2^53 rounds", uint64(9007199254740993), "9007199254740992"},
		{"typed int in safe range is exact", 1, "1"},
		{"exponent integer in range canonicalizes", json.Number("1e3"), "1000"},
		{"negative zero canonicalizes to 0", json.Number("-0"), "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizeRFC8785(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRFC8785_DivergesFromLegacyOnlyAboveSafeRange(t *testing.T) {
	// The legacy path's reason to exist: it preserves >2^53 literals verbatim.
	// Pinning both sides of the divergence keeps the legacy projection honest
	// (canon.jcs.int64-verbatim) and proves the new path is not the old one.
	unsafe := json.Number("9007199254740993")
	legacy, err := Canonicalize(unsafe)
	if err != nil {
		t.Fatalf("legacy Canonicalize: %v", err)
	}
	if string(legacy) != "9007199254740993" {
		t.Fatalf("legacy path changed: got %s, want verbatim 9007199254740993", legacy)
	}
	strict, err := CanonicalizeRFC8785(unsafe)
	if err != nil {
		t.Fatalf("CanonicalizeRFC8785: %v", err)
	}
	if string(strict) == string(legacy) {
		t.Errorf("RFC8785 must not preserve the legacy deviation: both emitted %s", strict)
	}
}

func TestRFC8785_AgreesWithLegacyInSafeRange(t *testing.T) {
	// Real data is numeric-free or safe-range, so the switch is byte-identical
	// there. This is the property the stored-address migration (decision B)
	// depends on.
	cases := []any{
		map[string]any{"v": 1},
		map[string]any{"n": json.Number("0")},
		map[string]any{"n": json.Number("9007199254740991")},
		map[string]any{"s": "no numbers here", "b": true, "z": nil},
	}
	for _, in := range cases {
		legacy, err := Canonicalize(in)
		if err != nil {
			t.Fatalf("legacy: %v", err)
		}
		strict, err := CanonicalizeRFC8785(in)
		if err != nil {
			t.Fatalf("rfc8785: %v", err)
		}
		if string(legacy) != string(strict) {
			t.Errorf("safe-range divergence: legacy=%s rfc8785=%s", legacy, strict)
		}
	}
}

func TestRFC8785_NameAndInterface(t *testing.T) {
	if got := (RFC8785{}).Name(); got != NameRFC8785 {
		t.Errorf("Name() = %q, want %q", got, NameRFC8785)
	}
	if NameRFC8785 != "jcs-rfc8785" {
		t.Errorf("wire id drifted: %q — the id is frozen by identity.wire-variant-id", NameRFC8785)
	}
	got, err := RFC8785{}.Canonicalize(map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Errorf("got %s", got)
	}
}

func TestRFC8785_HashMatchesCanonicalBytes(t *testing.T) {
	in := map[string]any{"a": "b"}
	h, err := HashRFC8785(in)
	if err != nil {
		t.Fatalf("HashRFC8785: %v", err)
	}
	// sha256 of {"a":"b"} — recomputed here from the canonical bytes so the
	// test pins the wiring, not a copied constant.
	want, err := hashOf(t, in)
	if err != nil {
		t.Fatalf("hashOf: %v", err)
	}
	if h != want {
		t.Errorf("HashRFC8785 = %s, want %s", h, want)
	}
}

func hashOf(t *testing.T, v any) (string, error) {
	t.Helper()
	b, err := CanonicalizeRFC8785(v)
	if err != nil {
		return "", err
	}
	return sha256Prefixed(b), nil
}
