package jcs_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
)

// RFC 8785 Section 3.2.3 canonicalization example. Values are built directly
// (numbers as json.Number literals, strings pre-decoded) so this test does
// not depend on the strict decoder.
func TestCanonicalizeRFC8785Example(t *testing.T) {
	v := map[string]any{
		"numbers": []any{
			json.Number("333333333.33333329"),
			json.Number("1E30"),
			json.Number("4.50"),
			json.Number("2e-3"),
			json.Number("0.000000000000000000000000001"),
		},
		// U+20AC, $, U+000F, LF, A, ', B, ", \, \, ", /
		"string":   "€$\nA'B\"\\\\\"/",
		"literals": []any{nil, true, false},
	}
	want := "{\"literals\":[null,true,false]," +
		"\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27]," +
		"\"string\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	got, err := jcs.Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

// ES6 Number::toString boundaries (RFC 8785 Appendix-style vectors).
func TestCanonicalizeNumbers(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{float64(0), "0"},
		{negZero(), "0"},
		{float64(1), "1"},
		{0.5, "0.5"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{1e-6, "0.000001"},
		{1e-7, "1e-7"},
		{-1.5e-9, "-1.5e-9"},
		{333333333.33333329, "333333333.3333333"},
		{float64(9007199254740994), "9007199254740994"},
		{5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"},
		// json.Number: 64-bit integers survive verbatim (deliberate RFC 8785
		// deviation -- see package doc), non-integer literals go the ES6 path.
		{json.Number("18446744073709551615"), "18446744073709551615"},
		{json.Number("-9223372036854775808"), "-9223372036854775808"},
		{json.Number("1e3"), "1000"},
		{json.Number("-0"), "0"},
		// Go native ints
		{int(42), "42"},
		{int64(-7), "-7"},
		{uint64(18446744073709551615), "18446744073709551615"},
	}
	for _, c := range cases {
		got, err := jcs.Canonicalize(c.in)
		if err != nil {
			t.Errorf("Canonicalize(%v): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Canonicalize(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func negZero() float64 {
	z := 0.0
	return -z
}

// Object keys sort by UTF-16 code units (RFC 8785 Section 3.2.3 sorting
// example): the emoji (high surrogate 0xD83D) sorts before U+FB33.
func TestCanonicalizeKeyOrderUTF16(t *testing.T) {
	v := map[string]any{
		"€":          "Euro Sign",
		"\r":         "Carriage Return",
		"דּ":          "Hebrew Letter Dalet With Dagesh",
		"1":          "One",
		"\U0001F600": "Emoji: Grinning Face",
		"":          "Control",
		"ö":          "Latin Small Letter O With Diaeresis",
	}
	got, err := jcs.Canonicalize(v)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	// Keys as they appear in the canonical output: CR escapes to the
	// two-character sequence \r; everything >= U+0020 stays raw UTF-8.
	wantOrder := []string{"\\r", "1", "", "ö", "€", "\U0001F600", "דּ"}
	pos := -1
	for _, k := range wantOrder {
		i := strings.Index(string(got), "\""+k+"\"")
		if i < 0 {
			t.Fatalf("key %q not found in output %s", k, got)
		}
		if i < pos {
			t.Errorf("key %q out of order in %s", k, got)
		}
		pos = i
	}
}

func TestCanonicalizeEmptyAndNested(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{map[string]any{}, "{}"},
		{[]any{}, "[]"},
		{nil, "null"},
		{map[string]any{"a": []any{map[string]any{"b": json.Number("1")}}}, "{\"a\":[{\"b\":1}]}"},
	}
	for _, c := range cases {
		got, err := jcs.Canonicalize(c.in)
		if err != nil {
			t.Errorf("Canonicalize(%#v): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("Canonicalize(%#v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeRejectsUnsupported(t *testing.T) {
	for _, v := range []any{struct{}{}, make(chan int), map[int]any{1: "x"}} {
		if _, err := jcs.Canonicalize(v); err == nil {
			t.Errorf("Canonicalize(%T): want error, got nil", v)
		}
	}
}

func TestHash(t *testing.T) {
	// SHA-256("{}") -- fixed vector pins the content-address format.
	got, err := jcs.Hash(map[string]any{})
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	want := "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if got != want {
		t.Errorf("Hash({}) = %s, want %s", got, want)
	}
}

func TestCanonicalizeRejectsInvalidUTF8(t *testing.T) {
	if _, err := jcs.Canonicalize("a\xffb"); err == nil {
		t.Error("invalid UTF-8 string value: want error, got nil")
	}
	if _, err := jcs.Canonicalize(map[string]any{"k\xff": 1}); err == nil {
		t.Error("invalid UTF-8 object key: want error, got nil")
	}
}
