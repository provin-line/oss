package vectors_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

// canonicalizeText runs the canonicalizer's stage the way the product reaches
// it: the strict decoder (numbers as json.Number) and then the RFC 8785
// serializer. (Admission, which refuses unsafe numbers such as 1e30 before
// this stage, is not part of it.)
func canonicalizeText(text []byte) ([]byte, error) {
	var v any
	if err := canon.NewStrictDecoder(text).Decode(&v); err != nil {
		return nil, err
	}
	return jcs.CanonicalizeRFC8785(v)
}

// serializeText runs the RFC 8785 serializer alone, over a value decoded by
// encoding/json with numbers as json.Number, as the product's decoder gives
// them.
func serializeText(text []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(text))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return jcs.CanonicalizeRFC8785(v)
}

// jcsReferenceNames are the input/output pairs of the RFC 8785 reference
// implementation's testdata.
var jcsReferenceNames = []string{"arrays", "french", "structures", "unicode", "values", "weird"}

func readJCSPair(t *testing.T, name string) (in, want []byte) {
	t.Helper()
	in, err := os.ReadFile("testdata/jcs/input/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	want, err = os.ReadFile("testdata/jcs/output/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	return in, want
}

// The serializer gives every reference input its canonical form, byte for
// byte.
func TestJCSReferenceImplementationVectors(t *testing.T) {
	for _, name := range jcsReferenceNames {
		t.Run(name, func(t *testing.T) {
			in, want := readJCSPair(t, name)
			got, err := serializeText(in)
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("canonical form:\n got=%s\nwant=%s", got, want)
			}
		})
	}
	entries, err := os.ReadDir("testdata/jcs/input")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(jcsReferenceNames) {
		t.Errorf("testdata/jcs/input holds %d files, the test names %d", len(entries), len(jcsReferenceNames))
	}
}

// strictDecoderRefuses are the reference inputs the product's strict decoder
// refuses, with the pairs of names it may name: names that differ only in
// case (canon.StrictDecoder refuses them as a *canon.DuplicateKeyError whose
// Other is set, as encoding/json folds names when it decodes into a struct).
// The input tests the order of such names.
var strictDecoderRefuses = map[string][][2]string{
	"structures": {{"F", "f"}, {"f", "F"}, {"E", "e"}, {"e", "E"}},
}

// Through the strict decoder, every reference input gives its canonical form
// or is refused for the reason listed above.
func TestJCSReferenceVectorsAtTheStrictDecoder(t *testing.T) {
	for _, name := range jcsReferenceNames {
		t.Run(name, func(t *testing.T) {
			in, want := readJCSPair(t, name)
			got, err := canonicalizeText(in)
			if pairs, refused := strictDecoderRefuses[name]; refused {
				var dup *canon.DuplicateKeyError
				if !errors.As(err, &dup) || dup.Other == "" {
					t.Fatalf("want a *canon.DuplicateKeyError for names that differ only in case, got %v", err)
				}
				if !slices.Contains(pairs, [2]string{dup.Key, dup.Other}) {
					t.Errorf("refused names %q and %q, want one of %q", dup.Key, dup.Other, pairs)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("canonical form:\n got=%s\nwant=%s", got, want)
			}
		})
	}
}

// rfc8785AppendixB is RFC 8785, Appendix B, Table 1 ("ECMAScript-Compatible
// JSON Number Serialization Samples"): a binary64 value as hex, and its JSON
// serialization; "" for NaN and Infinity, which have none.
var rfc8785AppendixB = []struct{ bits, json string }{
	{"0000000000000000", "0"},
	{"8000000000000000", "0"},
	{"0000000000000001", "5e-324"},
	{"8000000000000001", "-5e-324"},
	{"7fefffffffffffff", "1.7976931348623157e+308"},
	{"ffefffffffffffff", "-1.7976931348623157e+308"},
	{"4340000000000000", "9007199254740992"},
	{"c340000000000000", "-9007199254740992"},
	{"4430000000000000", "295147905179352830000"},
	{"7fffffffffffffff", ""},
	{"7ff0000000000000", ""},
	{"44b52d02c7e14af5", "9.999999999999997e+22"},
	{"44b52d02c7e14af6", "1e+23"},
	{"44b52d02c7e14af7", "1.0000000000000001e+23"},
	{"444b1ae4d6e2ef4e", "999999999999999700000"},
	{"444b1ae4d6e2ef4f", "999999999999999900000"},
	{"444b1ae4d6e2ef50", "1e+21"},
	{"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
	{"3eb0c6f7a0b5ed8d", "0.000001"},
	{"41b3de4355555553", "333333333.3333332"},
	{"41b3de4355555554", "333333333.33333325"},
	{"41b3de4355555555", "333333333.3333333"},
	{"41b3de4355555556", "333333333.3333334"},
	{"41b3de4355555557", "333333333.33333343"},
	{"becbf647612f3696", "-0.0000033333333333333333"},
	{"43143ff3c1cb0959", "1424953923781206.2"},
}

func appendixBValue(t *testing.T, bits string) float64 {
	t.Helper()
	u, err := strconv.ParseUint(bits, 16, 64)
	if err != nil {
		t.Fatalf("bits %q: %v", bits, err)
	}
	return math.Float64frombits(u)
}

// Each finite value of Appendix B, written as the shortest JSON number that
// reads back as that binary64, goes through the strict decoder and the
// serializer.
func TestRFC8785AppendixB(t *testing.T) {
	n := 0
	for _, row := range rfc8785AppendixB {
		if row.json == "" {
			continue
		}
		n++
		text := strconv.FormatFloat(appendixBValue(t, row.bits), 'e', -1, 64)
		got, err := canonicalizeText([]byte(text))
		if err != nil {
			t.Errorf("%s (%s): %v", row.bits, text, err)
			continue
		}
		if string(got) != row.json {
			t.Errorf("%s (%s): %s, want %s", row.bits, text, got, row.json)
		}
	}
	if n != 24 {
		t.Errorf("ran %d finite rows of Appendix B, want 24", n)
	}
}

// The serializer's float64 branch, with the same table: NaN and Infinity are
// refused.
func TestRFC8785AppendixBFloat64(t *testing.T) {
	for _, row := range rfc8785AppendixB {
		got, err := jcs.CanonicalizeRFC8785(appendixBValue(t, row.bits))
		if row.json == "" {
			if err == nil {
				t.Errorf("%s: %s, want an error (no JSON number)", row.bits, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", row.bits, err)
			continue
		}
		if string(got) != row.json {
			t.Errorf("%s: %s, want %s", row.bits, got, row.json)
		}
	}
}
