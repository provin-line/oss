package jcs_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
)

// jcs reads a json.Number as canon.Float64 does: spellings of one number give
// one canonical form, and only the RFC 8259 grammar is read.
func TestCanonicalizeRFC8785_ReadsNumbersAsCanonFloat64(t *testing.T) {
	for _, lit := range []string{"100", "1e2", "1.00e2", "0.1e3", "1000e-1"} {
		b, err := jcs.CanonicalizeRFC8785(map[string]any{"n": json.Number(lit)})
		if err != nil || string(b) != `{"n":100}` {
			t.Errorf("%s: %s, %v; want {\"n\":100}", lit, b, err)
		}
	}
	for _, lit := range []string{"+1", ".5", "01"} {
		if b, err := jcs.CanonicalizeRFC8785(map[string]any{"n": json.Number(lit)}); err == nil {
			t.Errorf("%s: %s, want an error", lit, b)
		}
	}
}

// The legacy canonicalizer keeps an int64 or uint64 literal as written, and
// reads only the RFC 8259 grammar as the RFC 8785 one does.
func TestCanonicalize_ReadsOnlyJSONNumbers(t *testing.T) {
	b, err := jcs.Canonicalize(map[string]any{"n": json.Number("9007199254740993")})
	if err != nil || string(b) != `{"n":9007199254740993}` {
		t.Errorf("9007199254740993: %s, %v; want {\"n\":9007199254740993}", b, err)
	}
	for _, lit := range []string{"+1", "01", "-01", ".5"} {
		if b, err := jcs.Canonicalize(map[string]any{"n": json.Number(lit)}); err == nil {
			t.Errorf("%s: %s, want an error", lit, b)
		}
	}
}

// A literal of a thousand digits gives the canonical form of its value, or
// an error when its value is beyond the double range.
func TestCanonicalizeRFC8785_ReadsLongLiterals(t *testing.T) {
	long := strings.Repeat("3", 1000)
	b, err := jcs.CanonicalizeRFC8785(map[string]any{"n": json.Number("0." + long)})
	if err != nil || string(b) != `{"n":0.3333333333333333}` {
		t.Errorf("0.333…: %s, %v; want {\"n\":0.3333333333333333}", b, err)
	}
	if b, err := jcs.CanonicalizeRFC8785(map[string]any{"n": json.Number(long)}); err == nil {
		t.Errorf("333…: %s, want an error", b)
	}
}
