package canon_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon"
)

// Float64 reads a JSON number as the double it denotes, rounded to nearest.
func TestFloat64_ReadsTheDoubleANumberDenotes(t *testing.T) {
	for lit, want := range map[string]float64{
		"0":                       0,
		"1":                       1,
		"-1.5":                    -1.5,
		"0.1":                     0.1,
		"123.456":                 123.456,
		"1e2":                     100,
		"1E-2":                    0.01,
		"2.5e+3":                  2500,
		"9007199254740993":        9007199254740992,
		"9007199254740995":        9007199254740996,
		"1.7976931348623157e308":  math.MaxFloat64,
		"1.7976931348623158e308":  math.MaxFloat64,
		"-1.7976931348623157e308": -math.MaxFloat64,
		"5e-324":                  math.SmallestNonzeroFloat64,
		"3e-324":                  math.SmallestNonzeroFloat64,
		"2e-324":                  0,
		"1e-400":                  0,
		"1e-1000001":              0,
		"1e-99999999999999999999": 0,
		"0e1000001":               0,
	} {
		got, err := canon.Float64(json.Number(lit))
		if err != nil || got != want {
			t.Errorf("Float64(%s) = %v, %v; want %v", lit, got, err, want)
		}
	}
	for _, lit := range []string{"-0", "-1e-400", "-1e-1000001"} {
		if got, err := canon.Float64(json.Number(lit)); err != nil || got != 0 || !math.Signbit(got) {
			t.Errorf("Float64(%s) = %v, %v; want -0", lit, got, err)
		}
	}
}

// Spellings of one number give one double.
func TestFloat64_IsTheSameForEverySpellingOfANumber(t *testing.T) {
	for _, lit := range []string{"100", "1e2", "1E+2", "1.00e2", "10e1", "0.1e3", "1000e-1", "100.000"} {
		if got, err := canon.Float64(json.Number(lit)); err != nil || got != 100 {
			t.Errorf("Float64(%s) = %v, %v; want 100", lit, got, err)
		}
	}
}

// Only the RFC 8259 grammar is read, and a number beyond the double range is
// an error.
func TestFloat64_RefusesWhatIsNotAJSONNumberOrADouble(t *testing.T) {
	for _, lit := range []string{"", "+1", ".5", "01", "1.", "1e", "0x10", "Inf", "NaN", "1/2", " 1", "1e309", "-1e309", "1.7976931348623159e308", "1e1000001", "1e99999999999999999999"} {
		if got, err := canon.Float64(json.Number(lit)); err == nil {
			t.Errorf("Float64(%q) = %v, want an error", lit, got)
		}
	}
}

// A literal of a thousand digits reads as its value, or is refused when its
// value is beyond the double range.
func TestFloat64_ReadsLongLiterals(t *testing.T) {
	long := strings.Repeat("3", 1000)
	for lit, want := range map[string]float64{
		"0." + long:                            1.0 / 3,
		"-0." + long:                           -1.0 / 3,
		"1." + strings.Repeat("0", 1000):       1,
		"0." + strings.Repeat("0", 1000) + "1": 0,
	} {
		if got, err := canon.Float64(json.Number(lit)); err != nil || got != want {
			t.Errorf("Float64(%.12s…) = %v, %v; want %v", lit, got, err, want)
		}
	}
	for _, lit := range []string{"1" + strings.Repeat("0", 1000), long, "-" + long} {
		if got, err := canon.Float64(json.Number(lit)); err == nil {
			t.Errorf("Float64(%.12s…) = %v, want an error", lit, got)
		}
	}
}
