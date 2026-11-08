package canon_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
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
// an error; errors.Is tells the two apart, and the message names the literal.
func TestFloat64_RefusesWhatIsNotAJSONNumberOrADouble(t *testing.T) {
	kinds := map[canon.Error][]string{
		canon.ErrNotJSONNumber:     {"", "+1", ".5", "01", "1.", "1e", "0x10", "Inf", "NaN", "1/2", " 1"},
		canon.ErrBeyondDoubleRange: {"1e309", "-1e309", "1.7976931348623159e308", "1e1000001", "1e99999999999999999999"},
	}
	for want, lits := range kinds {
		for _, lit := range lits {
			_, err := canon.Float64(json.Number(lit))
			checkRefusal(t, kinds, want, lit, err, strconv.Quote(lit))
		}
	}
}

// checkRefusal reports unless err wraps want and no other kind, and its
// message holds named.
func checkRefusal(t *testing.T, kinds map[canon.Error][]string, want canon.Error, lit string, err error, named string) {
	t.Helper()
	if err == nil {
		t.Errorf("Float64(%.12q…): no error, want %q", lit, want)
		return
	}
	for kind := range kinds {
		if errors.Is(err, kind) != (kind == want) {
			t.Errorf("Float64(%.12q…): %v, want an error wrapping %q only", lit, err, want)
		}
	}
	if !strings.Contains(err.Error(), named) {
		t.Errorf("Float64(%.12q…): %q does not name the literal", lit, err)
	}
}

// A literal of a thousand digits reads as its value, or is refused when its
// value is beyond the double range, named by its head within 128 bytes and
// its length.
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
	kinds := map[canon.Error][]string{canon.ErrNotJSONNumber: nil, canon.ErrBeyondDoubleRange: nil}
	for _, lit := range []string{"1" + strings.Repeat("0", 1000), long, "-" + long} {
		_, err := canon.Float64(json.Number(lit))
		checkRefusal(t, kinds, canon.ErrBeyondDoubleRange, lit, err, strconv.Quote(lit[:110])+fmt.Sprintf("… (%d bytes)", len(lit)))
	}
}
