package canon_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon"
)

const (
	reasonUnsafeInteger  = "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema"
	reasonInvalidLiteral = "not a valid JSON number literal"
)

// jsonNumberGrammar is the RFC 8259 number production.
var jsonNumberGrammar = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)

// referenceAdmitLiteral is the gate written with big.Rat, which reads every
// RFC 8259 number exactly, and refuses (as Go's math/big does) a literal
// whose exponent overflows int64 or, for a nonzero value, whose exponent net
// of the digits after its point lies beyond ±10^6. A spelling outside the RFC
// 8259 grammar is refused before big.Rat sees it, since big.Rat also reads
// spellings JSON does not have (+1, 0x10, 1/2). Its cost grows with the
// exponent, so it is a reference for answers, not for use. AdmitSafeNumbers
// must agree with it on every literal.
func referenceAdmitLiteral(lit string) error {
	if !jsonNumberGrammar.MatchString(lit) {
		return &canon.UnsafeNumberError{Literal: lit, Reason: reasonInvalidLiteral}
	}
	r, ok := new(big.Rat).SetString(lit)
	if !ok {
		return &canon.UnsafeNumberError{Literal: lit, Reason: reasonInvalidLiteral}
	}
	if !r.IsInt() {
		return nil
	}
	if i := r.Num(); i.IsInt64() && i.Int64() >= canon.MinSafeInteger && i.Int64() <= canon.MaxSafeInteger {
		return nil
	}
	return &canon.UnsafeNumberError{Literal: lit, Reason: reasonUnsafeInteger}
}

// verdictOf names the outcome as the table in testdata/number-literals.json
// does; anything else is reported as it is.
func verdictOf(err error) string {
	if err == nil {
		return "admit"
	}
	var u *canon.UnsafeNumberError
	if !errors.As(err, &u) {
		return fmt.Sprintf("error %T: %v", err, err)
	}
	switch u.Reason {
	case reasonUnsafeInteger:
		return "unsafe-integer"
	case reasonInvalidLiteral:
		return "invalid-literal"
	}
	return "reason " + u.Reason
}

func admitLiteral(lit string) error { return canon.AdmitSafeNumbers(json.Number(lit)) }

func checkAgainstReference(t *testing.T, lit string) {
	t.Helper()
	got, want := admitLiteral(lit), referenceAdmitLiteral(lit)
	if verdictOf(got) != verdictOf(want) {
		t.Errorf("AdmitSafeNumbers(%.40q) = %s, reference = %s", lit, verdictOf(got), verdictOf(want))
		return
	}
	var u *canon.UnsafeNumberError
	if errors.As(got, &u) && (u.Literal != lit || u.Path != "") {
		t.Errorf("AdmitSafeNumbers(%.40q): Literal %.40q, Path %q; want the literal as written at the root", lit, u.Literal, u.Path)
	}
}

type literalCase struct {
	Literal string `json:"literal"`
	Verdict string `json:"verdict"`
}

func literalTable(t testing.TB) []literalCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/number-literals.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases []literalCase `json:"cases"`
	}
	if err := canon.NewStrictDecoder(raw).Decode(&table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("testdata/number-literals.json has no cases")
	}
	return table.Cases
}

// The table holds every boundary of the gate: ±(2^53-1) and the 16 digits
// past it, one value in many spellings, zero with any exponent, the exponent
// bounds, and spellings that are not RFC 8259 numbers. The gate and the
// reference both give the table's verdict on each.
func TestAdmitSafeNumbers_LiteralTable(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range literalTable(t) {
		if seen[c.Literal] {
			t.Errorf("%q is in the table twice", c.Literal)
		}
		seen[c.Literal] = true
		if got := verdictOf(admitLiteral(c.Literal)); got != c.Verdict {
			t.Errorf("AdmitSafeNumbers(%q) = %s, table = %s", c.Literal, got, c.Verdict)
		}
		if got := verdictOf(referenceAdmitLiteral(c.Literal)); got != c.Verdict {
			t.Errorf("reference(%q) = %s, table = %s", c.Literal, got, c.Verdict)
		}
	}
}

// Long literals reach the exponent bound through the digits after the point,
// and integers far longer than 16 digits are still read as integers.
func TestAdmitSafeNumbers_LongLiteralsMatchReference(t *testing.T) {
	zeros := func(n int) string { return strings.Repeat("0", n) }
	for _, lit := range []string{
		"0." + zeros(999_999) + "1",
		"0." + zeros(1_000_000) + "1",
		"-0." + zeros(1_000_000) + "1e1",
		"0." + zeros(1_000_000) + "1e2",
		"1" + zeros(100_000),
		"-1" + zeros(100_000) + ".0",
		"1" + zeros(100_000) + "e-100000",
		"1" + zeros(100_000) + "e-100001",
		"9007199254740991" + zeros(100_000) + "e-100000",
		"9007199254740992" + zeros(100_000) + "e-100000",
		"0." + zeros(100_000) + "9007199254740991e100016",
		"0." + zeros(100_000) + "9007199254740992e100016",
		"0." + zeros(100_000) + "e999999999",
		"1e" + zeros(100_000) + "5",
		"1e-" + zeros(100_000) + "999999",
		"1e" + zeros(100_000) + "1000001",
	} {
		checkAgainstReference(t, lit)
	}
}

// The gate reads a literal without arithmetic on its value: a literal that
// costs big.Rat milliseconds costs the gate no allocation.
func TestAdmitSafeNumbers_ReadsALiteralWithoutAllocating(t *testing.T) {
	for _, lit := range []string{
		"1e-999999", "1.5e-999999", "0.1e-999999", "1e-1000000",
		"0e9223372036854775807", "9007199254740991", "-9.007199254740991e15", "4.50",
		"0." + strings.Repeat("0", 4096) + "1",
	} {
		v := any(json.Number(lit))
		if a := testing.AllocsPerRun(100, func() {
			if err := canon.AdmitSafeNumbers(v); err != nil {
				t.Fatalf("AdmitSafeNumbers(%.40q): %v", lit, err)
			}
		}); a != 0 {
			t.Errorf("AdmitSafeNumbers(%.40q) allocates %.0f times", lit, a)
		}
	}
}

func FuzzAdmitSafeNumbersMatchesReference(f *testing.F) {
	for _, c := range literalTable(f) {
		f.Add(c.Literal)
	}
	f.Fuzz(func(t *testing.T, lit string) {
		checkAgainstReference(t, lit)
	})
}

// The cost of a hostile literal grows with its length, not its value: the
// MB/s of each family stays flat as the input grows, where the reference
// spends milliseconds on one 9-byte literal.
func BenchmarkAdmitSafeNumbers_HostileLiterals(b *testing.B) {
	many := func(lit string, n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = json.Number(lit)
		}
		return out
	}
	for _, n := range []int{1, 64, 4096} {
		doc := many("1e-999999", n)
		b.Run(fmt.Sprintf("count/%d", n), func(b *testing.B) {
			b.SetBytes(int64(len("1e-999999") * n))
			for b.Loop() {
				if err := canon.AdmitSafeNumbers(doc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	for _, n := range []int{1 << 10, 1 << 14, 1 << 19} {
		zeros := strings.Repeat("0", n)
		for _, f := range []struct{ name, lit string }{
			{"fraction", "0." + zeros + "1e-1"},
			{"integer", "1" + zeros},
			{"exponent", "1e-" + zeros + "999999"},
		} {
			v := any(json.Number(f.lit))
			b.Run(fmt.Sprintf("%s/%d", f.name, n), func(b *testing.B) {
				b.SetBytes(int64(len(f.lit)))
				for b.Loop() {
					_ = canon.AdmitSafeNumbers(v)
				}
			})
		}
	}
	b.Run("reference/1e-999999", func(b *testing.B) {
		b.SetBytes(int64(len("1e-999999")))
		for b.Loop() {
			if err := referenceAdmitLiteral("1e-999999"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// FuzzAdmitSafeNumbersMatchesReferenceOnNumbers builds only RFC 8259 numbers,
// so every run reaches the value: long runs of zeros before and after the
// significant digits, both exponent letters and signs, leading zeros in the
// exponent, and any int64 exponent.
func FuzzAdmitSafeNumbersMatchesReferenceOnNumbers(f *testing.F) {
	f.Add(false, uint64(9007199254740991), uint16(0), uint64(0), uint16(0), uint8(0), int64(0))
	f.Add(true, uint64(1), uint16(3), uint64(5), uint16(2), uint8(0b011), int64(-999999))
	f.Add(false, uint64(0), uint16(999), uint64(1), uint16(0), uint8(0b001), int64(1000000))
	f.Add(false, uint64(15), uint16(0), uint64(0), uint16(0), uint8(0b110), int64(-9223372036854775808))
	f.Fuzz(func(t *testing.T, neg bool, whole uint64, fracZeros uint16, frac uint64, trailingZeros uint16, form uint8, exp int64) {
		var b strings.Builder
		if neg {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", whole)
		if form&1 != 0 {
			b.WriteByte('.')
			b.WriteString(strings.Repeat("0", int(fracZeros%2048)))
			fmt.Fprintf(&b, "%d", frac)
			b.WriteString(strings.Repeat("0", int(trailingZeros%2048)))
		} else if whole != 0 {
			b.WriteString(strings.Repeat("0", int(trailingZeros%2048)))
		}
		if form&2 != 0 {
			b.WriteByte("eE"[form>>2&1])
			if form&8 != 0 && exp >= 0 {
				b.WriteByte('+')
			}
			if exp < 0 {
				b.WriteByte('-')
			}
			b.WriteString(strings.Repeat("0", int(form>>4)))
			e := uint64(exp)
			if exp < 0 {
				e = -e
			}
			fmt.Fprintf(&b, "%d", e)
		}
		lit := b.String()
		if !jsonNumberGrammar.MatchString(lit) {
			t.Fatalf("built %q, not an RFC 8259 number", lit)
		}
		checkAgainstReference(t, lit)
	})
}

// A value nested deep costs the walk a step per level, not a path per level.
func BenchmarkAdmitSafeNumbers_DeepNesting(b *testing.B) {
	for _, depth := range []int{1 << 8, 1 << 11, 1 << 13} {
		v := any(json.Number("1"))
		for range depth {
			v = []any{v}
		}
		b.Run(fmt.Sprintf("depth/%d", depth), func(b *testing.B) {
			for b.Loop() {
				if err := canon.AdmitSafeNumbers(v); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
