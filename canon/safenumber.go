package canon

import (
	"encoding/json" // decoder-hygiene-exempt: json.Number is the raw-token carrier this gate reads
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MaxSafeInteger and MinSafeInteger bound the integers an artifact may carry as
// JSON numbers: ±(2^53-1), the range every IEEE-754 double represents exactly.
// Outside it, two conformant implementations in two languages can disagree about
// the value — which forks the canonical bytes and the signature with them.
const (
	MaxSafeInteger = int64(1)<<53 - 1
	MinSafeInteger = -(int64(1)<<53 - 1)
)

// UnsafeNumberError reports a JSON number an artifact may not carry, with the
// raw literal and the path to it. The literal is reported verbatim: a rounded
// rendering would hide the very precision loss the gate exists to catch.
type UnsafeNumberError struct {
	// Path locates the number, e.g. "credentialSubject.counts[1]".
	Path string
	// Literal is the raw token as written, e.g. "1e30".
	Literal string
	// Reason says which rule the number breaks.
	Reason string
}

func (e *UnsafeNumberError) Error() string {
	where := e.Path
	if where == "" {
		where = "(root)"
	}
	return fmt.Sprintf("canon: unsafe number %s at %s: %s", e.Literal, where, e.Reason)
}

// AdmitSafeNumbers reports whether v may be admitted as a new artifact
// (canon.number.safe-integer). It rejects:
//
//   - an integer-valued number outside ±(2^53-1), in ANY spelling — 9007199254740993,
//     1e21, 9007199254740993e0, and 9007199254740992.0 are the same rejection;
//   - NaN and Infinity, which have no JSON representation;
//   - a json.Number that is not an RFC 8259 number (+1, .5, 01, 0x10, 1/2), or
//     whose exponent, net of the digits after its point, lies beyond ±10^6
//     (1e1000001, 1.0e-1000000, an exponent beyond int64). No artifact writes
//     such a number; the bound is fixed and on the literal as written, so
//     10e-1000001 is refused where 1e-1000000 is admitted. A zero
//     (0e999999999, -0) is admitted whatever its exponent within int64.
//
// Non-integral values (4.50, 2e-3) are not its business: they are lossy by
// nature and RFC 8785 already fixes their canonical form.
//
// Its work is linear in v and in the length of each literal, without
// arbitrary-precision arithmetic, so it can run on input not yet
// authenticated. The path to a refused number is spelled only for the error.
//
// It runs at the raw-token stage, BEFORE canonicalization
// (canon.number.raw-token-guard): decode through StrictDecoder, gate, then
// canonicalize. Gating a value that a lossy parser already rounded is not a
// gate — the corruption happened at parse time, and the rounded value looks
// safe. This is why the check reads json.Number literals rather than float64s.
//
// It is deliberately separate from the canonicalizer: a serializer that
// rejected these could not be byte-for-byte RFC 8785 (canon.jcs.base), whose
// own example carries 1E30. The serializer emits; admission refuses.
func AdmitSafeNumbers(v any) error {
	var path []pathStep
	return admitSafeNumbers(v, &path)
}

// pathStep is one step of the path to a value: an array index when index is
// not negative, an object member otherwise.
type pathStep struct {
	key   string
	index int
}

// admitSafeNumbers admits v at path, the one path of the whole walk: a step
// is pushed before its value is admitted and popped after, and the path is
// spelled only into an error, so the walk is linear in v.
func admitSafeNumbers(v any, path *[]pathStep) error {
	var bad *UnsafeNumberError
	switch t := v.(type) {
	case json.Number:
		bad = admitLiteral(string(t))
	case float64:
		bad = admitFloat(t)
	case float32:
		bad = admitFloat(float64(t))
	case int:
		bad = admitInt64(int64(t))
	case int8:
		bad = admitInt64(int64(t))
	case int16:
		bad = admitInt64(int64(t))
	case int32:
		bad = admitInt64(int64(t))
	case int64:
		bad = admitInt64(t)
	case uint:
		bad = admitUint64(uint64(t))
	case uint8:
		bad = admitUint64(uint64(t))
	case uint16:
		bad = admitUint64(uint64(t))
	case uint32:
		bad = admitUint64(uint64(t))
	case uint64:
		bad = admitUint64(t)
	case []any:
		for i, e := range t {
			if err := admitStep(e, path, pathStep{index: i}); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range t {
			if err := admitStep(e, path, pathStep{key: k, index: -1}); err != nil {
				return err
			}
		}
	}
	if bad == nil {
		return nil
	}
	bad.Path = spellPath(*path)
	return bad
}

func admitStep(v any, path *[]pathStep, step pathStep) error {
	*path = append(*path, step)
	err := admitSafeNumbers(v, path)
	*path = (*path)[:len(*path)-1]
	return err
}

// spellPath spells a path as UnsafeNumberError.Path: members joined by ".",
// indexes as "[i]".
func spellPath(steps []pathStep) string {
	path := ""
	for _, s := range steps {
		if s.index >= 0 {
			path = fmt.Sprintf("%s[%d]", path, s.index)
		} else {
			path = joinPath(path, s.key)
		}
	}
	return path
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// admitLiteral reads the raw token. Its value is decided from where its
// significant digits stand, so "1e21" and "1000000000000000000000" reach the
// same verdict — the gate keys on the value, not on how it was written.
func admitLiteral(lit string) *UnsafeNumberError {
	safe, ok := safeLiteral(lit)
	if !ok {
		return &UnsafeNumberError{Literal: lit, Reason: "not a valid JSON number literal"}
	}
	if safe {
		return nil
	}
	return &UnsafeNumberError{
		Literal: lit,
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

// maxLiteralExponent bounds a literal's exponent net of the digits after its
// point: past it the literal is refused, whatever its value.
const maxLiteralExponent = 1_000_000

// safeDigits is the most digits an integer within ±(2^53-1) has.
const safeDigits = 16

// safeLiteral reports whether lit is an RFC 8259 number,
//
//	-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
//
// within the exponent bound (ok), and if so whether it is admitted (safe): it
// is zero, not an integer, or an integer within ±(2^53-1). Its work is linear
// in the length of lit, and it does not allocate unless the exponent
// overflows int64.
func safeLiteral(lit string) (safe, ok bool) {
	i := 0
	if i < len(lit) && lit[i] == '-' {
		i++
	}
	start := i
	switch {
	case i < len(lit) && lit[i] == '0':
		i++
	case i < len(lit) && '1' <= lit[i] && lit[i] <= '9':
		i = skipDigits(lit, i+1)
	default:
		return false, false
	}
	whole := lit[start:i]
	var frac string
	if i < len(lit) && lit[i] == '.' {
		j := skipDigits(lit, i+1)
		if j == i+1 {
			return false, false
		}
		frac, i = lit[i+1:j], j
	}
	var exp int64
	if i < len(lit) && (lit[i] == 'e' || lit[i] == 'E') {
		j := i + 1
		if j < len(lit) && (lit[j] == '+' || lit[j] == '-') {
			j++
		}
		k := skipDigits(lit, j)
		if k == j || k != len(lit) {
			return false, false
		}
		e, err := strconv.ParseInt(lit[i+1:], 10, 64)
		if err != nil {
			return false, false // beyond int64
		}
		exp, i = e, k
	}
	if i != len(lit) {
		return false, false
	}

	// The digits of whole and frac, read as one integer m, give the value
	// m × 10^(exp − len(frac)).
	n := len(whole) + len(frac)
	digit := func(k int) byte {
		if k < len(whole) {
			return whole[k]
		}
		return frac[k-len(whole)]
	}
	first := 0
	for first < n && digit(first) == '0' {
		first++
	}
	if first == n {
		return true, true // zero, -0 included
	}
	if exp > maxLiteralExponent+int64(len(frac)) || exp < int64(len(frac))-maxLiteralExponent {
		return false, false
	}
	end := n
	for digit(end-1) == '0' {
		end--
	}
	// The value is the significant digits digit(first..end-1) followed by
	// zeros zeros; a negative zeros leaves digits after the point.
	zeros := int64(n-end) + exp - int64(len(frac))
	if zeros < 0 {
		return true, true
	}
	if int64(end-first)+zeros > safeDigits {
		return false, true
	}
	var v uint64
	for k := first; k < end; k++ {
		v = v*10 + uint64(digit(k)-'0')
	}
	for ; zeros > 0; zeros-- {
		v *= 10
	}
	return v <= uint64(MaxSafeInteger), true
}

func skipDigits(s string, i int) int {
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}
	return i
}

func admitInt64(v int64) *UnsafeNumberError {
	if v >= MinSafeInteger && v <= MaxSafeInteger {
		return nil
	}
	return &UnsafeNumberError{
		Literal: fmt.Sprintf("%d", v),
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

func admitUint64(v uint64) *UnsafeNumberError {
	if v <= uint64(MaxSafeInteger) {
		return nil
	}
	return &UnsafeNumberError{
		Literal: fmt.Sprintf("%d", v),
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

func admitFloat(f float64) *UnsafeNumberError {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &UnsafeNumberError{
			Literal: strings.TrimSpace(fmt.Sprintf("%v", f)),
			Reason:  "NaN and Infinity have no JSON representation",
		}
	}
	// A float64 arrives already rounded, so its integrality is all that is left
	// to check: an integral value outside the safe range cannot be trusted to
	// mean what its source wrote.
	if f == math.Trunc(f) && (f > float64(MaxSafeInteger) || f < float64(MinSafeInteger)) {
		return &UnsafeNumberError{
			Literal: strings.TrimSpace(fmt.Sprintf("%v", f)),
			Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
		}
	}
	return nil
}
