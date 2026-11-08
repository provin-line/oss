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
//   - a number of magnitude 2^53-0.5 or more, integer or not, in ANY spelling,
//     which binary64 makes an integer outside ±(2^53-1) or infinite (ties to
//     even: 9007199254740991.5 becomes 9007199254740992). 9007199254740993,
//     1e21, 9007199254740993e0, 9007199254740992.0 and 9007199254740991.5 are
//     the same rejection;
//   - NaN and Infinity, which have no JSON representation;
//   - a json.Number that is not an RFC 8259 number (+1, .5, 01, 0x10, 1/2), or
//     whose exponent, net of the digits after its point, lies beyond ±10^6
//     (1e1000001, 1.0e-1000000, an exponent beyond int64). No artifact writes
//     such a number; the bound is fixed and on the literal as written, so
//     10e-1000001 is refused where 1e-1000000 is admitted. A zero
//     (0e999999999, -0) is admitted whatever its exponent within int64.
//
// Below 2^53-0.5, binary64 rounds every value correctly to one within
// ±(2^53-1), so what it admits RFC 8785 writes within ±(2^53-1), and the
// canonical form RFC 8785 defines is admitted again: a reader that checks
// those canonical bytes agrees with the writer that checked the value. Non-integral values (4.50, 2e-3) below the
// bound are admitted; they are lossy by nature and RFC 8785 fixes their
// canonical form.
//
// v is a value tree as decoding JSON into any gives it (map[string]any,
// []any, json.Number and the other scalars), and Go's numeric types are read
// too. A value of any other type, a typed slice or a struct among them, is
// not inspected and is admitted.
//
// Its work is linear in v and in the length of each literal, without
// arbitrary-precision arithmetic, so it can run on input not yet
// authenticated. The path to a refused number is spelled only for the error,
// once.
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
// indexes as "[i]". It writes each step once, so its work is linear in the
// length of the path.
func spellPath(steps []pathStep) string {
	var b strings.Builder
	for _, s := range steps {
		if s.index >= 0 {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.index))
			b.WriteByte(']')
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.key)
	}
	return b.String()
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
	return &UnsafeNumberError{Literal: lit, Reason: reasonOutOfRange}
}

// reasonOutOfRange is the Reason of every number refused for its magnitude.
const reasonOutOfRange = "magnitude 2^53-0.5 or more, which binary64 makes an integer outside ±(2^53-1) or infinite; values beyond it belong in the string domain under a versioned schema"

// maxLiteralExponent bounds a literal's exponent net of the digits after its
// point: past it the literal is refused, whatever its value.
const maxLiteralExponent = 1_000_000

// limitDigits are the significant digits of 2^53-0.5, 9007199254740991.5,
// whose integer part has limitIntDigits digits.
const (
	limitDigits    = "90071992547409915"
	limitIntDigits = 16
)

// scannedNumber is an RFC 8259 number as scanNumber reads it: its sign, the
// digits of its integer and fraction parts, its exponent, and the span
// [first, end) of its significant digits within whole+frac (first == end for
// zero). Its value is ±digits(first..end) × 10^scale(). expOverflow is the
// sign (+1 or -1) of an exponent beyond int64, which leaves exp unset.
type scannedNumber struct {
	neg         bool
	whole, frac string
	exp         int64
	expOverflow int
	first, end  int
}

func (sc scannedNumber) digit(k int) byte {
	if k < len(sc.whole) {
		return sc.whole[k]
	}
	return sc.frac[k-len(sc.whole)]
}

func (sc scannedNumber) zero() bool { return sc.first == sc.end }

// beyondBound reports whether the exponent, net of the digits after the
// point, lies beyond ±maxLiteralExponent (or beyond int64) for a nonzero
// number: the bound AdmitSafeNumbers refuses past.
func (sc scannedNumber) beyondBound() bool {
	if sc.expOverflow != 0 {
		return true
	}
	return !sc.zero() && (sc.exp > maxLiteralExponent+int64(len(sc.frac)) || sc.exp < int64(len(sc.frac))-maxLiteralExponent)
}

// scale is the power of ten the significant digits are multiplied by.
func (sc scannedNumber) scale() int64 {
	return int64(len(sc.whole)+len(sc.frac)-sc.end) + sc.exp - int64(len(sc.frac))
}

// scanNumber reads lit as an RFC 8259 number,
//
//	-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
//
// whatever its exponent: ok is false for anything else. Its work is linear in
// the length of lit, and it does not allocate unless the exponent overflows
// int64.
func scanNumber(lit string) (sc scannedNumber, ok bool) {
	i := 0
	if i < len(lit) && lit[i] == '-' {
		sc.neg = true
		i++
	}
	start := i
	switch {
	case i < len(lit) && lit[i] == '0':
		i++
	case i < len(lit) && '1' <= lit[i] && lit[i] <= '9':
		i = skipDigits(lit, i+1)
	default:
		return scannedNumber{}, false
	}
	sc.whole = lit[start:i]
	if i < len(lit) && lit[i] == '.' {
		j := skipDigits(lit, i+1)
		if j == i+1 {
			return scannedNumber{}, false
		}
		sc.frac, i = lit[i+1:j], j
	}
	if i < len(lit) && (lit[i] == 'e' || lit[i] == 'E') {
		j := i + 1
		if j < len(lit) && (lit[j] == '+' || lit[j] == '-') {
			j++
		}
		k := skipDigits(lit, j)
		if k == j || k != len(lit) {
			return scannedNumber{}, false
		}
		e, err := strconv.ParseInt(lit[i+1:], 10, 64)
		switch {
		case err != nil && lit[i+1] == '-':
			sc.expOverflow = -1
		case err != nil:
			sc.expOverflow = 1
		default:
			sc.exp = e
		}
		i = k
	}
	if i != len(lit) {
		return scannedNumber{}, false
	}
	n := len(sc.whole) + len(sc.frac)
	for sc.first < n && sc.digit(sc.first) == '0' {
		sc.first++
	}
	sc.end = n
	if sc.first == n {
		return sc, true // zero, -0 included
	}
	for sc.digit(sc.end-1) == '0' {
		sc.end--
	}
	return sc, true
}

// safeLiteral reports whether lit is an RFC 8259 number within the exponent
// bound (ok), and if so whether it is admitted (safe): its magnitude is less
// than 2^53-0.5. Its work is linear in the length of lit.
func safeLiteral(lit string) (safe, ok bool) {
	sc, ok := scanNumber(lit)
	if !ok || sc.expOverflow != 0 {
		return false, false
	}
	if sc.zero() {
		return true, true
	}
	if sc.beyondBound() {
		return false, false
	}
	// The value is the significant digits followed by scale() zeros; a
	// negative scale leaves digits after the point. Its integer part has
	// intDigits digits, so it is compared with 2^53-0.5 by that count first,
	// then digit by digit.
	switch intDigits := int64(sc.end-sc.first) + sc.scale(); {
	case intDigits < limitIntDigits:
		return true, true
	case intDigits > limitIntDigits:
		return false, true
	}
	for k := 0; sc.first+k < sc.end || k < len(limitDigits); k++ {
		d, l := byte('0'), byte('0')
		if sc.first+k < sc.end {
			d = sc.digit(sc.first + k)
		}
		if k < len(limitDigits) {
			l = limitDigits[k]
		}
		if d != l {
			return d < l, true
		}
	}
	return false, true // exactly 2^53-0.5
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
	return &UnsafeNumberError{Literal: fmt.Sprintf("%d", v), Reason: reasonOutOfRange}
}

func admitUint64(v uint64) *UnsafeNumberError {
	if v <= uint64(MaxSafeInteger) {
		return nil
	}
	return &UnsafeNumberError{Literal: fmt.Sprintf("%d", v), Reason: reasonOutOfRange}
}

func admitFloat(f float64) *UnsafeNumberError {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &UnsafeNumberError{
			Literal: strings.TrimSpace(fmt.Sprintf("%v", f)),
			Reason:  "NaN and Infinity have no JSON representation",
		}
	}
	// A float64 arrives already rounded: no binary64 lies between 2^53-1 and
	// 2^53, so one of magnitude 2^53-0.5 or more is one beyond ±(2^53-1), and
	// it cannot be trusted to mean what its source wrote.
	if math.Abs(f) > float64(MaxSafeInteger) {
		return &UnsafeNumberError{Literal: strings.TrimSpace(fmt.Sprintf("%v", f)), Reason: reasonOutOfRange}
	}
	return nil
}
