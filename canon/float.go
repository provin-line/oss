package canon

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/provin-line/oss/internal/excerpt"
)

// ErrNotJSONNumber reports a json.Number that is not an RFC 8259 number.
const ErrNotJSONNumber Error = "canon: not a JSON number"

// ErrBeyondDoubleRange reports a JSON number whose value rounds to infinity
// as an IEEE 754 double.
const ErrBeyondDoubleRange Error = "canon: beyond the double range"

// Float64 returns the IEEE 754 double nearest the value of a JSON number
// (ties to even), as RFC 8785 and every conformant JSON reader take it. It
// reads only the RFC 8259 grammar — no sign "+", no leading zero, no bare
// point, no hexadecimal, Inf or NaN — whatever the exponent, and its value
// does not depend on how the number is spelled (where its point is, how its
// exponent is written, leading or trailing zeros); the sign of zero is kept.
// A number that rounds to zero is ±0. Every error it returns wraps exactly
// one of ErrNotJSONNumber, for anything that is not an RFC 8259 number, and
// ErrBeyondDoubleRange, for a number that rounds to infinity, and names n,
// quoted, within 128 bytes: whole when it fits, else its head and its
// length. Its work is linear in the length of n.
//
// Reading a JSON number as a double goes through here, so every reader in
// this module takes one number as one double.
func Float64(n json.Number) (float64, error) {
	sc, ok := scanNumber(string(n))
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrNotJSONNumber, excerpt.Quoted(string(n), quotedLimit))
	}
	zero := 0.0
	if sc.neg {
		zero = math.Copysign(0, -1)
	}
	if sc.zero() {
		return zero, nil
	}
	// The value is ±0.D × 10^point, D the significant digits. An exponent
	// beyond ±2^62 outweighs any number of digits a literal can have.
	var point int64
	switch {
	case sc.expOverflow > 0 || sc.exp > 1<<62:
		point = math.MaxInt64
	case sc.expOverflow < 0 || sc.exp < -(1<<62):
		point = math.MinInt64
	default:
		point = int64(sc.end-sc.first) + sc.scale()
	}
	switch {
	case point > 310:
		return 0, fmt.Errorf("%w: %s", ErrBeyondDoubleRange, excerpt.Quoted(string(n), quotedLimit))
	case point < -330:
		return zero, nil
	}
	// strconv.ParseFloat reads "[-]0.D e<point>": every significant digit
	// after the point, and the point from a small exact exponent alone,
	// whatever the literal's spelling and length.
	var buf [64]byte
	b := buf[:0]
	if sc.neg {
		b = append(b, '-')
	}
	b = append(b, '0', '.')
	for k := sc.first; k < sc.end; k++ {
		b = append(b, sc.digit(k))
	}
	b = append(b, 'e')
	b = strconv.AppendInt(b, point, 10)
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil { // b is well formed, so the error is ErrRange: f rounds to ±Inf
		return 0, fmt.Errorf("%w: %s", ErrBeyondDoubleRange, excerpt.Quoted(string(n), quotedLimit))
	}
	return f, nil
}
