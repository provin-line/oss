package canon

import (
	"encoding/json" // decoder-hygiene-exempt: json.Number is the raw-token carrier this gate reads
	"fmt"
	"math"
	"math/big"
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
//   - NaN and Infinity, which have no JSON representation.
//
// Non-integral values (4.50, 2e-3) are not its business: they are lossy by
// nature and RFC 8785 already fixes their canonical form.
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
func AdmitSafeNumbers(v any) error { return admitSafeNumbers(v, "") }

func admitSafeNumbers(v any, path string) error {
	switch t := v.(type) {
	case json.Number:
		return admitLiteral(string(t), path)
	case float64:
		return admitFloat(t, path)
	case float32:
		return admitFloat(float64(t), path)
	case int:
		return admitInt64(int64(t), path)
	case int8:
		return admitInt64(int64(t), path)
	case int16:
		return admitInt64(int64(t), path)
	case int32:
		return admitInt64(int64(t), path)
	case int64:
		return admitInt64(t, path)
	case uint:
		return admitUint64(uint64(t), path)
	case uint8:
		return admitUint64(uint64(t), path)
	case uint16:
		return admitUint64(uint64(t), path)
	case uint32:
		return admitUint64(uint64(t), path)
	case uint64:
		return admitUint64(t, path)
	case []any:
		for i, e := range t {
			if err := admitSafeNumbers(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, e := range t {
			if err := admitSafeNumbers(e, joinPath(path, k)); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// admitLiteral reads the raw token. big.Rat parses every JSON number spelling
// losslessly, so "1e21" and "1000000000000000000000" reach the same verdict —
// the gate keys on the value, not on how it was written.
func admitLiteral(lit, path string) error {
	r, ok := new(big.Rat).SetString(lit)
	if !ok {
		return &UnsafeNumberError{Path: path, Literal: lit, Reason: "not a valid JSON number literal"}
	}
	if !r.IsInt() {
		return nil // non-integral: RFC 8785 fixes its form, the gate has no opinion
	}
	i := r.Num() // denominator is 1 for an integer
	if i.IsInt64() {
		v := i.Int64()
		if v >= MinSafeInteger && v <= MaxSafeInteger {
			return nil
		}
	}
	return &UnsafeNumberError{
		Path:    path,
		Literal: lit,
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

func admitInt64(v int64, path string) error {
	if v >= MinSafeInteger && v <= MaxSafeInteger {
		return nil
	}
	return &UnsafeNumberError{
		Path:    path,
		Literal: fmt.Sprintf("%d", v),
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

func admitUint64(v uint64, path string) error {
	if v <= uint64(MaxSafeInteger) {
		return nil
	}
	return &UnsafeNumberError{
		Path:    path,
		Literal: fmt.Sprintf("%d", v),
		Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
	}
}

func admitFloat(f float64, path string) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return &UnsafeNumberError{
			Path:    path,
			Literal: strings.TrimSpace(fmt.Sprintf("%v", f)),
			Reason:  "NaN and Infinity have no JSON representation",
		}
	}
	// A float64 arrives already rounded, so its integrality is all that is left
	// to check: an integral value outside the safe range cannot be trusted to
	// mean what its source wrote.
	if f == math.Trunc(f) && (f > float64(MaxSafeInteger) || f < float64(MinSafeInteger)) {
		return &UnsafeNumberError{
			Path:    path,
			Literal: strings.TrimSpace(fmt.Sprintf("%v", f)),
			Reason:  "integer outside ±(2^53-1); values beyond it belong in the string domain under a versioned schema",
		}
	}
	return nil
}
