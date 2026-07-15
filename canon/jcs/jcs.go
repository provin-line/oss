// Package jcs implements RFC 8785 (JSON Canonicalization Scheme) — the
// Phase 1 (MUST) canonicalization for dplaax signing scopes.
//
// Byte-for-byte RFC 8785 conformance is the contract, including the corners
// Go's encoder gets wrong by default: U+2028/U+2029 must appear as raw UTF-8
// (not \u-escaped), and numeric precision must survive via json.Number.
//
// Deliberate deviation from RFC 8785: a json.Number whose literal is an
// integer representable in int64/uint64 is emitted as its canonical decimal
// form verbatim, NOT round-tripped through an IEEE double (which would
// corrupt integers above 2^53 — the precision-loss failure mode this
// repository's wire conventions exist to prevent). All other numbers follow
// the ES6 Number::toString algorithm exactly. The rule is deterministic
// across implementations that adopt it; emitters must not rely on >2^53
// integers interoperating with strict-ES6 JCS implementations.
package jcs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Name is the wire identifier of the legacy int64-verbatim canonicalization.
const Name = "jcs"

// NameRFC8785 is the wire identifier of the conformant canonicalization. It is
// frozen: WireVariantIDs carry it (wire:v1:jcs-rfc8785:sha256:<hex>) and
// source_root_canonical names it, so changing it is a protocol change.
const NameRFC8785 = "jcs-rfc8785"

// numberMode selects how numbers reach the wire. The two modes are the whole
// difference between the conformant canonicalizer and the legacy one.
type numberMode int

const (
	// modeLegacyInt64 emits 64-bit-range integer literals verbatim, skipping
	// the binary64 round-trip (canon.jcs.int64-verbatim). Legacy verification
	// only: it is a deliberate RFC 8785 deviation.
	modeLegacyInt64 numberMode = iota
	// modeRFC8785 rounds every number through binary64 per ES6
	// Number::toString — byte-for-byte RFC 8785 (canon.jcs.base).
	modeRFC8785
)

// Canonicalize returns the legacy int64-verbatim canonical bytes for v.
//
// This is NOT RFC 8785: integers in 64-bit range are emitted verbatim rather
// than round-tripped through binary64. It exists to verify artifacts signed
// under the historical deviation (canon.jcs.int64-verbatim). New signature
// scopes and content hashes use CanonicalizeRFC8785.
func Canonicalize(v any) ([]byte, error) { return canonicalize(v, modeLegacyInt64) }

// CanonicalizeRFC8785 returns the byte-for-byte RFC 8785 canonical bytes for v
// (canon.jcs.base) — the canonicalization every new signature scope and content
// hash uses.
//
// It is a pure serializer: it rounds unsafe integers through binary64 exactly
// as a strict-ES6 implementation does, and it does NOT reject them. Rejecting
// an unsafe integer is admission's job, at the raw-token stage before
// canonicalization (canon.AdmitSafeNumbers / canon.number.raw-token-guard) —
// a serializer that rejected them could not stay RFC 8785 conformant, because
// the RFC's own examples contain 1E30.
func CanonicalizeRFC8785(v any) ([]byte, error) { return canonicalize(v, modeRFC8785) }

func canonicalize(v any, mode numberMode) ([]byte, error) {
	var sb strings.Builder
	if err := serialize(&sb, v, mode); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// Hash returns "sha256:<hex>" over the legacy canonical bytes of v.
// New content addresses use HashRFC8785.
func Hash(v any) (string, error) { return hashWith(v, modeLegacyInt64) }

// HashRFC8785 returns "sha256:<hex>" over the RFC 8785 canonical bytes of v —
// the content address for VC bodies and chain links.
func HashRFC8785(v any) (string, error) { return hashWith(v, modeRFC8785) }

func hashWith(v any, mode numberMode) (string, error) {
	b, err := canonicalize(v, mode)
	if err != nil {
		return "", err
	}
	return sha256Prefixed(b), nil
}

func sha256Prefixed(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Canonicalizer adapts the legacy int64-verbatim canonicalization to the
// canon.Canonicalizer interface. Legacy verification only — see Canonicalize.
type Canonicalizer struct{}

// Name implements canon.Canonicalizer.
func (Canonicalizer) Name() string { return Name }

// Canonicalize implements canon.Canonicalizer.
func (Canonicalizer) Canonicalize(v any) ([]byte, error) { return Canonicalize(v) }

// RFC8785 adapts the conformant canonicalization to the canon.Canonicalizer
// interface. This is the canonicalizer new artifacts are signed under.
type RFC8785 struct{}

// Name implements canon.Canonicalizer.
func (RFC8785) Name() string { return NameRFC8785 }

// Canonicalize implements canon.Canonicalizer.
func (RFC8785) Canonicalize(v any) ([]byte, error) { return CanonicalizeRFC8785(v) }

func serialize(sb *strings.Builder, v any, mode numberMode) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		if !utf8.ValidString(t) {
			return fmt.Errorf("jcs: string value is not valid UTF-8: %q", t)
		}
		writeString(sb, t)
	case json.Number:
		s, err := numberFromLiteral(t, mode)
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case float64:
		s, err := es6Number(t)
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case float32:
		// Widening is exact but can look surprising: float32(0.1) becomes
		// 0.10000000149011612 — the float64 nearest to the float32 value.
		s, err := es6Number(float64(t))
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case int:
		return writeInt(sb, int64(t), mode)
	case int8:
		return writeInt(sb, int64(t), mode)
	case int16:
		return writeInt(sb, int64(t), mode)
	case int32:
		return writeInt(sb, int64(t), mode)
	case int64:
		return writeInt(sb, t, mode)
	case uint:
		return writeUint(sb, uint64(t), mode)
	case uint8:
		return writeUint(sb, uint64(t), mode)
	case uint16:
		return writeUint(sb, uint64(t), mode)
	case uint32:
		return writeUint(sb, uint64(t), mode)
	case uint64:
		return writeUint(sb, t, mode)
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := serialize(sb, e, mode); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if !utf8.ValidString(k) {
				return fmt.Errorf("jcs: object key is not valid UTF-8: %q", k)
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, k)
			sb.WriteByte(':')
			if err := serialize(sb, t[k], mode); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

// writeString emits s per ES6 JSON.stringify (RFC 8785 §3.2.2.2): the short
// escapes for ", \, and the named controls; \u00xx (lowercase hex) for the
// remaining controls; everything else — including U+2028/U+2029 — as raw
// UTF-8 bytes. Invalid UTF-8 is rejected before this is called: emitting it
// raw would sign non-Unicode bytes, and []rune-based UTF-16 key comparison
// would collapse distinct invalid keys into U+FFFD — a nondeterministic
// canonical form.
func writeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(sb, `\u%04x`, c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
}

// lessUTF16 orders strings by their UTF-16 code units (RFC 8785 §3.2.3).
// This differs from byte order for code points above the BMP: surrogates
// (0xD800–0xDFFF) sort below U+E000 and above.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeInt emits a typed signed integer. Under modeRFC8785 it takes the same
// binary64 round-trip a literal would, so a typed value and its literal
// spelling can never canonicalize differently.
func writeInt(sb *strings.Builder, i int64, mode numberMode) error {
	if mode == modeLegacyInt64 {
		sb.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	s, err := es6Number(float64(i))
	if err != nil {
		return err
	}
	sb.WriteString(s)
	return nil
}

// writeUint is writeInt for unsigned values.
func writeUint(sb *strings.Builder, u uint64, mode numberMode) error {
	if mode == modeLegacyInt64 {
		sb.WriteString(strconv.FormatUint(u, 10))
		return nil
	}
	s, err := es6Number(float64(u))
	if err != nil {
		return err
	}
	sb.WriteString(s)
	return nil
}

// numberFromLiteral serializes a json.Number. Under modeLegacyInt64, 64-bit
// integer literals emit their canonical decimal form verbatim (the historical
// RFC 8785 deviation); everything else — and everything under modeRFC8785 —
// goes through the IEEE double / ES6 path.
func numberFromLiteral(n json.Number, mode numberMode) (string, error) {
	s := string(n)
	if mode == modeLegacyInt64 {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return strconv.FormatInt(i, 10), nil
		}
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return strconv.FormatUint(u, 10), nil
		}
	}
	f, err := n.Float64()
	if err != nil {
		return "", fmt.Errorf("jcs: invalid number literal %q: %w", s, err)
	}
	return es6Number(f)
}

// es6Number implements the ES6 Number::toString(10) algorithm
// (ECMA-262 §7.1.12.1) over the shortest round-trip decimal digits.
func es6Number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("jcs: NaN and Infinity have no JSON representation")
	}
	if f == 0 {
		return "0", nil // covers -0 (ES6 emits "0")
	}
	neg := math.Signbit(f)
	if neg {
		f = -f
	}
	// Shortest digits + decimal exponent via strconv's 'e' form: d[.ddd]e±dd
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	exp10, err := strconv.Atoi(expStr)
	if err != nil {
		return "", fmt.Errorf("jcs: internal exponent parse: %w", err)
	}
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp10 + 1 // position of the decimal point relative to digits

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		m := digits[:1]
		if k > 1 {
			m += "." + digits[1:]
		}
		if n-1 >= 0 {
			out = m + "e+" + strconv.Itoa(n-1)
		} else {
			out = m + "e-" + strconv.Itoa(1-n)
		}
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}
