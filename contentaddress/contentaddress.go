// Package contentaddress is the content address of dPLaaX (the
// contentAddress of its schemas): the address content is found by, spelled
// "sha256:" and the 64 lowercase hex digits of the content's SHA-256.
//
// An Address is made only by Of and Parse, so outside package unsafe every
// Address is in that one spelling; nothing else converts to one. The zero
// Address is no address.
package contentaddress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const prefix = "sha256:"

// Address is a content address. Two Addresses are equal (==) exactly when
// their spellings, and so their SHA-256 digests, are equal; an Address is
// also a map key.
type Address struct {
	s string
}

// Of returns the address of b.
func Of(b []byte) Address {
	sum := sha256.Sum256(b)
	return Address{prefix + hex.EncodeToString(sum[:])}
}

// Parse reads s as an address: "sha256:" and 64 lowercase hex digits, and
// nothing else (no other case, no other length, no surrounding space).
func Parse(s string) (Address, error) {
	if len(s) != len(prefix)+2*sha256.Size || s[:len(prefix)] != prefix {
		return Address{}, notAnAddress(s)
	}
	for i := len(prefix); i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Address{}, notAnAddress(s)
		}
	}
	return Address{s}, nil
}

// notAnAddress is Parse's refusal of s, quoting at most its first bytes: s
// may be any input, however long.
func notAnAddress(s string) error {
	const quoted = 80
	if len(s) > quoted {
		s = s[:quoted] + "…"
	}
	return fmt.Errorf("contentaddress: %q is not %s and %d lowercase hex digits", s, prefix, 2*sha256.Size)
}

// String returns a's spelling, or "" for the zero Address.
func (a Address) String() string { return a.s }

// IsZero reports whether a is no address.
func (a Address) IsZero() bool { return a.s == "" }

// MarshalText writes a in its spelling. The zero Address is an error: a field
// that may hold no address is a pointer, nil when there is none, or carries
// the omitzero option.
func (a Address) MarshalText() ([]byte, error) {
	if a.IsZero() {
		return nil, errors.New("contentaddress: no address to write")
	}
	return []byte(a.s), nil
}

// UnmarshalText reads text as Parse does. On an error a is left as it was.
func (a *Address) UnmarshalText(text []byte) error {
	p, err := Parse(string(text))
	if err != nil {
		return err
	}
	*a = p
	return nil
}
