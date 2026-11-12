// Package contentaddress is the content address of dPLaaX (the
// contentAddress of its schemas): the address content is found by, spelled
// "sha256:" and the 64 lowercase hex digits of the content's SHA-256.
//
// An Address is made only by Of, Parse and a Hasher's Address, so outside
// package unsafe every Address other than the zero one is in that one
// spelling; nothing else converts to one. The zero Address is no address.
package contentaddress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
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
	return fromDigest(sum[:])
}

// fromDigest returns the address of the content whose SHA-256 is sum.
func fromDigest(sum []byte) Address {
	return Address{prefix + hex.EncodeToString(sum)}
}

// Hasher makes the address of bytes written to it a part at a time, as Of
// makes it of bytes held at once: for bytes that arrive in parts, such as a
// stream, without holding them all. The zero Hasher is ready to use, with
// nothing written to it. A Hasher is not to be copied: a copy may share the
// bytes written to the original. Its methods are not safe for concurrent
// use.
type Hasher struct {
	noCopy noCopy
	h      hash.Hash
}

// noCopy makes go vet's copylocks check report a copied Hasher.
type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

// NewHasher returns a Hasher with nothing written to it.
func NewHasher() *Hasher {
	return &Hasher{h: sha256.New()}
}

// Write adds p to the bytes h has the address of. It never fails: it
// returns len(p) and a nil error.
func (h *Hasher) Write(p []byte) (int, error) {
	return h.digest().Write(p)
}

// Address returns the address of the bytes written to h so far, which is Of
// of those bytes held at once. It does not end h: Writes after it add to
// the same bytes.
func (h *Hasher) Address() Address {
	return fromDigest(h.digest().Sum(nil))
}

// digest returns h's SHA-256 state, made at the first use of a zero Hasher.
func (h *Hasher) digest() hash.Hash {
	if h.h == nil {
		h.h = sha256.New()
	}
	return h.h
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
