// Package rs256 is the RS256 implementation of crypto.Verifier: RSASSA-
// PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3, RFC 8017 section 8.2). It
// verifies only; it holds no keys.
//
// A public key is the DER of a PKCS #1 RSAPublicKey (RFC 8017 appendix A.1.1),
// with an odd modulus of MinBits to MaxBits bits and an odd exponent of at
// least 3. The upper bound keeps the cost of one verification small. A
// signature is the octet string of the modulus' length whose value is below
// the modulus.
package rs256

import (
	"bytes"
	stdcrypto "crypto"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm is the suite name.
const Algorithm = "RS256"

// The accepted modulus sizes, in bits.
const (
	MinBits = 2048
	MaxBits = 4096
)

// maxKeyBytes is longer than the DER of any acceptable key (a 4096-bit
// modulus and a 31-bit exponent take 527 bytes), so longer input is refused
// before it is parsed.
const maxKeyBytes = 600

// Error is the type of this package's sentinel errors. Being a constant string
// type, a sentinel cannot be reassigned by another package.
type Error string

func (e Error) Error() string { return string(e) }

// ErrInvalidPublicKey reports bytes that are not the DER of a PKCS #1
// RSAPublicKey with an odd modulus and an odd exponent of at least 3: another
// structure (such as a SubjectPublicKeyInfo), a BER form that is not DER,
// bytes after the structure, an even modulus, or an exponent that is even or
// 1. A key the underlying library refuses (as a FIPS 140-only build does some)
// is reported with it too.
const ErrInvalidPublicKey Error = "rs256: not an acceptable PKCS #1 RSA public key"

// ErrModulusSize reports a modulus shorter than MinBits or longer than
// MaxBits, or a key too long to have one of those sizes.
const ErrModulusSize Error = "rs256: modulus size out of range"

// ErrSignatureSize reports a signature whose length is not the modulus'.
const ErrSignatureSize Error = "rs256: wrong signature size"

// ErrInvalidSignature reports a signature whose value is not below the
// modulus, which no signature has (RFC 8017 section 8.2.2, "signature
// representative out of range").
const ErrInvalidSignature Error = "rs256: signature out of range"

// ValidatePublicKey checks that pub is an acceptable RS256 public key (else
// ErrInvalidPublicKey or ErrModulusSize).
func ValidatePublicKey(pub []byte) error {
	_, err := parse(pub)
	return err
}

func parse(pub []byte) (*stdrsa.PublicKey, error) {
	if len(pub) > maxKeyBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrModulusSize, len(pub))
	}
	key, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if bits := key.N.BitLen(); bits < MinBits || bits > MaxBits {
		return nil, fmt.Errorf("%w: %d bits, want %d to %d", ErrModulusSize, bits, MinBits, MaxBits)
	}
	if !bytes.Equal(x509.MarshalPKCS1PublicKey(key), pub) {
		return nil, fmt.Errorf("%w: not in DER", ErrInvalidPublicKey)
	}
	if key.N.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: even modulus", ErrInvalidPublicKey)
	}
	if key.E < 3 || key.E%2 == 0 {
		return nil, fmt.Errorf("%w: exponent %d", ErrInvalidPublicKey, key.E)
	}
	return key, nil
}

// Verifier verifies RS256 signatures against a raw public key. Implements
// crypto.Verifier.
type Verifier struct{}

// Verify reports whether sig is a valid RS256 signature over data by
// publicKey. Malformed input is an error, distinct from a genuine non-match
// (false, nil): a key ValidatePublicKey refuses or the underlying library
// refuses (ErrInvalidPublicKey), a signature whose length is not the
// modulus' (ErrSignatureSize), and one whose value is not below the modulus
// (ErrInvalidSignature).
func (Verifier) Verify(publicKey, data, sig []byte) (bool, error) {
	key, err := parse(publicKey)
	if err != nil {
		return false, err
	}
	if want := key.Size(); len(sig) != want {
		return false, fmt.Errorf("%w: %d, want %d", ErrSignatureSize, len(sig), want)
	}
	if new(big.Int).SetBytes(sig).Cmp(key.N) >= 0 {
		return false, ErrInvalidSignature
	}
	sum := sha256.Sum256(data)
	switch err := stdrsa.VerifyPKCS1v15(key, stdcrypto.SHA256, sum[:], sig); {
	case err == nil:
		return true, nil
	case errors.Is(err, stdrsa.ErrVerification):
		return false, nil
	default:
		return false, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
}

// Algorithm reports the suite name. Implements crypto.Verifier.
func (Verifier) Algorithm() string { return Algorithm }
