// Package es256 is the ES256 implementation of crypto.Verifier: ECDSA on
// P-256 with SHA-256 (RFC 7518 section 3.4). It verifies only; it holds no
// keys.
//
// A public key is the SEC1 uncompressed point (0x04 || X || Y, 65 bytes). A
// signature is r || s, each 32 bytes big-endian, the form JWS and COSE carry.
// A caller that receives another form (the ASN.1 DER of WebAuthn, a compressed
// point) converts it before calling.
//
// Signature bytes are not unique: when (r, s) verifies, so does (r, n-s). This
// package does not require low s, as WebAuthn authenticators and WebCrypto do
// not normalize s to it. Nothing may count or deduplicate signatures by their
// bytes.
package es256

import (
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Algorithm is the suite name.
const Algorithm = "ES256"

// Error is the type of this package's sentinel errors. Being a constant string
// type, a sentinel cannot be reassigned by another package.
type Error string

func (e Error) Error() string { return string(e) }

// ErrPublicKeySize reports a public key that is not 65 bytes.
const ErrPublicKeySize Error = "es256: wrong public key size"

// ErrInvalidPoint reports 65 bytes that are not the uncompressed encoding of a
// point on P-256: another prefix than 0x04, a coordinate not reduced modulo p,
// or a point off the curve. The point at infinity has no uncompressed
// encoding.
const ErrInvalidPoint Error = "es256: not an uncompressed point on P-256"

// ErrSignatureSize reports a signature that is not 64 bytes.
const ErrSignatureSize Error = "es256: wrong signature size"

// ErrInvalidSignature reports an r or an s outside [1, n-1], which no
// signature has.
const ErrInvalidSignature Error = "es256: r or s out of range"

const (
	publicKeySize = 65
	signatureSize = 64
)

var curveN = elliptic.P256().Params().N

// ValidatePublicKey checks that pub is an acceptable ES256 public key: 65
// bytes (else ErrPublicKeySize), the uncompressed encoding of a point on P-256
// (else ErrInvalidPoint).
func ValidatePublicKey(pub []byte) error {
	_, err := parse(pub)
	return err
}

func parse(pub []byte) (*stdecdsa.PublicKey, error) {
	if len(pub) != publicKeySize {
		return nil, fmt.Errorf("%w: %d, want %d", ErrPublicKeySize, len(pub), publicKeySize)
	}
	if pub[0] != 0x04 {
		return nil, ErrInvalidPoint
	}
	key, err := stdecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return key, nil
}

// Verifier verifies ES256 signatures against a raw public key. Implements
// crypto.Verifier.
type Verifier struct{}

// Verify reports whether sig is a valid ES256 signature over data by
// publicKey. Malformed input is an error, distinct from a genuine non-match
// (false, nil): a key ValidatePublicKey refuses, a signature that is not 64
// bytes (ErrSignatureSize), and an r or s outside [1, n-1]
// (ErrInvalidSignature).
func (Verifier) Verify(publicKey, data, sig []byte) (bool, error) {
	key, err := parse(publicKey)
	if err != nil {
		return false, err
	}
	if len(sig) != signatureSize {
		return false, fmt.Errorf("%w: %d, want %d", ErrSignatureSize, len(sig), signatureSize)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(curveN) >= 0 || s.Cmp(curveN) >= 0 {
		return false, ErrInvalidSignature
	}
	sum := sha256.Sum256(data)
	return stdecdsa.Verify(key, sum[:], r, s), nil
}

// Algorithm reports the suite name. Implements crypto.Verifier.
func (Verifier) Algorithm() string { return Algorithm }
