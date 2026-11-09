// Package ed25519 is the Ed25519 implementation of the crypto interfaces — the
// one suite that also generates keys and signs — plus the raw signing
// primitive. Generator, Verifier, and the package-level Sign are pure
// primitives over key bytes: they hold no key custody and are unaware of DIDs.
//
// The DID-aware signing seam is crypto.Signer (Sign(did, keyID, data)),
// implemented by keystore-backed stores that hold the keys; this package's raw
// Sign(privateKey, data) is the low-level building block those stores compose.
package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/provin-line/oss/crypto"
)

// Algorithm is the crypto.KeyPair.Algorithm tag for this suite.
const Algorithm = "Ed25519"

// Error is the type of this package's sentinel errors. Being a constant string
// type, a sentinel cannot be reassigned by another package.
type Error string

func (e Error) Error() string { return string(e) }

// ErrSmallOrder reports a point of small order (its order divides 8) where an
// Ed25519 public key or a signature's R is required. Such a point lets anyone
// produce signatures that verify, so it is refused. Test with errors.Is.
const ErrSmallOrder Error = "ed25519: point of small order"

// ErrPublicKeySize reports a public key that is not 32 bytes.
const ErrPublicKeySize Error = "ed25519: wrong public key size"

// ErrSignatureSize reports a signature that is not 64 bytes.
const ErrSignatureSize Error = "ed25519: wrong signature size"

// ErrInvalidPoint reports 32 bytes that are not the canonical encoding of a
// point on edwards25519: y is not reduced modulo p, or no x satisfies the curve
// equation for that y.
const ErrInvalidPoint Error = "ed25519: not a canonical point on the curve"

var fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// smallOrderEncodings are the encodings, with the sign bit of x cleared, of
// the points of order dividing 8 on edwards25519: y = 0 (the two points of
// order 4), y = 1 (the identity), y = p-1 (order 2), the two y of the four
// points of order 8, and y = p and y = p+1, the non-canonical spellings of 0
// and 1. They are every 255-bit value whose reduction modulo p = 2^255 - 19 is
// the y of a small-order point (the other small-order y plus p exceed 255
// bits), and they are libsodium's blacklist.
var smallOrderEncodings = [7][32]byte{
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// yOf returns the 32-byte encoding point with the sign bit of x cleared: the
// little-endian y, possibly not reduced modulo p.
func yOf(point []byte) [32]byte {
	var y [32]byte
	copy(y[:], point)
	y[31] &= 0x7f
	return y
}

// hasSmallOrder reports whether the 32-byte encoding point is a point of small
// order, in any spelling and with either sign bit.
func hasSmallOrder(point []byte) bool {
	y := yOf(point)
	for i := range smallOrderEncodings {
		if y == smallOrderEncodings[i] {
			return true
		}
	}
	return false
}

// isCanonicalY reports whether the little-endian y (sign bit cleared) is below
// p = 2^255 - 19. The values from p to 2^255 - 1 are 0x7f, then 30 bytes of
// 0xff, then a low byte of at least 0xed, read from the top.
func isCanonicalY(y [32]byte) bool {
	if y[31] != 0x7f || y[0] < 0xed {
		return true
	}
	for _, b := range y[1:31] {
		if b != 0xff {
			return true
		}
	}
	return false
}

// curveD is the edwards25519 constant d = -121665/121666 mod p.
var curveD = func() *big.Int {
	n := new(big.Int).Sub(fieldP, big.NewInt(121665))
	return n.Mul(n, new(big.Int).ModInverse(big.NewInt(121666), fieldP)).Mod(n, fieldP)
}()

// isOnCurve reports whether some x satisfies the curve equation for the
// reduced little-endian y: x^2 = u/v with u = y^2 - 1 and v = d*y^2 + 1. v is
// never 0 (-1/d is not a square modulo p), and u/v = u*v/v^2, so a solution
// exists exactly when u*v is a square modulo p — its Legendre symbol, which for
// the prime p is the Jacobi symbol, is not -1. That needs no modular inverse
// and no square root. The sign bit never makes an otherwise valid y invalid:
// the one case RFC 8032 rejects, x = 0 with the sign bit set, only occurs for
// y = 1 and y = p-1, which hasSmallOrder has already refused. The values are
// public, so variable-time arithmetic is fine.
func isOnCurve(y [32]byte) bool {
	var be [32]byte
	for i, b := range y {
		be[31-i] = b
	}
	yy := new(big.Int).SetBytes(be[:])
	yy.Mul(yy, yy).Mod(yy, fieldP)
	v := new(big.Int).Mul(curveD, yy)
	v.Add(v, big.NewInt(1))
	yy.Sub(yy, big.NewInt(1))
	yy.Mul(yy, v).Mod(yy, fieldP)
	return big.Jacobi(yy, fieldP) >= 0
}

// ValidatePublicKey checks that pub is an acceptable raw Ed25519 public key,
// with the same acceptance as libsodium's crypto_sign_verify_detached for the
// key. It must be:
//   - 32 bytes (else ErrPublicKeySize);
//   - not a point of small order in any encoding: the eight points, their
//     non-canonical spellings, either sign bit (else ErrSmallOrder), because
//     signatures under such a key can be forged by anyone;
//   - the canonical encoding (y < p) of a point on the curve (else
//     ErrInvalidPoint), because a non-canonical spelling is a second encoding of
//     the same key and an off-curve value is not a key at all.
//
// It does not check that the point lies in the prime-order subgroup.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != stded25519.PublicKeySize {
		return fmt.Errorf("%w: %d, want %d", ErrPublicKeySize, len(pub), stded25519.PublicKeySize)
	}
	if hasSmallOrder(pub) {
		return ErrSmallOrder
	}
	y := yOf(pub)
	if !isCanonicalY(y) || !isOnCurve(y) {
		return ErrInvalidPoint
	}
	return nil
}

// Generator generates Ed25519 key pairs. Implements crypto.KeyGenerator.
type Generator struct{}

// Generate produces a fresh Ed25519 key pair from crypto/rand. PrivateKey is
// the full 64-byte stded25519.PrivateKey (seed ‖ public key); PublicKey is the
// 32-byte point.
func (Generator) Generate() (*crypto.KeyPair, error) {
	pub, priv, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: generate: %w", err)
	}
	return &crypto.KeyPair{
		Algorithm:  Algorithm,
		PublicKey:  append([]byte(nil), pub...),
		PrivateKey: append([]byte(nil), priv...),
	}, nil
}

// Algorithm reports the suite name. Implements crypto.KeyGenerator.
func (Generator) Algorithm() string { return Algorithm }

// Verifier verifies Ed25519 signatures against a raw public key. Implements
// crypto.Verifier. It validates the key and the signature before delegating, so
// a malformed input is an error rather than a standard-library panic.
type Verifier struct{}

// Verify reports whether sig is a valid Ed25519 signature over data by
// publicKey. Malformed input is an error (not a false verdict), distinct from a
// genuine non-match. A key that is not 32 bytes is ErrPublicKeySize and a
// signature that is not 64 bytes is ErrSignatureSize. A public key of small
// order (see ValidatePublicKey) and a signature whose R (its first 32 bytes) is
// a point of small order are both ErrSmallOrder. A public key that is not the
// canonical encoding of a curve point is ErrInvalidPoint.
func (Verifier) Verify(publicKey, data, sig []byte) (bool, error) {
	if err := ValidatePublicKey(publicKey); err != nil {
		return false, err
	}
	if len(sig) != stded25519.SignatureSize {
		return false, fmt.Errorf("%w: %d, want %d", ErrSignatureSize, len(sig), stded25519.SignatureSize)
	}
	if hasSmallOrder(sig[:32]) {
		return false, ErrSmallOrder
	}
	return stded25519.Verify(stded25519.PublicKey(publicKey), data, sig), nil
}

// Algorithm reports the suite name. Implements crypto.Verifier.
func (Verifier) Algorithm() string { return Algorithm }

// Sign is the raw signing primitive: it signs data with a full 64-byte Ed25519
// private key (seed ‖ public key, as Generator emits). A wrong-size key is a
// typed error, not a standard-library panic — the counterpart to Verifier.Verify
// rejecting malformed sizes. This is NOT the DID-aware signing seam (that is
// crypto.Signer); it is the building block a keystore-backed store composes to
// implement crypto.Signer over the keys it holds.
func Sign(privateKey, data []byte) ([]byte, error) {
	if len(privateKey) != stded25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: private key size %d, want %d", len(privateKey), stded25519.PrivateKeySize)
	}
	return stded25519.Sign(stded25519.PrivateKey(privateKey), data), nil
}
