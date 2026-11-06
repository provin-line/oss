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

// smallOrderY holds the y coordinates of the eight points of order dividing 8
// on edwards25519, over the field of p = 2^255 - 19: 1 (the identity), p-1
// (order 2), 0 (the two points of order 4) and ±y8 (the four points of order
// 8). The two points sharing a y differ only in the sign of x, so the sign
// bit is not part of the lookup.
var smallOrderY = func() []*big.Int {
	y8, _ := new(big.Int).SetString("7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7", 16)
	return []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(fieldP, big.NewInt(1)),
		y8,
		new(big.Int).Sub(fieldP, y8),
	}
}()

// hasSmallOrder reports whether the 32-byte encoding point is a point of small
// order. The y coordinate is reduced modulo p first, so the non-canonical
// spellings (y >= p) of those points are caught as well.
func hasSmallOrder(point []byte) bool {
	be := make([]byte, 32)
	for i, b := range point {
		be[31-i] = b
	}
	be[0] &= 0x7f // the sign bit of x
	y := new(big.Int).SetBytes(be)
	y.Mod(y, fieldP)
	for _, s := range smallOrderY {
		if y.Cmp(s) == 0 {
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

// isCanonicalPoint reports whether the 32-byte encoding point (RFC 8032
// section 5.1.3) has y < p and an x with x^2 = (y^2-1)/(d*y^2+1) mod p. The
// sign bit never makes an otherwise valid y invalid here: the one case RFC 8032
// rejects, x = 0 with the sign bit set, only occurs for y = 1 and y = p-1,
// which are small-order points that hasSmallOrder has already refused. The
// values involved are public, so variable-time big.Int arithmetic is fine.
func isCanonicalPoint(point []byte) bool {
	be := make([]byte, 32)
	for i, b := range point {
		be[31-i] = b
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be)
	if y.Cmp(fieldP) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(curveD, y2)
	den.Add(den, big.NewInt(1)).Mod(den, fieldP)
	x2 := num.Mul(num, new(big.Int).ModInverse(den, fieldP)).Mod(num, fieldP)
	return x2.Sign() == 0 || new(big.Int).ModSqrt(x2, fieldP) != nil
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
	if !isCanonicalPoint(pub) {
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
