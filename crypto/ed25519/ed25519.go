// Package ed25519 is the Ed25519 implementation of the crypto interfaces — the
// PoC's only signature suite — plus the raw signing primitive. Generator,
// Verifier, and the package-level Sign are pure primitives over key bytes: they
// hold no key custody and are unaware of DIDs.
//
// The DID-aware signing seam is crypto.Signer (Sign(did, keyID, data)),
// implemented by keystore-backed stores that hold the keys; this package's raw
// Sign(privateKey, data) is the low-level building block those stores compose.
package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/provin-line/oss/crypto"
)

// Algorithm is the crypto.KeyPair.Algorithm tag for this suite.
const Algorithm = "Ed25519"

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
// crypto.Verifier. It validates key and signature sizes before delegating, so
// a malformed input is a typed error rather than a standard-library panic.
type Verifier struct{}

// Verify reports whether sig is a valid Ed25519 signature over data by
// publicKey. A size mismatch on the key or signature is an error (not a false
// verdict): malformed inputs are distinct from a genuine non-match.
func (Verifier) Verify(publicKey, data, sig []byte) (bool, error) {
	if len(publicKey) != stded25519.PublicKeySize {
		return false, fmt.Errorf("ed25519: public key size %d, want %d", len(publicKey), stded25519.PublicKeySize)
	}
	if len(sig) != stded25519.SignatureSize {
		return false, fmt.Errorf("ed25519: signature size %d, want %d", len(sig), stded25519.SignatureSize)
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
