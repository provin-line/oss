// Package ed25519 is the Ed25519 implementation of the crypto interfaces — the
// PoC's only signature suite. KeyGenerator and Verifier are pure primitives.
// Signer is the raw-key, KeyStore-backed signer the crypto.Signer contract
// reserves for tests and CLI-local owner keys: production signing goes through
// the registry's SignerService so private keys never leave it.
package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/keystore"
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

// Signer is the KeyStore-backed raw-key signer. It resolves the private key for
// (did, keyID) from the KeyStore and signs with Ed25519. Implements
// crypto.Signer. Use only for tests and CLI-local owner keys — production uses
// the registry SignerService.
type Signer struct {
	keys keystore.KeyStore
}

// NewSigner returns a Signer reading private keys from ks.
func NewSigner(ks keystore.KeyStore) *Signer {
	return &Signer{keys: ks}
}

// Sign signs data with the Ed25519 private key the KeyStore holds for
// (did, keyID). A missing or malformed key is a typed error.
func (s *Signer) Sign(did, keyID string, data []byte) ([]byte, error) {
	priv, err := s.keys.GetPrivateKey(did, keystore.KeyID(keyID))
	if err != nil {
		return nil, fmt.Errorf("ed25519: load key for %s#%s: %w", did, keyID, err)
	}
	if len(priv) != stded25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: private key size %d, want %d", len(priv), stded25519.PrivateKeySize)
	}
	return stded25519.Sign(stded25519.PrivateKey(priv), data), nil
}
