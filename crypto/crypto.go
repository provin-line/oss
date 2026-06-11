// Package crypto defines the key-generation, signing, and verification
// interfaces. Implementations live in subpackages (ed25519 for the PoC); the
// interfaces carry the algorithm dimension so adding suites is non-breaking.
package crypto

// KeyPair is a generated key pair. PrivateKey appears only inside the
// registry process (KMS model) and in CLI-local owner keys.
type KeyPair struct {
	Algorithm  string
	PublicKey  []byte
	PrivateKey []byte
}

// KeyGenerator generates key pairs for one algorithm.
type KeyGenerator interface {
	Generate() (*KeyPair, error)
	Algorithm() string
}

// Signer signs data on behalf of a DID's key.
//
// Signer is deliberately DID-aware rather than a raw primitive: production
// implementations call the registry's SignerService — private keys never
// leave the registry. Raw-key signers exist only for tests and CLI-local
// owner keys.
type Signer interface {
	Sign(did string, keyID string, data []byte) ([]byte, error)
}

// Verifier verifies a signature against a raw public key. Implementations
// reject malformed key/signature sizes before delegating to the underlying
// library.
type Verifier interface {
	Verify(publicKey []byte, data []byte, signature []byte) (bool, error)
	Algorithm() string
}
