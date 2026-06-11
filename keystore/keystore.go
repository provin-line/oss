// Package keystore defines the private-key custody contract — the KMS-model
// boundary that the DID registry (key generation at issuance) and the signer
// service (signing) both depend on, and the seam where Vault / HSM / cloud-KMS
// backends plug in.
//
// Implementations live with their service; this package owns only the
// contract.
package keystore

import "github.com/provin-line/oss/packages/crypto"

// KeyID is the logical key identifier within a DID Document.
type KeyID string

const (
	// KeyIDAuth maps to the #auth-key verification method (authentication
	// relationship; peer/connection auth).
	KeyIDAuth KeyID = "auth"
	// KeyIDSigning maps to the #signing-key verification method
	// (assertionMethod relationship; VC signing).
	KeyIDSigning KeyID = "signing"
)

// KeyStore persists private keys addressed by DID and logical key ID.
//
// Implementations must store keys with restrictive permissions and build any
// storage paths only from safety-checked DID segments.
type KeyStore interface {
	// SaveKeyPair persists all key pairs for a DID atomically.
	SaveKeyPair(did string, keys map[KeyID]*crypto.KeyPair) error
	// GetPrivateKey returns the private key bytes for the DID's logical key.
	GetPrivateKey(did string, keyID KeyID) ([]byte, error)
	// DeleteKeys removes every key held for the DID.
	DeleteKeys(did string) error
}
