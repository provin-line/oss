// Package keystore defines the raw private-key custody contract: persisting and
// retrieving key material for at-issuance key generation and for CLI-local /
// test owner keys. It is the key-at-rest storage seam (file-backed now; an
// encrypted store later) — NOT the signing seam. Because GetPrivateKey hands
// out key material by definition, a KeyStore cannot front an HSM / cloud-KMS;
// production signing routes through the registry's SignerService (crypto.Signer),
// where private keys never leave the boundary.
//
// Implementations live with their service; this package owns only the
// contract.
package keystore

import (
	"errors"

	"github.com/provin-line/oss/crypto"
)

// ErrNotFound is returned (wrapped) by GetPrivateKey when no key is held for the
// requested (did, keyID). Callers distinguish an absent key from a malformed or
// storage failure via errors.Is — e.g. the SignerService maps it to a NotFound
// response while keeping malformed-key/internal failures as Internal.
var ErrNotFound = errors.New("keystore: key not found")

// KeyID is the logical key identifier within a DID Document.
type KeyID string

const (
	// KeyIDAuth maps to the #auth verification method (authentication
	// relationship; peer/connection auth).
	KeyIDAuth KeyID = "auth"
	// KeyIDSigning maps to the #signing verification method
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
	// This is the raw-key path (CLI-local / test owner keys); production
	// signing never retrieves key material — it routes through SignerService.
	// When no key is held for (did, keyID), implementations return a wrapped
	// ErrNotFound (errors.Is) so callers can distinguish an absent key from a
	// storage failure.
	GetPrivateKey(did string, keyID KeyID) ([]byte, error)
	// DeleteKeys removes every key held for the DID.
	DeleteKeys(did string) error
}
