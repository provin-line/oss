// Package keystore defines the local key-custody contract: persisting key
// material for at-issuance key generation and signing on behalf of a DID's key.
// It is the local key-at-rest seam (file-backed now; a TPM / encrypted-at-rest
// store later) — NOT a universal cloud-KMS interface.
//
// The seam signs through Sign, whose shape is exactly crypto.Signer.Sign — so a
// KeyStore is-a crypto.Signer, and signing never requires raw key material to
// cross the store boundary. That is what lets a local backend that keeps keys
// opaque (encrypted-at-rest, TPM) implement the contract; raw-key egress is a
// file-backend detail (filestore.Store.GetPrivateKey), not part of the seam.
//
// A cloud KMS/HSM is served differently: signing plugs in as a remote
// crypto.Signer (the registry's SignerService), and in-backend key provisioning
// is a separate future interface — SaveKeyPair here takes externally-generated
// key material, which is the local provisioning contract.
//
// Implementations live with their service; this package owns only the contract.
package keystore

import (
	"errors"

	"github.com/provin-line/oss/crypto"
)

// ErrNotFound is returned (wrapped) by Sign — and by filestore's raw-key
// GetPrivateKey accessor — when no key is held for the requested (did, keyID).
// Callers distinguish an absent key from a malformed or storage failure via
// errors.Is — e.g. the SignerService maps it to a NotFound response while
// keeping malformed-key/internal failures as Internal.
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

// KeyStore persists key material addressed by DID and signs on its behalf.
//
// Implementations must store keys with restrictive permissions and build any
// storage paths only from safety-checked DID segments. Because Sign matches
// crypto.Signer.Sign exactly, every KeyStore is usable wherever a crypto.Signer
// is required.
type KeyStore interface {
	// SaveKeyPair persists all key pairs for a DID atomically. This is the local
	// provisioning path: key material is generated elsewhere (crypto.KeyGenerator)
	// and handed in. A KMS with in-backend generation would provision through a
	// separate interface, not this one.
	SaveKeyPair(did string, keys map[KeyID]*crypto.KeyPair) error
	// Sign returns a signature over data for the DID's logical key WITHOUT the
	// raw key crossing the store boundary — the KMS-shaped signing path, and the
	// one method a keep-keys-opaque backend can implement. Its signature is
	// exactly crypto.Signer.Sign: keyID is the DID-fragment string (e.g. the
	// KeyID constants, but the parameter is a plain string so the method is a
	// crypto.Signer). When no key is held for a well-formed (did, keyID),
	// implementations return a wrapped ErrNotFound (errors.Is). A malformed or
	// path-unsafe identifier is a separate hard error — never masked as
	// ErrNotFound, so a traversal attempt cannot be laundered into "not found".
	Sign(did string, keyID string, data []byte) ([]byte, error)
	// DeleteKeys removes every key held for the DID.
	DeleteKeys(did string) error
}
