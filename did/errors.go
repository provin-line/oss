package did

// Error is the type of this package's sentinel errors. The sentinels are
// constants, so no importer can reassign them; errors.Is matches them as it
// matches any comparable error.
type Error string

func (e Error) Error() string { return string(e) }

// ErrInvalidPublicKey reports a verification method whose key value is not a
// usable public key of its type. For Ed25519 that is a key
// crypto/ed25519.ValidatePublicKey refuses: a wrong size, a point of small
// order, a value off the curve, or a non-canonical encoding of a point. The
// error wraps the key type's own error as well (for example
// ed25519.ErrSmallOrder), so a caller can match either.
//
// A method that is absent, unlisted, ambiguous, controlled by another DID, or
// whose encoding cannot be read is a different failure and is not
// ErrInvalidPublicKey.
const ErrInvalidPublicKey Error = "did: invalid public key"
