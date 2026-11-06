package vc

// Error is the type of this package's constant sentinel errors: being
// constants, they cannot be reassigned by an importer.
type Error string

func (e Error) Error() string { return string(e) }

// ErrIssuerNotFound is an established negative about an issuer: there is no
// such issuer; the key the proof's verificationMethod names does not exist, is
// not authorized for assertion, or is revoked or deactivated; or the issuer
// reaches no Owner, or another Owner than its DID names. The axes read it as
// failed. An IssuerVerifier wraps it only for what it has established — never
// for a cache miss, a timeout, or an unreachable source, which are transient
// and read as indeterminate (as resolver.ErrNotFound is reserved for a
// definitive not-found).
const ErrIssuerNotFound Error = "vc: issuer not found"
