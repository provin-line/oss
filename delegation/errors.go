package delegation

import "github.com/provin-line/oss/internal/excerpt"

// Error is the type of this package's sentinel errors. The sentinels are
// constants, so no importer can reassign them; errors.Is matches them as it
// matches any comparable error.
//
// Compare an error with a sentinel by errors.Is alone: that an error is an
// Error under errors.As, or equal to a sentinel under ==, is not promised.
type Error string

func (e Error) Error() string { return string(e) }

// ErrNotForIdentity reports a delegation presented as authority for an
// identity other than the one its credentialSubject.id names.
const ErrNotForIdentity Error = "delegation: not for this identity"

// The sentinels of Verify's refusals, one for each kind of check it makes.
// Verify attaches exactly one of them to each error it returns (errors.Is);
// the error's text says which check failed.
const (
	// ErrMalformed: the credential is not a delegation credential in shape
	// (dplaax delegation.shape): no credential, no proof, a type without
	// VerifiableCredential or DelegationCredential, an empty issuer or
	// credentialSubject.id, or a delegatedBy other than the issuer (an empty
	// one too).
	ErrMalformed Error = "delegation: malformed"

	// ErrOwnerBinding: the issuer is not an Owner the deployment accepts, or
	// the subject is not a Pipeline or Process under it (dplaax
	// delegation.binding): an issuer or a subject id, present, that is not a
	// did:dplaax identifier (the error keeps dplaax.ErrSyntax), an issuer that
	// dplaax.ValidateDID refuses or that is not an Owner, a subject that is
	// neither a Pipeline nor a Process, or one under another Owner.
	ErrOwnerBinding Error = "delegation: not an Owner delegating a Pipeline or Process under it"

	// ErrProofPolicy: the proof is not one a delegation is verified under, as
	// the credential and its proof show without any key (dplaax
	// delegation.proof): a proof type and purpose other than DataIntegrityProof
	// and assertionMethod, a cryptosuite other than eddsa-jcs-2022, a created
	// time that does not parse as RFC 3339, a verificationMethod with no "#" or
	// whose part before the first "#" is not the issuer, or a proofValue that
	// does not decode.
	ErrProofPolicy Error = "delegation: proof outside the proof policy"

	// ErrScoped: the delegation carries a scope, an empty one too (dplaax
	// delegation.scope). The provin profile accepts no scoped delegation.
	ErrScoped Error = "delegation: carries a scope"

	// ErrIssuerNotFound: an established negative about the issuer's key: the
	// resolver answers that the issuer has no document (resolver.ErrNotFound,
	// which the error keeps), or did.ExtractPublicKeyAndEncoding finds in the
	// issuer's document no key usable for assertion under the proof's
	// verificationMethod: the method is absent, not listed under
	// assertionMethod, of another controller, or ambiguous, its key material is
	// malformed, or a method id of the document or the reference is not in the
	// one form it accepts (the error keeps did's).
	ErrIssuerNotFound Error = "delegation: issuer not found"

	// ErrSignatureInvalid: the proof, held against the issuer's key
	// established for it, does not verify: no claim contract takes the
	// proof's shape with the key's encoding, the proof's @context does not
	// mirror the credential's, the credential does not canonicalize under the
	// contract, or the signature does not verify under the key. An error of
	// the signature verifier is included, as crypto.Verifier has it mean a
	// signature not verified; the error keeps it.
	ErrSignatureInvalid Error = "delegation: proof does not verify under the issuer's key"

	// ErrSignatureUnestablished: the issuer's key could not be established
	// now: resolving the issuer failed without saying that it has no document
	// (a timeout, an ended context, an unreachable registry; the error keeps
	// the resolver's), returned neither a document nor an error, or returned
	// the document of another DID. It may verify later.
	ErrSignatureUnestablished Error = "delegation: the issuer's signature could not be established now"
)

// class is the kind of check a refusal of Verify failed, each naming one of
// the sentinels above. Its zero value, and every value past the seven, names
// none.
type class uint8

const (
	classMalformed class = iota + 1
	classOwnerBinding
	classProofPolicy
	classScoped
	classIssuerNotFound
	classSignatureInvalid
	classSignatureUnestablished
)

// sentinel is the sentinel c names, and false when c is no class.
func (c class) sentinel() (Error, bool) {
	switch c {
	case classMalformed:
		return ErrMalformed, true
	case classOwnerBinding:
		return ErrOwnerBinding, true
	case classProofPolicy:
		return ErrProofPolicy, true
	case classScoped:
		return ErrScoped, true
	case classIssuerNotFound:
		return ErrIssuerNotFound, true
	case classSignatureInvalid:
		return ErrSignatureInvalid, true
	case classSignatureUnestablished:
		return ErrSignatureUnestablished, true
	}
	return "", false
}

// refusal is an error of Verify: the text it reads, the one sentinel its
// class names (errors.Is), and the error of another package it keeps, if any
// (errors.Unwrap).
type refusal struct {
	class class
	text  string
	cause error
}

// refuse is the refusal of class c that reads text and keeps cause (nil for
// none). Every refusal of Verify is made by it.
func refuse(c class, text string, cause error) *refusal {
	return &refusal{class: c, text: text, cause: cause}
}

// refuseWrapping is the refusal of class c that reads prefix and cause's text
// within wrapLimit, and keeps cause.
func refuseWrapping(c class, prefix string, cause error) *refusal {
	return refuse(c, excerpt.Wrap(prefix, cause, wrapLimit).Error(), cause)
}

// wrapLimit is the most bytes of another package's error text Verify writes
// into its own: that text may quote what the credential holds, at any length.
const wrapLimit = 512

func (r *refusal) Error() string { return r.text }

func (r *refusal) Unwrap() error { return r.cause }

func (r *refusal) Is(target error) bool {
	s, ok := r.class.sentinel()
	return ok && target == s
}
