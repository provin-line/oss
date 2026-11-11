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
// definitive not-found). A Verifier also wraps it in
// SignerAuthenticityResult.Err when the key an IssuerVerifier returns is not
// the one the proof's verificationMethod names.
const ErrIssuerNotFound Error = "vc: issuer not found"

// ErrCryptosuiteNotRegistered is wrapped by the error with which a proof is
// refused because this process has not registered its cryptosuite. For
// eddsa-rdfc-2022 before RegisterEdDSARDFC2022 is called, CreateProof, the
// Builder, VerifyProof, VerifyProofUnderContract and VerifyProofWithContract
// return it, the error naming that function; a Verifier finds signer
// authenticity failed, with SignerAuthenticityResult.Err wrapping it. For a
// suite nothing registers, other than a no-op identifier (refused as
// alg:none), CreateProof, the Builder and VerifyProof return it; the contract
// functions refuse such a suite as one no claim contract names.
const ErrCryptosuiteNotRegistered Error = "vc: cryptosuite not registered"

// ErrUnsigned is SignerAuthenticityResult.Err for a credential that carries
// no proof.
const ErrUnsigned Error = "vc: credential has no proof"

// ErrProofPolicy is wrapped by SignerAuthenticityResult.Err when the proof is
// outside the policy the Verifier holds every proof to before it asks for the
// issuer's key: the proof type and purpose, a created time that parses as
// RFC 3339, no member the signature does not cover and no null @context, a
// credential that names an issuer, a verificationMethod whose part before the
// first "#" is the issuer, a cryptosuite a claim contract names, a proofValue
// that decodes, and, with a LifecycleRegistry, a cryptosuite Active or
// Deprecated at proof.created. The error says which.
const ErrProofPolicy Error = "vc: proof outside the proof policy"

// ErrSignatureInvalid is wrapped by SignerAuthenticityResult.Err when the
// issuer's key is established and the proof does not verify under it: no
// claim contract takes the proof's shape with the key's encoding, the proof's
// @context does not mirror the document's, the document does not canonicalize
// under the contract, or the signature does not verify under the key (the
// signature verifier's own error included). The error says which.
const ErrSignatureInvalid Error = "vc: proof does not verify under the issuer's key"

// ErrChainLinkBroken is what a *ChainLinkError is (errors.Is): a link of a
// chain does not hold.
const ErrChainLinkBroken Error = "vc: chain link broken"

// ErrChainMalformed is what the error is (errors.Is) with which
// ValidateChainLinks and ValidateChainFrom refuse a chain with nothing to
// link: an empty chain, or a nil credential in it. VerifyChain's and
// ClassifyChain's errors for an empty chain are not.
const ErrChainMalformed Error = "vc: chain has no credential to link"
