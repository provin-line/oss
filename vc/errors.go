package vc

// Error is the type of this package's constant sentinel errors: being
// constants, they cannot be reassigned by an importer.
//
// Compare an error with a sentinel by errors.Is alone: that an error is an
// Error under errors.As, or equal to a sentinel under ==, is not promised.
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
// not one the Verifier verifies at all, as the credential and its proof show
// without any key: a proof type and purpose other than the policy's, a
// created time that does not parse as RFC 3339, a member the signature does
// not cover or a null @context, a credential that names no issuer, a
// verificationMethod with no "#" or whose part before the first "#" is not
// the issuer, a cryptosuite no claim contract names, a proofValue that does
// not decode, or, with a LifecycleRegistry, a cryptosuite neither Active nor
// Deprecated at proof.created. The error says which. Each of these is
// ErrProofPolicy in whatever order the Verifier checks it.
const ErrProofPolicy Error = "vc: proof outside the proof policy"

// ErrSignatureInvalid is wrapped by SignerAuthenticityResult.Err when the
// proof, held against the issuer's key established for it, does not verify:
// no claim contract takes the proof's shape with the key's encoding, the
// proof's @context does not mirror the document's, the document does not
// canonicalize under the contract, or the signature does not verify under the
// key (the signature verifier's own error included). The error says which.
// Each of these is ErrSignatureInvalid in whatever order the Verifier checks
// it.
const ErrSignatureInvalid Error = "vc: proof does not verify under the issuer's key"

// ErrChainLinkBroken is what a *ChainLinkError is (errors.Is): a link of a
// chain does not hold.
const ErrChainLinkBroken Error = "vc: chain link broken"

// ErrChainOrder is what a *ChainOrderError is (errors.Is): the proofs'
// created times of a chain decrease along it, or a pair of them cannot be
// read and compared.
const ErrChainOrder Error = "vc: proof created times decrease along the chain"

// ErrChainEmpty is what the error is (errors.Is) with which a call that takes
// a chain refuses one with nothing to link: an empty chain, or a nil entry at
// a position in it. ValidateChainLinks, ValidateChainFrom, VerifyChain,
// ClassifyChain and VerifyChainSigners return it; their texts say which.
const ErrChainEmpty Error = "vc: chain has no credential to link"
