package vc

import (
	"context"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/resolver"
)

// Verifier performs credential verification: wire-form checks, issuer DID
// resolution, proof verification, and confidence evaluation.
type Verifier struct {
	resolver    resolver.Resolver
	sigVerifier crypto.Verifier
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// NewVerifier returns a Verifier resolving issuer DIDs through r and
// verifying signatures through sigVerifier.
func NewVerifier(r resolver.Resolver, sigVerifier crypto.Verifier, opts ...VerifierOption) *Verifier {
	v := &Verifier{resolver: r, sigVerifier: sigVerifier}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// VerifyResult is the structured verdict for one credential (or one chain):
// the three normative axes plus their weakest-link composition.
type VerifyResult struct {
	Overall ConfidenceState
	Axes    AxisResult
}

// Verify performs single-credential verification across the three normative
// axes: wire-form checks (@context, required fields, and the claim rules —
// ValidateTransformationClaim composes into this axis: grammar,
// bare-rejection, and grounding fail it, while unrecognized grounded
// claims pass open-world), issuer DID resolution
// and public-key extraction, proof verification with cryptosuite lifecycle
// evaluation at proof.created, controller-chain reconstruction to the
// terminal Owner DID, and weakest-link composition of the axis verdicts.
//
// Wire-form checks include source-commitment well-formedness: when the
// commitment fields are present (on any credential — they are orthogonal to
// previousCredential), derived_from must be a duplicate-free
// lexicographically sorted set and source_root a multihash-encoded digest.
// These are O(1)/O(n) shape checks; resolving the commitment itself stays
// off this path — see VerifySourceCommitment.
func (v *Verifier) Verify(ctx context.Context, cred *PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}

// VerifyChain verifies each credential individually, then checks the chain
// structure: previousCredential linkage, the data-flow invariant
// outputHash[n] == inputHash[n+1] between adjacent credentials, ordering
// consistency (proof.created monotonicity), that the chain origin carries
// no previousCredential, and that any chain-preserving credential carrying
// a source commitment includes its predecessor's issuer in derived_from
// (all-consumed semantics — an O(1) consistency check once the predecessor
// is at hand; full commitment resolution stays with
// VerifySourceCommitment).
func (v *Verifier) VerifyChain(ctx context.Context, chain []*PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}
