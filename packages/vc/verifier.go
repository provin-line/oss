package vc

import (
	"context"

	"github.com/provin-line/oss/packages/crypto"
	"github.com/provin-line/oss/packages/resolver"
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
// axes: wire-form checks (@context, required fields), issuer DID resolution
// and public-key extraction, proof verification with cryptosuite lifecycle
// evaluation at proof.created, controller-chain reconstruction to the
// terminal Owner DID, and weakest-link composition of the axis verdicts.
//
// Wire-form checks include the previous-XOR-origin invariant: origin
// commitment fields coexisting with a non-empty previousCredential fail the
// data-integrity axis. Builder enforces the invariant at issuance, but only
// for credentials built here — a non-conformant issuer can craft both, so
// every verification re-checks it (an O(1) presence check; resolving the
// commitment itself stays off this path — see VerifyOriginCommitment).
func (v *Verifier) Verify(ctx context.Context, cred *PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}

// VerifyChain verifies each credential individually, then checks the chain
// structure: previousCredential linkage, the data-flow invariant
// outputHash[n] == inputHash[n+1] between adjacent credentials, ordering
// consistency (proof.created monotonicity), that the chain origin carries
// no previousCredential, and that origin commitment fields appear nowhere
// but the chain origin.
func (v *Verifier) VerifyChain(ctx context.Context, chain []*PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}
