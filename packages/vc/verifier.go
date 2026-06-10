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
	panic("not implemented")
}

// VerifyResult is the L1 verdict for one credential.
type VerifyResult struct {
	Confidence ConfidenceLevel
	Axes       AxisResult
}

// Verify performs L1 verification of a single credential: @context wire form,
// derived_from duplicate check, source_root field coherence (both-or-neither
// with source_root_canonical), no-op canonicalizer ban, issuer DID
// resolution, public-key extraction, proof verification, and weakest-link
// confidence evaluation.
func (v *Verifier) Verify(ctx context.Context, cred *PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}

// VerifyChain verifies each credential individually, then checks
// previousCredential hash linkage (newest first) and the data-flow invariant
// outputHash[n] == inputHash[n+1] between adjacent credentials.
func (v *Verifier) VerifyChain(ctx context.Context, chain []*PipelinePassCredential) (*VerifyResult, error) {
	panic("not implemented")
}

// VerifyL2Reachability recomputes cred's source_root from the raw wire bytes
// of its source VCs using the canonicalizer named by source_root_canonical,
// and requires byte equality with the committed root.
func (v *Verifier) VerifyL2Reachability(ctx context.Context, cred *PipelinePassCredential, sourceWireBytes [][]byte) error {
	panic("not implemented")
}

// VerifyDerivedFromIssuerSet enforces set equality between cred's
// derived_from list and the issuer set of the presented source VCs.
func (v *Verifier) VerifyDerivedFromIssuerSet(cred *PipelinePassCredential, sourceIssuers []string) error {
	panic("not implemented")
}
