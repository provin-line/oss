package vc

import (
	"context"
	"fmt"
)

// AttributeOwner resolves an issuer Process DID to the Owner DID that bears
// responsibility for the credentials it signs, via the validated
// controller-binding walk shared with ClassifyChain and the chain-consistency
// axis (audit.attribution.segment). Applied to a chain origin's issuer it
// yields the origin-default attribution target — whoever cuts the chain
// answers for what lies beyond the cut (audit.attribution.origin-default);
// composing the two rules over a chain is deliberately the caller's job, so
// the exported contract stays the one stable primitive.
//
// It authenticates the DID controller binding ONLY — it does not verify any
// credential's proof: a caller attributing a credential MUST first verify
// that credential and pass its verified issuer. An unreachable or broken
// controller chain is an error — an owner is never fabricated.
func (v *Verifier) AttributeOwner(ctx context.Context, issuer string) (string, error) {
	owner, err := v.walkControllerChain(ctx, issuer)
	if err != nil {
		return "", fmt.Errorf("vc: attribute owner of %q: %w", issuer, err)
	}
	return owner, nil
}
