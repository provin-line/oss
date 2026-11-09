package vc

import (
	"context"
	"errors"
	"fmt"
)

// ChainClass categorizes a verified credential chain by its signature-chain
// structure — who signed and how many trust boundaries were crossed, not how
// the data was produced. Because aggregation starts a fresh chain (trigger
// rule), an
// aggregated result distributed from its origin classifies as ChainOrigin
// regardless of how many upstream sources contributed; that is a deliberate
// consequence of the linear-chain design, not a limitation. The zero value
// is Unknown.
type ChainClass int

const (
	ChainClassUnknown ChainClass = iota
	// ChainOrigin — the chain begins at this process.
	ChainOrigin
	// ChainSingleOwnerDerived — derivation remains under a single owner.
	ChainSingleOwnerDerived
	// ChainMultiOwnerDerived — derivation crosses multiple owners.
	ChainMultiOwnerDerived
)

// ClassifyChain establishes each issuer's Owner DID (as AttributeOwner does)
// and classifies the chain by how many distinct owners it crosses.
//
// A single-credential chain is a bare origin (ChainOrigin) — no derivation
// occurred, regardless of how many upstream sources an aggregation folded
// (aggregation starts a fresh chain). A multi-credential chain is
// ChainSingleOwnerDerived when every issuer resolves to one owner, otherwise
// ChainMultiOwnerDerived. Classification is orthogonal to confidence, but it
// shares the Owner check: an Owner that cannot be established is an error
// (the owner cannot be attributed), not a class.
func (v *Verifier) ClassifyChain(ctx context.Context, chain []*PipelinePassCredential) (ChainClass, error) {
	if len(chain) == 0 {
		return ChainClassUnknown, errors.New("vc: empty chain")
	}
	if len(chain) == 1 {
		return ChainOrigin, nil
	}
	owners := make(map[string]bool, len(chain))
	for _, cred := range chain {
		owner, err := v.ownerOf(ctx, cred.Issuer())
		if err != nil {
			return ChainClassUnknown, fmt.Errorf("vc: classify chain: resolving owner of %q: %w", cred.Issuer(), err)
		}
		owners[owner] = true
	}
	if len(owners) <= 1 {
		return ChainSingleOwnerDerived, nil
	}
	return ChainMultiOwnerDerived, nil
}
