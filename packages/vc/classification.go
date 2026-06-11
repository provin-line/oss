package vc

import "context"

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

// ClassifyChain resolves each issuer's controller chain to its terminal
// Owner DID and classifies the chain by how many distinct owners it crosses.
func (v *Verifier) ClassifyChain(ctx context.Context, chain []*PipelinePassCredential) (ChainClass, error) {
	panic("not implemented")
}
