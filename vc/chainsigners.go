package vc

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ChainSignersResult is VerifyChainSigners' verdict on a chain: its links, the
// order of its proofs' created times, and each credential's signer, with State
// folding the three. It establishes no Owner and not the chain-consistency
// axis (Order is one part of that axis).
//
// A check VerifyChainSigners comes to make later is folded into State and
// into these fields: a caller that decides on State reads no new field to
// keep deciding on all of it.
type ChainSignersResult struct {
	// Links is nil when the chain is linked as ValidateChainLinks says, else
	// the *ChainLinkError of the first credential whose link does not hold
	// (errors.Is ErrChainLinkBroken).
	Links error
	// Order is nil when every adjacent pair's proof created times read and do
	// not decrease, else the *ChainOrderError of the first pair out of order
	// (errors.Is ErrChainOrder).
	Order error
	// Signers is each credential's signer-authenticity verdict, in chain
	// order: the evaluation Verify's signer-authenticity axis makes, under the
	// key the IssuerKeys establishes for it, SuiteContract, Notations and Err
	// included. It is VerifySignerAuthenticity's, with the issuer read as
	// PipelinePassCredential.Issuer reads it: a string, so an issuer written
	// in another form names none.
	Signers []SignerAuthenticityResult
}

// State is the verdict of the whole result, on the lattice VerifyResult.Overall
// uses: failed when Links or Order is set or a Signers entry is failed; else
// indeterminate when an entry is indeterminate; else verified. Verified is
// exactly the condition under which VerifyChainSigners' documentation says
// what the chain establishes, for a result as VerifyChainSigners returned it:
// State reads the fields and verifies nothing again. A result with no Signers
// (none VerifyChainSigners returns), a nil result, and an entry whose State is
// none of the three are failed.
//
// State does not read an entry's SuiteContract, Issuer or VerificationMethod:
// verified does not say the chain is one to accept. A caller still accepts
// only the contract, the issuers and the keys it requires, as
// VerifyChainSigners says.
func (r *ChainSignersResult) State() ConfidenceState {
	if r == nil || r.Links != nil || r.Order != nil || len(r.Signers) == 0 {
		return ConfidenceFailed
	}
	state := ConfidenceVerified
	for _, s := range r.Signers {
		switch s.State {
		case ConfidenceVerified:
		case ConfidenceIndeterminate:
			state = ConfidenceIndeterminate
		default:
			return ConfidenceFailed
		}
	}
	return state
}

// ChainOrderError reports the first pair of a chain (origin first) whose
// proofs' created times are out of order: the later credential's time is
// before the earlier one's, or a proof or its time on either side is missing
// or does not parse. It is ErrChainOrder (errors.Is).
type ChainOrderError struct {
	// Index is the later credential's position: the pair is (Index-1, Index),
	// also when it is the earlier credential's time that cannot be read.
	Index int
	// FaultIndex is the position of the credential the order break was found
	// at, Index-1 or Index: of the pair's defects, the first in this order is
	// reported, the earlier credential's proof missing (Index-1), the later
	// one's proof missing (Index), the earlier one's created time not
	// parsing (Index-1), the later one's not parsing (Index), the later one's
	// time before the earlier one's (Index). It names the credential the
	// reported defect is in, not which of the two is in error.
	FaultIndex int
	// Reason says why. It is for people; callers branch on errors.Is
	// ErrChainOrder, the error's type, Index and FaultIndex, not on this text.
	Reason string
}

func (e *ChainOrderError) Error() string {
	return fmt.Sprintf("vc: chain credential %d: %s", e.Index, e.Reason)
}

// Is reports whether target is ErrChainOrder.
func (e *ChainOrderError) Is(target error) bool { return target == ErrChainOrder }

// VerifyChainSigners verifies a chain (origin first) by its keys alone: that
// it is linked (ValidateChainLinks' rules), that its proofs' created times do
// not decrease along it, and each credential's signer authenticity under the
// key keys establishes for it, with the Verifier's proof policy and
// cryptosuite lifecycle. It is for a caller whose credentials' issuers are
// not Process DIDs under an Owner, which VerifyChain requires.
//
// The verdict is in the result, not the error. The error is for a chain it
// cannot evaluate: an empty chain or a nil credential (ErrChainEmpty), a
// nil keys, or ctx done when a credential is about to be evaluated. A key
// lookup ctx ends inside is that credential's indeterminate entry, its Err
// wrapping the context's error. A result has all three parts evaluated: no
// part stops the others.
//
// With a nil error and State verified (a nil Links, a nil Order and every
// Signers entry verified), the chain's credentials are linked as
// ValidateChainLinks says, their created times as written do not decrease,
// and each credential's proof verifies, under the key keys established for
// it, over a document equivalent to its body under that entry's
// SuiteContract (see
// VerifySignerAuthenticity for what equivalent means). Links reads the
// chain's JSON as received. For an entry whose signer is verified, the
// members the links read are then members of what was signed, up to that
// equivalence: a contract that signs the JSON (ContractW3CEdDSAJCS2022,
// ContractLegacyProvinEdDSAJCSInt64) covers them as written, and an
// eddsa-rdfc-2022 credential is held to the closed form ValidateWireForm
// describes (that form alone, not the rest of the wire form) under the
// contexts its signature verified with.
//
// A caller accepts the chain only with all of that, only the SuiteContract its
// credential type requires on every entry, and only the issuers and keys
// (each entry's Issuer and VerificationMethod) it lets sign each credential.
//
// It does not establish, and a caller does not read into the result:
//
//   - who is responsible for an issuer (Owners), or the chain-consistency
//     axis as a whole;
//   - the credentials' types, wire forms or contents (VerifyChain checks
//     types, wire forms and Owners);
//   - whether they are currently valid or revoked: no verifier here checks
//     that;
//   - that the origin started from a given input (ValidateChainFrom binds
//     it), or that the chain is complete (a prefix of a linked chain is
//     linked), or that it answers a given request;
//   - which of a predecessor's proofs a successor saw (the content address
//     excludes the proof), or that the created times are true.
func (v *Verifier) VerifyChainSigners(ctx context.Context, keys IssuerKeys, chain []*PipelinePassCredential) (*ChainSignersResult, error) {
	if err := checkChainEntries(chain); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("vc: VerifyChainSigners: nil IssuerKeys")
	}
	res := &ChainSignersResult{Signers: make([]SignerAuthenticityResult, 0, len(chain))}
	for _, cred := range chain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res.Signers = append(res.Signers, v.signerAuthenticity(ctx, keys, cred.Issuer(), cred.proof, cred.body))
	}
	if l := firstBrokenLink(chain); l != nil {
		res.Links = l
	}
	if o := firstOrderBreak(chain); o != nil {
		res.Order = o
	}
	return res, nil
}

// firstOrderBreak returns the first pair (n-1, n) of chain whose proofs'
// created times are out of order, as a *ChainOrderError at n, or nil. It is
// the one ordering check, for VerifyChain and VerifyChainSigners.
func firstOrderBreak(chain []*PipelinePassCredential) *ChainOrderError {
	for n := 1; n < len(chain); n++ {
		if reason, atPrev := orderBreak(chain[n-1], chain[n]); reason != "" {
			fault := n
			if atPrev {
				fault = n - 1
			}
			return &ChainOrderError{Index: n, FaultIndex: fault, Reason: reason}
		}
	}
	return nil
}

// orderBreak says why cur's proof.created is not at or after prev's, naming
// the side at fault, and whether that side is prev ("" and false when it is
// in order). A missing proof or a created time that does not parse, on
// either side, is out of order (the signer-authenticity axis surfaces the
// unsigned or malformed proof separately).
func orderBreak(prev, cur *PipelinePassCredential) (reason string, atPrev bool) {
	pp, cp := prev.Proof(), cur.Proof()
	switch {
	case pp == nil:
		return "the predecessor's proof is missing", true
	case cp == nil:
		return "its proof is missing", false
	}
	pt, err := time.Parse(time.RFC3339, pp.Created)
	if err != nil {
		return "the predecessor's proof created time does not parse", true
	}
	ct, err := time.Parse(time.RFC3339, cp.Created)
	if err != nil {
		return "its proof created time does not parse", false
	}
	if ct.Before(pt) {
		return "its proof created time is before its predecessor's", false
	}
	return "", false
}
