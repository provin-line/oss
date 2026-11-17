package vc

import (
	"errors"
	"fmt"
)

// ChainLinkError reports the first credential of a chain (origin first) whose
// link to what precedes it does not hold: for the origin, the chain's input;
// for a successor, its predecessor. An eddsa-rdfc-2022 credential not in its
// closed form (ValidateWireForm) is one: its links are not read. It is
// ErrChainLinkBroken (errors.Is).
type ChainLinkError struct {
	// Index is the credential's position in the chain, the origin being 0.
	Index int
	// Reason says which link does not hold. It is for people; callers branch
	// on errors.Is ErrChainLinkBroken, the error's type and Index, not on this
	// text.
	Reason string
}

func (e *ChainLinkError) Error() string {
	return fmt.Sprintf("vc: chain credential %d: %s", e.Index, e.Reason)
}

// Is reports whether target is ErrChainLinkBroken: a broken link is told from
// a chain with nothing to link (ErrChainEmpty) without reading text.
func (e *ChainLinkError) Is(target error) bool { return target == ErrChainLinkBroken }

// ValidateChainLinks checks that chain (origin first) is linked, reading no
// signature:
//
//   - the origin carries no previousCredential (absent or null);
//   - each later credential names its predecessor's content address in
//     previousCredential, its inputHash is the predecessor's (non-empty)
//     outputHash, and a source commitment it carries includes the
//     predecessor's issuer;
//   - a credential whose proof names eddsa-rdfc-2022 holds the members vc
//     reads under their names and in their forms, and no others (the closed
//     form ValidateWireForm describes). One that does not is a broken link at
//     its position: its links are not read.
//
// These are the links VerifyChain checks, through the same implementation. A
// broken link is a *ChainLinkError, and errors.Is ErrChainLinkBroken. An empty
// chain or a nil credential is ErrChainEmpty, an error of another kind:
// there is nothing to link.
//
// It detects a gap, a reordering, a credential from another chain, and an
// origin that claims a predecessor. It does not detect a missing tail: every
// prefix of a linked chain is itself linked. Nor does it bind the origin to an
// input — ValidateChainFrom does — so it accepts a chain whose origin has no
// inputHash, such as an aggregation's. A chain that links is not a verified
// chain: the credentials may be unsigned or forged, and their wire forms
// (beyond an eddsa-rdfc-2022 credential's closed form), issuers and ordering
// are not checked; VerifyChain verifies those.
func ValidateChainLinks(chain []*PipelinePassCredential) error {
	if err := checkChainEntries(chain); err != nil {
		return err
	}
	if err := firstBrokenLink(chain); err != nil {
		return err
	}
	return nil
}

// ValidateChainFrom checks that chain is linked (ValidateChainLinks) and that
// it starts from originInput: the origin's inputHash is originInput. It is for
// a party that knows the input the chain must start from — one that extends
// only a chain started from the request it carries, say. Its errors
// are ValidateChainLinks', and an origin from another input is a
// *ChainLinkError at 0. An empty originInput is an error, not a match for an
// origin without inputHash, and neither ErrChainLinkBroken nor
// ErrChainEmpty: it is the caller's argument, not the chain.
func ValidateChainFrom(chain []*PipelinePassCredential, originInput string) error {
	if err := checkChainEntries(chain); err != nil {
		return err
	}
	if originInput == "" {
		return errors.New("vc: no origin input to bind the chain to")
	}
	if err := closedFormBreak(0, chain[0]); err != nil {
		return err
	}
	subject, err := chain[0].Subject()
	if err != nil {
		return &ChainLinkError{Index: 0, Reason: "unreadable credentialSubject"}
	}
	if subject.InputHash != originInput {
		return &ChainLinkError{Index: 0, Reason: "the origin's inputHash is not the chain's input"}
	}
	if err := firstBrokenLink(chain); err != nil {
		return err
	}
	return nil
}

// checkChainEntries refuses an empty chain and a nil credential, with an
// error that is ErrChainEmpty: there is nothing at that position to link.
func checkChainEntries(chain []*PipelinePassCredential) error {
	if len(chain) == 0 {
		return chainEmptyError("vc: empty chain")
	}
	for i, c := range chain {
		if c == nil {
			return chainEmptyError(fmt.Sprintf("vc: chain credential %d is nil", i))
		}
	}
	return nil
}

// chainEmptyError is the error of a chain with nothing to link: its text
// says what is missing, and it is ErrChainEmpty (errors.Is).
type chainEmptyError string

func (e chainEmptyError) Error() string        { return string(e) }
func (e chainEmptyError) Is(target error) bool { return target == ErrChainEmpty }

// firstBrokenLink returns the first credential of chain (origin first,
// non-empty, no nil entries) whose link to its predecessor does not hold, or
// nil when every link holds: the origin carries no previousCredential; each
// successor names its predecessor's content address, takes the predecessor's
// non-empty outputHash as its inputHash, and, when it carries a source
// commitment, includes the predecessor's (non-empty) issuer in it; and each
// credential is in its closed form (checkRDFCClosedForm) before any of its links is
// read. It is the one implementation of these links, for VerifyChain,
// ValidateChainLinks and ValidateChainFrom.
func firstBrokenLink(chain []*PipelinePassCredential) *ChainLinkError {
	if err := closedFormBreak(0, chain[0]); err != nil {
		return err
	}
	if hasPredecessor(chain[0]) {
		return &ChainLinkError{Index: 0, Reason: "the origin carries a previousCredential"}
	}
	for n := 1; n < len(chain); n++ {
		prev, cur := chain[n-1], chain[n]
		if err := closedFormBreak(n, cur); err != nil {
			return err
		}
		prevHash, err := prev.Hash()
		if err != nil {
			return &ChainLinkError{Index: n, Reason: "the predecessor has no content address"}
		}
		if cur.PreviousCredential() != prevHash {
			return &ChainLinkError{Index: n, Reason: "previousCredential is not the predecessor's content address"}
		}
		ps, err := prev.Subject()
		if err != nil {
			return &ChainLinkError{Index: n, Reason: "the predecessor's credentialSubject is unreadable"}
		}
		cs, err := cur.Subject()
		if err != nil {
			return &ChainLinkError{Index: n, Reason: "unreadable credentialSubject"}
		}
		if ps.OutputHash == "" || ps.OutputHash != cs.InputHash {
			return &ChainLinkError{Index: n, Reason: "inputHash is not the predecessor's outputHash"}
		}
		if sc := cur.SourceCommitment(); sc != nil && (prev.Issuer() == "" || !containsString(sc.DerivedFrom, prev.Issuer())) {
			return &ChainLinkError{Index: n, Reason: "the source commitment does not include the predecessor's issuer"}
		}
	}
	return nil
}

// closedFormBreak is the *ChainLinkError at index for c when c is not in its closed
// form (checkRDFCClosedForm), or nil.
func closedFormBreak(index int, c *PipelinePassCredential) *ChainLinkError {
	if err := checkRDFCClosedForm(c); err != nil {
		return &ChainLinkError{Index: index, Reason: err.Error()}
	}
	return nil
}

// hasPredecessor reports whether the credential's subject carries a
// previousCredential member with any value but null. It reads the raw member,
// not the string accessor, so a non-string value is not mistaken for none.
func hasPredecessor(c *PipelinePassCredential) bool {
	m, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return false
	}
	pc, present := m[keyPreviousCredential]
	return present && pc != nil
}
