package vc

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/resolver"
)

// IssuerKey is the key a credential's proof must verify under.
type IssuerKey struct {
	// ID is the verification method the key is: the proof's
	// verificationMethod, absolute (<issuer>#fragment). The Verifier uses the
	// key only when ID is exactly that.
	ID string
	// PublicKey is the raw public key.
	PublicKey []byte
	// Encoding is how the key is registered (did.EncodingMultikey for anything
	// issued now). It selects the suite contract the proof is verified under,
	// so it is the key's registered encoding, never one derived from the
	// proof's shape.
	Encoding did.KeyEncoding
}

// IssuerVerifier establishes a credential's issuer: the key its proof must
// verify under (the signer-authenticity axis) and the Owner DID responsible for
// the issuer (the chain-consistency axis, AttributeOwner, ClassifyChain). The
// default, NewDIDDocumentIssuers, reads both from DID documents; a deployment
// that registers its issuers elsewhere supplies its own.
//
// The Verifier keeps the rest of each axis to itself: the proof policy (proof
// type and purpose, members, a verificationMethod naming the issuer, the
// cryptosuite lifecycle) runs before IssuerKey is asked; the key is used only
// when its ID is the proof's verificationMethod; the proof is verified against
// it under the exact suite contract; and the Owner must be the Owner the
// issuer's Process DID names. An IssuerVerifier cannot loosen any of these.
//
// Errors: one wrapping ErrIssuerNotFound is an established negative (failed);
// any other is transient (indeterminate).
type IssuerVerifier interface {
	// IssuerKey returns the key that cred's proof verificationMethod names,
	// one the issuer authorizes for assertion at the proof's created time, with
	// ID set to that verificationMethod. A verificationMethod the issuer has no
	// such key for is ErrIssuerNotFound. cred has not been verified when this
	// is asked: it is the credential as received.
	IssuerKey(ctx context.Context, cred *Credential) (IssuerKey, error)
	// Owner returns the Owner DID responsible for issuer, a Process DID.
	Owner(ctx context.Context, issuer string) (string, error)
}

// WithIssuerVerifier sets how the Verifier establishes issuers. nil keeps the
// default (NewDIDDocumentIssuers over the Verifier's resolver).
func WithIssuerVerifier(iv IssuerVerifier) VerifierOption {
	return func(v *Verifier) {
		if iv != nil {
			v.issuers = iv
		}
	}
}

// NewDIDDocumentIssuers establishes issuers from DID documents resolved through
// r: the key is the issuer document's assertionMethod key that the proof's
// verificationMethod names, and the Owner is reached by walking the controller
// chain from the issuer's Process DID, every hop held to the
// registry-substitution defense (doc.ID == requested DID) and to structural
// ancestry. A definitive not-found (resolver.ErrNotFound), a key that does not
// extract, and a broken controller chain are ErrIssuerNotFound; a transient
// resolution failure or a substituted document is not.
func NewDIDDocumentIssuers(r resolver.Resolver) IssuerVerifier {
	return didDocumentIssuers{resolver: r}
}

type didDocumentIssuers struct {
	resolver resolver.Resolver
}

func (d didDocumentIssuers) IssuerKey(ctx context.Context, cred *Credential) (IssuerKey, error) {
	issuer := cred.Issuer()
	proof := cred.Proof()
	if proof == nil {
		return IssuerKey{}, fmt.Errorf("vc: %s: unsigned: %w", issuer, ErrIssuerNotFound)
	}
	doc, err := d.resolver.Resolve(ctx, issuer)
	switch {
	case errors.Is(err, resolver.ErrNotFound):
		return IssuerKey{}, fmt.Errorf("vc: %s: %w: %w", issuer, err, ErrIssuerNotFound)
	case err != nil:
		return IssuerKey{}, fmt.Errorf("vc: resolve %s: %w", issuer, err)
	}
	if doc.ID() != issuer {
		// Misconfiguration and attack are indistinguishable here: never
		// honoured, but not an established negative either.
		return IssuerKey{}, fmt.Errorf("vc: resolving %s returned the document of %s", issuer, doc.ID())
	}
	// Key and encoding come from one resolution: the encoding decides which
	// claim contract the proof is checked under, so reading it separately would
	// let the dispatch and the key disagree about which method they mean.
	pub, encoding, err := did.ExtractPublicKeyAndEncoding(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		return IssuerKey{}, fmt.Errorf("vc: %s: %w: %w", issuer, err, ErrIssuerNotFound)
	}
	return IssuerKey{ID: proof.VerificationMethod, PublicKey: pub, Encoding: encoding}, nil
}

func (d didDocumentIssuers) Owner(ctx context.Context, issuer string) (string, error) {
	owner, err := walkControllerChain(ctx, d.resolver, issuer)
	switch {
	case errors.Is(err, errControllerUnreachable):
		return "", err
	case err != nil:
		return "", fmt.Errorf("%w: %w", err, ErrIssuerNotFound)
	}
	return owner, nil
}

// ownerOf returns the Owner the Verifier's IssuerVerifier establishes for
// issuer, a Process DID, once it is checked to be the Owner the issuer's DID
// names (credential.field.issuer: the issuer's controller chain reaches the
// responsible Owner). It is the one place the three readers of the Owner —
// the chain-consistency axis, AttributeOwner and ClassifyChain — get it from.
// An issuer that is not a Process DID, and a foreign Owner, wrap
// ErrIssuerNotFound.
func (v *Verifier) ownerOf(ctx context.Context, issuer string) (string, error) {
	d, err := dplaax.Parse(issuer)
	if err != nil || !d.IsProcess() {
		return "", fmt.Errorf("vc: issuer %q is not a Process DID: %w", issuer, ErrIssuerNotFound)
	}
	owner, err := v.issuers.Owner(ctx, issuer)
	if err != nil {
		return "", err
	}
	if want := d.OwnerDID().String(); owner != want {
		return "", fmt.Errorf("vc: the Owner established for %q is %q, not %q, the one its DID names: %w", issuer, owner, want, ErrIssuerNotFound)
	}
	return owner, nil
}

// ownerState is the chain-consistency state of an ownerOf result.
func ownerState(err error) ConfidenceState {
	switch {
	case err == nil:
		return ConfidenceVerified
	case errors.Is(err, ErrIssuerNotFound):
		return ConfidenceFailed
	default:
		return ConfidenceIndeterminate
	}
}

// maxControllerDepth bounds the controller-chain walk. The dplaax hierarchy is
// Process → Pipeline → Owner (two hops); the bound is generous headroom, and a
// seen-set guards cycles independently.
const maxControllerDepth = 8

// Sentinel errors distinguishing the controller-walk outcomes: a resolution gap
// (may resolve later → indeterminate) from a structural inconsistency
// (established → failed).
var (
	errControllerUnreachable = errors.New("vc: controller document unavailable")
	errControllerBroken      = errors.New("vc: controller chain broken")
)

// walkControllerChain walks from a Process DID up to its terminal Owner DID
// using only DID Documents, verifying every hop: each resolved document is held
// to the registry-substitution defense (doc.ID == requested DID), each
// controller link must be a structural ancestor of the current DID, the owner
// must be self-controlled, and the walk is bounded with a cycle guard. It
// returns the reached Owner DID, or errControllerUnreachable / errControllerBroken.
// The two normative consumers — evalChainConsistency (a confidence verdict) and
// ClassifyChain (the terminal owner) — share this one walk.
//
// The depth bound and cycle guard are defence-in-depth: isStructuralAncestor
// forces each hop to a strictly shorter resource path (Process len 4 → Pipeline
// len 2 / Owner len 0 → Owner terminal), so the walk is already bounded at two
// hops and cannot revisit a DID through the public API. The guards exist so a
// future relaxation of that invariant fails safe rather than looping.
func walkControllerChain(ctx context.Context, r resolver.Resolver, start string) (string, error) {
	if d0, err := dplaax.Parse(start); err != nil || !d0.IsProcess() {
		return "", errControllerBroken
	}
	cur := start
	seen := map[string]bool{}
	for depth := 0; depth <= maxControllerDepth; depth++ {
		if seen[cur] {
			return "", errControllerBroken // cycle
		}
		seen[cur] = true
		d, err := dplaax.Parse(cur)
		if err != nil {
			return "", errControllerBroken
		}
		doc, err := r.Resolve(ctx, cur)
		switch {
		case errors.Is(err, resolver.ErrNotFound):
			return "", errControllerBroken // the controller target definitively does not exist — broken link
		case err != nil:
			return "", errControllerUnreachable // transient: the document may resolve later
		}
		if doc.ID() != cur {
			// Registry-substitution defense: never honour the substituted document.
			// Misconfiguration and attack are indistinguishable here, so treat the
			// hop as unresolved (indeterminate) rather than an established break.
			return "", errControllerUnreachable
		}
		ctrl := doc.Controller()
		if d.IsOwner() {
			if ctrl != "" && ctrl != cur {
				return "", errControllerBroken // owner must be self-controlled
			}
			return cur, nil
		}
		if ctrl == "" {
			return "", errControllerBroken // a non-owner with no controller cannot reach an owner
		}
		parent, err := dplaax.Parse(ctrl)
		if err != nil || !isStructuralAncestor(parent, d) {
			return "", errControllerBroken
		}
		cur = ctrl
	}
	return "", errControllerBroken // exceeded the depth bound without reaching the owner
}

// isStructuralAncestor reports whether anc is a proper structural ancestor of
// d: same owner triple (registry / accountType / accountId), a strictly
// shorter resource path that prefixes d's, and itself a known DID pattern.
func isStructuralAncestor(anc, d *dplaax.DID) bool {
	if anc.Registry != d.Registry || anc.AccountType != d.AccountType || anc.AccountID != d.AccountID {
		return false
	}
	if len(anc.ResourcePath) >= len(d.ResourcePath) {
		return false
	}
	for i, seg := range anc.ResourcePath {
		if d.ResourcePath[i] != seg {
			return false
		}
	}
	return anc.IsOwner() || anc.IsPipeline() || anc.IsProcess()
}
