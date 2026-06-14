package vc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/resolver"
)

// maxControllerDepth bounds the controller-chain walk. The dplaax hierarchy is
// Process → Pipeline → Owner (two hops); the bound is generous headroom, and a
// seen-set guards cycles independently.
const maxControllerDepth = 8

// allowedProofMembers is the exact wire member set of a provin DataIntegrityProof.
// Any other member is not covered by the signature and so is rejected at
// verification (proof-malleability defense).
var allowedProofMembers = map[string]bool{
	"type":               true,
	"cryptosuite":        true,
	"verificationMethod": true,
	"proofPurpose":       true,
	"created":            true,
	"proofValue":         true,
}

// Verifier performs credential verification: wire-form checks, issuer DID
// resolution, proof verification, and confidence evaluation.
type Verifier struct {
	resolver    resolver.Resolver
	sigVerifier crypto.Verifier
	lifecycle   LifecycleRegistry
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
	if cred == nil {
		return nil, errors.New("vc: nil credential")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	axes := AxisResult{
		DataIntegrity:      v.evalDataIntegrity(cred),
		SignerAuthenticity: v.evalSignerAuthenticity(ctx, cred),
		ChainConsistency:   v.evalChainConsistency(ctx, cred),
	}
	return &VerifyResult{Overall: EvaluateConfidence(axes), Axes: axes}, nil
}

// evalDataIntegrity evaluates the data-integrity axis from this credential
// alone: @context/claim grammar and grounding, the required wire fields, and
// source-commitment shape well-formedness. The cross-credential binding
// (outputHash[n] == inputHash[n+1]) and schema content-hash resolution refine
// this axis in VerifyChain and the schema layer respectively; in isolation a
// well-formed credential is verified, a malformed one failed (no input is
// missing, so there is no indeterminate at this level).
func (v *Verifier) evalDataIntegrity(cred *PipelinePassCredential) ConfidenceState {
	if cred.Issuer() == "" {
		return ConfidenceFailed
	}
	if !hasRequiredVCTypes(cred) {
		return ConfidenceFailed // type MUST carry VerifiableCredential + PipelinePassCredential
	}
	if _, err := cred.ValidFrom(); err != nil {
		return ConfidenceFailed
	}
	rawSubject, ok := cred.body[keySubject].(map[string]any)
	if !ok {
		return ConfidenceFailed // credentialSubject must be an object
	}
	// Raw wire-shape validation BEFORE the typed accessors — the typed views are
	// lossy (they drop present-but-wrong-typed fields to zero values), so a
	// malformed field would otherwise read as "absent" and slip through.
	if !rawSubjectWellFormed(rawSubject) {
		return ConfidenceFailed
	}
	subj, err := cred.Subject()
	if err != nil {
		return ConfidenceFailed
	}
	if subj.PipelineID == "" || subj.ProcessID == "" || subj.OutputHash == "" {
		return ConfidenceFailed
	}
	// Claim rules (presence, grammar, grounding) and the @context array shape.
	if err := cred.ValidateTransformationClaim(); err != nil {
		return ConfidenceFailed
	}
	// Source-commitment value well-formedness — orthogonal to previousCredential,
	// so checked on any credential that carries the fields (raw type-shape was
	// validated above; this checks the sorted-unique set and multihash digest).
	if sc := cred.SourceCommitment(); sc != nil {
		if !isSortedUniqueSet(sc.DerivedFrom) || !isSourceRootMultihash(sc.SourceRoot) {
			return ConfidenceFailed
		}
	}
	return ConfidenceVerified
}

// Required VC type tokens — every PipelinePassCredential carries both.
const (
	vcTypeVerifiableCredential   = "VerifiableCredential"
	vcTypePipelinePassCredential = "PipelinePassCredential"
)

// hasRequiredVCTypes reports whether the credential's type array carries both
// the base VerifiableCredential and the PipelinePassCredential type tokens.
func hasRequiredVCTypes(cred *PipelinePassCredential) bool {
	types, ok := cred.body[keyType].([]any)
	if !ok {
		return false
	}
	var hasBase, hasPass bool
	for _, t := range types {
		switch t {
		case vcTypeVerifiableCredential:
			hasBase = true
		case vcTypePipelinePassCredential:
			hasPass = true
		}
	}
	return hasBase && hasPass
}

// rawSubjectWellFormed validates the wire types of the optional credentialSubject
// fields that the typed accessors collapse lossily: previousCredential must be a
// string when present, and a source commitment (any of derived_from /
// source_root / source_root_canonical present) must carry all three with
// derived_from a string array and the roots strings.
func rawSubjectWellFormed(subject map[string]any) bool {
	if pc, present := subject[keyPreviousCredential]; present {
		if _, ok := pc.(string); !ok {
			return false
		}
	}
	_, hasDerived := subject[keyDerivedFrom]
	_, hasRoot := subject[keySourceRoot]
	_, hasCanon := subject[keySourceRootCanon]
	if !hasDerived && !hasRoot && !hasCanon {
		return true // no commitment fields
	}
	derived, ok := subject[keyDerivedFrom].([]any)
	if !ok {
		return false // a partial or wrong-typed commitment is malformed
	}
	for _, e := range derived {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	if _, ok := subject[keySourceRoot].(string); !ok {
		return false
	}
	if _, ok := subject[keySourceRootCanon].(string); !ok {
		return false
	}
	return true
}

// evalSignerAuthenticity evaluates the signer-authenticity axis: the typed
// proof field policy, the FCoT obligations (extra-member rejection and
// verificationMethod-names-the-issuer), issuer DID resolution and assertion-key
// extraction, Ed25519 proof verification, and the cryptosuite lifecycle phase
// at proof.created. A resolver miss is treated as a definitive not-found
// (failed): the in-memory/registry resolvers have no transient class — a
// resolver that can time out must surface a typed transient error to yield
// indeterminate here.
func (v *Verifier) evalSignerAuthenticity(ctx context.Context, cred *PipelinePassCredential) ConfidenceState {
	proof := cred.Proof()
	if proof == nil {
		return ConfidenceFailed // unsigned
	}
	if proof.Type != proofType || proof.ProofPurpose != proofPurposeSign {
		return ConfidenceFailed
	}
	created, err := time.Parse(time.RFC3339, proof.Created)
	if err != nil {
		return ConfidenceFailed
	}
	// FCoT: reject a proof carrying any member outside the typed six — extra
	// members ride outside the signature and would be malleable if trusted.
	for k := range cred.proof {
		if !allowedProofMembers[k] {
			return ConfidenceFailed
		}
	}
	// FCoT: the verificationMethod MUST be an absolute issuer#fragment reference
	// naming the issuer; a bare DID, or a key fragment in another DID's document,
	// must not be honoured.
	issuer := cred.Issuer()
	vmDID, _, found := strings.Cut(proof.VerificationMethod, "#")
	if !found || vmDID != issuer {
		return ConfidenceFailed
	}
	doc, err := v.resolver.Resolve(ctx, issuer)
	if err != nil {
		return ConfidenceFailed // definitive not-found
	}
	if doc.ID != issuer {
		return ConfidenceFailed // registry-substitution defense on the signing path
	}
	pub, err := did.ExtractPublicKey(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		return ConfidenceFailed
	}
	if err := VerifyProof(v.sigVerifier, pub, proof, cred.Body()); err != nil {
		return ConfidenceFailed
	}
	// Cryptosuite lifecycle at proof.created (optional hardening layer; a nil
	// registry means no lifecycle gating — a registered, non-no-op suite is
	// acceptable, the registration gate alone applies).
	if v.lifecycle != nil {
		phase, err := v.lifecycle.PhaseAt(ctx, proof.Cryptosuite, created)
		if err != nil {
			return ConfidenceIndeterminate
		}
		switch phase {
		case PhaseActive, PhaseDeprecated:
			// acceptable — Deprecated will carry an annotation once VerifyResult
			// grows the channel; verified for now.
		default:
			return ConfidenceFailed // Sunset / Unknown fail closed
		}
	}
	return ConfidenceVerified
}

// evalChainConsistency reconstructs the controller chain from the issuer
// Process DID up to its terminal Owner DID using only DID Documents, verifying
// every hop. Each resolved document is held to the registry-substitution
// defense (doc.ID == requested DID); each controller link must be a structural
// ancestor of the current DID (moving strictly up toward the owner); the walk
// must terminate at the issuer's own owner, self-controlled. An unavailable
// intermediate document is indeterminate (may resolve later); a broken link, a
// foreign owner, or a cycle is failed.
func (v *Verifier) evalChainConsistency(ctx context.Context, cred *PipelinePassCredential) ConfidenceState {
	issuer, err := dplaax.Parse(cred.Issuer())
	if err != nil || !issuer.IsProcess() {
		return ConfidenceFailed
	}
	owner, err := v.walkControllerChain(ctx, cred.Issuer())
	switch {
	case errors.Is(err, errControllerUnreachable):
		return ConfidenceIndeterminate // an intermediate document may resolve later
	case err != nil:
		return ConfidenceFailed // broken link, foreign owner, or cycle
	}
	if owner != issuer.OwnerDID().String() {
		return ConfidenceFailed // terminated at an owner outside the issuer's lineage
	}
	return ConfidenceVerified
}

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
func (v *Verifier) walkControllerChain(ctx context.Context, start string) (string, error) {
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
		doc, err := v.resolver.Resolve(ctx, cur)
		if err != nil {
			return "", errControllerUnreachable // intermediate (or issuer) document unavailable
		}
		if doc.ID != cur {
			return "", errControllerBroken // registry-substitution defense
		}
		if d.IsOwner() {
			if doc.Controller != "" && doc.Controller != cur {
				return "", errControllerBroken // owner must be self-controlled
			}
			return cur, nil
		}
		if doc.Controller == "" {
			return "", errControllerBroken // a non-owner with no controller cannot reach an owner
		}
		parent, err := dplaax.Parse(doc.Controller)
		if err != nil || !isStructuralAncestor(parent, d) {
			return "", errControllerBroken
		}
		cur = doc.Controller
	}
	return "", errControllerBroken // exceeded the depth bound without reaching the owner
}

// VerifyChain verifies each credential individually (folding the per-credential
// axis verdicts by weakest link), then layers the chain-structure checks.
//
// The structure checks map onto the axes by their definitions: the data-flow
// invariant (outputHash[n] == inputHash[n+1]), previousCredential linkage, the
// no-predecessor-at-origin rule, and the all-consumed source-commitment
// consistency are input/output binding → DataIntegrity; proof.created
// monotonicity is ordering → ChainConsistency.
//
// chain MUST be in origin-first order (chain[0] is the origin, chain[len-1] the
// head) — the order chainwalk produces before delegating here.
func (v *Verifier) VerifyChain(ctx context.Context, chain []*PipelinePassCredential) (*VerifyResult, error) {
	if len(chain) == 0 {
		return nil, errors.New("vc: empty chain")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Per-credential verification, folded by weakest link per axis.
	acc := AxisResult{ConfidenceVerified, ConfidenceVerified, ConfidenceVerified}
	for _, cred := range chain {
		r, err := v.Verify(ctx, cred)
		if err != nil {
			return nil, err
		}
		acc = glbAxes(acc, r.Axes)
	}

	// 2. Chain-structure checks contributing to DataIntegrity / ChainConsistency.
	di, cc := ConfidenceVerified, ConfidenceVerified
	if chain[0].PreviousCredential() != "" {
		di = ConfidenceFailed // a chain origin must carry no previousCredential
	}
	for n := 1; n < len(chain); n++ {
		prev, cur := chain[n-1], chain[n]
		// A deterministic malformation (un-hashable body, malformed subject) is a
		// FAILED verdict, not a Go error: the per-credential pass already recorded
		// the failure, and returning an error here would let a chain walker map a
		// definitive malformation to an indeterminate transport hole.
		if !createdMonotonic(prev, cur) {
			cc = ConfidenceFailed // ordering
		}
		prevHash, err := prev.Hash()
		if err != nil {
			di = ConfidenceFailed
			continue
		}
		if cur.PreviousCredential() != prevHash {
			di = ConfidenceFailed // linkage: cur must reference prev's content address
		}
		ps, err := prev.Subject()
		if err != nil {
			di = ConfidenceFailed
			continue
		}
		cs, err := cur.Subject()
		if err != nil {
			di = ConfidenceFailed
			continue
		}
		if ps.OutputHash == "" || ps.OutputHash != cs.InputHash {
			di = ConfidenceFailed // data-flow invariant
		}
		if sc := cur.SourceCommitment(); sc != nil && !containsString(sc.DerivedFrom, prev.Issuer()) {
			di = ConfidenceFailed // all-consumed: commitment must include the predecessor's issuer
		}
	}
	acc = glbAxes(acc, AxisResult{
		DataIntegrity:      di,
		SignerAuthenticity: ConfidenceVerified,
		ChainConsistency:   cc,
	})
	return &VerifyResult{Overall: EvaluateConfidence(acc), Axes: acc}, nil
}

// glbAxes folds two axis results by the per-axis greatest lower bound.
func glbAxes(a, b AxisResult) AxisResult {
	return AxisResult{
		DataIntegrity:      minState(a.DataIntegrity, b.DataIntegrity),
		SignerAuthenticity: minState(a.SignerAuthenticity, b.SignerAuthenticity),
		ChainConsistency:   minState(a.ChainConsistency, b.ChainConsistency),
	}
}

func minState(x, y ConfidenceState) ConfidenceState {
	if x < y {
		return x
	}
	return y
}

// createdMonotonic reports whether cur's proof.created is at or after prev's. A
// missing or unparseable proof on either side is treated as non-monotonic
// (the signer-authenticity axis surfaces the unsigned/malformed proof
// separately).
func createdMonotonic(prev, cur *PipelinePassCredential) bool {
	pp, cp := prev.Proof(), cur.Proof()
	if pp == nil || cp == nil {
		return false
	}
	pt, err1 := time.Parse(time.RFC3339, pp.Created)
	ct, err2 := time.Parse(time.RFC3339, cp.Created)
	if err1 != nil || err2 != nil {
		return false
	}
	return !ct.Before(pt)
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
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

// isSortedUniqueSet reports whether s is strictly ascending (hence
// duplicate-free) — the derived_from wire grammar.
func isSortedUniqueSet(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

// isSourceRootMultihash reports whether s is the multibase-hex ("f") multihash
// form of a sha2-256 digest — "f1220" (multibase 'f' + multihash code 0x12,
// length 0x20) followed by 64 lowercase hex characters, the only form emitters
// produce (see ComputeSourceRoot).
func isSourceRootMultihash(s string) bool {
	const prefix = "f1220"
	const hexLen = 64 // sha2-256 is 32 bytes
	if len(s) != len(prefix)+hexLen || s[:len(prefix)] != prefix {
		return false
	}
	for _, r := range s[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
