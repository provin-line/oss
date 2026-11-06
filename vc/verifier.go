package vc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/resolver"
)

// allowedProofMembers is the exact wire member set of a provin DataIntegrityProof.
// Any other member is not covered by the signature and so is rejected at
// verification (proof-malleability defense).
var allowedProofMembers = map[string]bool{
	// @context is the W3C shape's proof-local context (vc-di-eddsa §3.3.1
	// step 2). It is admissible because the proof config commits to it: unlike
	// an arbitrary extra member, it cannot be changed without breaking the
	// signature.
	"@context":           true,
	"type":               true,
	"cryptosuite":        true,
	"verificationMethod": true,
	"proofPurpose":       true,
	"created":            true,
	"proofValue":         true,
}

// AllowedProofMembers returns the exact wire member set a Data Integrity proof
// may carry. Every member in it is covered by the signature; anything else rides
// outside it and is rejected.
//
// It is exported because the proof shape is one contract with more than one
// reader — the credential verifier and the DID registry both police it — and a
// second, hand-maintained copy of the set drifts. When it drifts, one component
// accepts a proof another rejects, which reads as an authorization bug long
// before anyone suspects the list. The returned map is a copy: a caller
// tightening or loosening its own view must not silently redefine everyone's.
func AllowedProofMembers() map[string]bool {
	out := make(map[string]bool, len(allowedProofMembers))
	for k, v := range allowedProofMembers {
		out[k] = v
	}
	return out
}

// Verifier performs credential verification: wire-form checks, issuer
// establishment (an IssuerVerifier; by default DID documents), proof
// verification, and confidence evaluation.
type Verifier struct {
	issuers        IssuerVerifier
	sigVerifier    crypto.Verifier
	lifecycle      LifecycleRegistry
	schemaResolver SchemaResolver
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// NewVerifier returns a Verifier verifying signatures through sigVerifier and
// establishing issuers from DID documents resolved through r
// (NewDIDDocumentIssuers), unless WithIssuerVerifier replaces that; r is then
// unused and may be nil.
func NewVerifier(r resolver.Resolver, sigVerifier crypto.Verifier, opts ...VerifierOption) *Verifier {
	v := &Verifier{sigVerifier: sigVerifier, issuers: NewDIDDocumentIssuers(r)}
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
	// Notations carry advisory annotations on an otherwise-verified verdict —
	// e.g. a Deprecated cryptosuite, which the lifecycle rule accepts as
	// "verified with notation" (confidence.cryptosuite-lifecycle). Empty when
	// the verdict is unannotated. For a chain, the per-credential notations are
	// concatenated.
	Notations []string
	// SuiteContract names WHICH rules produced this verdict: the W3C suite or
	// the legacy int64-verbatim projection. One cryptosuite identifier covers
	// both, so "verified under eddsa-jcs-2022" is not an answer
	// (claims.suite.contract-id).
	//
	// It is a typed field rather than a Notation because it is not advisory: a
	// consumer deciding whether to accept an artifact needs it, and a headline
	// that compresses it away to a bare "Verified" is exactly what
	// claims.headline.suite-contract forbids. Notations are for exceptions;
	// this is for every verdict.
	//
	// Empty when signer authenticity did not reach proof verification. For a
	// chain, this is the contract of the head credential — the per-credential
	// contracts of a mixed chain are not collapsible into one, so a caller
	// needing them verifies per credential.
	SuiteContract SuiteContract
}

// Verify performs single-credential verification across the three normative
// axes: wire-form checks (@context, required fields, and the claim rules —
// ValidateTransformationClaim composes into this axis: grammar,
// bare-rejection, and grounding fail it, while unrecognized grounded
// claims pass open-world), the issuer's key from the IssuerVerifier (by
// default, DID resolution and public-key extraction), proof verification with
// cryptosuite lifecycle evaluation at proof.created, the issuer's Owner from
// the IssuerVerifier checked against the Owner its Process DID names (by
// default, controller-chain reconstruction to the terminal Owner DID), and
// weakest-link composition of the axis verdicts.
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
	var notations []string
	var contract SuiteContract
	axes := AxisResult{
		DataIntegrity:      v.evalDataIntegrity(ctx, cred),
		SignerAuthenticity: v.evalSignerAuthenticity(ctx, cred, &notations, &contract),
		ChainConsistency:   v.evalChainConsistency(ctx, cred),
	}
	return &VerifyResult{
		Overall:       EvaluateConfidence(axes),
		Axes:          axes,
		Notations:     notations,
		SuiteContract: contract,
	}, nil
}

// SignerAuthenticityResult is the signer-authenticity verdict on one
// credential, on its own.
type SignerAuthenticityResult struct {
	// State is the axis state.
	State ConfidenceState
	// SuiteContract names the rules the proof verified under. Issuer is the
	// issuer the verdict is about, and VerificationMethod the key, listed under
	// the issuer's assertionMethod, that made the proof. The three are set
	// exactly when the proof verified, and empty otherwise; State may then still
	// be indeterminate, when the cryptosuite lifecycle could not be read.
	SuiteContract      SuiteContract
	Issuer             string
	VerificationMethod string
	// Notations carry advisory annotations (e.g. a Deprecated cryptosuite).
	Notations []string
}

// VerifySignerAuthenticity evaluates the signer-authenticity axis alone, for a
// credential of any type: the proof policy, the issuer's key from the
// IssuerVerifier (by default the assertionMethod key of the issuer's DID
// document), the proof, and the cryptosuite lifecycle — the same evaluation,
// through the same implementation, as Verify's axis.
//
// Verified establishes that Issuer signed, with VerificationMethod, a document
// equivalent to this body under SuiteContract. Equivalent is not always
// identical:
//
//   - Under ContractW3CEdDSAJCS2022 the comparison is of RFC 8785 forms, in
//     which two JSON numbers beyond ±(2^53−1) can be alike
//     (canon.AdmitSafeNumbers refuses them at issuance; verification does
//     not). ContractLegacyProvinEdDSAJCSInt64 keeps integers verbatim, so they
//     are not alike there.
//   - Under ContractW3CEdDSARDFC2022 the signature covers the RDF dataset the
//     body expands to, not its JSON shape. Array order, duplicate entries, a
//     single value or a one-element array, "id" or "@id", an IRI string or an
//     object with that id, a compact or an expanded term, and a member whose
//     value is an empty array all verify alike.
//
// It checks nothing else: not the credential's type, wire form, content,
// validity period, status, or any chain it belongs to. A caller accepts only
// the contract its credential type is issued under — ContractW3CEdDSAJCS2022
// for a caller that reads fields by their JSON shape;
// ContractLegacyProvinEdDSAJCSInt64 names historical provin evidence and is
// issued into by nothing new — and only the key its type requires
// (VerificationMethod), and then checks the type, the fields and the validity
// on Body().
func (v *Verifier) VerifySignerAuthenticity(ctx context.Context, cred *Credential) (*SignerAuthenticityResult, error) {
	if cred == nil {
		return nil, errors.New("vc: nil credential")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res := v.signerAuthenticity(ctx, cred.Issuer(), cred.proof, cred.body)
	return &res, nil
}

// evalDataIntegrity evaluates the data-integrity axis for one credential: the
// wire-form verdict (via ValidateWireForm — the single implementation, so a
// standalone check and the axis can never drift) refined by the schema
// reference. The cross-credential binding (outputHash[n] == inputHash[n+1])
// refines this axis further in VerifyChain. A malformed credential is failed;
// a well-formed one is verified unless its schema reference resolves to a
// mismatch (failed) or cannot be checked (indeterminate) — see evalSchema.
func (v *Verifier) evalDataIntegrity(ctx context.Context, cred *PipelinePassCredential) ConfidenceState {
	if err := cred.ValidateWireForm(); err != nil {
		return ConfidenceFailed
	}
	subject, err := cred.Subject()
	if err != nil {
		return ConfidenceFailed // unreadable subject after a passing wire-form is a defect
	}
	return v.evalSchema(ctx, subject.Schema)
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
// string when present (a JSON null is equivalent to omission — a chain origin
// may carry either, credential.subject.previous-credential), and a source
// commitment (any of derived_from / source_root / source_root_canonical
// present) must carry all three with derived_from a string array and the
// roots strings.
func rawSubjectWellFormed(subject map[string]any) bool {
	if pc, present := subject[keyPreviousCredential]; present && pc != nil {
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

// evalSignerAuthenticity evaluates the signer-authenticity axis of a
// PipelinePassCredential through signerAuthenticity, the one implementation the
// type-agnostic VerifySignerAuthenticity shares.
func (v *Verifier) evalSignerAuthenticity(ctx context.Context, cred *PipelinePassCredential, notations *[]string, outContract *SuiteContract) ConfidenceState {
	r := v.signerAuthenticity(ctx, cred.Issuer(), cred.proof, cred.body)
	*notations = append(*notations, r.Notations...)
	*outContract = r.SuiteContract
	return r.State
}

// signerAuthenticity evaluates the signer-authenticity axis of a credential,
// given its issuer, its raw wire proof (nil when unsigned) and its body: the typed
// proof field policy, the FCoT obligations (extra-member rejection and
// verificationMethod-names-the-issuer), the issuer's key from the
// IssuerVerifier (which must be the key the verificationMethod names), the
// proof under the exact suite contract, and the cryptosuite lifecycle phase at
// proof.created. An IssuerVerifier error wrapping ErrIssuerNotFound is an
// established negative (failed); any other is transient (indeterminate — may
// resolve later). The default's taxonomy: see NewDIDDocumentIssuers.
//
// It reads nothing of the credential's type or content, so it applies to a
// credential of any type.
func (v *Verifier) signerAuthenticity(ctx context.Context, issuer string, rawProof, body map[string]any) SignerAuthenticityResult {
	failed := SignerAuthenticityResult{State: ConfidenceFailed}
	indeterminate := SignerAuthenticityResult{State: ConfidenceIndeterminate}
	proof := proofView(rawProof)
	if proof == nil {
		return failed // unsigned
	}
	if proof.Type != proofType || proof.ProofPurpose != proofPurposeSign {
		return failed
	}
	created, err := time.Parse(time.RFC3339, proof.Created)
	if err != nil {
		return failed
	}
	// FCoT: reject a proof carrying any member outside the typed six — extra
	// members ride outside the signature and would be malleable if trusted.
	for k := range rawProof {
		if !allowedProofMembers[k] {
			return failed
		}
	}
	// "@context": null is present-but-nil: after parsing it reads as absence,
	// which classifies as the legacy row — where the mirror check cannot pin
	// it. No contract accepts the shape (see DataIntegrityProof.UnmarshalJSON,
	// which closes the typed path the same way).
	if v, present := rawProof[keyContext]; present && v == nil {
		return failed
	}
	// FCoT: the verificationMethod MUST be an absolute issuer#fragment reference
	// naming the issuer; a bare DID, or a key fragment in another DID's document,
	// must not be honoured.
	vmDID, _, found := strings.Cut(proof.VerificationMethod, "#")
	if issuer == "" || !found || vmDID != issuer {
		return failed
	}
	// Cryptosuite lifecycle at proof.created (optional hardening layer; a nil
	// registry means no lifecycle gating — a registered, non-no-op suite is
	// acceptable, the registration gate alone applies). The phase is evaluated
	// BEFORE issuer resolution because it is resolver-independent: a transient
	// resolution failure must not downgrade an established Sunset/Unknown
	// failure to a retryable indeterminate (failed ⊏ indeterminate). The
	// registry's own lookup error stays indeterminate and is applied only after
	// the proof verifies, so a definitive signature failure still wins.
	var phase LifecyclePhase
	var phaseErr error
	if v.lifecycle != nil {
		phase, phaseErr = v.lifecycle.PhaseAt(ctx, proof.Cryptosuite, created)
		if phaseErr == nil && phase != PhaseActive && phase != PhaseDeprecated {
			return failed // Sunset / Unknown fail closed
		}
	}
	key, err := v.issuers.IssuerKey(ctx, &Credential{body: body, proof: rawProof})
	switch {
	case errors.Is(err, ErrIssuerNotFound):
		return failed // established: no such issuer, or no usable key under the verificationMethod
	case err != nil:
		return indeterminate // transient — may resolve later
	case key.ID != proof.VerificationMethod:
		return failed // a key of another method than the proof names is not the signer's
	}
	// Exact dispatch: the contract is resolved from the suite id, the proof
	// shape, and the key encoding, and the canonicalizer follows from the
	// contract. A proof whose shape matches no contract fails here rather than
	// being retried under the other canonicalizer to see if it happens to check
	// out (signer.suite.exact-dispatch).
	contract, err := VerifyProofWithContract(v.sigVerifier, key.PublicKey, key.Encoding, proof, deepCopyMap(body))
	if err != nil {
		return failed
	}
	// The contract reaches the caller as a typed field, not a notation: it
	// applies to every verdict, and Notations are for exceptions.
	res := SignerAuthenticityResult{
		State:              ConfidenceVerified,
		SuiteContract:      contract,
		Issuer:             issuer,
		VerificationMethod: proof.VerificationMethod,
	}
	if v.lifecycle != nil {
		if phaseErr != nil {
			res.State = ConfidenceIndeterminate
			return res
		}
		if phase == PhaseDeprecated {
			// acceptable, but the verdict carries an annotation.
			res.Notations = append(res.Notations,
				"signer-authenticity: cryptosuite "+proof.Cryptosuite+" is Deprecated (verified with notation)")
		}
	}
	return res
}

// evalChainConsistency establishes the Owner responsible for the issuer
// Process DID through ownerOf: the IssuerVerifier's Owner (by default, the
// controller chain reconstructed from DID documents), which must be the Owner
// the issuer's DID names. An established negative (ErrIssuerNotFound, a
// foreign Owner, an issuer that is not a Process DID) is failed; any other
// failure is indeterminate.
func (v *Verifier) evalChainConsistency(ctx context.Context, cred *PipelinePassCredential) ConfidenceState {
	_, err := v.ownerOf(ctx, cred.Issuer())
	return ownerState(err)
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

	// 1. Per-credential verification, folded by weakest link per axis; the
	// per-credential notations concatenate onto the chain verdict.
	acc := AxisResult{ConfidenceVerified, ConfidenceVerified, ConfidenceVerified}
	var notations []string
	var headContract SuiteContract
	for i, cred := range chain {
		r, err := v.Verify(ctx, cred)
		if err != nil {
			return nil, err
		}
		acc = glbAxes(acc, r.Axes)
		notations = append(notations, r.Notations...)
		if i == len(chain)-1 {
			// The chain verdict reports the HEAD credential's contract (the
			// field's documented meaning). A mixed chain's per-credential
			// contracts are not collapsible into one; a caller needing them
			// verifies per credential.
			headContract = r.SuiteContract
		}
	}

	// 2. Chain-structure checks contributing to DataIntegrity / ChainConsistency.
	// A deterministic malformation (un-hashable body, malformed subject) is a
	// FAILED verdict, not a Go error: the per-credential pass already recorded
	// the failure, and returning an error here would let a chain walker map a
	// definitive malformation to an indeterminate transport hole.
	di, cc := ConfidenceVerified, ConfidenceVerified
	if firstBrokenLink(chain) != nil {
		di = ConfidenceFailed // the links: no predecessor at origin, linkage, data flow, all-consumed
	}
	for n := 1; n < len(chain); n++ {
		if !createdMonotonic(chain[n-1], chain[n]) {
			cc = ConfidenceFailed // ordering
		}
	}
	acc = glbAxes(acc, AxisResult{
		DataIntegrity:      di,
		SignerAuthenticity: ConfidenceVerified,
		ChainConsistency:   cc,
	})
	return &VerifyResult{
		Overall:       EvaluateConfidence(acc),
		Axes:          acc,
		Notations:     notations,
		SuiteContract: headContract,
	}, nil
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
