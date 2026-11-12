// Package delegation implements the owner-signed DelegationCredential:
// an Owner DID's assertion that a Pipeline or Process DID acts under its
// authority. Proof mechanics are reused from vc; this package owns only the
// delegation-specific shape and rules.
//
// The subject's pipeline is part of its DID under the did:dplaax structural
// hierarchy, so the credential carries no pipelineId; a catalog role is the
// delegated process's own type, declared in the credentials it issues, not
// granted here. The provin profile does not use a scope and Verify rejects any
// delegation that carries one fail-closed (spec rule delegation.scope keeps
// scope optional for other wire profiles; provin is a profile that opts out).
package delegation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/internal/excerpt"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/vc"
)

// Wire constants for the delegation profile. The credential reuses the dplaax
// VC contexts (structure + profile vocabulary); it grounds no claim namespace,
// so the provin claim context is not needed. The type token mirrors the
// PipelinePassCredential pattern ("VerifiableCredential" + the profile type).
const (
	delegationType = "DelegationCredential"
	// proofType / proofPurpose are the proof-policy values the verifier enforces
	// — vc.VerifyProof is a primitive that trusts a resolved key and does NOT
	// check these (see its contract), so the caller must. assertionMethod is the
	// only purpose a delegation accepts; a proof minted for another purpose by
	// the owner key must not pass as an assertion-grade delegation.
	proofType    = "DataIntegrityProof"
	proofPurpose = "assertionMethod"
)

// DelegationSubject asserts the delegation.
type DelegationSubject struct {
	// ID is the delegated DID (pipeline or process).
	ID string `json:"id"`
	// DelegatedBy is the owner DID; must equal the credential issuer.
	DelegatedBy string `json:"delegatedBy"`
	// Scope is NOT part of the provin signed body — provin does not use scope
	// (the protocol keeps it optional for other wire profiles, spec rule
	// delegation.scope). This field exists only so Verify can DETECT a scope on
	// inbound wire and reject it fail-closed: provin must not accept a credential
	// whose scope it cannot verify, lest a downstream scope-aware consumer treat
	// provin's acceptance as endorsement of an unsigned scope (authority laundering).
	Scope []string `json:"scope,omitempty"`
}

// DelegationCredential is the owner-signed delegation VC.
type DelegationCredential struct {
	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	ValidFrom         time.Time              `json:"validFrom"`
	CredentialSubject DelegationSubject      `json:"credentialSubject"`
	Proof             *vc.DataIntegrityProof `json:"proof,omitempty"`
}

// UnmarshalJSON reads c under canon.StrictDecoder's rules (duplicate keys,
// invalid Unicode, trailing data), so a delegation credential is read as
// strictly by encoding/json as by the registry that decodes it strictly.
//
// Members the document omits keep the values c had. On an error no member of
// c is assigned, though elements of a slice c already holds may have been
// overwritten. A struct that embeds DelegationCredential gets this method, so
// encoding/json hands it the whole object and does not decode the struct's
// own fields: such a struct needs its own UnmarshalJSON.
func (c *DelegationCredential) UnmarshalJSON(data []byte) error {
	type plain DelegationCredential
	v := plain(*c)
	if err := canon.NewStrictDecoder(data).Decode(&v); err != nil {
		return fmt.Errorf("delegation: decode: %w", err)
	}
	*c = DelegationCredential(v)
	return nil
}

// Build constructs and signs a delegation credential with the owner's key. The
// issuer is ownerDID; subject.DelegatedBy MUST equal it (the owner delegates on
// its own behalf). The proof is an eddsa-jcs-2022 Data Integrity proof over the
// owner's #signing assertion key — the same mechanics as a PipelinePassCredential.
func Build(signer crypto.Signer, ownerDID string, subject DelegationSubject) (*DelegationCredential, error) {
	if subject.DelegatedBy != ownerDID {
		return nil, fmt.Errorf("delegation: subject.DelegatedBy %q must equal the issuer %q", subject.DelegatedBy, ownerDID)
	}
	cred := &DelegationCredential{
		Context:           []string{vc.ContextCredentialsV2, vc.ContextDplaaxVCV1},
		Type:              []string{"VerifiableCredential", delegationType},
		Issuer:            ownerDID,
		ValidFrom:         time.Now().UTC().Truncate(time.Second),
		CredentialSubject: subject,
	}
	vm := ownerDID + "#" + string(keystore.KeyIDSigning)
	proof, err := vc.CreateProof(signer, ownerDID, string(keystore.KeyIDSigning), vm, cred.signingBody(), vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		return nil, fmt.Errorf("delegation: sign: %w", err)
	}
	cred.Proof = proof
	return cred, nil
}

// VerifyFor checks cred as authority for identity, the DID of the identity a
// consumer acts for: cred's credentialSubject.id is identity, byte for byte,
// and Verify accepts cred. A delegation is authority for the one identity it
// names, not for another under the same Owner nor for a Process under a
// delegated Pipeline (dplaax delegation.use.subject-bound). The identity is
// compared first, so a delegation presented for another identity resolves
// nothing; that refusal is ErrNotForIdentity, and any other is Verify's.
func VerifyFor(ctx context.Context, verifier crypto.Verifier, r resolver.Resolver, cred *DelegationCredential, identity string) error {
	if cred != nil && cred.CredentialSubject.ID != identity {
		return fmt.Errorf("%w: it names %s, not %s", ErrNotForIdentity, excerpt.Quoted(cred.CredentialSubject.ID, 128), excerpt.Quoted(identity, 128))
	}
	return Verify(ctx, verifier, r, cred)
}

// Verify checks the delegation: delegatedBy == issuer, the issuer is an Owner
// DID, the proof's verificationMethod names the issuer, the issuer's DID
// Document resolves (with the registry-substitution defense), and the proof
// verifies under the owner's assertion key over the signed body. It does not
// say for which identity the delegation is authority: a consumer acting for an
// identity calls VerifyFor.
//
// Verify attaches to each error it returns exactly one of ErrMalformed,
// ErrOwnerBinding, ErrProofPolicy, ErrScoped, ErrIssuerNotFound,
// ErrSignatureInvalid and ErrSignatureUnestablished (errors.Is): the one for
// the kind of check that failed. The error's text says which check that was.
// A delegation that fails several checks is refused for one of them; which
// one is not promised. ErrSignatureUnestablished is the one a caller may
// retry: the resolver gave no definite answer about the issuer.
//
// An error another package returned to a check stays reachable (errors.Is,
// errors.As): dplaax.ErrSyntax, a *time.ParseError, vc's error of the proof,
// and the error of the resolver and of the signature verifier given, as they
// return it. If such an error is a sentinel of this package under errors.Is
// (it is one, wraps one, or its Is method matches one), errors.Is finds that
// one too, beside the one Verify attaches.
func Verify(ctx context.Context, verifier crypto.Verifier, r resolver.Resolver, cred *DelegationCredential) error {
	if rf := verify(ctx, verifier, r, cred); rf != nil {
		return rf
	}
	return nil
}

// verify is Verify's checks: the refusal of the first one cred fails, or nil.
func verify(ctx context.Context, verifier crypto.Verifier, r resolver.Resolver, cred *DelegationCredential) *refusal {
	if cred == nil {
		return refuse(classMalformed, "delegation: nil credential", nil)
	}
	if cred.Proof == nil {
		return refuse(classMalformed, "delegation: unsigned credential", nil)
	}
	// Proof-policy obligations (vc.VerifyProof checks none of these): the proof
	// must be a DataIntegrityProof for assertionMethod, and the cryptosuite is
	// constrained to the one delegation emits — no suite downgrade.
	if cred.Proof.Type != proofType || cred.Proof.ProofPurpose != proofPurpose {
		return refuse(classProofPolicy, fmt.Sprintf("delegation: proof type/purpose %s/%s not %q/%q", excerpt.Quoted(cred.Proof.Type, 128), excerpt.Quoted(cred.Proof.ProofPurpose, 128), proofType, proofPurpose), nil)
	}
	if cred.Proof.Cryptosuite != vc.CryptosuiteEdDSAJCS2022 {
		return refuse(classProofPolicy, fmt.Sprintf("delegation: unsupported cryptosuite %s (want %q)", excerpt.Quoted(cred.Proof.Cryptosuite, 128), vc.CryptosuiteEdDSAJCS2022), nil)
	}
	if _, err := time.Parse(time.RFC3339, cred.Proof.Created); err != nil {
		return refuseWrapping(classProofPolicy, "delegation: proof.created "+excerpt.Quoted(cred.Proof.Created, 128)+" is not RFC3339", err)
	}
	// VC type must carry both the base and the profile token.
	if !contains(cred.Type, "VerifiableCredential") || !contains(cred.Type, delegationType) {
		return refuse(classMalformed, fmt.Sprintf("delegation: type %s missing VerifiableCredential / %s", excerpt.Quoted(strings.Join(cred.Type, ", "), 128), delegationType), nil)
	}
	// provin does not use scope and does not sign it. A scope on inbound wire is
	// rejected fail-closed: provin cannot verify it (it is outside the signed
	// body) and must not pass on an unverified scope to a scope-aware consumer.
	if cred.CredentialSubject.Scope != nil {
		return refuse(classScoped, fmt.Sprintf("delegation: credentialSubject.scope is present (%d token(s)); the provin profile does not accept scoped delegations", len(cred.CredentialSubject.Scope)), nil)
	}
	if cred.CredentialSubject.DelegatedBy != cred.Issuer {
		return refuse(classMalformed, fmt.Sprintf("delegation: delegatedBy %s != issuer %s", excerpt.Quoted(cred.CredentialSubject.DelegatedBy, 128), excerpt.Quoted(cred.Issuer, 128)), nil)
	}
	// Delegations are owner-signed: the issuer MUST be a deployment-valid Owner DID.
	issuer, err := dplaax.Parse(cred.Issuer)
	if err != nil {
		return refuse(unparsedMember(cred.Issuer), fmt.Sprintf("delegation: issuer is not a did:dplaax identifier: %v", err), err)
	}
	if err := dplaax.ValidateDID(issuer); err != nil {
		return refuse(classOwnerBinding, fmt.Sprintf("delegation: issuer: %v", err), err)
	}
	if err := dplaax.RequireOwner(issuer); err != nil {
		return refuse(classOwnerBinding, fmt.Sprintf("delegation: %v", err), err)
	}
	// Authority scoping: the delegated subject MUST be a Pipeline or Process DID
	// under the issuing owner — an owner cannot delegate authority over another
	// owner's identities.
	subj, err := dplaax.Parse(cred.CredentialSubject.ID)
	if err != nil {
		return refuse(unparsedMember(cred.CredentialSubject.ID), fmt.Sprintf("delegation: subject id is not a did:dplaax identifier: %v", err), err)
	}
	if !subj.IsPipeline() && !subj.IsProcess() {
		return refuse(classOwnerBinding, fmt.Sprintf("delegation: subject %s is neither a pipeline nor a process DID", excerpt.Quoted(cred.CredentialSubject.ID, 128)), nil)
	}
	if subj.OwnerDID().String() != cred.Issuer {
		return refuse(classOwnerBinding, fmt.Sprintf("delegation: subject %s is not under the issuing owner %s", excerpt.Quoted(cred.CredentialSubject.ID, 128), excerpt.Quoted(cred.Issuer, 128)), nil)
	}
	// The verificationMethod MUST name the issuer.
	vmDID, _, found := strings.Cut(cred.Proof.VerificationMethod, "#")
	if !found || vmDID != cred.Issuer {
		return refuse(classProofPolicy, fmt.Sprintf("delegation: verificationMethod %s does not name the issuer %s", excerpt.Quoted(cred.Proof.VerificationMethod, 128), excerpt.Quoted(cred.Issuer, 128)), nil)
	}
	// A proofValue that does not decode verifies under no key, so it is
	// refused before the issuer is resolved.
	if _, err := cred.Proof.ProofValueBytes(); err != nil {
		return refuseWrapping(classProofPolicy, "delegation", err)
	}
	doc, err := r.Resolve(ctx, cred.Issuer)
	if err != nil {
		// The text is taken once, before anything else is asked of err, so it
		// is the resolver's own whatever err's other methods do.
		text := excerpt.Wrap("delegation: resolve issuer", err, wrapLimit).Error()
		// Only resolver.ErrNotFound says the issuer has no document; any other
		// error says nothing definite about it.
		c := classSignatureUnestablished
		if errors.Is(err, resolver.ErrNotFound) {
			c = classIssuerNotFound
		}
		return refuse(c, text, err)
	}
	if doc == nil {
		return refuse(classSignatureUnestablished, "delegation: resolve issuer: no document and no error", nil)
	}
	if doc.ID() != cred.Issuer {
		// Misconfiguration and attack are indistinguishable here: never
		// honoured, and not an established negative either.
		return refuse(classSignatureUnestablished, fmt.Sprintf("delegation: resolved document id %s != issuer %s (registry-substitution defense)", excerpt.Quoted(doc.ID(), 128), excerpt.Quoted(cred.Issuer, 128)), nil)
	}
	// Key and encoding from one resolution: the encoding selects the claim
	// contract, and the contract selects the canonicalization.
	pub, encoding, err := did.ExtractPublicKeyAndEncoding(doc, cred.Proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		return refuseWrapping(classIssuerNotFound, "delegation: extract owner key", err)
	}
	// Exact dispatch (signer.suite.exact-dispatch): a delegation whose proof
	// shape matches no contract fails here rather than being retried under the
	// other canonicalizer to see which one accepts it.
	if _, err := vc.VerifyProofWithContract(verifier, pub, encoding, cred.Proof, cred.signingBody()); err != nil {
		return refuseWrapping(classSignatureInvalid, "delegation", err)
	}
	return nil
}

// unparsedMember is the class of an issuer or a subject id that does not
// parse as a did:dplaax identifier: an empty one is missing, which the shape
// refuses (dplaax delegation.shape); a present one names no identity the
// binding accepts (delegation.binding).
func unparsedMember(v string) class {
	if v == "" {
		return classMalformed
	}
	return classOwnerBinding
}

// signingBody renders the canonicalization input — the credential body without
// its proof — as a map. Build and Verify both derive the hashed bytes through
// this one helper, so the signed and reconstructed bytes are identical by
// construction. validFrom is formatted to whole-second RFC 3339 (matching the
// vc credential discipline) so the bytes do not depend on clock resolution.
//
// validFrom is formatted with RFC3339Nano (not RFC3339) so the hash commits to
// the FULL precision of the timestamp: Build truncates to whole seconds, so a
// genuine credential hashes "…00Z", while a wire credential tampered to a
// sub-second value ("…00.999Z") hashes differently and fails — the verified
// instant is exactly the signed instant, not a normalized one.
//
// ACCEPTED LIMITATION: this helper still RECONSTRUCTS the body from typed
// fields, so encodings that are semantically identical after parsing — a "Z" vs
// "+00:00" zone — hash the same even though the wire bytes differ. That is
// instant- and authority-preserving (an attacker cannot change the subject id
// or delegatedBy without breaking the signature), and delegation credentials
// are not content-addressed, so byte-exact wire reproduction is not required
// here. Any future field on DelegationSubject must be added to this map or it
// travels unsigned; if the shape grows, move to a body-as-source-of-truth model
// like vc.PipelinePassCredential.
func (c *DelegationCredential) signingBody() map[string]any {
	return map[string]any{
		"@context":  toAnySlice(c.Context),
		"type":      toAnySlice(c.Type),
		"issuer":    c.Issuer,
		"validFrom": c.ValidFrom.UTC().Format(time.RFC3339Nano),
		"credentialSubject": map[string]any{
			"id":          c.CredentialSubject.ID,
			"delegatedBy": c.CredentialSubject.DelegatedBy,
		},
	}
}

func toAnySlice(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
