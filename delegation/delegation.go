// Package delegation implements the owner-signed DelegationCredential:
// an Owner DID's assertion that a Pipeline or Process DID acts under its
// authority, with explicit scopes. Proof mechanics are reused from
// vc; this package owns only the delegation-specific shape and
// rules.
package delegation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
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
	// Scope lists the delegated authorities (e.g. "pipeline:operate",
	// "process:sign").
	Scope []string `json:"scope"`
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

// Verify checks the delegation: delegatedBy == issuer, the issuer is an Owner
// DID, the proof's verificationMethod names the issuer, the issuer's DID
// Document resolves (with the registry-substitution defense), and the proof
// verifies under the owner's assertion key over the signed body.
func Verify(ctx context.Context, verifier crypto.Verifier, r resolver.Resolver, cred *DelegationCredential) error {
	if cred == nil {
		return errors.New("delegation: nil credential")
	}
	if cred.Proof == nil {
		return errors.New("delegation: unsigned credential")
	}
	// Proof-policy obligations (vc.VerifyProof checks none of these): the proof
	// must be a DataIntegrityProof for assertionMethod, and the cryptosuite is
	// constrained to the one delegation emits — no suite downgrade.
	if cred.Proof.Type != proofType || cred.Proof.ProofPurpose != proofPurpose {
		return fmt.Errorf("delegation: proof type/purpose %q/%q not %q/%q", cred.Proof.Type, cred.Proof.ProofPurpose, proofType, proofPurpose)
	}
	if cred.Proof.Cryptosuite != vc.CryptosuiteEdDSAJCS2022 {
		return fmt.Errorf("delegation: unsupported cryptosuite %q (want %q)", cred.Proof.Cryptosuite, vc.CryptosuiteEdDSAJCS2022)
	}
	if _, err := time.Parse(time.RFC3339, cred.Proof.Created); err != nil {
		return fmt.Errorf("delegation: proof.created is not RFC3339: %w", err)
	}
	// VC type must carry both the base and the profile token.
	if !contains(cred.Type, "VerifiableCredential") || !contains(cred.Type, delegationType) {
		return fmt.Errorf("delegation: type %v missing VerifiableCredential / %s", cred.Type, delegationType)
	}
	if cred.CredentialSubject.DelegatedBy != cred.Issuer {
		return fmt.Errorf("delegation: delegatedBy %q != issuer %q", cred.CredentialSubject.DelegatedBy, cred.Issuer)
	}
	// Delegations are owner-signed: the issuer MUST be a deployment-valid Owner DID.
	issuer, err := dplaax.Parse(cred.Issuer)
	if err != nil {
		return fmt.Errorf("delegation: issuer is not a did:dplaax identifier: %w", err)
	}
	if err := dplaax.ValidateDID(issuer); err != nil {
		return fmt.Errorf("delegation: issuer: %w", err)
	}
	if err := dplaax.RequireOwner(issuer); err != nil {
		return fmt.Errorf("delegation: %w", err)
	}
	// Authority scoping: the delegated subject MUST be a Pipeline or Process DID
	// under the issuing owner — an owner cannot delegate authority over another
	// owner's identities.
	subj, err := dplaax.Parse(cred.CredentialSubject.ID)
	if err != nil {
		return fmt.Errorf("delegation: subject id is not a did:dplaax identifier: %w", err)
	}
	if !subj.IsPipeline() && !subj.IsProcess() {
		return fmt.Errorf("delegation: subject %q is neither a pipeline nor a process DID", cred.CredentialSubject.ID)
	}
	if subj.OwnerDID().String() != cred.Issuer {
		return fmt.Errorf("delegation: subject %q is not under the issuing owner %q", cred.CredentialSubject.ID, cred.Issuer)
	}
	// The verificationMethod MUST name the issuer.
	vmDID, _, found := strings.Cut(cred.Proof.VerificationMethod, "#")
	if !found || vmDID != cred.Issuer {
		return fmt.Errorf("delegation: verificationMethod %q does not name the issuer %q", cred.Proof.VerificationMethod, cred.Issuer)
	}
	doc, err := r.Resolve(ctx, cred.Issuer)
	if err != nil {
		return fmt.Errorf("delegation: resolve issuer: %w", err)
	}
	if doc.ID != cred.Issuer {
		return fmt.Errorf("delegation: resolved document id %q != issuer %q (registry-substitution defense)", doc.ID, cred.Issuer)
	}
	pub, err := did.ExtractPublicKey(doc, cred.Proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		return fmt.Errorf("delegation: extract owner key: %w", err)
	}
	if err := vc.VerifyProof(verifier, pub, cred.Proof, cred.signingBody()); err != nil {
		return fmt.Errorf("delegation: %w", err)
	}
	return nil
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
// "+00:00" zone, a null vs an empty scope array — hash the same even though the
// wire bytes differ. That is instant- and authority-preserving (an attacker
// cannot change a non-empty subject or scope without breaking the signature),
// and delegation credentials are not content-addressed, so byte-exact wire
// reproduction is not required here. A future field on DelegationSubject MUST be
// added to this map or it travels unsigned; if the shape grows, move to a
// body-as-source-of-truth model like vc.PipelinePassCredential.
func (c *DelegationCredential) signingBody() map[string]any {
	return map[string]any{
		"@context":  toAnySlice(c.Context),
		"type":      toAnySlice(c.Type),
		"issuer":    c.Issuer,
		"validFrom": c.ValidFrom.UTC().Format(time.RFC3339Nano),
		"credentialSubject": map[string]any{
			"id":          c.CredentialSubject.ID,
			"delegatedBy": c.CredentialSubject.DelegatedBy,
			"scope":       toAnySlice(c.CredentialSubject.Scope),
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
