// Package delegation implements the owner-signed DelegationCredential:
// an Owner DID's assertion that a Pipeline or Process DID acts under its
// authority, with explicit scopes. Proof mechanics are reused from
// packages/vc; this package owns only the delegation-specific shape and
// rules.
package delegation

import (
	"context"
	"time"

	"github.com/provin-line/oss/packages/crypto"
	"github.com/provin-line/oss/packages/resolver"
	"github.com/provin-line/oss/packages/vc"
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

// Build constructs and signs a delegation credential with the owner's key.
func Build(signer crypto.Signer, ownerDID string, subject DelegationSubject) (*DelegationCredential, error) {
	panic("not implemented")
}

// Verify checks delegatedBy == issuer, resolves the issuer DID, extracts the
// owner's assertion key, and verifies the proof.
func Verify(ctx context.Context, verifier crypto.Verifier, r resolver.Resolver, cred *DelegationCredential) error {
	panic("not implemented")
}
