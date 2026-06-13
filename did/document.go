package did

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// DIDDocument is the W3C DID Document model served by registries.
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Service            []ServiceEndpoint    `json:"service,omitempty"`
}

// VerificationMethod is a public key entry in a DID Document. Keys are
// expressed as JWK (type "JsonWebKey2020"); the PoC supports OKP/Ed25519.
type VerificationMethod struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Controller   string         `json:"controller"`
	PublicKeyJWK map[string]any `json:"publicKeyJwk,omitempty"`
}

// ServiceEndpoint is a service entry in a DID Document (e.g. #vc-resolver,
// #chain-manager).
type ServiceEndpoint struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// VerificationRelationship names the DID Document relationship a key must be
// listed under for a given use.
type VerificationRelationship string

const (
	// RelationshipAuthentication gates peer/connection authentication keys
	// (#auth-key).
	RelationshipAuthentication VerificationRelationship = "authentication"
	// RelationshipAssertionMethod gates credential-signing keys
	// (#signing-key).
	RelationshipAssertionMethod VerificationRelationship = "assertionMethod"
)

// ExtractPublicKey returns the raw public key bytes for keyID (absolute or
// fragment-relative reference) after checking that the verification method is
// listed under the required relationship and that its controller matches the
// document. This is the single extraction implementation in the repository —
// consumers must not maintain copies.
//
// The PoC supports OKP/Ed25519 JWKs only. The relationship and controller
// checks are security gates: a key not listed under the required relationship,
// or whose controller is not the document subject, is rejected (key-confusion
// and cross-document injection defense).
func ExtractPublicKey(doc *DIDDocument, keyID string, rel VerificationRelationship) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("did: nil document")
	}
	frag := fragmentOf(keyID)
	if frag == "" {
		return nil, fmt.Errorf("did: empty key reference")
	}

	// The key must be listed under the required relationship.
	var refs []string
	switch rel {
	case RelationshipAuthentication:
		refs = doc.Authentication
	case RelationshipAssertionMethod:
		refs = doc.AssertionMethod
	default:
		return nil, fmt.Errorf("did: unknown verification relationship %q", rel)
	}
	listed := false
	for _, r := range refs {
		if fragmentOf(r) == frag {
			listed = true
			break
		}
	}
	if !listed {
		return nil, fmt.Errorf("did: key %q is not listed under relationship %q", keyID, rel)
	}

	// Locate the verification method by fragment.
	var vm *VerificationMethod
	for i := range doc.VerificationMethod {
		if fragmentOf(doc.VerificationMethod[i].ID) == frag {
			vm = &doc.VerificationMethod[i]
			break
		}
	}
	if vm == nil {
		return nil, fmt.Errorf("did: no verification method for key %q", keyID)
	}

	// The verification method must be controlled by the document subject.
	if vm.Controller != doc.ID {
		return nil, fmt.Errorf("did: verification method controller %q != document %q", vm.Controller, doc.ID)
	}

	return decodeEd25519JWK(vm.PublicKeyJWK)
}

// fragmentOf returns the fragment of a key reference: the part after the last
// "#", or the whole string when there is no "#" (a bare fragment id).
func fragmentOf(ref string) string {
	if i := strings.LastIndex(ref, "#"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

// decodeEd25519JWK extracts the 32-byte Ed25519 public key from an OKP JWK.
func decodeEd25519JWK(jwk map[string]any) ([]byte, error) {
	if jwk == nil {
		return nil, fmt.Errorf("did: verification method has no publicKeyJwk")
	}
	if kty, _ := jwk["kty"].(string); kty != "OKP" {
		return nil, fmt.Errorf("did: unsupported JWK kty %q (want OKP)", jwk["kty"])
	}
	if crv, _ := jwk["crv"].(string); crv != "Ed25519" {
		return nil, fmt.Errorf("did: unsupported JWK crv %q (want Ed25519)", jwk["crv"])
	}
	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("did: JWK has no string x parameter")
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("did: JWK x is not valid base64url: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("did: Ed25519 public key length %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}
