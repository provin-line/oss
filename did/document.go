package did

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
func ExtractPublicKey(doc *DIDDocument, keyID string, rel VerificationRelationship) ([]byte, error) {
	panic("not implemented")
}
