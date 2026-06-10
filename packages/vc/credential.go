// Package vc implements W3C Verifiable Credentials with Data Integrity
// proofs: the credential model, proof creation/verification, cryptosuite
// dispatch, and trust evaluation for PipelinePassCredential — the VC issued
// at every pipeline process boundary.
package vc

import "time"

// PipelinePassCredential is the per-event provenance credential.
//
// Body-as-source-of-truth: the struct exposes no data fields. The canonical
// body map is the single source of truth for signing and hashing; accessors
// return defensive copies. Unknown signed-scope fields survive unmarshal →
// marshal round-trips so future vocabulary additions participate in hashes
// without code changes.
//
// Construction has exactly three paths: Builder (signed), New (unsigned;
// tests/relay), and UnmarshalJSON (verifier path).
type PipelinePassCredential struct {
	body  map[string]any
	proof *DataIntegrityProof
}

// DataIntegrityProof is the W3C Data Integrity proof. Proof fields are
// outside the signing scope of the document body (the proof configuration is
// hashed separately — see CreateProof).
type DataIntegrityProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	// Created is the RFC 3339 UTC signature creation time. Cryptosuite
	// lifecycle is evaluated at this instant — not at the credential's
	// validFrom.
	Created string `json:"created"`
	// ProofValue is the base58btc ("z" multibase) encoded signature.
	ProofValue string `json:"proofValue"`
}

// TransformationType declares the kind of transformation a process boundary
// performed (Paper 01 §4.3 vocabulary). Combinations are "+"-joined
// ("filter+convert"); wire profiles may add namespace-prefixed extensions
// ("provin:..."). The base vocabulary is provisional until the dPLaaX
// Layer 5 specification stabilizes.
type TransformationType string

const (
	TransformationFilter  TransformationType = "filter"
	TransformationConvert TransformationType = "convert"
	// TransformationAggregate marks a new derivation origin: the result has
	// no identity relationship with any single input, so previousCredential
	// is absent and a fresh chain begins (Paper 01 §4.8).
	TransformationAggregate TransformationType = "aggregate"
)

// SchemaRef is the content-hashed reference to the registered output schema.
// The content hash makes retroactive schema modification cryptographically
// detectable: a verifier resolves the schema from the registry and compares
// hashes; mismatch fails the data-integrity axis.
type SchemaRef struct {
	ID string
	// Type names the schema language (e.g. "JsonSchema").
	Type string
	// ContentHash is "sha256:<hex>" of the schema at issuance time.
	ContentHash string
}

// CredentialSubjectFields is the write-side input for the credential subject.
//
// The subject carries hashes, never the payload itself: integrity is proven
// without embedding data in the credential (Paper 01 §4.3). How payload
// bytes travel alongside credentials is a transport-composition concern,
// outside this package.
type CredentialSubjectFields struct {
	PipelineID         string
	ProcessID          string
	TransformationType TransformationType
	// Schema is the content-hashed reference to the registered output
	// schema.
	Schema SchemaRef
	// InputHash / OutputHash are sha256 hex digests of the raw input and
	// produced output. Adjacent chain links satisfy
	// outputHash[n] == inputHash[n+1].
	InputHash  string
	OutputHash string
}

// CredentialFields is the write-side input for unsigned construction (New).
// Signed construction goes through Builder, which owns chain and origin
// fields.
type CredentialFields struct {
	Issuer    string
	ValidFrom time.Time
	Subject   CredentialSubjectFields
	// PreviousCredential references the predecessor VC (content-commitment
	// hash baseline); empty means this credential is a chain origin
	// (FirstDrop). On the wire this field lives inside credentialSubject.
	// The chain is strictly linear: exactly zero or one predecessor, never
	// multiple (Paper 01 §4.8).
	PreviousCredential string
}

// New constructs an unsigned credential (tests / relay). It does not
// validate; verification-grade checks live in Verifier.
func New(fields CredentialFields) (*PipelinePassCredential, error) { panic("not implemented") }

// Issuer returns the issuer DID (a Process DID).
func (c *PipelinePassCredential) Issuer() string { panic("not implemented") }

// ValidFrom returns the issuance instant.
func (c *PipelinePassCredential) ValidFrom() (time.Time, error) { panic("not implemented") }

// Subject returns the credential subject fields (defensive copy).
func (c *PipelinePassCredential) Subject() (CredentialSubjectFields, error) { panic("not implemented") }

// PreviousCredential returns the predecessor reference; empty for a chain
// origin (FirstDrop). Upstream references beyond this single link are
// deliberately not part of the credential schema — recording which inputs
// fed an aggregation is a data-payload concern (Paper 01 §4.8).
func (c *PipelinePassCredential) PreviousCredential() string { panic("not implemented") }

// Proof returns the proof (defensive copy); nil when unsigned.
func (c *PipelinePassCredential) Proof() *DataIntegrityProof { panic("not implemented") }

// Body returns a defensive copy of the canonical body map (the signing
// scope, proof excluded).
func (c *PipelinePassCredential) Body() map[string]any { panic("not implemented") }

// Hash returns "sha256:<hex>" over the JCS-canonical body — the credential's
// content address used by previousCredential links and the VC resolver.
func (c *PipelinePassCredential) Hash() (string, error) { panic("not implemented") }

// MarshalJSON emits the wire form (body fields + proof).
func (c *PipelinePassCredential) MarshalJSON() ([]byte, error) { panic("not implemented") }

// UnmarshalJSON parses the wire form under strict-decoder rules, preserving
// unknown signed-scope fields in the body.
func (c *PipelinePassCredential) UnmarshalJSON(data []byte) error { panic("not implemented") }
