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
	// ProofValue is the base58btc ("z" multibase) encoded signature.
	ProofValue string `json:"proofValue"`
}

// CredentialSubjectFields is the write-side input for the credential subject.
type CredentialSubjectFields struct {
	PipelineID string
	// Payload is the event data. Numeric values must preserve precision
	// (json.Number) — see packages/canon.
	Payload map[string]any
	// Schema is the pinned schema reference "name:version" (required — no
	// "latest").
	Schema string
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
	// PreviousCredential is the hash of the predecessor VC; empty means this
	// credential is a FirstDrop (chain origin).
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

// PreviousCredential returns the predecessor hash link; empty for a
// FirstDrop.
func (c *PipelinePassCredential) PreviousCredential() string { panic("not implemented") }

// DerivedFrom returns the Origin Source's upstream Pipeline source DID set
// (defensive copy; empty for non-origin credentials).
func (c *PipelinePassCredential) DerivedFrom() []string { panic("not implemented") }

// SourceRoot returns the Merkle commitment over source VC wire bytes (empty
// for non-origin credentials).
func (c *PipelinePassCredential) SourceRoot() string { panic("not implemented") }

// SourceRootCanonical returns the name of the canonicalizer used for
// source_root leaves.
func (c *PipelinePassCredential) SourceRootCanonical() string { panic("not implemented") }

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
