// Package vc implements W3C Verifiable Credentials with Data Integrity
// proofs: the credential model, proof creation/verification, cryptosuite
// dispatch, and trust evaluation for PipelinePassCredential — the VC issued
// at every pipeline process boundary.
package vc

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/provin-line/oss/packages/canon"
	"github.com/provin-line/oss/packages/canon/jcs"
)

// JSON-LD context IRIs embedded in every credential issued by New/Builder.
// The poc.* tier explicitly permits pre-GA byte-level context evolution;
// post-GA immutability is a spec-layer concern.
const (
	ContextCredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ContextDplaaxVCV1    = "https://poc.dplaax.io/vc/v1"
)

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
	body map[string]any
	// proof is stored as the raw wire map so unknown proof members survive
	// round-trips byte-faithfully — source-root leaves hash the VC as
	// received, so a lossy proof projection would corrupt audit
	// recomputation. The typed DataIntegrityProof is a read view (Proof()).
	proof map[string]any
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
	// TransformationEnrich is the provin wire-profile extension for
	// enrichment: a chain-preserving boundary that joins side-fetched
	// external data onto the triggering predecessor event.
	TransformationEnrich TransformationType = "provin:enrich"
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
	// outputHash[n] == inputHash[n+1]. InputHash is absent for aggregation
	// FirstDrops — no single input exists; input manifests are a payload
	// concern, and the cryptographic claim over the consumed source set,
	// when emitted, is the OriginCommitment.
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
	// PreviousCredential references the predecessor VC. The provin wire
	// profile adopts the content-commitment form exclusively
	// ("sha256:<hex>" over the predecessor's canonical body): long-horizon
	// audits and reproducibility need a byte-exact commitment, not a name
	// whose registry may be gone. Empty means this credential is a chain
	// origin (FirstDrop). On the wire this field lives inside
	// credentialSubject. The chain is strictly linear: exactly zero or one
	// predecessor, never multiple (Paper 01 §4.8).
	PreviousCredential string
	// Origin is the optional audit commitment of a chain origin
	// (audit-reachable conformance class). Nil means no commitment. Only
	// valid when PreviousCredential is empty — a chain-preserving credential
	// never carries one. On the wire its fields (derived_from, source_root,
	// source_root_canonical) ride alongside previousCredential inside
	// credentialSubject, within the signing scope.
	Origin *OriginCommitment
}

// Wire field names (credential body / credentialSubject). The origin
// commitment names are pinned by the dPLaaX Origin Source specification.
const (
	keyContext            = "@context"
	keyType               = "type"
	keyIssuer             = "issuer"
	keyValidFrom          = "validFrom"
	keySubject            = "credentialSubject"
	keyProof              = "proof"
	keyPipelineID         = "pipelineId"
	keyProcessID          = "processId"
	keyTransformationType = "transformationType"
	keySchema             = "schema"
	keyInputHash          = "inputHash"
	keyOutputHash         = "outputHash"
	keyPreviousCredential = "previousCredential"
	keyDerivedFrom        = "derived_from"
	keySourceRoot         = "source_root"
	keySourceRootCanon    = "source_root_canonical"
)

// New constructs an unsigned credential (tests / relay). It does not
// validate; verification-grade checks live in Verifier.
func New(fields CredentialFields) (*PipelinePassCredential, error) {
	subject := map[string]any{
		keyPipelineID:         fields.Subject.PipelineID,
		keyProcessID:          fields.Subject.ProcessID,
		keyTransformationType: string(fields.Subject.TransformationType),
	}
	if fields.Subject.Schema != (SchemaRef{}) {
		subject[keySchema] = map[string]any{
			"id":          fields.Subject.Schema.ID,
			"type":        fields.Subject.Schema.Type,
			"contentHash": fields.Subject.Schema.ContentHash,
		}
	}
	if fields.Subject.InputHash != "" {
		subject[keyInputHash] = fields.Subject.InputHash
	}
	if fields.Subject.OutputHash != "" {
		subject[keyOutputHash] = fields.Subject.OutputHash
	}
	if fields.PreviousCredential != "" {
		subject[keyPreviousCredential] = fields.PreviousCredential
	}
	if fields.Origin != nil {
		// Normalize to the wire grammar: unique set, lexicographic ascending.
		set := make(map[string]bool, len(fields.Origin.DerivedFrom))
		for _, d := range fields.Origin.DerivedFrom {
			set[d] = true
		}
		derived := make([]string, 0, len(set))
		for d := range set {
			derived = append(derived, d)
		}
		sort.Strings(derived)
		wire := make([]any, len(derived))
		for i, d := range derived {
			wire[i] = d
		}
		subject[keyDerivedFrom] = wire
		subject[keySourceRoot] = fields.Origin.SourceRoot
		subject[keySourceRootCanon] = fields.Origin.SourceRootCanonical
	}
	body := map[string]any{
		keyContext: []any{ContextCredentialsV2, ContextDplaaxVCV1},
		keyType:    []any{"VerifiableCredential", "PipelinePassCredential"},
		keyIssuer:  fields.Issuer,
		// Wire granularity is whole seconds (RFC 3339): sub-second
		// precision is truncated at issuance, deliberately — proof.created
		// and validFrom comparisons must not depend on clock resolution.
		keyValidFrom: fields.ValidFrom.UTC().Format(time.RFC3339),
		keySubject:   subject,
	}
	return &PipelinePassCredential{body: body}, nil
}

// Issuer returns the issuer DID (a Process DID).
func (c *PipelinePassCredential) Issuer() string {
	s, _ := c.body[keyIssuer].(string)
	return s
}

// ValidFrom returns the issuance instant.
func (c *PipelinePassCredential) ValidFrom() (time.Time, error) {
	s, ok := c.body[keyValidFrom].(string)
	if !ok {
		return time.Time{}, errors.New("vc: validFrom missing or not a string")
	}
	return time.Parse(time.RFC3339, s)
}

// Subject returns the credential subject fields (defensive copy).
func (c *PipelinePassCredential) Subject() (CredentialSubjectFields, error) {
	m, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return CredentialSubjectFields{}, errors.New("vc: credentialSubject missing or not an object")
	}
	subj := CredentialSubjectFields{
		PipelineID:         getString(m, keyPipelineID),
		ProcessID:          getString(m, keyProcessID),
		TransformationType: TransformationType(getString(m, keyTransformationType)),
		InputHash:          getString(m, keyInputHash),
		OutputHash:         getString(m, keyOutputHash),
	}
	if sm, ok := m[keySchema].(map[string]any); ok {
		subj.Schema = SchemaRef{
			ID:          getString(sm, "id"),
			Type:        getString(sm, "type"),
			ContentHash: getString(sm, "contentHash"),
		}
	}
	return subj, nil
}

// PreviousCredential returns the predecessor reference; empty for a chain
// origin (FirstDrop). The base credential schema carries no upstream
// references beyond this single link (Paper 01 §4.8 — chain topology stays
// linear); the only sanctioned exception is the optional, non-linking
// OriginCommitment audit attribute (see Origin).
func (c *PipelinePassCredential) PreviousCredential() string {
	m, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return ""
	}
	return getString(m, keyPreviousCredential)
}

// Origin returns the origin audit commitment (defensive copy); nil when the
// credential carries none — which is every chain-preserving credential and
// any FirstDrop issued outside the audit-reachable class.
func (c *PipelinePassCredential) Origin() *OriginCommitment {
	m, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return nil
	}
	_, hasDerived := m[keyDerivedFrom]
	_, hasRoot := m[keySourceRoot]
	_, hasCanon := m[keySourceRootCanon]
	if !hasDerived && !hasRoot && !hasCanon {
		return nil
	}
	oc := &OriginCommitment{
		SourceRoot:          getString(m, keySourceRoot),
		SourceRootCanonical: getString(m, keySourceRootCanon),
	}
	if list, ok := m[keyDerivedFrom].([]any); ok {
		oc.DerivedFrom = make([]string, 0, len(list))
		for _, e := range list {
			if s, ok := e.(string); ok {
				oc.DerivedFrom = append(oc.DerivedFrom, s)
			}
		}
	}
	return oc
}

// Proof returns the typed proof view (defensive copy); nil when unsigned.
// The view extracts the six Data Integrity members; unknown or non-string
// proof members are not visible here but survive round-trips in the raw
// proof map (see MarshalJSON).
func (c *PipelinePassCredential) Proof() *DataIntegrityProof {
	if c.proof == nil {
		return nil
	}
	return &DataIntegrityProof{
		Type:               getString(c.proof, "type"),
		Cryptosuite:        getString(c.proof, "cryptosuite"),
		VerificationMethod: getString(c.proof, "verificationMethod"),
		ProofPurpose:       getString(c.proof, "proofPurpose"),
		Created:            getString(c.proof, "created"),
		ProofValue:         getString(c.proof, "proofValue"),
	}
}

// Body returns a defensive copy of the canonical body map (the signing
// scope, proof excluded).
func (c *PipelinePassCredential) Body() map[string]any {
	return deepCopyMap(c.body)
}

// Hash returns "sha256:<hex>" over the JCS-canonical body — the credential's
// content address used by previousCredential links and the VC resolver.
func (c *PipelinePassCredential) Hash() (string, error) {
	return jcs.Hash(c.body)
}

// MarshalJSON emits the wire form (body fields + proof). The bytes are
// JCS-canonical — deterministic output keeps wire comparisons trivial.
func (c *PipelinePassCredential) MarshalJSON() ([]byte, error) {
	return jcs.Canonicalize(c.wireDocument())
}

// UnmarshalJSON parses the wire form under strict-decoder rules, preserving
// unknown signed-scope fields in the body.
func (c *PipelinePassCredential) UnmarshalJSON(data []byte) error {
	var doc map[string]any
	if err := canon.NewStrictDecoder(data).Decode(&doc); err != nil {
		return fmt.Errorf("vc: %w", err)
	}
	var proof map[string]any
	if raw, present := doc[keyProof]; present {
		pm, ok := raw.(map[string]any)
		if !ok {
			// Proof sets (arrays) and scalar proofs are not supported yet:
			// reject loudly rather than present a signed credential as
			// unsigned.
			return fmt.Errorf("vc: proof must be a JSON object, got %T", raw)
		}
		proof = pm
		delete(doc, keyProof)
	}
	c.body = doc
	c.proof = proof
	return nil
}

// wireDocument assembles the full wire-form map: body plus the raw proof.
// This is the value source-root leaves are computed over (the VC as
// received) — which is why the proof must round-trip byte-faithfully.
func (c *PipelinePassCredential) wireDocument() map[string]any {
	doc := deepCopyMap(c.body)
	if c.proof != nil {
		doc[keyProof] = deepCopyMap(c.proof)
	}
	return doc
}

func getString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func deepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return deepCopyMap(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopyValue(e)
		}
		return out
	default:
		// Scalars (string, json.Number, bool, nil) are immutable.
		return v
	}
}
