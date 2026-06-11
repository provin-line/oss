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

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

// JSON-LD context IRIs embedded in every credential issued by New/Builder.
// ContextDplaaxVCV1 is the dplaax protocol context (canonical document
// owned by the spec, vendored byte-exact here — see
// ContextDplaaxVCV1Document); a profile may append its own extension
// context for profile-owned custom subject fields. The poc.* tier
// explicitly permits pre-GA byte-level context evolution; at GA the URI
// promotes to https://dplaax.io/vc/v1 and freezes.
const (
	ContextCredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ContextDplaaxVCV1    = "https://poc.dplaax.io/vc/v1"
	// ContextProvinVCV1 is the provin profile context: grounds the "provin"
	// claim namespace prefix (credential.claim.grounding) and hosts
	// profile-owned custom subject field terms. poc tier — the provin-line.io
	// domain acquisition must be confirmed before external deployment.
	ContextProvinVCV1 = "https://poc.provin-line.io/vc/v1"
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

// TransformationClaim is the boundary's claim about the output's
// information source — the value of the wire field transformationClaim.
// The dPLaaX protocol pins only the grammar (a single <namespace>:<label>
// token; no bare values, no "+" joins) and the open-world default:
// verifiers MUST NOT draw closed-world inferences from claims they do not
// recognize. Claim semantics live with the profile.
//
// The constants below are the provin wire profile's claim registry. Each
// pins whether the claim is closed-world — the declared conformant inputs
// are the output's complete information source, so absence from the
// declared set licenses an exclusion inference — or acknowledges
// information beyond them. Claims do not bind chain topology:
// previousCredential presence follows the trigger rules alone, and the
// source commitment is orthogonal to both. (Deliberate divergence from
// Paper 01 §4.3's protocol-owned base vocabulary and "+" joins —
// composites are single profile labels.)
type TransformationClaim string

const (
	// ClaimFilter — closed: content-preserving selection of the input;
	// nothing was added or re-encoded.
	ClaimFilter TransformationClaim = "provin:filter"
	// ClaimConvert — closed: re-encoding of the input; the output's
	// information derives entirely from it.
	ClaimConvert TransformationClaim = "provin:convert"
	// ClaimFilterConvert — closed: selection and re-encoding composed (the
	// grammar has no "+" join; composites are single labels).
	ClaimFilterConvert TransformationClaim = "provin:filter-convert"
	// ClaimAggregate — closed fold: the output derives entirely from the
	// consumed conformant source set (committed via SourceCommitment under
	// the audit-reachable class).
	ClaimAggregate TransformationClaim = "provin:aggregate"
	// ClaimEnrich — conformant-closed: the output derives from the consumed
	// conformant inputs (committed when a SourceCommitment is emitted —
	// audit-reachable class) plus side-fetched external (non-conformant)
	// data joined in, so the output's information is NOT closed over the
	// conformant set; exclusion inferences hold for conformant flows only,
	// and accountability for the external data concentrates on the issuer.
	ClaimEnrich TransformationClaim = "provin:enrich"
	// ClaimGenerate — open: the dominant information source is the model's
	// weights (hence its training corpus); consumed materials are
	// conditioning only, so the output's information is NOT closed over the
	// declared set and no exclusion inference is licensed. Declaring a
	// synthesis as ClaimAggregate would falsely license the closed-world
	// reading — the N:1 shape is the same, the claim is not. When a
	// SourceCommitment is emitted it covers the full consumed conformant
	// set: the materials, plus the triggering predecessor when
	// chain-preserving; empty only when no conformant source was consumed
	// (text2img — RFC 6962 empty-string hash). Model identifier, weights
	// digest, prompt, and per-material roles are payload concerns pinned
	// via SchemaRef.
	ClaimGenerate TransformationClaim = "provin:generate"
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
	PipelineID          string
	ProcessID           string
	TransformationClaim TransformationClaim
	// Schema is the content-hashed reference to the registered output
	// schema.
	Schema SchemaRef
	// InputHash / OutputHash are sha256 hex digests of the raw input and
	// produced output. Adjacent chain links satisfy
	// outputHash[n] == inputHash[n+1]. InputHash is absent for aggregation
	// FirstDrops — no single input exists; input manifests are a payload
	// concern, and the cryptographic claim over the consumed source set,
	// when emitted, is the SourceCommitment.
	InputHash  string
	OutputHash string
}

// CredentialFields is the write-side input for unsigned construction (New).
// Signed construction goes through Builder, which owns chain and commitment
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
	// SourceCommitment is the optional audit commitment over the full
	// consumed conformant source set (audit-reachable conformance class).
	// Nil means no commitment. Orthogonal to PreviousCredential — chain
	// origins and chain-preserving credentials alike may carry it; on a
	// chain-preserving credential the committed set includes the
	// predecessor (all-consumed semantics). On the wire its fields
	// (derived_from, source_root, source_root_canonical) ride alongside
	// previousCredential inside credentialSubject, within the signing
	// scope.
	SourceCommitment *SourceCommitment
}

// Wire field names (credential body / credentialSubject). The
// source-commitment names are pinned by the dPLaaX specification.
const (
	keyContext             = "@context"
	keyType                = "type"
	keyIssuer              = "issuer"
	keyValidFrom           = "validFrom"
	keySubject             = "credentialSubject"
	keyProof               = "proof"
	keyPipelineID          = "pipelineId"
	keyProcessID           = "processId"
	keyTransformationClaim = "transformationClaim"
	keySchema              = "schema"
	keyInputHash           = "inputHash"
	keyOutputHash          = "outputHash"
	keyPreviousCredential  = "previousCredential"
	keyDerivedFrom         = "derived_from"
	keySourceRoot          = "source_root"
	keySourceRootCanon     = "source_root_canonical"
)

// New constructs an unsigned credential (tests / relay) and enforces the
// issue-path claim MUSTs: transformationClaim presence, token grammar,
// and namespace grounding (see ValidateTransformationClaim). Other
// verification-grade checks live in Verifier.
func New(fields CredentialFields) (*PipelinePassCredential, error) {
	subject := map[string]any{
		keyPipelineID:          fields.Subject.PipelineID,
		keyProcessID:           fields.Subject.ProcessID,
		keyTransformationClaim: string(fields.Subject.TransformationClaim),
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
	if fields.SourceCommitment != nil {
		// Normalize to the wire grammar: unique set, lexicographic ascending.
		set := make(map[string]bool, len(fields.SourceCommitment.DerivedFrom))
		for _, d := range fields.SourceCommitment.DerivedFrom {
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
		subject[keySourceRoot] = fields.SourceCommitment.SourceRoot
		subject[keySourceRootCanon] = fields.SourceCommitment.SourceRootCanonical
	}
	body := map[string]any{
		keyContext: []any{ContextCredentialsV2, ContextDplaaxVCV1, ContextProvinVCV1},
		keyType:    []any{"VerifiableCredential", "PipelinePassCredential"},
		keyIssuer:  fields.Issuer,
		// Wire granularity is whole seconds (RFC 3339): sub-second
		// precision is truncated at issuance, deliberately — proof.created
		// and validFrom comparisons must not depend on clock resolution.
		keyValidFrom: fields.ValidFrom.UTC().Format(time.RFC3339),
		keySubject:   subject,
	}
	cred := &PipelinePassCredential{body: body}
	// Issue-path enforcement: the issuer MUST emit a present, grammar-valid,
	// grounded claim (credential.subject.transformation-claim,
	// credential.claim.grammar, credential.claim.grounding).
	if err := cred.ValidateTransformationClaim(); err != nil {
		return nil, err
	}
	return cred, nil
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
		PipelineID:          getString(m, keyPipelineID),
		ProcessID:           getString(m, keyProcessID),
		TransformationClaim: TransformationClaim(getString(m, keyTransformationClaim)),
		InputHash:           getString(m, keyInputHash),
		OutputHash:          getString(m, keyOutputHash),
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
// SourceCommitment audit attribute.
func (c *PipelinePassCredential) PreviousCredential() string {
	m, ok := c.body[keySubject].(map[string]any)
	if !ok {
		return ""
	}
	return getString(m, keyPreviousCredential)
}

// SourceCommitment returns the source audit commitment (defensive copy);
// nil when the credential carries none — any credential issued outside the
// audit-reachable class.
func (c *PipelinePassCredential) SourceCommitment() *SourceCommitment {
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
	oc := &SourceCommitment{
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
