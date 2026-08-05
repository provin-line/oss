// Package appraisal defines the pure domain model for an exact evidence view
// and a policy-relative decision over its scoped evidence vector.
//
// An EvidenceViewID names the inputs to an evaluation, not the truth of the
// payload and not a universally portable acceptance decision. The manifest
// fixes the selected credential variants and external snapshots. A Decision
// is derived separately under one local, versioned profile.
package appraisal

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
)

const CanonicalizerRFC8785 = "jcs-rfc8785"

var (
	contentAddressPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	wireVariantPattern    = regexp.MustCompile(`^wire:v1:jcs-rfc8785:sha256:[0-9a-f]{64}$`)
	versionedIDPattern    = regexp.MustCompile(`^.+@[0-9]+$`)
)

var (
	ErrInvalidManifest = errors.New("appraisal: invalid EvaluationViewManifest")
	ErrInvalidView     = errors.New("appraisal: invalid evidence view")
	ErrViewIDMismatch  = errors.New("appraisal: EvidenceViewID does not match manifest")
	ErrInvalidVector   = errors.New("appraisal: invalid scoped evidence vector")
	ErrInvalidProfile  = errors.New("appraisal: invalid decision profile")
)

// Coverage says whether a named scope was assessed.
type Coverage string

const (
	CoverageEvaluated    Coverage = "EVALUATED"
	CoverageNotEvaluated Coverage = "NOT_EVALUATED"
	CoverageUnsupported  Coverage = "UNSUPPORTED"
)

// TruthState is present only when Coverage is EVALUATED.
type TruthState string

const (
	TruthFailed        TruthState = "FAILED"
	TruthIndeterminate TruthState = "INDETERMINATE"
	TruthVerified      TruthState = "VERIFIED"
)

// Decision is local policy output and is deliberately separate from evidence.
type Decision string

const (
	DecisionAccept      Decision = "ACCEPT"
	DecisionQuarantine  Decision = "QUARANTINE"
	DecisionDeny        Decision = "DENY"
	DecisionDenyExpired Decision = "DENY_EXPIRED"
)

// SpineEntry fixes one selected signed wire variant in origin-to-head order.
type SpineEntry struct {
	BodyAddress   string `json:"bodyAddress"`
	WireVariantID string `json:"wireVariantId"`
}

// Manifest fixes all inputs on which an evaluation depends. Extensions are
// preserved and included in its identity because the dPLaaX schema is
// extensible; dropping an unknown member before hashing would rename a view.
type Manifest struct {
	Head                 string            `json:"head"`
	Spine                []SpineEntry      `json:"spine"`
	ClaimContractID      string            `json:"claimContractId"`
	CanonicalizerID      string            `json:"canonicalizerId"`
	CryptosuiteID        string            `json:"cryptosuiteId"`
	SchemaVersion        string            `json:"schemaVersion"`
	InputSnapshotDigests map[string]string `json:"inputSnapshotDigests"`
	Extensions           map[string]any    `json:"-"`
}

var manifestFields = map[string]bool{
	"head": true, "spine": true, "claimContractId": true,
	"canonicalizerId": true, "cryptosuiteId": true,
	"schemaVersion": true, "inputSnapshotDigests": true,
}

// UnmarshalJSON preserves extension members and rejects duplicate JSON keys.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := canon.NewStrictDecoder(data).Decode(&raw); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	// Decode intermediary only: these bytes feed json.Unmarshal for field
	// extraction and are never hashed or signed (canonicalizer-hygiene-exempt).
	known, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("%w: normalize: %v", ErrInvalidManifest, err)
	}
	type plain Manifest
	var decoded plain
	if err := json.Unmarshal(known, &decoded); err != nil {
		return fmt.Errorf("%w: fields: %v", ErrInvalidManifest, err)
	}
	decoded.Extensions = make(map[string]any)
	for key, value := range raw {
		if !manifestFields[key] {
			decoded.Extensions[key] = value
		}
	}
	*m = Manifest(decoded)
	return nil
}

// MarshalJSON retains extension members. Canonical identity uses CanonicalBytes.
func (m Manifest) MarshalJSON() ([]byte, error) {
	projection, err := m.projection()
	if err != nil {
		return nil, err
	}
	// Display/transport serialization; the identity digest hashes
	// CanonicalBytes, never these bytes (canonicalizer-hygiene-exempt).
	return json.Marshal(projection)
}

// CanonicalBytes returns the exact RFC 8785 projection hashed by ID.
func (m Manifest) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	projection, err := m.projection()
	if err != nil {
		return nil, err
	}
	return jcs.CanonicalizeRFC8785(projection)
}

// ID returns the content address of the canonical manifest.
func (m Manifest) ID() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	projection, err := m.projection()
	if err != nil {
		return "", err
	}
	return jcs.HashRFC8785(projection)
}

// Validate checks the manifest invariants needed for unambiguous identity.
func (m Manifest) Validate() error {
	if !contentAddressPattern.MatchString(m.Head) {
		return fmt.Errorf("%w: head is not a content address", ErrInvalidManifest)
	}
	if len(m.Spine) == 0 {
		return fmt.Errorf("%w: spine is empty", ErrInvalidManifest)
	}
	seen := make(map[string]bool, len(m.Spine))
	for i, entry := range m.Spine {
		if !contentAddressPattern.MatchString(entry.BodyAddress) {
			return fmt.Errorf("%w: spine[%d] body address", ErrInvalidManifest, i)
		}
		if !wireVariantPattern.MatchString(entry.WireVariantID) {
			return fmt.Errorf("%w: spine[%d] wire variant", ErrInvalidManifest, i)
		}
		if seen[entry.BodyAddress] {
			return fmt.Errorf("%w: repeated spine body %s", ErrInvalidManifest, entry.BodyAddress)
		}
		seen[entry.BodyAddress] = true
	}
	if m.Spine[len(m.Spine)-1].BodyAddress != m.Head {
		return fmt.Errorf("%w: final spine entry is not head", ErrInvalidManifest)
	}
	if !versionedIDPattern.MatchString(m.ClaimContractID) {
		return fmt.Errorf("%w: claim contract is not versioned", ErrInvalidManifest)
	}
	if strings.TrimSpace(m.CanonicalizerID) == "" {
		return fmt.Errorf("%w: canonicalizer id is empty", ErrInvalidManifest)
	}
	if !versionedIDPattern.MatchString(m.CryptosuiteID) {
		return fmt.Errorf("%w: cryptosuite id is not versioned", ErrInvalidManifest)
	}
	if strings.TrimSpace(m.SchemaVersion) == "" {
		return fmt.Errorf("%w: schema version is empty", ErrInvalidManifest)
	}
	if len(m.InputSnapshotDigests) == 0 {
		return fmt.Errorf("%w: no input snapshot digests", ErrInvalidManifest)
	}
	for name, digest := range m.InputSnapshotDigests {
		if strings.TrimSpace(name) == "" || !contentAddressPattern.MatchString(digest) {
			return fmt.Errorf("%w: invalid input snapshot %q", ErrInvalidManifest, name)
		}
	}
	for key := range m.Extensions {
		if manifestFields[key] {
			return fmt.Errorf("%w: extension collides with %q", ErrInvalidManifest, key)
		}
	}
	return nil
}

func (m Manifest) projection() (map[string]any, error) {
	out := map[string]any{
		"head":            m.Head,
		"claimContractId": m.ClaimContractID,
		"canonicalizerId": m.CanonicalizerID,
		"cryptosuiteId":   m.CryptosuiteID,
		"schemaVersion":   m.SchemaVersion,
	}
	spine := make([]any, len(m.Spine))
	for i, entry := range m.Spine {
		spine[i] = map[string]any{
			"bodyAddress":   entry.BodyAddress,
			"wireVariantId": entry.WireVariantID,
		}
	}
	out["spine"] = spine
	snapshots := make(map[string]any, len(m.InputSnapshotDigests))
	for key, value := range m.InputSnapshotDigests {
		snapshots[key] = value
	}
	out["inputSnapshotDigests"] = snapshots
	for key, value := range m.Extensions {
		if manifestFields[key] {
			return nil, fmt.Errorf("%w: extension collides with %q", ErrInvalidManifest, key)
		}
		out[key] = value
	}
	return out, nil
}

// ScopeEntry keeps coverage and evaluation truth as separate axes.
type ScopeEntry struct {
	Scope      string      `json:"scope"`
	Coverage   Coverage    `json:"coverage"`
	TruthState *TruthState `json:"truthState,omitempty"`
}

// PolicyDecision is a decision plus the exact local profile that derived it.
type PolicyDecision struct {
	Decision          Decision `json:"decision"`
	DecisionProfileID string   `json:"decisionProfileId"`
}

// View is the durable evidence artifact. PolicyDecision is optional because
// evidence can exist before or independently of a local policy evaluation.
type View struct {
	Manifest       Manifest        `json:"manifest"`
	EvidenceViewID string          `json:"evidenceViewId"`
	Vector         []ScopeEntry    `json:"vector"`
	PolicyDecision *PolicyDecision `json:"policyDecision,omitempty"`
}

// NewView validates the manifest and vector and derives the exact ID.
func NewView(manifest Manifest, vector []ScopeEntry) (*View, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateVector(vector); err != nil {
		return nil, err
	}
	id, err := manifest.ID()
	if err != nil {
		return nil, err
	}
	return &View{Manifest: manifest, EvidenceViewID: id, Vector: vector}, nil
}

// ValidateShape validates the manifest and coverage-vector relationship but
// deliberately does not compare the supplied EvidenceViewID. It is used where
// structural conformance and identity conformance are separate checks.
func (v View) ValidateShape() error {
	if err := v.Manifest.Validate(); err != nil {
		return err
	}
	if !contentAddressPattern.MatchString(v.EvidenceViewID) {
		return fmt.Errorf("%w: malformed EvidenceViewID", ErrInvalidView)
	}
	if err := ValidateVector(v.Vector); err != nil {
		return err
	}
	if v.PolicyDecision != nil {
		if !versionedIDPattern.MatchString(v.PolicyDecision.DecisionProfileID) {
			return fmt.Errorf("%w: decision profile is not versioned", ErrInvalidView)
		}
		switch v.PolicyDecision.Decision {
		case DecisionAccept, DecisionQuarantine, DecisionDeny, DecisionDenyExpired:
		default:
			return fmt.Errorf("%w: unknown decision %q", ErrInvalidView, v.PolicyDecision.Decision)
		}
	}
	return nil
}

// ValidateID proves that the supplied identity names this exact manifest.
func (v View) ValidateID() error {
	if err := v.ValidateShape(); err != nil {
		return err
	}
	want, err := v.Manifest.ID()
	if err != nil {
		return err
	}
	if v.EvidenceViewID != want {
		return fmt.Errorf("%w: got %s want %s", ErrViewIDMismatch, v.EvidenceViewID, want)
	}
	return nil
}

// ValidateVector enforces one result per scope and the coverage/truth shape.
func ValidateVector(vector []ScopeEntry) error {
	if len(vector) == 0 {
		return fmt.Errorf("%w: vector is empty", ErrInvalidVector)
	}
	seen := make(map[string]bool, len(vector))
	for i, entry := range vector {
		if !versionedIDPattern.MatchString(entry.Scope) || seen[entry.Scope] {
			return fmt.Errorf("%w: missing, unversioned, or duplicate scope at %d", ErrInvalidVector, i)
		}
		seen[entry.Scope] = true
		switch entry.Coverage {
		case CoverageEvaluated:
			if entry.TruthState == nil {
				return fmt.Errorf("%w: evaluated scope %s has no truth state", ErrInvalidVector, entry.Scope)
			}
			switch *entry.TruthState {
			case TruthFailed, TruthIndeterminate, TruthVerified:
			default:
				return fmt.Errorf("%w: scope %s has unknown truth state", ErrInvalidVector, entry.Scope)
			}
		case CoverageNotEvaluated, CoverageUnsupported:
			if entry.TruthState != nil {
				return fmt.Errorf("%w: unevaluated scope %s has truth state", ErrInvalidVector, entry.Scope)
			}
		default:
			return fmt.Errorf("%w: scope %s has unknown coverage", ErrInvalidVector, entry.Scope)
		}
	}
	return nil
}

// Profile is the complete local policy input used by Decide.
type Profile struct {
	ID             string   `json:"decisionProfileId"`
	RequiredScopes []string `json:"requiredScopes"`
}

// Decide applies the fail-closed mapping. FAILED has priority over retryable or
// missing evidence; every other non-VERIFIED required scope is quarantined.
func Decide(profile Profile, vector []ScopeEntry) (PolicyDecision, error) {
	if !versionedIDPattern.MatchString(profile.ID) || len(profile.RequiredScopes) == 0 {
		return PolicyDecision{}, ErrInvalidProfile
	}
	required := make(map[string]bool, len(profile.RequiredScopes))
	for _, scope := range profile.RequiredScopes {
		if !versionedIDPattern.MatchString(scope) || required[scope] {
			return PolicyDecision{}, fmt.Errorf("%w: missing, unversioned, or duplicate required scope", ErrInvalidProfile)
		}
		required[scope] = true
	}
	if err := ValidateVector(vector); err != nil {
		return PolicyDecision{}, err
	}
	byScope := make(map[string]ScopeEntry, len(vector))
	for _, entry := range vector {
		byScope[entry.Scope] = entry
	}

	quarantine := false
	for scope := range required {
		entry, ok := byScope[scope]
		if !ok || entry.Coverage != CoverageEvaluated || entry.TruthState == nil {
			quarantine = true
			continue
		}
		switch *entry.TruthState {
		case TruthFailed:
			return PolicyDecision{Decision: DecisionDeny, DecisionProfileID: profile.ID}, nil
		case TruthVerified:
			// continue
		case TruthIndeterminate:
			quarantine = true
		default:
			return PolicyDecision{}, ErrInvalidVector
		}
	}
	decision := DecisionAccept
	if quarantine {
		decision = DecisionQuarantine
	}
	return PolicyDecision{Decision: decision, DecisionProfileID: profile.ID}, nil
}
