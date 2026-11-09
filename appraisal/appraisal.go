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
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/internal/jsondepth"
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
// Extensions are its other members, preserved and included in the manifest's
// identity as Manifest.Extensions are: the dPLaaX schema admits members of a
// spine entry beyond its two fields. An extension may nest at most 9,997
// objects and arrays deep, as the manifest holds it three levels down and
// nests at most 10,000, as encoding/json decodes.
type SpineEntry struct {
	BodyAddress   string         `json:"bodyAddress"`
	WireVariantID string         `json:"wireVariantId"`
	Extensions    map[string]any `json:"-"`
}

var spineEntryFields = map[string]bool{"bodyAddress": true, "wireVariantId": true}

// UnmarshalJSON reads the entry as a manifest reads it: its two fields from
// their own names (one spelled in another case is refused), and every other
// member kept as an extension. Duplicate keys are refused. On an error the
// entry is left as it was.
func (e *SpineEntry) UnmarshalJSON(data []byte) error {
	var raw any
	if err := canon.NewStrictDecoder(data).Decode(&raw); err != nil {
		return fmt.Errorf("%w: spine entry: decode: %v", ErrInvalidManifest, err)
	}
	entry, err := readSpineEntry("spine entry", raw)
	if err != nil {
		return err
	}
	*e = entry
	return nil
}

// MarshalJSON writes the entry's two fields and its extensions.
func (e SpineEntry) MarshalJSON() ([]byte, error) {
	projection, err := e.projection("spine entry")
	if err != nil {
		return nil, err
	}
	// Display/transport serialization; the identity digest hashes the
	// manifest's CanonicalBytes, never these bytes (canonicalizer-hygiene-exempt).
	return json.Marshal(projection)
}

func (e SpineEntry) projection(where string) (map[string]any, error) {
	if err := validExtensions(where+" extension", e.Extensions, spineEntryFields, spineExtensionDepth); err != nil {
		return nil, err
	}
	out := map[string]any{
		"bodyAddress":   e.BodyAddress,
		"wireVariantId": e.WireVariantID,
	}
	for key, value := range e.Extensions {
		out[key] = value
	}
	return out, nil
}

// Manifest fixes all inputs on which an evaluation depends. Extensions are
// preserved and included in its identity because the dPLaaX schema is
// extensible; dropping an unknown member before hashing would rename a view.
// An extension may nest at most 9,999 objects and arrays deep, as the
// manifest holds it one level down and nests at most 10,000, as
// encoding/json decodes.
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

// UnmarshalJSON reads each member exactly as named: a known field from its
// own name (one spelled in another case is refused, not read as the field),
// a spine entry from exactly its two members, and every other top-level
// member kept as an extension, in the identity. So no member is read under
// another spelling, and none is dropped. Duplicate keys are refused.
func (m *Manifest) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := canon.NewStrictDecoder(data).Decode(&raw); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	if raw == nil {
		return fmt.Errorf("%w: null, want an object", ErrInvalidManifest)
	}
	out := Manifest{Extensions: map[string]any{}}
	for _, key := range slices.Sorted(maps.Keys(raw)) {
		value := raw[key]
		var err error
		switch key {
		case "head":
			out.Head, err = manifestString(key, value)
		case "claimContractId":
			out.ClaimContractID, err = manifestString(key, value)
		case "canonicalizerId":
			out.CanonicalizerID, err = manifestString(key, value)
		case "cryptosuiteId":
			out.CryptosuiteID, err = manifestString(key, value)
		case "schemaVersion":
			out.SchemaVersion, err = manifestString(key, value)
		case "spine":
			out.Spine, err = manifestSpine(value)
		case "inputSnapshotDigests":
			out.InputSnapshotDigests, err = manifestDigests(value)
		default:
			if name, ok := foldsTo(key, manifestFields); ok {
				return fmt.Errorf("%w: member %q is %q in another case", ErrInvalidManifest, key, name)
			}
			out.Extensions[key] = value
		}
		if err != nil {
			return err
		}
	}
	*m = out
	return nil
}

// foldsTo reports the field of fields that key equals only as encoding/json
// folds names (strings.EqualFold), if any: such a member is read as that field
// by a reader that folds names, so it cannot be an extension.
func foldsTo(key string, fields map[string]bool) (string, bool) {
	for name := range fields {
		if key != name && strings.EqualFold(key, name) {
			return name, true
		}
	}
	return "", false
}

func manifestString(key string, value any) (string, error) {
	s, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is %T, want a string", ErrInvalidManifest, key, value)
	}
	return s, nil
}

func manifestSpine(value any) ([]SpineEntry, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: spine is %T, want an array", ErrInvalidManifest, value)
	}
	spine := make([]SpineEntry, len(list))
	for i, item := range list {
		entry, err := readSpineEntry(fmt.Sprintf("spine[%d]", i), item)
		if err != nil {
			return nil, err
		}
		spine[i] = entry
	}
	return spine, nil
}

// readSpineEntry reads one decoded spine entry; where names it in errors.
func readSpineEntry(where string, value any) (SpineEntry, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return SpineEntry{}, fmt.Errorf("%w: %s is %T, want an object", ErrInvalidManifest, where, value)
	}
	entry := SpineEntry{Extensions: map[string]any{}}
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		v := obj[key]
		var err error
		switch key {
		case "bodyAddress":
			entry.BodyAddress, err = manifestString(where+".bodyAddress", v)
		case "wireVariantId":
			entry.WireVariantID, err = manifestString(where+".wireVariantId", v)
		default:
			if name, ok := foldsTo(key, spineEntryFields); ok {
				return SpineEntry{}, fmt.Errorf("%w: %s member %q is %q in another case", ErrInvalidManifest, where, key, name)
			}
			entry.Extensions[key] = v
		}
		if err != nil {
			return SpineEntry{}, err
		}
	}
	return entry, nil
}

func manifestDigests(value any) (map[string]string, error) {
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: inputSnapshotDigests is %T, want an object", ErrInvalidManifest, value)
	}
	digests := make(map[string]string, len(obj))
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		v := obj[key]
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w: inputSnapshotDigests[%q] is %T, want a string", ErrInvalidManifest, key, v)
		}
		digests[key] = s
	}
	return digests, nil
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

// Validate checks the manifest invariants needed for unambiguous identity. A
// number in an extension, at the top or in a spine entry, must be one
// canon.AdmitSafeNumbers admits before it is canonicalized, as on the other
// identity paths (canon.number.raw-token-guard).
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
		if err := validExtensions(fmt.Sprintf("spine[%d] extension", i), entry.Extensions, spineEntryFields, spineExtensionDepth); err != nil {
			return err
		}
		if err := canon.AdmitSafeNumbers(entry.Extensions); err != nil {
			return fmt.Errorf("%w: spine[%d] extension: %w", ErrInvalidManifest, i, err)
		}
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
	if err := validExtensions("extension", m.Extensions, manifestFields, manifestExtensionDepth); err != nil {
		return err
	}
	if err := canon.AdmitSafeNumbers(m.Extensions); err != nil {
		return fmt.Errorf("%w: extension: %w", ErrInvalidManifest, err)
	}
	return nil
}

// validExtensions refuses an extension that is one of fields, exactly or in
// another case (a reader would take it for that field), and one whose value
// is not a JSON value (jsonValue). Keys are checked in sorted order, so the
// refusal reported does not depend on map order.
func validExtensions(what string, extensions map[string]any, fields map[string]bool, depth int) error {
	for _, key := range slices.Sorted(maps.Keys(extensions)) {
		if fields[key] {
			return fmt.Errorf("%w: %s collides with %q", ErrInvalidManifest, what, key)
		}
		if name, ok := foldsTo(key, fields); ok {
			return fmt.Errorf("%w: %s %q is %q in another case", ErrInvalidManifest, what, key, name)
		}
		if err := jsonValue(extensions[key], depth); err != nil {
			return fmt.Errorf("%w: %s %q %v", ErrInvalidManifest, what, key, err)
		}
	}
	return nil
}

// jsonValue refuses a value that is neither one decoding JSON gives (nil,
// bool, string, json.Number, float64, []any, map[string]any) nor a Go integer.
// The JSON form of any other value reads back as another value (a float32 is
// widened when canonicalized but written short), so the identity would not be
// that of the document the manifest encodes to.
//
// v sits depth objects and arrays deep in the manifest's document
// (manifestExtensionDepth, spineExtensionDepth). An object or array deeper
// than jsondepth.Max is refused before the check enters it: it recurses once
// per level, and a goroutine stack exhausted is a fatal error. So the
// manifest's document nests at most jsondepth.Max deep, and what passes is
// canonicalized and encoded without a refusal.
func jsonValue(v any, depth int) error {
	switch t := v.(type) {
	case nil, bool, string, json.Number, float64,
		int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return nil
	case []any:
		if depth > jsondepth.Max {
			return errNestedTooDeep
		}
		for _, e := range t {
			if err := jsonValue(e, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if depth > jsondepth.Max {
			return errNestedTooDeep
		}
		for _, k := range slices.Sorted(maps.Keys(t)) {
			if err := jsonValue(t[k], depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("holds a %T, not a JSON value", v)
	}
}

// errNestedTooDeep refuses an extension that would nest the manifest past
// jsondepth.Max (jsonValue).
var errNestedTooDeep = fmt.Errorf("is nested deeper than %d objects and arrays, the manifest counted", jsondepth.Max)

// The depth at which an extension's value sits in the manifest's document: a
// manifest's is a member of the manifest; a spine entry's, a member of an
// entry of the manifest's spine. A spine entry encoded alone is held to the
// same, as it is a part of a manifest.
const (
	manifestExtensionDepth = 2
	spineExtensionDepth    = 4
)

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
		p, err := entry.projection(fmt.Sprintf("spine[%d]", i))
		if err != nil {
			return nil, err
		}
		spine[i] = p
	}
	out["spine"] = spine
	snapshots := make(map[string]any, len(m.InputSnapshotDigests))
	for key, value := range m.InputSnapshotDigests {
		snapshots[key] = value
	}
	out["inputSnapshotDigests"] = snapshots
	if err := validExtensions("extension", m.Extensions, manifestFields, manifestExtensionDepth); err != nil {
		return nil, err
	}
	for key, value := range m.Extensions {
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
