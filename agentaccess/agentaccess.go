// Package agentaccess defines the profile-level artifacts for successful,
// evidence-qualified AI Agent delivery and for declaring the evaluated access
// paths of a deployment. It contains no transport or pipeline dependencies.
package agentaccess

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/provin-line/oss/appraisal"
)

const LocalAuthority = "LOCAL"

var (
	ErrInvalidDelivery   = errors.New("agentaccess: invalid delivery")
	ErrInvalidDeployment = errors.New("agentaccess: invalid deployment path declaration")
	contentAddress       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionedID          = regexp.MustCompile(`^.+@[0-9]+$`)
)

// ValidateBoundaryID lets a composition root fail closed at boot instead of
// discovering a malformed delivery-boundary identity on the first event.
func ValidateBoundaryID(id string) error {
	if !versionedID.MatchString(id) {
		return fmt.Errorf("%w: boundary id is not versioned", ErrInvalidDelivery)
	}
	return nil
}

// AppraisalRef fixes the accepted local decision used for this delivery.
type AppraisalRef struct {
	Authority         string             `json:"authority"`
	EvidenceViewID    string             `json:"evidenceViewId"`
	Decision          appraisal.Decision `json:"decision"`
	DecisionProfileID string             `json:"decisionProfileId"`
}

// DeliveryRecord is emitted only after a successful Agent writer call. It
// binds the actual payload bytes to the head credential and accepted view.
type DeliveryRecord struct {
	BoundaryID     string       `json:"boundaryId"`
	PayloadDigest  string       `json:"payloadDigest"`
	HeadOutputHash string       `json:"headOutputHash"`
	EvidenceViewID string       `json:"evidenceViewId"`
	Appraisal      AppraisalRef `json:"appraisal"`
}

// NewDelivery constructs and validates the successful-delivery artifact.
func NewDelivery(boundaryID string, payload []byte, headOutputHash string, view *appraisal.View) (*DeliveryRecord, error) {
	if view == nil || view.PolicyDecision == nil {
		return nil, fmt.Errorf("%w: local appraisal is missing", ErrInvalidDelivery)
	}
	if err := view.ValidateID(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDelivery, err)
	}
	record := &DeliveryRecord{
		BoundaryID:     boundaryID,
		PayloadDigest:  hashBytes(payload),
		HeadOutputHash: headOutputHash,
		EvidenceViewID: view.EvidenceViewID,
		Appraisal: AppraisalRef{
			Authority:         LocalAuthority,
			EvidenceViewID:    view.EvidenceViewID,
			Decision:          view.PolicyDecision.Decision,
			DecisionProfileID: view.PolicyDecision.DecisionProfileID,
		},
	}
	if err := record.Validate(payload); err != nil {
		return nil, err
	}
	return record, nil
}

// Validate enforces the cross-field exact-occurrence relationship.
func (r DeliveryRecord) Validate(payload []byte) error {
	if err := ValidateBoundaryID(r.BoundaryID); err != nil {
		return err
	}
	actual := hashBytes(payload)
	if !contentAddress.MatchString(r.PayloadDigest) || r.PayloadDigest != actual {
		return fmt.Errorf("%w: payload digest mismatch", ErrInvalidDelivery)
	}
	if !contentAddress.MatchString(r.HeadOutputHash) || r.HeadOutputHash != actual {
		return fmt.Errorf("%w: head output hash mismatch", ErrInvalidDelivery)
	}
	if !contentAddress.MatchString(r.EvidenceViewID) || r.Appraisal.EvidenceViewID != r.EvidenceViewID {
		return fmt.Errorf("%w: appraisal view mismatch", ErrInvalidDelivery)
	}
	if r.Appraisal.Authority != LocalAuthority {
		return fmt.Errorf("%w: appraisal is not local", ErrInvalidDelivery)
	}
	if r.Appraisal.Decision != appraisal.DecisionAccept {
		return fmt.Errorf("%w: decision is %s", ErrInvalidDelivery, r.Appraisal.Decision)
	}
	if !versionedID.MatchString(r.Appraisal.DecisionProfileID) {
		return fmt.Errorf("%w: decision profile is not versioned", ErrInvalidDelivery)
	}
	return nil
}

// PathState declares whether a potential Agent-readable path is configured.
type PathState string

const (
	PathEnabled  PathState = "ENABLED"
	PathDisabled PathState = "DISABLED"
)

// Path is one declared potential data path.
type Path struct {
	ID         string    `json:"id"`
	State      PathState `json:"state"`
	BoundaryID string    `json:"boundaryId,omitempty"`
}

// Deployment declares the finite set of access paths evaluated by a claim.
type Deployment struct {
	DeploymentID        string `json:"deploymentId"`
	AppraisalBoundaryID string `json:"appraisalBoundaryId"`
	Paths               []Path `json:"paths"`
}

// Validate rejects every enabled path outside the one appraisal boundary.
func (d Deployment) Validate() error {
	if !versionedID.MatchString(d.DeploymentID) || !versionedID.MatchString(d.AppraisalBoundaryID) || len(d.Paths) == 0 {
		return ErrInvalidDeployment
	}
	seen := make(map[string]bool, len(d.Paths))
	enabled := 0
	for _, path := range d.Paths {
		if path.ID == "" || seen[path.ID] {
			return fmt.Errorf("%w: missing or duplicate path", ErrInvalidDeployment)
		}
		seen[path.ID] = true
		switch path.State {
		case PathEnabled:
			enabled++
			if path.BoundaryID != d.AppraisalBoundaryID {
				return fmt.Errorf("%w: enabled path %s bypasses %s", ErrInvalidDeployment, path.ID, d.AppraisalBoundaryID)
			}
		case PathDisabled:
			if path.BoundaryID != "" {
				return fmt.Errorf("%w: disabled path %s names a boundary", ErrInvalidDeployment, path.ID)
			}
		default:
			return fmt.Errorf("%w: path %s has unknown state", ErrInvalidDeployment, path.ID)
		}
	}
	if enabled == 0 {
		return fmt.Errorf("%w: no enabled Agent delivery path", ErrInvalidDeployment)
	}
	return nil
}

func hashBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
