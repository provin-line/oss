// Package chain builds a dPLaaX EvidenceView from the exact credential spine
// selected and verified by a chain walker, then applies one local profile.
package chain

import (
	"context"
	"errors"
	"fmt"

	"github.com/provin-line/oss/appraisal"
	"github.com/provin-line/oss/appraisal/inputcapture"
	"github.com/provin-line/oss/vc"
)

const LinearAttestationScope = "LINEAR_ATTESTATION@1"

// ProjectedChainSelection identifies the current resolver semantics: each
// previousCredential body address is resolved to the resolver's projected
// signed wire variant. It deliberately does not claim bounded-DAG search or a
// globally least EvidenceViewID across every available variant.
const ProjectedChainSelection = "projected-chain@1"

var knownScopeCatalog = []string{
	"CREDENTIAL_ATTESTATION@1",
	"SIGNATURE_ONLY@1",
	LinearAttestationScope,
	"SOURCE_SET_BINDING@1",
	"SOURCE_CREDENTIAL_ATTESTATION@1",
	"SEMANTIC_EXECUTION@1",
	"TLOG_REPLAY@1",
	"TLOG_INCLUSION@1",
	"TLOG_CONSISTENCY@1",
	"TLOG_NON_EQUIVOCATION@1",
	"TLOG_TRUSTED_TIME@1",
	"RECEIPT_SIGNATURE@1",
	"RECEIPT_EXTERNAL_EFFECT@1",
	"RECEIPT_IDEMPOTENCY@1",
	"RECEIPT_EXACTLY_ONCE@1",
	"KEY_AUTHORIZATION_AT_STATE@1",
	"CONTROLLER_CHAIN_AUTHORIZATION_AT_STATE@1",
	"ANCHORED_OBSERVATION_ORDER@1",
	"LIFECYCLE_FRESHNESS@1",
	"TRUSTED_OBSERVATION_TIME@1",
	"AUTHORIZATION_AT_ISSUANCE_WITH_MAX_AGE@1",
	"CURRENT_AUTHORIZATION_AT_REQUEST@1",
}

// KnownScopes returns the dPLaaX scope catalog understood by this runtime.
// Only LINEAR_ATTESTATION@1 is evaluated by this appraiser; every other entry
// is emitted as UNSUPPORTED so a stricter local profile quarantines instead of
// becoming an unknown-scope boot failure or silently omitting coverage.
func KnownScopes() []string { return append([]string(nil), knownScopeCatalog...) }

var (
	ErrInvalidConfig = errors.New("chain appraisal: invalid config")
	ErrNoSuite       = errors.New("chain appraisal: verifier returned no cryptosuite contract")
)

// Walker returns the exact origin-first selection and verdict from one pass.
type Walker interface {
	VerifyChainEvidence(ctx context.Context, head *vc.PipelinePassCredential) ([]*vc.PipelinePassCredential, *vc.VerifyResult, error)
}

// Config fixes the portable evaluation contract and the local policy contract.
type Config struct {
	ClaimContractID   string
	SchemaVersion     string
	SelectionPolicyID string
	KnownScopes       []string
	Profile           appraisal.Profile
}

// Appraiser is safe for concurrent use when its Walker is safe. Snapshot
// sessions are context-local and never shared between calls.
type Appraiser struct {
	walker   Walker
	recorder inputcapture.Recorder
	cfg      Config
}

func New(walker Walker, recorder inputcapture.Recorder, cfg Config) (*Appraiser, error) {
	if walker == nil || cfg.ClaimContractID == "" || cfg.SchemaVersion == "" || cfg.SelectionPolicyID == "" || len(cfg.KnownScopes) == 0 {
		return nil, ErrInvalidConfig
	}
	known := make(map[string]bool, len(cfg.KnownScopes))
	for _, scope := range cfg.KnownScopes {
		if scope == "" || known[scope] {
			return nil, fmt.Errorf("%w: missing or duplicate known scope", ErrInvalidConfig)
		}
		known[scope] = true
	}
	for _, required := range cfg.Profile.RequiredScopes {
		if !known[required] {
			return nil, fmt.Errorf("%w: required scope %s is not enumerated as known", ErrInvalidConfig, required)
		}
	}
	// Exercise profile validation without allowing a boot-time ACCEPT: a single
	// unsupported entry is shape-valid and produces a quarantined decision.
	probe := make([]appraisal.ScopeEntry, 0, len(cfg.KnownScopes))
	for _, scope := range cfg.KnownScopes {
		probe = append(probe, appraisal.ScopeEntry{Scope: scope, Coverage: appraisal.CoverageUnsupported})
	}
	if _, err := appraisal.Decide(cfg.Profile, probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return &Appraiser{walker: walker, recorder: recorder, cfg: cfg}, nil
}

// Appraise performs one resolver-snapshot capture around one exact chain walk.
func (a *Appraiser) Appraise(ctx context.Context, head *vc.PipelinePassCredential) (*appraisal.View, *vc.VerifyResult, error) {
	captureCtx, session := a.recorder.Start(ctx)
	chain, result, err := a.walker.VerifyChainEvidence(captureCtx, head)
	if err != nil {
		return nil, nil, err
	}
	if result == nil {
		return nil, nil, errors.New("chain appraisal: walker returned nil result")
	}
	snapshots, err := session.Digests()
	if err != nil {
		return nil, nil, err
	}
	if result.SuiteContract == "" || result.SuiteContract.CanonicalizerID() == "" {
		return nil, result, ErrNoSuite
	}
	spine := make([]appraisal.SpineEntry, len(chain))
	for i, credential := range chain {
		if credential == nil {
			return nil, result, fmt.Errorf("chain appraisal: nil credential at spine %d", i)
		}
		body, err := credential.Hash()
		if err != nil {
			return nil, result, fmt.Errorf("chain appraisal: hash spine %d: %w", i, err)
		}
		variant, err := credential.WireVariantID()
		if err != nil {
			return nil, result, fmt.Errorf("chain appraisal: variant spine %d: %w", i, err)
		}
		spine[i] = appraisal.SpineEntry{BodyAddress: body, WireVariantID: variant}
	}
	if len(spine) == 0 {
		return nil, result, errors.New("chain appraisal: walker returned empty spine")
	}
	vector := make([]appraisal.ScopeEntry, 0, len(a.cfg.KnownScopes))
	for _, scope := range a.cfg.KnownScopes {
		entry := appraisal.ScopeEntry{Scope: scope, Coverage: appraisal.CoverageUnsupported}
		if scope == LinearAttestationScope {
			state := truthFromConfidence(result.Overall)
			entry.Coverage = appraisal.CoverageEvaluated
			entry.TruthState = &state
		}
		vector = append(vector, entry)
	}
	view, err := appraisal.NewView(appraisal.Manifest{
		Head:                 spine[len(spine)-1].BodyAddress,
		Spine:                spine,
		ClaimContractID:      a.cfg.ClaimContractID,
		CanonicalizerID:      result.SuiteContract.CanonicalizerID(),
		CryptosuiteID:        string(result.SuiteContract),
		SchemaVersion:        a.cfg.SchemaVersion,
		InputSnapshotDigests: snapshots,
		Extensions: map[string]any{
			"selectionPolicyId": a.cfg.SelectionPolicyID,
		},
	}, vector)
	if err != nil {
		return nil, result, err
	}
	decision, err := appraisal.Decide(a.cfg.Profile, view.Vector)
	if err != nil {
		return nil, result, err
	}
	view.PolicyDecision = &decision
	return view, result, nil
}

func truthFromConfidence(state vc.ConfidenceState) appraisal.TruthState {
	switch state {
	case vc.ConfidenceVerified:
		return appraisal.TruthVerified
	case vc.ConfidenceIndeterminate:
		return appraisal.TruthIndeterminate
	default:
		return appraisal.TruthFailed
	}
}
