package vc

// ConfidenceState is the three-state verification domain used by every
// confidence axis, by the overall verdict, and by on-demand audit checks
// outside the axes (VerifySourceCommitment), with partial order
// failed ⊏ indeterminate ⊏ verified. The zero value is the weakest
// (fail-closed).
//
// failed and indeterminate are semantically distinct: failed means
// "verification completed and an inconsistency was established";
// indeterminate means "verification could not complete with the current
// inputs" and may later resolve to verified or failed as inputs become
// available (e.g. a DID Document propagates, a predecessor body appears in
// the VC resolver). The distinction is what keeps verification
// deterministic: any verifier given the same DID Document, VC-resolver, and
// lifecycle snapshots produces the same result.
type ConfidenceState int

const (
	ConfidenceFailed ConfidenceState = iota
	ConfidenceIndeterminate
	ConfidenceVerified
)

// AxisResult carries the verdicts of the three normative confidence axes.
type AxisResult struct {
	// DataIntegrity — input/output binding: the credential's hashes are
	// consistent with the predecessor credential (outputHash[n] ==
	// inputHash[n+1]) and, when the verifier holds the actual data, with
	// that data. Schema-reference mismatch (content hash vs the registry)
	// is part of this axis: the schema reference is part of the content
	// commitment. Transient unavailability of the predecessor body or the
	// schema → indeterminate; established mismatch → failed.
	DataIntegrity ConfidenceState
	// SignerAuthenticity — identity binding: the signature verifies under
	// the public key resolved from proof.verificationMethod in the issuer's
	// DID Document, and the cryptosuite is acceptable at proof.created per
	// the lifecycle policy. Resolution timeout → indeterminate; definitive
	// not-found, cryptographic failure, or Sunset/unregistered cryptosuite
	// → failed.
	SignerAuthenticity ConfidenceState
	// ChainConsistency — organizational attribution: the controller chain
	// from the issuer Process DID reconstructs to a terminal Owner DID
	// using only public DID Documents, and ordering against the predecessor
	// (proof.created monotonicity) is consistent. Unavailable intermediate
	// document → indeterminate; broken controller link or inconsistent
	// ordering → failed.
	ChainConsistency ConfidenceState
}

// EvaluateConfidence computes the overall verdict as the greatest lower
// bound (weakest link) of the three axes: any failed → failed; all verified
// → verified; otherwise indeterminate.
//
// The glb is the minimum under the lattice order, which the ConfidenceState
// iota encodes directly (ConfidenceFailed < ConfidenceIndeterminate <
// ConfidenceVerified). The zero AxisResult therefore composes to
// ConfidenceFailed — the lattice fails closed.
func EvaluateConfidence(axes AxisResult) ConfidenceState {
	min := axes.DataIntegrity
	if axes.SignerAuthenticity < min {
		min = axes.SignerAuthenticity
	}
	if axes.ChainConsistency < min {
		min = axes.ChainConsistency
	}
	return min
}

// LifecyclePhase is the lifecycle position of a protocol identifier
// (cryptosuite, canonicalizer), evaluated at the credential's proof.created
// instant against the published lifecycle policy. The zero value is Unknown
// and fails closed (verification treats it as failed).
type LifecyclePhase int

const (
	PhaseUnknown LifecyclePhase = iota
	PhaseActive
	PhaseDeprecated
	PhaseSunset
)
