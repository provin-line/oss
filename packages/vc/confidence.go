package vc

// ConfidenceLevel is the L1 verdict for a credential. The zero value is the
// most restrictive (fail-closed).
type ConfidenceLevel int

const (
	ConfidenceInvalid ConfidenceLevel = iota
	ConfidenceLimited
	ConfidenceVerified
)

// AxisStatus is the verdict of one verification axis. The zero value is the
// most restrictive (fail-closed).
type AxisStatus int

const (
	AxisInvalid AxisStatus = iota
	AxisLimited
	AxisValid
)

// AxisResult carries the per-axis verdicts that compose the confidence level.
type AxisResult struct {
	Signature     AxisStatus
	DIDResolution AxisStatus
	Schema        AxisStatus
}

// EvaluateConfidence computes the weakest-link confidence over all axes.
func EvaluateConfidence(axes AxisResult) ConfidenceLevel { panic("not implemented") }

// LifecyclePhase is the lifecycle position of a protocol identifier
// (cryptosuite, canonicalizer). The zero value is Unknown and fails closed.
type LifecyclePhase int

const (
	PhaseUnknown LifecyclePhase = iota
	PhaseActive
	PhaseDeprecated
	PhaseSunset
)
