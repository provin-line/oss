package runtime

import (
	"time"

	"github.com/provin-line/oss/vc"
)

// Loop roles. String-identical to network/pkg/pipelineconfig's Role* constants
// (cmd/pipeline's pipelineRuntimeConfigFrom copies the loaded config's Role
// verbatim) so a loop's metrics-bookkeeping Role label does not shift across
// the severance that gave this package its own copy of the type.
const (
	RoleSource    = "source"
	RoleSink      = "sink"
	RoleChained   = "chained"
	RoleAggregate = "aggregate"
)

// Sink kinds — the verdict policy a terminating sink applies. String-identical
// to network/pkg/pipelineconfig's Sink* constants.
const (
	SinkObservationOnly = "observation-only"
	SinkProduction      = "production"
	SinkArchival        = "archival"
)

// StrategyAdjacent is the only verification strategy a non-source loop may
// declare: verify the immediately preceding credential. String-identical to
// network/pkg/pipelineconfig.StrategyAdjacent.
const StrategyAdjacent = "adjacent"

// Sink output types. String-identical to network/pkg/pipelineconfig's
// SinkOutput* constants.
const (
	SinkOutputConsole = "console"
	SinkOutputFile    = "file"
)

// NATSConfig holds the nats connection parameters Build dials with — the
// exact field set natstransport.Config takes. cmd/pipeline's
// pipelineRuntimeConfigFrom copies these straight out of the loaded chain config.
type NATSConfig struct {
	URL         string
	AccountSeed string
	ConnectWait time.Duration
}

// Config is the runtime-owned data-plane configuration: the loops this node
// runs, the nats parameters to dial with, and the two durable-log root
// directories (TlogDir/RejectLogDir — config, not a dependency, so they live
// here rather than on Deps). cmd/pipeline's pipelineRuntimeConfigFrom maps
// its own chainconfig.Config + pipelineconfig.Config into this shape — the
// drift guard between the two config trees is cmd/pipeline's own
// wiring_test.go golden mapping test.
type Config struct {
	NATS         NATSConfig
	Loops        []LoopConfig
	TlogDir      string
	RejectLogDir string
}

// IssuerConfig is the issuing process identity for a producing loop or a
// sink's receipt issuer.
type IssuerConfig struct {
	DID                string
	KeyID              string
	VerificationMethod string
}

// LoopConfig is one transport loop's typed configuration: shared fields plus
// exactly one role sub-struct, selected by Role.
type LoopConfig struct {
	Name           string
	Role           string
	IngressSubject string
	Source         SourceConfig
	Sink           SinkConfig
	Chained        ChainedConfig
	Aggregate      AggregateConfig
}

// SourceConfig is a producing source loop's identity + output (Role == RoleSource).
type SourceConfig struct {
	OutputSubject       string
	Issuer              IssuerConfig
	PipelineID          string
	ProcessID           string
	TransformationClaim vc.TransformationClaim
	// SchemaRef is the optional output-schema reference in "<name>@<version>"
	// short-form, resolved against the registry at boot.
	SchemaRef string
	// PushIngress exposes this loop's ingress as an HTTP push endpoint —
	// cmd/pipeline mounts one apipush adapter per PushBinding.
	PushIngress bool
}

// SinkOutputConfig selects a sink loop's delivery surface.
type SinkOutputConfig struct {
	Type string
	Path string
}

// SinkReceiptConfig configures a sink's receipt issuance.
type SinkReceiptConfig struct {
	Issue      bool
	Issuer     IssuerConfig
	PipelineID string
	ProcessID  string
}

// SinkConfig is a terminating sink loop's verification + write policy (Role == RoleSink).
type SinkConfig struct {
	Kind                 string
	VerificationStrategy string
	UpstreamEndpoint     string
	PayloadDelivery      string
	AllowIssuers         []string
	AgentAccess          AgentAccessConfig
	Receipt              SinkReceiptConfig
	Output               SinkOutputConfig
}

// AgentAccessConfig opts a production/archival sink into synchronous exact
// EvidenceView appraisal. Zero value is the legacy adjacent-only mode.
type AgentAccessConfig struct {
	Enabled           bool
	BoundaryID        string
	DecisionProfileID string
	RequiredScopes    []string
}

// ChainedConfig is a relay loop's producing identity + consuming verification
// + optional transform (Role == RoleChained).
type ChainedConfig struct {
	OutputSubject        string
	Issuer               IssuerConfig
	PipelineID           string
	ProcessID            string
	TransformationClaim  vc.TransformationClaim
	SchemaRef            string
	VerificationStrategy string
	UpstreamEndpoint     string
	PayloadDelivery      string
	// Converter/Filters compile at loop-build time — a malformed expression
	// fails closed there.
	Converter string
	Filters   []string
}

// AggregateIngress is one upstream the aggregate pools from.
type AggregateIngress struct {
	Subject          string
	UpstreamEndpoint string
	PayloadDelivery  string
}

// AggregateConfig is an aggregate loop's producing identity + N-ary consuming
// side + window (Role == RoleAggregate). The aggregate runtime declares
// VerificationAdjacent intrinsically (the config-side VerificationStrategy
// key is validated at load but never read by the loop builder), so it has no
// field here.
type AggregateConfig struct {
	OutputSubject string
	Issuer        IssuerConfig
	PipelineID    string
	ProcessID     string
	SchemaRef     string
	Ingresses     []AggregateIngress
	Window        time.Duration
}
