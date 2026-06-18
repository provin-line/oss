// Package pipelineconfig is the data-plane configuration layer: it declares the
// pipeline transport loops a standalone node runs. It owns only the config contract
// (its reference.conf + a fail-closed loader); the values feed the standalone's
// data-plane runner (nats transport + ingest/processor + memlog emission).
//
// Loops are a keyed map (key = loop name) because a node runs zero or more loops of
// potentially different roles — the layer's responsibility is a SET of loops, not one
// fixed loop. slice-17b implements role = "source"; slice-17c adds role = "sink" (a
// terminating subscriber that verifies and writes out-of-network); role = "chained"
// remains a fail-closed boot error until its assembly lands (17d).
package pipelineconfig

import (
	_ "embed"
	"fmt"

	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/vc"
)

//go:embed reference.conf
var referenceConf string

func init() {
	hoconconfig.RegisterPackageReference("network/pipeline", referenceConf)
}

// Loop roles. slice-17c implements RoleSource (17b) and RoleSink; RoleChained is a
// recognized-but-unsupported role (typed boot error) until 17d.
const (
	RoleSource  = "source"
	RoleSink    = "sink"
	RoleChained = "chained"
)

// Sink kinds — the verdict policy a terminating sink applies (mirrors contract.SinkKind).
const (
	SinkObservationOnly = "observation-only"
	SinkProduction      = "production"
	SinkArchival        = "archival"
)

// Verification strategies a non-source loop may declare. slice-17c implements
// StrategyAdjacent; StrategyFull is recognized-but-unsupported (typed boot error) until
// a network credential resolver lands (17d).
const (
	StrategyAdjacent = "adjacent"
	StrategyFull     = "full"
)

const loopsKey = "provin.network.pipeline.loops"

// claimByName maps the config transformation-claim token to the vc constant. The
// config uses the bare token (e.g. "convert"); the vc value is the namespaced form
// (e.g. "provin:convert").
var claimByName = map[string]vc.TransformationClaim{
	"filter":         vc.ClaimFilter,
	"convert":        vc.ClaimConvert,
	"filter-convert": vc.ClaimFilterConvert,
	"aggregate":      vc.ClaimAggregate,
	"enrich":         vc.ClaimEnrich,
	"generate":       vc.ClaimGenerate,
}

// Config is the typed data-plane config: the loops this node runs.
type Config struct {
	Loops []LoopConfig
}

// IssuerConfig is the issuing process identity for a producing loop.
type IssuerConfig struct {
	DID                string
	KeyID              string
	VerificationMethod string
}

// LoopConfig is one transport loop's typed configuration: shared fields plus exactly
// one role sub-struct, selected by Role. The loader populates and validates the
// sub-struct that matches Role and rejects fields that belong to a different role.
type LoopConfig struct {
	// Name is the loop's config key.
	Name string
	// Role selects the processor wiring: RoleSource | RoleSink (RoleChained → 17d).
	Role string
	// IngressSubject is the subject the loop subscribes to for inbound events. For a
	// sink it is the GRANTED upstream subject (the upstream source's output-subject /
	// pipeline DID, imported into this node's account).
	IngressSubject string
	// Source is populated when Role == RoleSource.
	Source SourceConfig
	// Sink is populated when Role == RoleSink.
	Sink SinkConfig
	// Chained is populated when Role == RoleChained.
	Chained ChainedConfig
}

// SourceConfig is a producing source loop's identity + output (Role == RoleSource).
type SourceConfig struct {
	// OutputSubject is the subject the loop publishes to — the node's publisher
	// subject, a pipeline DID.
	OutputSubject string
	// Issuer is the signing identity for produced credentials.
	Issuer IssuerConfig
	// PipelineID / ProcessID are the constant subject metadata of issued credentials.
	PipelineID string
	ProcessID  string
	// TransformationClaim is the validated transformation claim of issued credentials.
	TransformationClaim vc.TransformationClaim
	// SchemaRef is the (currently empty-only) schema reference; non-empty is rejected.
	SchemaRef string
}

// SinkConfig is a terminating sink loop's verification + write policy (Role == RoleSink).
// A sink produces nothing in-network, so it has no issuer and no output subject.
type SinkConfig struct {
	// Kind is the verdict policy: SinkObservationOnly | SinkProduction | SinkArchival.
	Kind string
	// VerificationStrategy is the ingress-credential verification depth (17c: adjacent).
	VerificationStrategy string
	// UpstreamEndpoint is the upstream publisher's serving boundary, stored with the
	// verified ingress VC for audit reachability.
	UpstreamEndpoint string
}

// ChainedConfig is a relay loop's producing identity + consuming verification + optional
// transform (Role == RoleChained). A chained loop both consumes (verifies its ingress,
// like a sink) and produces (re-signs a ChainPreserving credential, like a source).
type ChainedConfig struct {
	// Producing side (mirrors SourceConfig minus SchemaRef).
	OutputSubject       string
	Issuer              IssuerConfig
	PipelineID          string
	ProcessID           string
	TransformationClaim vc.TransformationClaim
	// Consuming side (mirrors SinkConfig minus Kind).
	VerificationStrategy string
	UpstreamEndpoint     string
	// Transform (optional). Converter is a whole-document JSONata expression ("" =
	// passthrough); Filters are JSONata predicates (empty = no filtering). Both are
	// compiled at loop-build time — a malformed expression is a boot error there.
	Converter string
	Filters   []string
}

// LoadPipelineConfig reads and validates the pipeline block. It fails closed: an
// unknown role, a missing required field, a malformed output/issuer DID, an unknown
// transformation-claim/sink-kind/verification-strategy, a non-empty schema-ref, or a
// field that does not belong to the loop's role is a boot error naming the loop and key.
// An absent or empty loops map is valid (zero loops): the node runs the HTTP control
// plane only.
func LoadPipelineConfig(cfg *hoconconfig.Config) (*Config, error) {
	if !cfg.Has(loopsKey) {
		return &Config{}, nil
	}
	names, err := cfg.Keys(loopsKey)
	if err != nil {
		return nil, fmt.Errorf("pipeline: config %s: %w", loopsKey, err)
	}
	out := &Config{}
	for _, name := range names {
		lc, err := loadLoop(cfg, name)
		if err != nil {
			return nil, err
		}
		out.Loops = append(out.Loops, lc)
	}
	return out, nil
}

// sourceKeys / sinkKeys / chainedKeys are the role-exclusive config keys. The loader
// rejects keys from the OTHER roles' sets so a loop cannot silently carry fields it does
// not use (e.g. an issuer block under a sink, or a sink block under a chained loop).
// Source fields are top-level (17b shape); sink and chained fields nest under their block.
var (
	sourceKeys  = []string{"output-subject", "issuer", "pipeline-id", "process-id", "transformation-claim", "schema-ref"}
	sinkKeys    = []string{"sink"}
	chainedKeys = []string{"chained"}
)

func loadLoop(cfg *hoconconfig.Config, name string) (LoopConfig, error) {
	base := loopsKey + "." + name
	lc := LoopConfig{Name: name}

	role, err := requireString(cfg, base+".role")
	if err != nil {
		return lc, err
	}
	lc.Role = role

	if lc.IngressSubject, err = requireString(cfg, base+".ingress-subject"); err != nil {
		return lc, err
	}

	switch role {
	case RoleSource:
		if err := rejectKeys(cfg, base, name, role, sinkKeys, chainedKeys); err != nil {
			return lc, err
		}
		if lc.Source, err = loadSourceConfig(cfg, base, name); err != nil {
			return lc, err
		}
	case RoleSink:
		if err := rejectKeys(cfg, base, name, role, sourceKeys, chainedKeys); err != nil {
			return lc, err
		}
		// A sink's ingress is the GRANTED upstream subject == an upstream source's
		// output-subject, which is a pipeline DID. Validate it so a typo or wildcard
		// (e.g. ">") fails closed instead of subscribing the sink to unintended subjects.
		if err := requirePipelineDID(lc.IngressSubject, name, "ingress-subject"); err != nil {
			return lc, err
		}
		if lc.Sink, err = loadSinkConfig(cfg, base, name); err != nil {
			return lc, err
		}
	case RoleChained:
		if err := rejectKeys(cfg, base, name, role, sourceKeys, sinkKeys); err != nil {
			return lc, err
		}
		// Like a sink, a chained loop's ingress is the granted upstream pipeline DID.
		if err := requirePipelineDID(lc.IngressSubject, name, "ingress-subject"); err != nil {
			return lc, err
		}
		if lc.Chained, err = loadChainedConfig(cfg, base, name); err != nil {
			return lc, err
		}
	default:
		return lc, fmt.Errorf("pipeline: loop %q: unknown role %q", name, role)
	}
	return lc, nil
}

func loadSourceConfig(cfg *hoconconfig.Config, base, name string) (SourceConfig, error) {
	var sc SourceConfig
	var err error

	if sc.OutputSubject, err = requireString(cfg, base+".output-subject"); err != nil {
		return sc, err
	}
	if err := requirePipelineDID(sc.OutputSubject, name, "output-subject"); err != nil {
		return sc, err
	}

	if sc.Issuer, err = loadIssuer(cfg, base, name, "issuer"); err != nil {
		return sc, err
	}

	if sc.PipelineID, err = requireString(cfg, base+".pipeline-id"); err != nil {
		return sc, err
	}
	if sc.ProcessID, err = requireString(cfg, base+".process-id"); err != nil {
		return sc, err
	}

	if sc.TransformationClaim, err = loadClaim(cfg, base+".transformation-claim", name); err != nil {
		return sc, err
	}

	// schema-ref must be empty (ingest does no schema validation; a single-string ->
	// vc.SchemaRef mapping is deferred to a chained loop). Absent is treated as empty.
	if cfg.Has(base + ".schema-ref") {
		if sc.SchemaRef, err = cfg.String(base + ".schema-ref"); err != nil {
			return sc, fmt.Errorf("pipeline: loop %q: config schema-ref: %w", name, err)
		}
		if sc.SchemaRef != "" {
			return sc, fmt.Errorf("pipeline: loop %q: schema-ref must be empty (got %q)", name, sc.SchemaRef)
		}
	}

	return sc, nil
}

func loadSinkConfig(cfg *hoconconfig.Config, base, name string) (SinkConfig, error) {
	var sc SinkConfig
	var err error

	if sc.Kind, err = requireString(cfg, base+".sink.kind"); err != nil {
		return sc, err
	}
	switch sc.Kind {
	case SinkObservationOnly:
	case SinkProduction, SinkArchival:
		// production/archival carry contract MUST obligations beyond verdict filtering
		// (mutual allow-list, receipts, audit log — contract.SinkKind) that the sink
		// runtime does not yet wire. Fail closed until they exist rather than boot a
		// sink that silently under-delivers its kind's guarantees.
		return sc, fmt.Errorf("pipeline: loop %q: sink.kind %q is unsupported in slice-17c (%q only; production/archival obligations not yet wired)", name, sc.Kind, SinkObservationOnly)
	default:
		return sc, fmt.Errorf("pipeline: loop %q: unknown sink.kind %q (want %q|%q|%q)", name, sc.Kind, SinkObservationOnly, SinkProduction, SinkArchival)
	}

	if sc.VerificationStrategy, err = loadAdjacentStrategy(cfg, base+".sink.verification-strategy", name); err != nil {
		return sc, err
	}

	if sc.UpstreamEndpoint, err = requireString(cfg, base+".sink.upstream-endpoint"); err != nil {
		return sc, err
	}

	return sc, nil
}

// rejectKeys errors if any key from the given sets is present under the loop — used to
// fail closed when a loop carries fields that belong to a different role.
func rejectKeys(cfg *hoconconfig.Config, base, name, role string, keySets ...[]string) error {
	for _, keys := range keySets {
		for _, k := range keys {
			if cfg.Has(base + "." + k) {
				return fmt.Errorf("pipeline: loop %q: key %q does not belong to role %q", name, k, role)
			}
		}
	}
	return nil
}

// loadIssuer reads and validates an issuer block at <keyBase>.issuer: the DID must be a
// process DID and the verification-method must name the issuer's own signing key
// (<issuer.did>#<key-id>) — a bare DID, another DID's key, or a different fragment would
// boot a loop whose proofs are rejected by the VC verifier or attributed to the wrong key.
// fieldPrefix names the block in error messages (e.g. "issuer" or "chained.issuer").
func loadIssuer(cfg *hoconconfig.Config, keyBase, name, fieldPrefix string) (IssuerConfig, error) {
	var ic IssuerConfig
	var err error
	if ic.DID, err = requireString(cfg, keyBase+".issuer.did"); err != nil {
		return ic, err
	}
	if err := requireProcessDID(ic.DID, name, fieldPrefix+".did"); err != nil {
		return ic, err
	}
	if ic.KeyID, err = requireString(cfg, keyBase+".issuer.key-id"); err != nil {
		return ic, err
	}
	if ic.VerificationMethod, err = requireString(cfg, keyBase+".issuer.verification-method"); err != nil {
		return ic, err
	}
	if expected := ic.DID + "#" + ic.KeyID; ic.VerificationMethod != expected {
		return ic, fmt.Errorf("pipeline: loop %q: %s.verification-method %q must be %q (issuer.did#key-id)", name, fieldPrefix, ic.VerificationMethod, expected)
	}
	return ic, nil
}

// loadClaim reads and maps a transformation-claim token to its vc constant.
func loadClaim(cfg *hoconconfig.Config, key, name string) (vc.TransformationClaim, error) {
	token, err := requireString(cfg, key)
	if err != nil {
		return "", err
	}
	claim, ok := claimByName[token]
	if !ok {
		return "", fmt.Errorf("pipeline: loop %q: unknown transformation-claim %q", name, token)
	}
	return claim, nil
}

// loadAdjacentStrategy reads a verification-strategy that must be "adjacent": "full" is a
// recognized-but-unsupported boot error (chainwalk needs a network credential resolver +
// VC-store publication, both unbuilt — lands in 17e); anything else is unknown.
func loadAdjacentStrategy(cfg *hoconconfig.Config, key, name string) (string, error) {
	s, err := requireString(cfg, key)
	if err != nil {
		return "", err
	}
	switch s {
	case StrategyAdjacent:
		return s, nil
	case StrategyFull:
		return "", fmt.Errorf("pipeline: loop %q: verification-strategy %q is unsupported (%q only; %q lands in 17e)", name, s, StrategyAdjacent, StrategyFull)
	default:
		return "", fmt.Errorf("pipeline: loop %q: unknown verification-strategy %q (want %q|%q)", name, s, StrategyAdjacent, StrategyFull)
	}
}

// loadChainedConfig validates a relay loop's producing identity + consuming verification
// + optional transform. Producing/issuer rules mirror a source; strategy/upstream mirror a
// sink; the converter (whole-document JSONata) and filters (JSONata predicates) are read
// as raw expressions here and compiled at loop-build time.
func loadChainedConfig(cfg *hoconconfig.Config, base, name string) (ChainedConfig, error) {
	var cc ChainedConfig
	var err error
	cbase := base + ".chained"

	if cc.OutputSubject, err = requireString(cfg, cbase+".output-subject"); err != nil {
		return cc, err
	}
	if err := requirePipelineDID(cc.OutputSubject, name, "chained.output-subject"); err != nil {
		return cc, err
	}
	if cc.Issuer, err = loadIssuer(cfg, cbase, name, "chained.issuer"); err != nil {
		return cc, err
	}
	if cc.PipelineID, err = requireString(cfg, cbase+".pipeline-id"); err != nil {
		return cc, err
	}
	if cc.ProcessID, err = requireString(cfg, cbase+".process-id"); err != nil {
		return cc, err
	}
	if cc.TransformationClaim, err = loadClaim(cfg, cbase+".transformation-claim", name); err != nil {
		return cc, err
	}
	if cc.VerificationStrategy, err = loadAdjacentStrategy(cfg, cbase+".verification-strategy", name); err != nil {
		return cc, err
	}
	if cc.UpstreamEndpoint, err = requireString(cfg, cbase+".upstream-endpoint"); err != nil {
		return cc, err
	}

	// Transform is optional: an absent converter is a passthrough relay; absent filters
	// means no filtering.
	if cfg.Has(cbase + ".converter") {
		if cc.Converter, err = cfg.String(cbase + ".converter"); err != nil {
			return cc, fmt.Errorf("pipeline: loop %q: config chained.converter: %w", name, err)
		}
	}
	if cfg.Has(cbase + ".filters") {
		if cc.Filters, err = cfg.StringList(cbase + ".filters"); err != nil {
			return cc, fmt.Errorf("pipeline: loop %q: config chained.filters: %w", name, err)
		}
	}
	return cc, nil
}

func requireString(cfg *hoconconfig.Config, key string) (string, error) {
	v, err := cfg.String(key)
	if err != nil {
		return "", fmt.Errorf("pipeline: config %s: %w", key, err)
	}
	if v == "" {
		return "", fmt.Errorf("pipeline: config %s: must not be empty", key)
	}
	return v, nil
}

func requirePipelineDID(didStr, loop, field string) error {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return fmt.Errorf("pipeline: loop %q: %s %q: %w", loop, field, didStr, err)
	}
	if !d.IsPipeline() {
		return fmt.Errorf("pipeline: loop %q: %s %q is not a pipeline DID", loop, field, didStr)
	}
	return nil
}

func requireProcessDID(didStr, loop, field string) error {
	d, err := dplaax.Parse(didStr)
	if err != nil {
		return fmt.Errorf("pipeline: loop %q: %s %q: %w", loop, field, didStr, err)
	}
	if !d.IsProcess() {
		return fmt.Errorf("pipeline: loop %q: %s %q is not a process DID", loop, field, didStr)
	}
	return nil
}
