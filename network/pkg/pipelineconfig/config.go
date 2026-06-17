// Package pipelineconfig is the data-plane configuration layer: it declares the
// pipeline transport loops a standalone node runs. It owns only the config contract
// (its reference.conf + a fail-closed loader); the values feed the standalone's
// data-plane runner (nats transport + ingest/processor + memlog emission).
//
// Loops are a keyed map (key = loop name) because a node runs zero or more loops of
// potentially different roles — the layer's responsibility is a SET of loops, not one
// fixed loop. slice-17b implements role = "source"; other roles are a fail-closed boot
// error until their assembly lands.
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

// RoleSource is the only loop role implemented in slice-17b.
const RoleSource = "source"

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

// LoopConfig is one transport loop's typed configuration.
type LoopConfig struct {
	// Name is the loop's config key.
	Name string
	// Role selects the processor wiring (slice-17b: RoleSource only).
	Role string
	// IngressSubject is the subject the loop subscribes to for inbound events.
	IngressSubject string
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
}

// LoadPipelineConfig reads and validates the pipeline block. It fails closed: an
// unknown role, a missing required field, a malformed output/issuer DID, an unknown
// transformation-claim, or a non-empty schema-ref (unsupported in 17b) is a boot
// error naming the loop and key. An absent or empty loops map is valid (zero loops):
// the node runs the HTTP control plane only.
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

func loadLoop(cfg *hoconconfig.Config, name string) (LoopConfig, error) {
	base := loopsKey + "." + name
	lc := LoopConfig{Name: name}

	role, err := requireString(cfg, base+".role")
	if err != nil {
		return lc, err
	}
	if role != RoleSource {
		return lc, fmt.Errorf("pipeline: loop %q: unsupported role %q (slice-17b implements %q only)", name, role, RoleSource)
	}
	lc.Role = role

	if lc.IngressSubject, err = requireString(cfg, base+".ingress-subject"); err != nil {
		return lc, err
	}
	if lc.OutputSubject, err = requireString(cfg, base+".output-subject"); err != nil {
		return lc, err
	}
	if err := requirePipelineDID(lc.OutputSubject, name, "output-subject"); err != nil {
		return lc, err
	}

	if lc.Issuer.DID, err = requireString(cfg, base+".issuer.did"); err != nil {
		return lc, err
	}
	if err := requireProcessDID(lc.Issuer.DID, name, "issuer.did"); err != nil {
		return lc, err
	}
	if lc.Issuer.KeyID, err = requireString(cfg, base+".issuer.key-id"); err != nil {
		return lc, err
	}
	if lc.Issuer.VerificationMethod, err = requireString(cfg, base+".issuer.verification-method"); err != nil {
		return lc, err
	}
	// The verification-method must name the issuer's own signing key: <issuer.did>#<key-id>.
	// A bare DID, another DID's key, or a different fragment would boot a loop whose
	// proofs are rejected by the VC verifier or attributed to the wrong key.
	if expected := lc.Issuer.DID + "#" + lc.Issuer.KeyID; lc.Issuer.VerificationMethod != expected {
		return lc, fmt.Errorf("pipeline: loop %q: issuer.verification-method %q must be %q (issuer.did#key-id)", name, lc.Issuer.VerificationMethod, expected)
	}

	if lc.PipelineID, err = requireString(cfg, base+".pipeline-id"); err != nil {
		return lc, err
	}
	if lc.ProcessID, err = requireString(cfg, base+".process-id"); err != nil {
		return lc, err
	}

	claimToken, err := requireString(cfg, base+".transformation-claim")
	if err != nil {
		return lc, err
	}
	claim, ok := claimByName[claimToken]
	if !ok {
		return lc, fmt.Errorf("pipeline: loop %q: unknown transformation-claim %q", name, claimToken)
	}
	lc.TransformationClaim = claim

	// schema-ref must be empty in slice-17b (ingest does no schema validation; a
	// single-string -> vc.SchemaRef mapping is deferred to a chained/sink loop). An
	// absent schema-ref is treated as empty — the field is optional, not required.
	if cfg.Has(base + ".schema-ref") {
		schemaRef, err := cfg.String(base + ".schema-ref")
		if err != nil {
			return lc, fmt.Errorf("pipeline: loop %q: config schema-ref: %w", name, err)
		}
		if schemaRef != "" {
			return lc, fmt.Errorf("pipeline: loop %q: schema-ref must be empty in slice-17b (got %q)", name, schemaRef)
		}
	}

	return lc, nil
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
