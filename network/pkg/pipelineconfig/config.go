// Package pipelineconfig is the data-plane configuration layer: it declares the
// pipeline transport loops a standalone node runs. It owns only the config contract
// (its reference.conf + a fail-closed loader); the values feed the standalone's
// data-plane runner (nats transport + ingest/processor + memlog emission).
//
// Loops are a keyed map (key = loop name) because a node runs zero or more loops of
// potentially different roles — the layer's responsibility is a SET of loops, not one
// fixed loop. All four roles are implemented: "source" (external ingestion, 17b),
// "sink" (terminating subscriber that verifies and writes out-of-network, 17c),
// "chained" (verify-and-relay, 17d), and "aggregate" (N-ary pool + window, 17m).
// An unknown role remains a fail-closed boot error.
package pipelineconfig

import (
	_ "embed"
	"fmt"
	"net/url"
	"sort"
	"time"

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
	RoleSource    = "source"
	RoleSink      = "sink"
	RoleChained   = "chained"
	RoleAggregate = "aggregate"
)

// Sink kinds — the verdict policy a terminating sink applies (mirrors contract.SinkKind).
const (
	SinkObservationOnly = "observation-only"
	SinkProduction      = "production"
	SinkArchival        = "archival"
)

// StrategyAdjacent is the only verification strategy a non-source loop may declare: verify
// the immediately preceding credential. Full-chain verification is the async audit runner's
// job (slice-17h); the real-time "full" strategy was retired in slice-17j.
const StrategyAdjacent = "adjacent"

const (
	pipelineKey          = "provin.network.pipeline"
	loopsKey             = pipelineKey + ".loops"
	vcStoreEndpointKey   = pipelineKey + ".vc-store-endpoint"
	vcStoreBearerKey     = pipelineKey + ".vc-store-bearer"
	maxCredentialSizeKey = pipelineKey + ".max-credential-size"
	maxPushBodySizeKey   = pipelineKey + ".max-push-body-size"
	batchResolverKey     = pipelineKey + ".batch-resolver"
	brIntervalKey        = batchResolverKey + ".interval"
	brBatchSizeKey       = batchResolverKey + ".batch-size"
	brMaxRetriesKey      = batchResolverKey + ".max-retries"
	brMaxDepthKey        = batchResolverKey + ".max-depth"
	auditRunnerKey       = pipelineKey + ".audit-runner"
	arIntervalKey        = auditRunnerKey + ".interval"
	arBatchSizeKey       = auditRunnerKey + ".batch-size"
	arMaxAttemptsKey     = auditRunnerKey + ".max-attempts"
)

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
	// VCStoreEndpoint is the node-level VCResolverService base URL where producing
	// loops publish issued credentials. Empty when the node publishes nothing.
	// (Full-chain coverage is the async audit runner's job — slice-17h — which resolves
	// over the local store, not this endpoint; slice-17j retired real-time "full".)
	VCStoreEndpoint string
	// VCStoreBearer is the L1 PDP token the VC-store client presents (the store sits
	// behind the node's auth interceptors). Required whenever VCStoreEndpoint is set,
	// and whenever any consuming loop runs (the async batch resolver presents the same
	// token for peer predecessor fetches) — a tokenless client would be rejected at
	// runtime, so LoadPipelineConfig fails closed on both.
	VCStoreBearer string
	// MaxCredentialSize bounds the bytes of a single VC on the fetch/store path (the
	// VCResolverService client and handler) — a hostile peer must not OOM the node with a
	// bloated body. Node-level: it governs every fetch/store, not just the async resolver.
	// Sourced from reference.conf (no Go default); a non-positive value fails startup.
	MaxCredentialSize int
	// MaxPushBodySize bounds an HTTP push request body (the apipush adapter). Distinct
	// from MaxCredentialSize: that key bounds credentials on the fetch/store path, this
	// one bounds a raw ingest payload. Sourced from reference.conf (no Go default); a
	// non-positive value fails startup.
	MaxPushBodySize int
	// BatchResolver tunes the async chain-audit resolver (the Runner that drains the
	// unresolved pool). Sourced from reference.conf; a non-positive value fails startup.
	BatchResolver BatchResolverConfig
	// AuditRunner tunes the async audit runner (slice-17h — verifies assembled chains and
	// records verdicts). Sourced from reference.conf; a non-positive value fails startup.
	AuditRunner AuditRunnerConfig
}

// HasConsumingLoop reports whether any loop consumes upstream credentials — a sink,
// chained, or aggregate role. Consuming loops perform verified-ingress storage and so
// accumulate predecessor holes that the async chain audit drains with L1-authenticated
// peer fetches.
func (c *Config) HasConsumingLoop() bool {
	for _, lc := range c.Loops {
		switch lc.Role {
		case RoleSink, RoleChained, RoleAggregate:
			return true
		}
	}
	return false
}

// AuditRunnerConfig is the node-level tuning for the async audit runner (slice-17h). All
// values come from reference.conf (no Go defaults) and must be positive; the runner runs
// only on a node with a consuming loop (the population that registers audit heads).
type AuditRunnerConfig struct {
	// Interval is the delay between audit ticks.
	Interval time.Duration
	// BatchSize is the max number of heads audited per tick.
	BatchSize int
	// MaxAttempts bounds a persistently-indeterminate NON-hole verdict before it is dropped
	// (a hole's liveness is governed by the unresolved pool, not this count).
	MaxAttempts int
}

// BatchResolverConfig is the node-level tuning for the async batch resolver (slice-17g).
// All values come from reference.conf (no Go-side defaults) and must be positive; the
// Runner runs only on a node with a consuming loop (it is the population that accumulates
// unresolved holes), but the tuning is always loaded.
type BatchResolverConfig struct {
	// Interval is the delay between drain ticks.
	Interval time.Duration
	// BatchSize is the max number of holes drained per tick.
	BatchSize int
	// MaxRetries is the transient-failure retry budget before a hole is dropped.
	MaxRetries int
	// MaxDepth bounds assembly: a hole at or beyond this distance from a consumed head is
	// dropped without fetching (the DoS backstop against an unbounded fabricated chain).
	MaxDepth int
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
	// Aggregate is populated when Role == RoleAggregate. Unlike the other roles it
	// consumes N upstream subjects (its own Ingresses list), so IngressSubject is
	// not read for the aggregate role.
	Aggregate AggregateConfig
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
	// PushIngress exposes this loop's ingress as an HTTP push endpoint on the node
	// listener (the apipush adapter, mounted at /ingest/<loop-name>/). The loop name
	// enters URL space, so loading validates it as a safe segment when set.
	PushIngress bool
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
	// Output is where this loop delivers consumed events (per-loop: each sink
	// loop is one delivery target).
	Output SinkOutputConfig
}

// SinkOutputConfig selects a sink loop's delivery surface. The in-repo surfaces
// are reference implementations (console for inspection, file for a durable
// NDJSON stream a consumer can tail without scraping process stdout); vendor
// adapters (EDC, warehouses, …) implement pipeline/contract in extension repos.
type SinkOutputConfig struct {
	// Type is SinkOutputConsole (default when the output block is absent) or
	// SinkOutputFile.
	Type string
	// Path is the NDJSON file to append to (file type only; required there, and
	// rejected on console — a path on a console output is a misconfig).
	Path string
}

// Sink output types.
const (
	SinkOutputConsole = "console"
	SinkOutputFile    = "file"
)

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

// AggregateIngress is one upstream the aggregate pools from: the granted upstream
// subject (a pipeline DID) and the endpoint where its credentials can later be
// fetched (the StoreIngressVC hint).
type AggregateIngress struct {
	Subject          string
	UpstreamEndpoint string
}

// AggregateConfig is an aggregate loop's producing identity + N-ary consuming side +
// window (Role == RoleAggregate). It produces a provin:aggregate FirstDrop (like a
// source) but consumes MULTIPLE Pipeline-conformant ingress subjects (unlike any
// single-ingress role), so the shared LoopConfig.IngressSubject is unused and the
// subjects live in Ingresses. The transformation-claim (provin:aggregate) and the
// source-root canonical (JCS) are fixed by the runtime, not config keys.
type AggregateConfig struct {
	// Producing side (mirrors SourceConfig minus SchemaRef/TransformationClaim).
	OutputSubject string
	Issuer        IssuerConfig
	PipelineID    string
	ProcessID     string
	// Consuming side. Ingresses is the set of upstream subjects to pool (≥1), loaded
	// from the aggregate.ingresses.<key> object map by sorted key. VerificationStrategy
	// is the per-input ingress depth (adjacent).
	Ingresses            []AggregateIngress
	VerificationStrategy string
	// Window is the fold trigger interval (> 0).
	Window time.Duration
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
	if err := validateProducingIdentities(out.Loops); err != nil {
		return nil, err
	}
	if out.VCStoreEndpoint, err = loadVCStoreEndpoint(cfg); err != nil {
		return nil, err
	}
	if cfg.Has(vcStoreBearerKey) {
		if out.VCStoreBearer, err = cfg.String(vcStoreBearerKey); err != nil {
			return nil, fmt.Errorf("pipeline: config %s: %w", vcStoreBearerKey, err)
		}
	}
	// The VC store sits behind L1 auth, so a configured endpoint needs a bearer — a
	// tokenless publish/resolve would be rejected at runtime. Fail closed at boot.
	if out.VCStoreEndpoint != "" && out.VCStoreBearer == "" {
		return nil, fmt.Errorf("pipeline: config %s requires %s (the VC store is L1-protected)", vcStoreEndpointKey, vcStoreBearerKey)
	}
	// A consuming loop drives the async chain audit, whose peer predecessor fetches
	// present this bearer against L1-protected peers. An empty bearer would not fail
	// until the first cross-node hole silently starves an audit at runtime, so it
	// fails closed at boot instead.
	if out.VCStoreBearer == "" && out.HasConsumingLoop() {
		return nil, fmt.Errorf("pipeline: a consuming loop (sink/chained/aggregate) requires %s — the async audit's peer fetches are L1-authenticated", vcStoreBearerKey)
	}
	if out.MaxCredentialSize, err = loadMaxCredentialSize(cfg); err != nil {
		return nil, err
	}
	if out.MaxPushBodySize, err = loadPositiveInt(cfg, maxPushBodySizeKey); err != nil {
		return nil, err
	}
	if out.BatchResolver, err = loadBatchResolver(cfg); err != nil {
		return nil, err
	}
	if out.AuditRunner, err = loadAuditRunner(cfg); err != nil {
		return nil, err
	}
	return out, nil
}

// loadAuditRunner reads the async audit-runner tuning from the (layered) config. All three
// values live in reference.conf (always present); each must be positive — a non-positive
// override fails startup (no Go-side defaults).
func loadAuditRunner(cfg *hoconconfig.Config) (AuditRunnerConfig, error) {
	var ar AuditRunnerConfig
	interval, err := cfg.Duration(arIntervalKey)
	if err != nil {
		return ar, fmt.Errorf("pipeline: config %s: %w", arIntervalKey, err)
	}
	ints := []struct {
		key string
		dst *int
	}{
		{arBatchSizeKey, &ar.BatchSize},
		{arMaxAttemptsKey, &ar.MaxAttempts},
	}
	for _, it := range ints {
		v, err := cfg.Int(it.key)
		if err != nil {
			return AuditRunnerConfig{}, fmt.Errorf("pipeline: config %s: %w", it.key, err)
		}
		if v <= 0 {
			return AuditRunnerConfig{}, fmt.Errorf("pipeline: config %s must be positive, got %d", it.key, v)
		}
		*it.dst = v
	}
	if interval <= 0 {
		return AuditRunnerConfig{}, fmt.Errorf("pipeline: config %s must be positive, got %s", arIntervalKey, interval)
	}
	ar.Interval = interval
	return ar, nil
}

// loadMaxCredentialSize reads the node-level per-credential byte cap from the (layered)
// config. The value lives in reference.conf, so it is always present; a non-positive
// override fails closed (a zero/negative cap would admit any size or reject everything).
func loadMaxCredentialSize(cfg *hoconconfig.Config) (int, error) {
	return loadPositiveInt(cfg, maxCredentialSizeKey)
}

// loadPositiveInt reads a required positive integer key from the (layered) config. The
// value lives in reference.conf, so it is always present; a non-positive override fails
// closed (a zero/negative byte cap would admit any size or reject everything).
func loadPositiveInt(cfg *hoconconfig.Config, key string) (int, error) {
	n, err := cfg.Int(key)
	if err != nil {
		return 0, fmt.Errorf("pipeline: config %s: %w", key, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("pipeline: config %s must be positive, got %d", key, n)
	}
	return n, nil
}

// loadBatchResolver reads the async batch-resolver tuning from the (layered) config. All
// four values live in reference.conf (always present); each must be positive — a
// non-positive override fails startup (no Go-side defaults).
func loadBatchResolver(cfg *hoconconfig.Config) (BatchResolverConfig, error) {
	var br BatchResolverConfig
	interval, err := cfg.Duration(brIntervalKey)
	if err != nil {
		return br, fmt.Errorf("pipeline: config %s: %w", brIntervalKey, err)
	}
	ints := []struct {
		key string
		dst *int
	}{
		{brBatchSizeKey, &br.BatchSize},
		{brMaxRetriesKey, &br.MaxRetries},
		{brMaxDepthKey, &br.MaxDepth},
	}
	for _, it := range ints {
		v, err := cfg.Int(it.key)
		if err != nil {
			return BatchResolverConfig{}, fmt.Errorf("pipeline: config %s: %w", it.key, err)
		}
		if v <= 0 {
			return BatchResolverConfig{}, fmt.Errorf("pipeline: config %s must be positive, got %d", it.key, v)
		}
		*it.dst = v
	}
	if interval <= 0 {
		return BatchResolverConfig{}, fmt.Errorf("pipeline: config %s must be positive, got %s", brIntervalKey, interval)
	}
	br.Interval = interval
	return br, nil
}

// producingIdentity extracts a producing loop's (output subject, issuer DID);
// ok is false for consuming-only roles.
func producingIdentity(lc LoopConfig) (subject, issuer string, ok bool) {
	switch lc.Role {
	case RoleSource:
		return lc.Source.OutputSubject, lc.Source.Issuer.DID, true
	case RoleChained:
		return lc.Chained.OutputSubject, lc.Chained.Issuer.DID, true
	case RoleAggregate:
		return lc.Aggregate.OutputSubject, lc.Aggregate.Issuer.DID, true
	}
	return "", "", false
}

// validateProducingIdentities enforces the two cross-loop boot invariants the
// emission-log exposure rests on (tlog spec):
//
//	(a) producing output-subjects are unique per node — the output subject is
//	    the loop's emission-log identity, and two loops sharing one would
//	    interleave two sequence spaces into one "log";
//	(b) each producing issuer structurally belongs to its output subject
//	    (issuer.PipelineDID() == output-subject) — the property that lets a
//	    consumer check a tlog checkpoint's signed_by against its log id.
func validateProducingIdentities(loops []LoopConfig) error {
	bySubject := map[string]string{}
	for _, lc := range loops {
		subject, issuer, ok := producingIdentity(lc)
		if !ok {
			continue
		}
		if other, dup := bySubject[subject]; dup {
			return fmt.Errorf("pipeline: loops %q and %q share output-subject %q — a producing output subject is the loop's emission-log identity and must be unique per node", other, lc.Name, subject)
		}
		bySubject[subject] = lc.Name
		d, err := dplaax.Parse(issuer)
		if err != nil {
			// loadIssuer already validated the shape; defensive.
			return fmt.Errorf("pipeline: loop %q: issuer %q: %w", lc.Name, issuer, err)
		}
		pipelineDID := d.PipelineDID()
		if pipelineDID == nil {
			// loadIssuer requires a process DID, which always has a pipeline
			// ancestor; defensive against a future load-path change.
			return fmt.Errorf("pipeline: loop %q: issuer %q has no pipeline ancestor", lc.Name, issuer)
		}
		if pipelineDID.String() != subject {
			return fmt.Errorf("pipeline: loop %q: issuer %q does not belong to output-subject %q — the issuer's pipeline DID must equal the output subject (a tlog checkpoint's signed_by must be verifiable against its log id)", lc.Name, issuer, subject)
		}
	}
	return nil
}

// loadVCStoreEndpoint reads the optional node-level vc-store-endpoint. Absent is "" (no
// publication; full unavailable). Present must be a clean http/https base URL: the Connect
// client appends the RPC procedure to this string verbatim, so a query or fragment would
// corrupt every request path — reject those at boot rather than fail every RPC at runtime.
func loadVCStoreEndpoint(cfg *hoconconfig.Config) (string, error) {
	if !cfg.Has(vcStoreEndpointKey) {
		return "", nil
	}
	v, err := cfg.String(vcStoreEndpointKey)
	if err != nil {
		return "", fmt.Errorf("pipeline: config %s: %w", vcStoreEndpointKey, err)
	}
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("pipeline: config %s: %q is not an http(s) URL", vcStoreEndpointKey, v)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("pipeline: config %s: %q must be a base URL with no query or fragment", vcStoreEndpointKey, v)
	}
	return v, nil
}

// sourceKeys / sinkKeys / chainedKeys are the role-exclusive config keys. The loader
// rejects keys from the OTHER roles' sets so a loop cannot silently carry fields it does
// not use (e.g. an issuer block under a sink, or a sink block under a chained loop).
// Source fields are top-level (17b shape); sink and chained fields nest under their block.
var (
	sourceKeys    = []string{"output-subject", "issuer", "pipeline-id", "process-id", "transformation-claim", "schema-ref", "push-ingress"}
	sinkKeys      = []string{"sink"}
	chainedKeys   = []string{"chained"}
	aggregateKeys = []string{"aggregate"}
)

func loadLoop(cfg *hoconconfig.Config, name string) (LoopConfig, error) {
	base := loopsKey + "." + name
	lc := LoopConfig{Name: name}

	role, err := requireString(cfg, base+".role")
	if err != nil {
		return lc, err
	}
	lc.Role = role

	// ingress-subject is the shared single-ingress field for source/sink/chained. The
	// aggregate role consumes N subjects from its own aggregate.ingresses map, so it
	// does not read ingress-subject — the requirement is per-role below.
	switch role {
	case RoleSource:
		if lc.IngressSubject, err = requireString(cfg, base+".ingress-subject"); err != nil {
			return lc, err
		}
		if err := rejectKeys(cfg, base, name, role, sinkKeys, chainedKeys, aggregateKeys); err != nil {
			return lc, err
		}
		if lc.Source, err = loadSourceConfig(cfg, base, name); err != nil {
			return lc, err
		}
	case RoleSink:
		if lc.IngressSubject, err = requireString(cfg, base+".ingress-subject"); err != nil {
			return lc, err
		}
		if err := rejectKeys(cfg, base, name, role, sourceKeys, chainedKeys, aggregateKeys); err != nil {
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
		if lc.IngressSubject, err = requireString(cfg, base+".ingress-subject"); err != nil {
			return lc, err
		}
		if err := rejectKeys(cfg, base, name, role, sourceKeys, sinkKeys, aggregateKeys); err != nil {
			return lc, err
		}
		// Like a sink, a chained loop's ingress is the granted upstream pipeline DID.
		if err := requirePipelineDID(lc.IngressSubject, name, "ingress-subject"); err != nil {
			return lc, err
		}
		if lc.Chained, err = loadChainedConfig(cfg, base, name); err != nil {
			return lc, err
		}
		// A relay publishing back to its own ingress would consume its own output and
		// re-sign indefinitely (the nats connection does not suppress self-delivery) — a
		// message storm. Fail closed on equal ingress/output subjects.
		if lc.Chained.OutputSubject == lc.IngressSubject {
			return lc, fmt.Errorf("pipeline: loop %q: chained.output-subject %q must differ from ingress-subject (a relay must not publish back to its own ingress)", name, lc.Chained.OutputSubject)
		}
	case RoleAggregate:
		// An aggregate lists its N subjects under aggregate.ingresses, so a stray shared
		// ingress-subject is a misconfiguration — reject it (fail-closed) rather than
		// silently ignoring it. (ingress-subject is the shared key, not in any role set.)
		if cfg.Has(base + ".ingress-subject") {
			return lc, fmt.Errorf("pipeline: loop %q: key %q does not belong to role %q (an aggregate lists its subjects under aggregate.ingresses)", name, "ingress-subject", role)
		}
		if err := rejectKeys(cfg, base, name, role, sourceKeys, sinkKeys, chainedKeys); err != nil {
			return lc, err
		}
		if lc.Aggregate, err = loadAggregateConfig(cfg, base, name); err != nil {
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

	// push-ingress (optional, default false) exposes the loop's ingress as an HTTP
	// push endpoint. The loop name becomes a URL path segment (/ingest/<name>/), so
	// it must satisfy the safe-segment rule — but only when the name actually enters
	// URL space (no retroactive breakage for NATS-only loops).
	if cfg.Has(base + ".push-ingress") {
		if sc.PushIngress, err = cfg.Bool(base + ".push-ingress"); err != nil {
			return sc, fmt.Errorf("pipeline: loop %q: config push-ingress: %w", name, err)
		}
		if sc.PushIngress && !dplaax.IsSafeSegment(name) {
			return sc, fmt.Errorf("pipeline: loop %q: push-ingress requires a URL-safe loop name ([a-zA-Z0-9._-], not all dots) — the name becomes the /ingest/<name>/ path segment", name)
		}
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

	if sc.VerificationStrategy, err = loadStrategy(cfg, base+".sink.verification-strategy", name); err != nil {
		return sc, err
	}

	if sc.UpstreamEndpoint, err = requireString(cfg, base+".sink.upstream-endpoint"); err != nil {
		return sc, err
	}

	if sc.Output, err = loadSinkOutput(cfg, base, name); err != nil {
		return sc, err
	}

	return sc, nil
}

// loadSinkOutput reads the optional sink.output block. Absent == console (the
// pre-existing stdout behaviour); file requires a path; a path on console is
// rejected as a misconfig (the operator almost certainly meant type = "file").
func loadSinkOutput(cfg *hoconconfig.Config, base, name string) (SinkOutputConfig, error) {
	out := SinkOutputConfig{Type: SinkOutputConsole}
	typeKey, pathKey := base+".sink.output.type", base+".sink.output.path"
	if cfg.Has(typeKey) {
		t, err := requireString(cfg, typeKey)
		if err != nil {
			return out, err
		}
		out.Type = t
	}
	if cfg.Has(pathKey) {
		p, err := cfg.String(pathKey)
		if err != nil {
			return out, fmt.Errorf("pipeline: config %s: %w", pathKey, err)
		}
		out.Path = p
	}
	switch out.Type {
	case SinkOutputConsole:
		if out.Path != "" {
			return out, fmt.Errorf("pipeline: loop %q: sink.output.path is set but type is %q — a console output takes no path (want type = %q?)", name, SinkOutputConsole, SinkOutputFile)
		}
	case SinkOutputFile:
		if out.Path == "" {
			return out, fmt.Errorf("pipeline: loop %q: sink.output.type %q requires sink.output.path", name, SinkOutputFile)
		}
	default:
		return out, fmt.Errorf("pipeline: loop %q: unknown sink.output.type %q (want %q|%q)", name, out.Type, SinkOutputConsole, SinkOutputFile)
	}
	return out, nil
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

// loadStrategy reads a verification-strategy that must be "adjacent"; anything else
// (including the retired "full", slice-17j) is a typed boot error. Full-chain coverage is
// the async audit runner's job, not a real-time ingress strategy.
func loadStrategy(cfg *hoconconfig.Config, key, name string) (string, error) {
	s, err := requireString(cfg, key)
	if err != nil {
		return "", err
	}
	switch s {
	case StrategyAdjacent:
		return s, nil
	default:
		return "", fmt.Errorf("pipeline: loop %q: unknown verification-strategy %q (want %q)", name, s, StrategyAdjacent)
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
	if cc.VerificationStrategy, err = loadStrategy(cfg, cbase+".verification-strategy", name); err != nil {
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

// loadAggregateConfig validates an aggregate loop's producing identity + N-ary
// consuming side + window. Producing/issuer rules mirror a source; the ingresses are
// an object-keyed map (aggregate.ingresses.<key> { subject, upstream-endpoint }) loaded
// by sorted key for determinism. Fails closed on: an empty ingress set, a malformed
// subject/endpoint, a duplicate ingress subject, output-subject equal to any ingress
// subject (self-consumption), an unknown strategy, or a non-positive window.
func loadAggregateConfig(cfg *hoconconfig.Config, base, name string) (AggregateConfig, error) {
	var ac AggregateConfig
	var err error
	abase := base + ".aggregate"

	if ac.OutputSubject, err = requireString(cfg, abase+".output-subject"); err != nil {
		return ac, err
	}
	if err := requirePipelineDID(ac.OutputSubject, name, "aggregate.output-subject"); err != nil {
		return ac, err
	}
	if ac.Issuer, err = loadIssuer(cfg, abase, name, "aggregate.issuer"); err != nil {
		return ac, err
	}
	if ac.PipelineID, err = requireString(cfg, abase+".pipeline-id"); err != nil {
		return ac, err
	}
	if ac.ProcessID, err = requireString(cfg, abase+".process-id"); err != nil {
		return ac, err
	}
	if ac.VerificationStrategy, err = loadStrategy(cfg, abase+".verification-strategy", name); err != nil {
		return ac, err
	}
	if !cfg.Has(abase + ".window") {
		return ac, fmt.Errorf("pipeline: loop %q: aggregate.window is required", name)
	}
	if ac.Window, err = cfg.Duration(abase + ".window"); err != nil {
		return ac, fmt.Errorf("pipeline: loop %q: config aggregate.window: %w", name, err)
	}
	if ac.Window <= 0 {
		return ac, fmt.Errorf("pipeline: loop %q: aggregate.window must be > 0 (got %s)", name, ac.Window)
	}

	// Ingresses: an object-keyed map, loaded by sorted key for a deterministic order.
	if !cfg.Has(abase + ".ingresses") {
		return ac, fmt.Errorf("pipeline: loop %q: aggregate.ingresses is required (at least one entry)", name)
	}
	keys, err := cfg.Keys(abase + ".ingresses")
	if err != nil {
		return ac, fmt.Errorf("pipeline: loop %q: config aggregate.ingresses: %w", name, err)
	}
	if len(keys) == 0 {
		return ac, fmt.Errorf("pipeline: loop %q: aggregate.ingresses must have at least one entry", name)
	}
	// Sort the ingress keys for a deterministic Ingresses order: the consumed set feeds
	// the fold + source commitment, so a stable order is load-bearing. (The top-level
	// loops loader does NOT sort — loop order is not semantically significant there.)
	sort.Strings(keys)
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		ibase := abase + ".ingresses." + k
		// Parse all per-ingress fields first, then apply the cross-field guards.
		var ing AggregateIngress
		if ing.Subject, err = requireString(cfg, ibase+".subject"); err != nil {
			return ac, err
		}
		if err := requirePipelineDID(ing.Subject, name, "aggregate.ingresses."+k+".subject"); err != nil {
			return ac, err
		}
		if ing.UpstreamEndpoint, err = requireString(cfg, ibase+".upstream-endpoint"); err != nil {
			return ac, err
		}
		if seen[ing.Subject] {
			return ac, fmt.Errorf("pipeline: loop %q: duplicate aggregate ingress subject %q", name, ing.Subject)
		}
		if ing.Subject == ac.OutputSubject {
			return ac, fmt.Errorf("pipeline: loop %q: aggregate.output-subject %q must differ from every ingress subject (an aggregate must not consume its own output)", name, ac.OutputSubject)
		}
		seen[ing.Subject] = true
		ac.Ingresses = append(ac.Ingresses, ing)
	}
	return ac, nil
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
