package netcompose

// The /metrics bridge (P1-2): the ONLY place OpenTelemetry (and its
// Prometheus exporter) enters the module. Library packages stay
// dependency-free and expose poll accessors (transport.Emitter counters,
// verifycount snapshots, auditor.Runner.VerdictCounts); this composition-root
// bridge reads them at collect time through ObservableCounters — the OTel
// async-instrument idiom for externally-maintained monotonic counts. A deps
// guard test pins the boundary (metrics_deps_guard_test.go).
//
// Family-presence contract: an instrument is observed only for loops holding
// the capability (emit for producers, stripped for dual-emitters, verify for
// consumers; audit verdicts when a runner exists), and a registered
// capability is ALWAYS observed — zero-valued series included — so "family
// present ⇔ capability configured" is a stable Prometheus contract. The
// exporter's default name translation renders the stable OTel names
// (provin.pipeline.emit.attempts, …) as provin_pipeline_emit_attempts_total
// etc. (underscores, counter _total suffix).

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// EmitCounters is the emit-outcome accessor pair every producing handle
// (transport.Loop, aggregate.Process) exposes — the metrics bridge's poll
// seam. Relocated here (formerly cmd/standalone/dataplane.go) alongside
// LoopMetrics, the struct it is a field type of.
type EmitCounters interface {
	EmitSuccesses() uint64
	EmitFailures() uint64
}

// StrippedCounter is the stripped-publish failure accessor producing handles
// expose; registered only for loops that actually dual-emit.
type StrippedCounter interface {
	StrippedPublishFailures() uint64
}

// VerifyCounts is the per-loop verify-outcome snapshot the metrics bridge
// polls — satisfied by *verifycount.Verifier.
type VerifyCounts interface {
	Snapshot() map[string]uint64
}

// LoopMetrics is one loop's metrics wiring for the composition root's
// /metrics bridge (P1-2): Name becomes the series' `loop` attribute, Role
// records which capability set the wiring followed (test/bookkeeping only —
// not a series attribute), and the non-nil accessors decide which metric
// families the loop participates in (nil = the loop does not have that
// capability, so no series is registered — family presence is the capability
// contract). Fields are exported so a data-plane composer can construct and
// populate these directly as it builds each loop. cmd/network's own
// composition never runs producing/consuming loops, so it always passes nil
// here; cmd/pipeline (the data-plane composer) does not import netcompose at
// all (AGENTS.md layer rule 2) and does not yet mount this bridge — see its
// package doc.
type LoopMetrics struct {
	Name string
	Role string // pipelineconfig.Role* value
	// Emits is non-nil for producing loops (source/chained/aggregate).
	Emits EmitCounters
	// Stripped is non-nil when the loop dual-emits (a PayloadStore is wired).
	Stripped StrippedCounter
	// Verify is non-nil for consuming loops (sink/chained/aggregate).
	Verify VerifyCounts
}

// BuildMetricsHandler assembles the OTel meter provider over a DEDICATED
// Prometheus registry (no default-registry collectors leak in) and registers
// the four stable counter families over the polled sources. scope is the
// OTel instrumentation-scope name (the calling binary's own import path, e.g.
// "github.com/provin-line/oss/cmd/network") — every node binary composing
// this bridge self-identifies rather than borrowing another binary's name.
// verdicts is the audit runner's VerdictCounts, or nil when the node runs no
// audit runner (the family is then absent). The returned handler serves the
// exposition; the caller mounts it (see WithMetrics).
func BuildMetricsHandler(scope string, loops []LoopMetrics, verdicts func() map[string]uint64) (http.Handler, error) {
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics exporter: %w", err)
	}
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)).
		Meter(scope)

	emitAttempts, err := meter.Int64ObservableCounter("provin.pipeline.emit.attempts",
		metric.WithDescription("Emit outcomes per producing loop, keyed on the Emit call's return (success = primary form delivered)."))
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics instrument provin.pipeline.emit.attempts: %w", err)
	}
	strippedFailures, err := meter.Int64ObservableCounter("provin.pipeline.emit.stripped_failures",
		metric.WithDescription("Stripped-publish (dual-emit) failures per dual-emitting loop; the primary delivery already succeeded."))
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics instrument provin.pipeline.emit.stripped_failures: %w", err)
	}
	verifyResults, err := meter.Int64ObservableCounter("provin.pipeline.verify.results",
		metric.WithDescription("Per-credential verifier API outcomes per consuming loop (the seam below the loop's accept/reject policy)."))
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics instrument provin.pipeline.verify.results: %w", err)
	}
	auditVerdicts, err := meter.Int64ObservableCounter("provin.audit.verdicts",
		metric.WithDescription("Durably recorded audit verdict writes by linear-chain overall verdict (writes, not audited heads)."))
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics instrument provin.audit.verdicts: %w", err)
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for _, lm := range loops {
			loopAttr := attribute.String("loop", lm.Name)
			if lm.Emits != nil {
				o.ObserveInt64(emitAttempts, int64(lm.Emits.EmitSuccesses()),
					metric.WithAttributes(loopAttr, attribute.String("outcome", "success")))
				o.ObserveInt64(emitAttempts, int64(lm.Emits.EmitFailures()),
					metric.WithAttributes(loopAttr, attribute.String("outcome", "failure")))
			}
			if lm.Stripped != nil {
				o.ObserveInt64(strippedFailures, int64(lm.Stripped.StrippedPublishFailures()),
					metric.WithAttributes(loopAttr))
			}
			if lm.Verify != nil {
				for outcome, n := range lm.Verify.Snapshot() {
					o.ObserveInt64(verifyResults, int64(n),
						metric.WithAttributes(loopAttr, attribute.String("outcome", outcome)))
				}
			}
		}
		if verdicts != nil {
			for verdict, n := range verdicts() {
				o.ObserveInt64(auditVerdicts, int64(n),
					metric.WithAttributes(attribute.String("verdict", verdict)))
			}
		}
		return nil
	}, emitAttempts, strippedFailures, verifyResults, auditVerdicts)
	if err != nil {
		return nil, fmt.Errorf("netcompose: metrics callback: %w", err)
	}

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), nil
}

// WithMetrics mounts the metrics exposition at /metrics beside inner, which
// keeps every other route — main composes this OUTSIDE BuildHandler so the
// control-plane wiring stays metrics-agnostic and the endpoint exists only
// when config enables it (default off; see core reference.conf).
func WithMetrics(inner, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics)
	mux.Handle("/", inner)
	return mux
}

// MaybeMountMetrics is the config gate main serves through: with metrics
// disabled (the default) it returns inner UNCHANGED — no /metrics route, no
// exporter, no SDK — and with it enabled it composes the bridge over the
// node's polled sources. scope is passed straight through to
// BuildMetricsHandler — the calling binary's own import path. verdicts may
// be nil (no audit runner). Extracted from main so the default-off security
// ruling is testable.
func MaybeMountMetrics(scope string, enabled bool, inner http.Handler, loops []LoopMetrics, verdicts func() map[string]uint64) (http.Handler, error) {
	if !enabled {
		return inner, nil
	}
	metricsHandler, err := BuildMetricsHandler(scope, loops, verdicts)
	if err != nil {
		return nil, err
	}
	return WithMetrics(inner, metricsHandler), nil
}
