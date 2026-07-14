package main

// The /metrics bridge (P1-2): the ONLY place OpenTelemetry (and its
// Prometheus exporter) enters the module. Library packages stay
// dependency-free and expose poll accessors (transport.Emitter counters,
// verifycount snapshots, auditor.Runner.VerdictCounts); this composition-root
// bridge reads them at collect time through ObservableCounters — the OTel
// async-instrument idiom for externally-maintained monotonic counts. A deps
// guard test pins the boundary (deps_guard_test.go).
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

// buildMetricsHandler assembles the OTel meter provider over a DEDICATED
// Prometheus registry (no default-registry collectors leak in) and registers
// the four stable counter families over the polled sources. verdicts is the
// audit runner's VerdictCounts, or nil when the node runs no audit runner
// (the family is then absent). The returned handler serves the exposition;
// the caller mounts it (see withMetrics).
func buildMetricsHandler(loops []loopMetrics, verdicts func() map[string]uint64) (http.Handler, error) {
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("standalone: metrics exporter: %w", err)
	}
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)).
		Meter("github.com/provin-line/oss/cmd/standalone")

	emitAttempts, err := meter.Int64ObservableCounter("provin.pipeline.emit.attempts",
		metric.WithDescription("Emit outcomes per producing loop, keyed on the Emit call's return (success = primary form delivered)."))
	if err != nil {
		return nil, fmt.Errorf("standalone: metrics instrument provin.pipeline.emit.attempts: %w", err)
	}
	strippedFailures, err := meter.Int64ObservableCounter("provin.pipeline.emit.stripped_failures",
		metric.WithDescription("Stripped-publish (dual-emit) failures per dual-emitting loop; the primary delivery already succeeded."))
	if err != nil {
		return nil, fmt.Errorf("standalone: metrics instrument provin.pipeline.emit.stripped_failures: %w", err)
	}
	verifyResults, err := meter.Int64ObservableCounter("provin.pipeline.verify.results",
		metric.WithDescription("Per-credential verifier API outcomes per consuming loop (the seam below the loop's accept/reject policy)."))
	if err != nil {
		return nil, fmt.Errorf("standalone: metrics instrument provin.pipeline.verify.results: %w", err)
	}
	auditVerdicts, err := meter.Int64ObservableCounter("provin.audit.verdicts",
		metric.WithDescription("Durably recorded audit verdict writes by linear-chain overall verdict (writes, not audited heads)."))
	if err != nil {
		return nil, fmt.Errorf("standalone: metrics instrument provin.audit.verdicts: %w", err)
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for _, lm := range loops {
			loopAttr := attribute.String("loop", lm.name)
			if lm.emits != nil {
				o.ObserveInt64(emitAttempts, int64(lm.emits.EmitSuccesses()),
					metric.WithAttributes(loopAttr, attribute.String("outcome", "success")))
				o.ObserveInt64(emitAttempts, int64(lm.emits.EmitFailures()),
					metric.WithAttributes(loopAttr, attribute.String("outcome", "failure")))
			}
			if lm.stripped != nil {
				o.ObserveInt64(strippedFailures, int64(lm.stripped.StrippedPublishFailures()),
					metric.WithAttributes(loopAttr))
			}
			if lm.verify != nil {
				for outcome, n := range lm.verify.Snapshot() {
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
		return nil, fmt.Errorf("standalone: metrics callback: %w", err)
	}

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), nil
}

// withMetrics mounts the metrics exposition at /metrics beside inner, which
// keeps every other route — main composes this OUTSIDE BuildHandler so the
// control-plane wiring stays metrics-agnostic and the endpoint exists only
// when config enables it (default off; see core reference.conf).
func withMetrics(inner, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics)
	mux.Handle("/", inner)
	return mux
}

// maybeMountMetrics is the config gate main serves through: with metrics
// disabled (the default) it returns inner UNCHANGED — no /metrics route, no
// exporter, no SDK — and with it enabled it composes the bridge over the
// node's polled sources. verdicts may be nil (no audit runner). Extracted
// from main so the default-off security ruling is testable.
func maybeMountMetrics(enabled bool, inner http.Handler, loops []loopMetrics, verdicts func() map[string]uint64) (http.Handler, error) {
	if !enabled {
		return inner, nil
	}
	metricsHandler, err := buildMetricsHandler(loops, verdicts)
	if err != nil {
		return nil, err
	}
	return withMetrics(inner, metricsHandler), nil
}
