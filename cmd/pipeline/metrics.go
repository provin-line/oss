/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package main

// The /metrics bridge for cmd/pipeline (PR3c follow-up — see main.go's own
// meterScope doc): copied and adapted from internal/netcompose/metrics.go's
// OTel/Prometheus composition-root bridge. This binary may not import
// internal/netcompose at all (depsguard_test.go's
// TestProdDeps_NoRegistryServerCodeInPipelineBinary pins the ban), so the
// ~65-line bridge is duplicated here rather than shared — the SAME
// duplication cmd/network's own copy (via netcompose) would otherwise force,
// just on the other side of the layer boundary this binary must not cross.
//
// Unlike internal/netcompose.BuildMetricsHandler (loops always nil for
// cmd/network — it composes no data-plane loops of its own; verdicts from
// its OWN audit runner), this binary mounts the data-plane loop families
// ONLY — pipeline/runtime.LoopMetrics (dp.Metrics()) directly, via the SAME
// Emits/Stripped/Verify accessor shape internal/netcompose's own LoopMetrics
// uses (pipeline/runtime/metrics.go's own doc: "Field-shape mirrors
// internal/netcompose's own LoopMetrics ... a composition root field-copies
// between the two" — no field-copy is even needed here, since
// pipeline/runtime.LoopMetrics structurally satisfies what this file needs
// directly). There is no verdicts parameter and no provin_audit_verdicts_total
// family: cmd/pipeline runs no audit runner (that is cmd/network's own
// /metrics concern, network/pkg's own audit-runner never runs here).

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

	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// BuildMetricsHandler assembles the OTel meter provider over a DEDICATED
// Prometheus registry (no default-registry collectors leak in) and registers
// the THREE data-plane counter families — emit attempts, stripped-publish
// failures, verify results — over loops' polled sources. scope is the OTel
// instrumentation-scope name (this binary's own import path — meterScope in
// main.go). Mirrors internal/netcompose.BuildMetricsHandler minus the
// verdicts parameter and the provin.audit.verdicts instrument: this binary
// runs no audit runner, so that family can never apply here.
func BuildMetricsHandler(scope string, loops []pipelineruntime.LoopMetrics) (http.Handler, error) {
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("pipeline: metrics exporter: %w", err)
	}
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter)).
		Meter(scope)

	emitAttempts, err := meter.Int64ObservableCounter("provin.pipeline.emit.attempts",
		metric.WithDescription("Emit outcomes per producing loop, keyed on the Emit call's return (success = primary form delivered)."))
	if err != nil {
		return nil, fmt.Errorf("pipeline: metrics instrument provin.pipeline.emit.attempts: %w", err)
	}
	strippedFailures, err := meter.Int64ObservableCounter("provin.pipeline.emit.stripped_failures",
		metric.WithDescription("Stripped-publish (dual-emit) failures per dual-emitting loop; the primary delivery already succeeded."))
	if err != nil {
		return nil, fmt.Errorf("pipeline: metrics instrument provin.pipeline.emit.stripped_failures: %w", err)
	}
	verifyResults, err := meter.Int64ObservableCounter("provin.pipeline.verify.results",
		metric.WithDescription("Per-credential verifier API outcomes per consuming loop (the seam below the loop's accept/reject policy)."))
	if err != nil {
		return nil, fmt.Errorf("pipeline: metrics instrument provin.pipeline.verify.results: %w", err)
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
		return nil
	}, emitAttempts, strippedFailures, verifyResults)
	if err != nil {
		return nil, fmt.Errorf("pipeline: metrics callback: %w", err)
	}

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), nil
}

// WithMetrics mounts the metrics exposition at /metrics beside inner, which
// keeps every other route — main composes this OUTSIDE buildHandler, same
// as internal/netcompose.WithMetrics/cmd/network's own composition, so the
// control-plane-shaped HTTP wiring in buildHandler stays metrics-agnostic
// and the endpoint exists only when config enables it (default off; see
// core reference.conf).
func WithMetrics(inner, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics)
	mux.Handle("/", inner)
	return mux
}

// MaybeMountMetrics is the config gate main serves through: with metrics
// disabled (the default) it returns inner UNCHANGED — no /metrics route, no
// exporter, no SDK — and with it enabled it composes the bridge over
// dp.Metrics(). Mirrors internal/netcompose.MaybeMountMetrics minus the
// verdicts parameter (see BuildMetricsHandler's doc for why).
func MaybeMountMetrics(scope string, enabled bool, inner http.Handler, loops []pipelineruntime.LoopMetrics) (http.Handler, error) {
	if !enabled {
		return inner, nil
	}
	metricsHandler, err := BuildMetricsHandler(scope, loops)
	if err != nil {
		return nil, err
	}
	return WithMetrics(inner, metricsHandler), nil
}
