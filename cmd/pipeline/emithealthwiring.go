package main

// EmitHealth reporter wiring (PR3b Task 7, Task 10 D4): this binary reports
// each by-reference PUBLISHER's stripped-publish health via
// ChainService.ReportEmitHealth so a report-mode registry (cmd/network,
// chainmanager.WithPublisherHealth backed by
// network/pkg/services/chainmanager/emithealth.Store) can gate by-reference
// advertisement per publisher instead of leaving it permanently degraded —
// with no reporter ever calling in, every publisher reads NeverReported
// forever, and advertise-without-reports=false then NEVER offers
// by-reference for it. buildDeps (wiring.go) wires a PayloadStore
// unconditionally, so — per D-6, "PayloadStore wired ⇒ every producing loop
// dual-emits, no per-loop opt-out" — every producing loop this binary runs
// is such a publisher.
//
// Identity (IMPORTANT, and a deliberate departure from a looser "sign as the
// loop's issuer" reading): the reported publisher_did — and the wireauth
// identity that signs it, since the handler enforces signer_did ==
// publisher_did (network/pkg/services/chainmanager/handler/operator.go,
// ReportEmitHealth) — MUST be the loop's own PIPELINE DID (its
// OutputSubject), never its process-scoped issuer DID. This is not a style
// choice: chainmanager's subscription flow (Service.admit, called from both
// PublisherInfo and RegisterSubscription) runs requirePipelineDID on the
// publisherDID argument BEFORE ever consulting the health store, so
// publisherHealthLookup is only ever queried with a Pipeline DID
// (did:dplaax:{registry}:{type}:{id}:pipeline:{id}, no :process: suffix) —
// see network/pkg/services/chainmanager/service_peer.go and service.go's
// requirePipelineDID. A report filed under a process-scoped issuer DID would
// still succeed on the wire (that identity's #auth key already exists, and
// resolves fine — it is used for credential issuance) while never being
// found by that lookup, silently leaving the gate permanently degraded
// despite reports "succeeding". Reporting under OutputSubject is therefore
// the only choice consistent with the actual wire contract, though it does
// mean the operator/CLI provisioning step this binary's own keystore doc
// comment (main.go) describes must ALSO provision a #auth key for every
// producing loop's OutputSubject, not only its issuer DID — see main.go's
// keyStore doc for the updated provisioning note.
import (
	"context"
	"log"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/reportclient"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// emitHealthReportClient is cmd/pipeline's own narrow dependency on
// ChainService's ReportEmitHealth RPC. *reportclient.Client satisfies it
// structurally. A local interface (rather than the concrete type) lets
// emitHealthReporter's cadence be driven by a spy in tests without a live
// wire round trip; this file otherwise uses reportclient.Client directly
// (this binary is free to import network/, unlike pipeline/tlogship, whose
// own MirrorClient interface exists for the AGENTS.md layer rule instead).
type emitHealthReportClient interface {
	ReportEmitHealth(ctx context.Context, publisherDID string, healthy bool) (time.Duration, error)
}

// reportClientFactory builds and caches one reportclient.Client per
// publisher identity (DID) — mirrors mirrorClientFactory/auditClientFactory
// exactly. Safe for concurrent use.
type reportClientFactory struct {
	signer     crypto.Signer
	baseURL    string
	bearer     string
	httpClient connect.HTTPClient

	mu      sync.Mutex
	clients map[string]*reportclient.Client
}

func newReportClientFactory(signer crypto.Signer, baseURL, bearer string, httpClient connect.HTTPClient) *reportClientFactory {
	return &reportClientFactory{signer: signer, baseURL: baseURL, bearer: bearer, httpClient: httpClient, clients: map[string]*reportclient.Client{}}
}

// For returns the cached client signing/reporting as publisherDID, building
// and caching one on first use.
func (f *reportClientFactory) For(publisherDID string) *reportclient.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[publisherDID]; ok {
		return c
	}
	c := reportclient.New(reportclient.Config{
		Signer:     f.signer,
		SignerDID:  publisherDID,
		BaseURL:    f.baseURL,
		HTTPClient: f.httpClient,
		Bearer:     f.bearer,
	})
	f.clients[publisherDID] = c
	return c
}

// forClient adapts For to buildEmitHealthReporters' reportClientFor seam.
func (f *reportClientFactory) forClient(publisherDID string) emitHealthReportClient {
	return f.For(publisherDID)
}

// minEmitHealthCadence floors the reporting cadence: a TTL small enough to
// imply a sub-5s report interval would flood the registry with no
// operational benefit — no real dependency needs sub-5s freshness. This is
// the floor for the INITIAL/fallback cadence (emitHealthCadence, below,
// seeded from this binary's OWN chainCfg.EmitHealth.TTL config); the
// steady-state cadence (cadenceFromReturnedTTL) uses the SAME numeric floor
// but lets it yield to a tighter registry-returned TTL — see that function's
// doc for why an unconditional floor is wrong there.
const minEmitHealthCadence = 5 * time.Second

// minAbsoluteEmitHealthCadence is the hard floor cadenceFromReturnedTTL never
// goes below, regardless of how short the registry's returned TTL is — a
// degenerate near-zero TTL must not report-storm the registry even though
// honoring it exactly would imply an even shorter interval.
const minAbsoluteEmitHealthCadence = 1 * time.Second

// emitHealthCadence derives the ReportEmitHealth ticking interval from the
// configured TTL (chainCfg.EmitHealth.TTL, provin.network.chain.emit-health.
// ttl): TTL/3, so at least two reports land inside every freshness window
// even if one is delayed or dropped, floored at minEmitHealthCadence. This
// seeds ONLY the reporter's INITIAL interval (main.go) — every report after
// the first re-derives its OWN next interval from the REGISTRY's actually
// returned TTL via cadenceFromReturnedTTL, below, since the registry (not
// this binary's local config) is authoritative over how long a report stays
// fresh (P2 Codex).
func emitHealthCadence(ttl time.Duration) time.Duration {
	if c := ttl / 3; c > minEmitHealthCadence {
		return c
	}
	return minEmitHealthCadence
}

// cadenceFromReturnedTTL derives the reporter's NEXT cadence from the
// REGISTRY's own returned TTL (reportclient.Client.ReportEmitHealth's
// response — the registry is authoritative over freshness, not this
// binary's local chainCfg.EmitHealth.TTL config, which only seeds the
// INITIAL cadence via emitHealthCadence, above). Ideally ttl/3 (so at least
// two reports land inside every freshness window even if one is delayed),
// floored at minEmitHealthCadence — but that floor must itself YIELD when
// applying it would push the cadence PAST ttl/2: a reporter that lands only
// once per freshness window, with no margin, is one delayed/dropped report
// away from the registry expiring it. So the floor is capped at ttl/2
// instead of applied unconditionally, with minAbsoluteEmitHealthCadence as
// the last-resort floor under a degenerate near-zero ttl. A non-positive ttl
// (a misbehaving or older registry that never sets the field) is reported by
// returning 0 — the caller (report, below) then leaves the CURRENT cadence
// untouched rather than collapsing to the absolute minimum on bad input.
func cadenceFromReturnedTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return 0
	}
	if ideal := ttl / 3; ideal >= minEmitHealthCadence {
		return ideal
	}
	cadence := minEmitHealthCadence
	if cap := ttl / 2; cadence > cap {
		cadence = cap
	}
	if cadence < minAbsoluteEmitHealthCadence {
		cadence = minAbsoluteEmitHealthCadence
	}
	return cadence
}

// emitHealthSource is the local accessor for a producing loop's CURRENT
// stripped-publish health — the same method
// pipeline/transport.Loop.StrippedPublishHealthy and
// pipeline/source/aggregate.Process.StrippedPublishHealthy both implement,
// and pipeline/runtime.LoopMetrics.Stripped's concrete value satisfies
// structurally whenever a loop dual-emits (D-6 — every producing loop does,
// since buildDeps always wires a PayloadStore). internal/netcompose.
// StrippedPublishHealthSource is this binary's counterpart on
// cmd/standalone's side (this binary must not import internal/netcompose;
// same method, independent declaration).
type emitHealthSource interface {
	StrippedPublishHealthy() bool
}

// emitHealthSourcesByName indexes metrics' Stripped accessor by loop name —
// pipeline/runtime.LoopMetrics.Name mirrors pipelineconfig.LoopConfig.Name
// exactly, one entry per configured loop, in the SAME order Build iterates
// cfg.Loops (dataplane.go's own construction loop). A metrics entry whose
// Stripped value is nil (no PayloadStore wired) or does not implement
// emitHealthSource is simply absent from the returned map.
func emitHealthSourcesByName(metrics []pipelineruntime.LoopMetrics) map[string]emitHealthSource {
	out := make(map[string]emitHealthSource, len(metrics))
	for _, m := range metrics {
		if src, ok := m.Stripped.(emitHealthSource); ok {
			out[m.Name] = src
		}
	}
	return out
}

// emitHealthReporterSpec pairs a producing loop's own pipeline DID
// (OutputSubject — the identity it reports as, see this file's package doc)
// with an accessor reading THAT SAME loop's producer handle's CURRENT
// stripped-publish health.
type emitHealthReporterSpec struct {
	OutputSubject string
	Healthy       func() bool
}

// alwaysHealthy is emitHealthReporterSpecsFor's fallback accessor for a
// producing loop with no matching health source — defensive only: D-6
// guarantees buildDeps always wires a PayloadStore, so every producing
// loop's Stripped accessor is always populated in production; this exists so
// a (should-be-impossible) gap reports the pre-D4 "always healthy" behavior
// rather than a nil-func panic.
func alwaysHealthy() bool { return true }

// emitHealthReporterSpecsFor pairs every producing loop's OutputSubject with
// an accessor reading THAT loop's own producer handle's CURRENT
// stripped-publish health (matched by loop config Name against metrics —
// see emitHealthSourcesByName). Replaces the pre-fix behavior of hardcoding
// healthy=true on every report regardless of the producer's actual state
// (P1, converged finding from both reviewers).
func emitHealthReporterSpecsFor(loops []pipelineconfig.LoopConfig, metrics []pipelineruntime.LoopMetrics) []emitHealthReporterSpec {
	refs := producingLoops(loops)
	if len(refs) == 0 {
		return nil
	}
	sources := emitHealthSourcesByName(metrics)
	specs := make([]emitHealthReporterSpec, len(refs))
	for i, ref := range refs {
		healthy := alwaysHealthy
		if src, ok := sources[ref.Name]; ok {
			healthy = src.StrippedPublishHealthy
		}
		specs[i] = emitHealthReporterSpec{OutputSubject: ref.OutputSubject, Healthy: healthy}
	}
	return specs
}

// emitHealthReporter periodically self-reports one by-reference publisher's
// stripped-publish health. See this file's package doc for why
// publisherDID must be the loop's pipeline DID.
type emitHealthReporter struct {
	client       emitHealthReportClient
	publisherDID string
	interval     time.Duration
	// healthy reports the CURRENT stripped-publish health to send on the next
	// tick (P1 fix — every report used to hardcode true regardless of the
	// producer's actual state). nil is treated as unconditionally healthy —
	// only a hand-built test reporter that does not care about this path
	// leaves it nil; every reporter buildEmitHealthReporters constructs
	// always sets one (via emitHealthReporterSpec.Healthy).
	healthy func() bool
}

// currentlyHealthy reports r's current health, defaulting to true when no
// accessor is configured (see the healthy field's own doc).
func (r *emitHealthReporter) currentlyHealthy() bool {
	if r.healthy == nil {
		return true
	}
	return r.healthy()
}

// run ticks at r.interval (retuned after every SUCCESSFUL report — see
// report's own doc), reporting r.currentlyHealthy() each time, until ctx is
// done. It reports once immediately on entry (not only after the first
// tick) so a freshly booted node is not left degraded for up to a whole
// interval before its first report lands. A report failure is logged and
// never stops the loop — mirrors tlogship.Shipper.Run's own
// never-blocks-never-stops posture (a dead registry must not wedge
// shutdown).
func (r *emitHealthReporter) run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.report(ctx, ticker)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.report(ctx, ticker)
		}
	}
}

// report makes one bounded ReportEmitHealth call, sending r.currentlyHealthy()
// (P1 fix). The per-call timeout (r.interval) keeps a hung registry from
// stalling ctx-cancellation observance past the next tick. On success, the
// REGISTRY's own returned TTL re-derives r's cadence for every SUBSEQUENT
// tick (P2 Codex — cadenceFromReturnedTTL) and retunes ticker to match; a
// failed call leaves the cadence untouched (the last known-good interval is
// the safest fallback for a registry that just proved unreachable).
func (r *emitHealthReporter) report(ctx context.Context, ticker *time.Ticker) {
	reportCtx, cancel := context.WithTimeout(ctx, r.interval)
	defer cancel()
	ttl, err := r.client.ReportEmitHealth(reportCtx, r.publisherDID, r.currentlyHealthy())
	if err != nil {
		log.Printf("pipeline: emit-health report for %s failed: %v", r.publisherDID, err)
		return
	}
	if next := cadenceFromReturnedTTL(ttl); next > 0 && next != r.interval {
		r.interval = next
		ticker.Reset(next)
	}
}

// producingLoopRef pairs a producing loop's config name with its own output
// pipeline DID — both halves main.go's D9 boot preflight
// (preflightPayloadRetainKeys, wiring.go) needs to name the loop a missing
// payload-retain key belongs to; emitHealthReporterSpecsFor (below) needs
// both halves too (the DID to report under, the name to bind the loop's
// stripped-publish health accessor by).
type producingLoopRef struct {
	Name          string
	OutputSubject string
}

// producingLoops returns the (Name, OutputSubject) pair for every PRODUCING
// loop in loops — source, chained, and aggregate roles (a sink loop
// consumes, never publishes; it has no OutputSubject and needs neither an
// emit-health reporter nor a payload-retain key).
func producingLoops(loops []pipelineconfig.LoopConfig) []producingLoopRef {
	var out []producingLoopRef
	for _, lc := range loops {
		switch lc.Role {
		case pipelineconfig.RoleSource:
			out = append(out, producingLoopRef{Name: lc.Name, OutputSubject: lc.Source.OutputSubject})
		case pipelineconfig.RoleChained:
			out = append(out, producingLoopRef{Name: lc.Name, OutputSubject: lc.Chained.OutputSubject})
		case pipelineconfig.RoleAggregate:
			out = append(out, producingLoopRef{Name: lc.Name, OutputSubject: lc.Aggregate.OutputSubject})
		}
	}
	return out
}

// buildEmitHealthReporters returns one reporter per spec, each signing/
// reporting through reportClientFor(spec.OutputSubject) — the SAME identity
// it reports as (the wire handler enforces signer_did == publisher_did; see
// this file's package doc) — at the given INITIAL cadence (retuned per
// reporter thereafter from the registry's own returned TTL — see
// emitHealthReporter.report's doc), sending spec.Healthy() on every tick
// (P1 fix — see emitHealthReporterSpecsFor's doc).
func buildEmitHealthReporters(specs []emitHealthReporterSpec, reportClientFor func(publisherDID string) emitHealthReportClient, cadence time.Duration) []*emitHealthReporter {
	reporters := make([]*emitHealthReporter, 0, len(specs))
	for _, s := range specs {
		reporters = append(reporters, &emitHealthReporter{
			client:       reportClientFor(s.OutputSubject),
			publisherDID: s.OutputSubject,
			interval:     cadence,
			healthy:      s.Healthy,
		})
	}
	return reporters
}
