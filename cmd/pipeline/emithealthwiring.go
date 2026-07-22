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
// operational benefit — no real dependency needs sub-5s freshness.
const minEmitHealthCadence = 5 * time.Second

// emitHealthCadence derives the ReportEmitHealth ticking interval from the
// configured TTL (chainCfg.EmitHealth.TTL, provin.network.chain.emit-health.
// ttl): TTL/3, so at least two reports land inside every freshness window
// even if one is delayed or dropped, floored at minEmitHealthCadence.
func emitHealthCadence(ttl time.Duration) time.Duration {
	if c := ttl / 3; c > minEmitHealthCadence {
		return c
	}
	return minEmitHealthCadence
}

// emitHealthReporter periodically self-reports one by-reference publisher's
// stripped-publish health. See this file's package doc for why
// publisherDID must be the loop's pipeline DID.
type emitHealthReporter struct {
	client       emitHealthReportClient
	publisherDID string
	interval     time.Duration
}

// run ticks at r.interval, reporting healthy=true each time, until ctx is
// done. It reports once immediately on entry (not only after the first
// tick) so a freshly booted node is not left degraded for up to a whole
// interval before its first report lands. A report failure is logged and
// never stops the loop — mirrors tlogship.Shipper.Run's own
// never-blocks-never-stops posture (a dead registry must not wedge
// shutdown).
func (r *emitHealthReporter) run(ctx context.Context) {
	r.report(ctx)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.report(ctx)
		}
	}
}

// report makes one bounded ReportEmitHealth call. The per-call timeout
// (r.interval) keeps a hung registry from stalling ctx-cancellation
// observance past the next tick.
func (r *emitHealthReporter) report(ctx context.Context) {
	reportCtx, cancel := context.WithTimeout(ctx, r.interval)
	defer cancel()
	if _, err := r.client.ReportEmitHealth(reportCtx, r.publisherDID, true); err != nil {
		log.Printf("pipeline: emit-health report for %s failed: %v", r.publisherDID, err)
	}
}

// producingLoopPublishers returns the pipeline DID (OutputSubject) of every
// PRODUCING loop in loops — source, chained, and aggregate roles (a sink
// loop consumes, never publishes, so it advertises nothing and needs no
// reporter).
func producingLoopPublishers(loops []pipelineconfig.LoopConfig) []string {
	var out []string
	for _, lc := range loops {
		switch lc.Role {
		case pipelineconfig.RoleSource:
			out = append(out, lc.Source.OutputSubject)
		case pipelineconfig.RoleChained:
			out = append(out, lc.Chained.OutputSubject)
		case pipelineconfig.RoleAggregate:
			out = append(out, lc.Aggregate.OutputSubject)
		}
	}
	return out
}

// buildEmitHealthReporters returns one reporter per publisher DID in
// publishers, each signing/reporting through
// reportClientFor(publisherDID) — the SAME identity it reports as (the wire
// handler enforces signer_did == publisher_did; see this file's package
// doc) — at cadence.
func buildEmitHealthReporters(publishers []string, reportClientFor func(publisherDID string) emitHealthReportClient, cadence time.Duration) []*emitHealthReporter {
	reporters := make([]*emitHealthReporter, 0, len(publishers))
	for _, p := range publishers {
		reporters = append(reporters, &emitHealthReporter{client: reportClientFor(p), publisherDID: p, interval: cadence})
	}
	return reporters
}
