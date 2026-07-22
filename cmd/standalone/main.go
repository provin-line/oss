// Command standalone is the dplaax network registry server: a single binary that
// loads its HOCON config, constructs the DID / Schema / Signer services over
// file-backed stores, and serves them via ConnectRPC (h2c) behind the L1
// authorization interceptors, plus the public W3C DID resolution route,
// /healthz (liveness), and /readyz (dependency-aware readiness). Every config
// value is validated at boot — a misconfigured binary dies at startup, never
// on first request.
//
// Alongside the HTTP control plane it runs the data plane: the pipeline transport
// loops declared in the pipeline config (slice-17b). Both run concurrently under one
// signal-cancelled context; on SIGINT/SIGTERM the loops drain and the HTTP server
// shuts down gracefully before the process exits.
//
// Deprecated: cmd/standalone is the all-in-one composition (control plane +
// data plane in one process). It is being replaced by cmd/network (control
// plane) and the pipeline runtime; see docs/architecture/deployment.md.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/internal/netcompose"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	auditfilestore "github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadclient "github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
	payloadfilestore "github.com/provin-line/oss/network/pkg/services/payloadresolver/filestore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/batchresolver"
	vcfilestore "github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/pipeline/contract"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// meterScope is this binary's OTel instrumentation-scope name — the metrics
// bridge's self-identification (P1-2 follow-up: the scope used to be
// hardcoded inside internal/netcompose/metrics.go; each binary now supplies
// its own import path so cmd/network doesn't report under cmd/standalone's
// name). Unchanged from the literal metrics.go used before, so this binary's
// exposition is byte-identical to today's.
const meterScope = "github.com/provin-line/oss/cmd/standalone"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Layer the embedded references with ./config/application.conf and the
	// operator overlay named by CONFIG_OVERLAY (the network-binary convention).
	cfg, err := hoconconfig.Load(".", "CONFIG_OVERLAY")
	if err != nil {
		log.Fatalf("standalone: load config: %v", err)
	}

	coreCfg, err := core.LoadCoreConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	// TLS preflight (P0-6): validate the certificate pair before ANY
	// side-effectful boot work — a node that cannot serve must die here, with
	// stores untouched and transports unconnected, not after first request.
	// The loaded pair rides in tlsConf and is what serving uses (no re-read).
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	authCfg, err := auth.LoadAuthConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	regCfg, err := registry.LoadRegistryConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	chainCfg, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	pipeCfg, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	verifier, err := auth.NewVerifier(authCfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	// The SSRF guard + DID resolver are shared across both planes: the control plane's
	// chain manager and the data plane's sink-loop credential verification (slice-17c).
	guard, resolver, err := newDIDResolution(coreCfg, chainCfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	// The evidence substrate is DURABLE (spec: evidence-persistence; e2e finding #23 —
	// a restart must not erase what a later audit needs): every store below is
	// file-backed under data-dir/evidence/. An uncreatable evidence dir is a boot
	// error — a node that cannot persist evidence must not pretend to.
	evidenceDir := filepath.Join(coreCfg.DataDir, "evidence")

	// The VC store is built once in main and shared across both planes (D-17f-5):
	// BuildHandler mounts it under the VCResolverService RPC; pipelineruntime.Build
	// threads it into consuming loops' ingress store so every verified ingress credential is
	// immediately resolvable and its predecessor is enqueued in the one shared pool. The
	// pool is a named var so the batch resolver drains exactly the pool StoreVC feeds (D-17g-1).
	credBackend, err := vcfilestore.NewBackend(filepath.Join(evidenceDir, "credentials"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	pool, err := vcfilestore.NewPool(filepath.Join(evidenceDir, "pool"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(credBackend), pool)

	// The audit substrate (slice-17h): a registry of consumed heads (fed at ingress) and a
	// verdict store, both shared between the ingress path and the audit runner.
	auditQueue, err := auditfilestore.NewQueue(filepath.Join(evidenceDir, "auditqueue"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	auditStatus, err := auditfilestore.NewStatusStore(filepath.Join(evidenceDir, "verdicts"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	// The emit-time consumed-set receipt store (slice-17o), shared between an aggregate's
	// self-audit registration (emit path) and the audit runner's source-commitment step.
	auditReceipts, err := auditfilestore.NewReceiptStore(filepath.Join(evidenceDir, "receipts"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	// The chain operator is built BEFORE the data plane: its construction publishes
	// the node account's claims (findings #14), and on a fresh broker the data
	// plane's NATS connect needs those claims to be resolvable.
	chainOp, err := chainOperator(chainCfg)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	// The data plane signs (source loops) with the same file-backed keystore the control
	// plane uses (dataDir/keys) and verifies (sink loops) through the shared resolver. Each
	// sink loop's delivery surface comes from its sink.output config (console/stdout
	// default, file per path). With zero loops this dials nothing.
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))
	// The schema registry is built here (not inside BuildHandler) so a single
	// instance backs the control plane's SchemaService RPC, the data plane's
	// boot-time schema-ref resolution (issuance), and the verifier's schema
	// content-hash resolution (verify) — one store, no divergent handles.
	schemaSvc := schemaregistry.New(schemayaml.New(filepath.Join(coreCfg.DataDir, "schemas")))
	schemaBridge := netcompose.SchemaBridge{Svc: schemaSvc} // the one registry->vc.SchemaResolver bridge, shared by both verifiers
	// The by-reference payload serving boundary: producing loops retain their
	// payload here (data-dir/payloads), and BuildHandler mounts a PayloadService
	// serving them back by content address. One store backs both the retain
	// (data plane) and serve (control plane) sides.
	payloadStore, err := payloadfilestore.NewStore(filepath.Join(coreCfg.DataDir, "payloads"))
	if err != nil {
		log.Fatalf("standalone: build payload store: %v", err)
	}
	payloadSvc := payloadresolver.New(payloadStore)
	// The consumer-side fetch client signs as the node identity (like the chain
	// peer client). It is nil for a node without a DID (dev/noop transport):
	// inline loops need no resolver, and a by-reference loop on an identity-less
	// node fails closed at boot (ErrMissingPayloadResolver).
	var payloadClient contract.PayloadResolver
	if nodeDID := nodeDIDOf(chainCfg); nodeDID != "" {
		payloadClient = payloadclient.New(payloadclient.Config{Signer: keyStore, SignerDID: nodeDID, HTTPClient: guard.HTTPClient()})
	}
	rtCfg, err := runtimeConfigFrom(chainCfg, pipeCfg, coreCfg.DataDir)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	dp, err := pipelineruntime.Build(ctx, &rtCfg, keyStore, pipelineruntime.Deps{
		Resolver:            resolver,
		VCStore:             ingressStoreAdapter{svc: vcSvc},
		AuditQueue:          auditQueue,
		Receipts:            auditReceipts,
		SchemaResolver:      schemaBridge,
		SchemaGetter:        schemaGetterAdapter{svc: schemaSvc},
		PayloadStore:        payloadSvc,
		PayloadResolver:     payloadClient,
		CredentialPublisher: credentialPublisherFrom(pipeCfg, nil),
	})
	if err != nil {
		log.Fatalf("standalone: build data plane: %v", err)
	}

	// Readiness (/readyz) checks: only what THIS node is configured with — the
	// evidence substrate always, the shared broker connection when a data plane
	// runs, and the external PDP when one is configured (static has no probe).
	readiness := []readinessCheck{evidenceStoreCheck(evidenceDir)}
	if dp.Conn() != nil {
		readiness = append(readiness, natsCheck(dp.Conn().Healthy))
	}
	if check, ok := pdpCheck(authCfg); ok {
		readiness = append(readiness, check)
	}

	// The by-reference advertisement health gate: every producing loop and
	// aggregate is a stripped-publish health source, so the control-plane
	// advertiser degrades by-reference when any of them is failing (D-5).
	var byRefSources []strippedPublishHealthSource
	for _, lp := range dp.Loops() {
		byRefSources = append(byRefSources, lp)
	}
	for _, ag := range dp.Aggregates() {
		byRefSources = append(byRefSources, ag)
	}
	byRefGate := newByRefHealthGate(byRefSources)

	// mountIngest is the callback seam BuildHandler mounts the data plane's HTTP
	// push-ingest routes through (nil would mount nothing) — it replaces the old
	// ingestMounts{bindings, maxBodySize} value now that BuildHandler lives in
	// internal/netcompose, which must stay free of the pipeline/runtime
	// PushBinding type.
	mountIngest := func(mux *http.ServeMux) error {
		return mountPushRoutes(mux, dp.PushBindings(), verifier, pipeCfg.MaxPushBodySize)
	}
	// emitHealth is nil: cmd/standalone gates by-reference advertisement with
	// its own in-process byRefGate above (the global model), never the
	// per-publisher report-mode gate (chainmanager.New would panic if both
	// were wired on the same Service).
	// mirror is nil: cmd/standalone stays on the map-only path (D-T4) — it
	// runs no registry-side mirror store, only the local producing logs
	// dp.Tlogs() returns.
	handler, err := BuildHandler(coreCfg, regCfg, chainCfg, chainOp, verifier, guard, resolver, vcSvc, auditStatus, auditReceipts, auditQueue,
		schemaSvc, payloadSvc, payloadStore, dp.Tlogs(), nil, pipeCfg.MaxCredentialSize, pipeCfg.MaxRetainChunkSize, pipeCfg.MaxRetainPayloadSize, mountIngest, readiness, byRefGate.Healthy, nil)
	if err != nil {
		log.Fatalf("standalone: build server: %v", err)
	}

	// The async chain-audit resolver drains the pool the consuming loops populate, and the
	// audit runner verifies assembled chains and records per-head verdicts. Both builders
	// now build unconditionally from their args (Task 9); gateConsumingLoopRunners below
	// reproduces their old internal gate at this call site, so a source-only node still
	// gets nil for both (no holes to drain, no consumed heads register) exactly as before.
	batchRunner, err := buildBatchResolver(pool, vcSvc, guard, resolver, pipeCfg)
	if err != nil {
		log.Fatalf("standalone: build batch resolver: %v", err)
	}
	auditRunner, err := buildAuditRunner(auditQueue, auditStatus, auditReceipts, vcSvc, pool, resolver, schemaBridge, pipeCfg)
	if err != nil {
		log.Fatalf("standalone: build audit runner: %v", err)
	}
	batchRunner, auditRunner = gateConsumingLoopRunners(pipeCfg, batchRunner, auditRunner)

	// The /metrics bridge composes OUTSIDE BuildHandler, after the audit
	// runner exists (its VerdictCounts is one of the polled sources). Config
	// gated, default off — the listener is not loopback-bound and metrics
	// expose more than /healthz (see core reference.conf).
	var verdicts func() map[string]uint64
	if auditRunner != nil {
		verdicts = auditRunner.VerdictCounts
	}
	handler, err = maybeMountMetrics(meterScope, coreCfg.MetricsEnabled, handler, netcomposeMetricsFrom(dp.Metrics()), verdicts)
	if err != nil {
		log.Fatalf("standalone: build metrics: %v", err)
	}
	if coreCfg.MetricsEnabled {
		log.Printf("standalone: metrics exposition mounted at /metrics")
	}

	// Outer raw-body cap: h2c.NewHandler reads an HTTP/1 upgrade request's body
	// in full before the inner Connect handler (and its per-RPC read cap) runs,
	// so a single generous outer bound closes that pre-auth path. Sized to the
	// largest legitimate request (a stored credential, a pushed body, or a full
	// RetainPayload stream) plus headroom; per-RPC caps stay tight below it.
	// The fourth argument (mirror batch bytes) is 0: this binary never wires a
	// mirror store (D-T4's map-only posture), so it never mounts
	// MirrorLogSegment's derived cap override for that class to cover.
	maxHTTPRequestBytes := outerRequestCapBytes(pipeCfg.MaxCredentialSize, pipeCfg.MaxPushBodySize, pipeCfg.MaxRetainPayloadSize, 0)
	srv, listen, mode, err := httpserve.BuildServer(coreCfg, tlsConf, handler, maxHTTPRequestBytes)
	if err != nil {
		log.Fatalf("standalone: build server: %v", err)
	}
	log.Printf("standalone: serving mode = %s", mode)
	// Endpoint migration matrix (P0-6 #7): a TLS listener does not rewrite what
	// this node ADVERTISES. An http:// service endpoint or resolution override
	// on a TLS posture means peers never reach the listener, while the node
	// looks perfectly healthy from the inside. Advisory, not fail-closed: a
	// migration is allowed to be partway through.
	for _, w := range core.RequireHTTPSEndpoints(coreCfg.TLS, endpointURLs(regCfg, chainCfg)) {
		log.Printf("standalone: transport posture: %s", w)
	}
	log.Printf("standalone: listening on %s (registry %q, %d data-plane loop(s))",
		coreCfg.ListenAddr, regCfg.ID, len(pipeCfg.Loops))

	// A failed boot (e.g. the HTTP port is already in use) or a data-plane failure is
	// NOT a clean stop: exit non-zero so a supervisor restarts the node. This preserves
	// the fatal-on-serve-error behavior the pre-data-plane main had via log.Fatalf.
	if err := runServices(ctx, srv, listen, dp, batchRunner, auditRunner); err != nil {
		log.Printf("standalone: %v", err)
		os.Exit(1)
	}
	log.Printf("standalone: shutdown complete")
}

// gateConsumingLoopRunners nils batchRunner/auditRunner when pipeCfg has no consuming
// loop, reproducing BuildBatchResolver/BuildAuditRunner's former internal gate at this
// call site (Task 9: the builders now build unconditionally from their args — see their
// doc comments in internal/netcompose). A source-only or zero-loop node accumulates no
// holes and registers no consumed heads, so it still runs neither background runner;
// otherwise the two runners the builders returned pass through unchanged.
func gateConsumingLoopRunners(pipeCfg *pipelineconfig.Config, batchRunner *batchresolver.Runner, auditRunner *auditor.Runner) (*batchresolver.Runner, *auditor.Runner) {
	if !pipeCfg.HasConsumingLoop() {
		return nil, nil
	}
	return batchRunner, auditRunner
}

// runServices runs the HTTP server, the data plane, and the two async background runners
// (the batch resolver assembling chains, the audit runner verifying them) concurrently
// under a shared cancellable context, waits for them to drain, and returns the first
// non-shutdown error (nil on a clean shutdown). The HTTP server is the primary service: if
// it returns, the context is cancelled so the others drain. A data-plane ERROR also cancels
// (the node cannot do its job); a clean data-plane return (zero loops) does not bring the
// HTTP server down. Both background runners are degraded-tolerant (log-and-continue,
// D-17g-9 / D-17h-8): they never cancel their siblings and return nil on shutdown; each is
// nil for a source-only node (no consuming loop).
func runServices(ctx context.Context, srv *http.Server, listen func() error, dp *pipelineruntime.Runtime, batchRunner *batchresolver.Runner, auditRunner *auditor.Runner) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := httpserve.ServeHTTP(runCtx, srv, listen); err != nil {
			errs <- fmt.Errorf("http server: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := dp.Run(runCtx); err != nil {
			cancel()
			errs <- fmt.Errorf("data plane: %w", err)
		}
	}()
	// Degraded-tolerant background runners: each loops logging per-tick failures, pushes no
	// error, and never cancels its siblings.
	if batchRunner != nil {
		wg.Add(1)
		go func() { defer wg.Done(); _ = batchRunner.Run(runCtx) }()
	}
	if auditRunner != nil {
		wg.Add(1)
		go func() { defer wg.Done(); _ = auditRunner.Run(runCtx) }()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
