// Command network is the dplaax network node: a control-plane-only binary
// that loads its HOCON config, constructs the DID / Schema / Signer / VC /
// Audit / Chain services over file-backed stores, and serves them via
// ConnectRPC (h2c) behind the L1 authorization interceptors, plus the public
// W3C DID resolution route, /healthz (liveness), and /readyz
// (dependency-aware readiness). Every config value is validated at boot — a
// misconfigured binary dies at startup, never on first request.
//
// It carries NO data plane (recomposition task 5: cmd/standalone's control
// plane half, extracted): it refuses to boot if its pipeline config declares
// any transport loop (the guard right after LoadPipelineConfig, below) —
// loops belong to the pipeline runtime (cmd/standalone until it lands as its
// own binary), never here. TestProdDeps_NoPipelineInNetworkBinary
// (depsguard_test.go) pins this on the production import graph. On
// SIGINT/SIGTERM the HTTP server shuts down gracefully before the process
// exits.
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
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	"github.com/provin-line/oss/network/pkg/registry"
	"github.com/provin-line/oss/network/pkg/services/auditor"
	auditfilestore "github.com/provin-line/oss/network/pkg/services/auditor/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/emithealth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	payloadfilestore "github.com/provin-line/oss/network/pkg/services/payloadresolver/filestore"
	"github.com/provin-line/oss/network/pkg/services/schemaregistry"
	schemayaml "github.com/provin-line/oss/network/pkg/services/schemaregistry/store/yamlstore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/batchresolver"
	vcfilestore "github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/tlog"
)

// meterScope is this binary's OTel instrumentation-scope name — the metrics
// bridge's self-identification (see cmd/standalone/main.go's meterScope for
// the shared rationale). cmd/network reports under its own import path
// rather than borrowing cmd/standalone's.
const meterScope = "github.com/provin-line/oss/cmd/network"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Layer the embedded references with ./config/application.conf and the
	// operator overlay named by CONFIG_OVERLAY (the network-binary convention).
	cfg, err := hoconconfig.Load(".", "CONFIG_OVERLAY")
	if err != nil {
		log.Fatalf("network: load config: %v", err)
	}

	coreCfg, err := core.LoadCoreConfig(cfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	// TLS preflight (P0-6): validate the certificate pair before ANY
	// side-effectful boot work — a node that cannot serve must die here, with
	// stores untouched and transports unconnected, not after first request.
	// The loaded pair rides in tlsConf and is what serving uses (no re-read).
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	authCfg, err := auth.LoadAuthConfig(cfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	regCfg, err := registry.LoadRegistryConfig(cfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	chainCfg, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	pipeCfg, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	// This binary is the control-plane-only node: it carries no data-plane
	// code (TestProdDeps_NoPipelineInNetworkBinary pins the import graph) and
	// so cannot run transport loops. A configured loop here belongs to the
	// pipeline runtime, not this binary, and is an operator error that must
	// die loudly rather than silently ignore the config.
	if len(pipeCfg.Loops) > 0 {
		log.Fatalf("network: %d pipeline loop(s) configured, but this binary runs no data plane — run loops with the pipeline runtime (cmd/standalone until it lands)", len(pipeCfg.Loops))
	}
	// This binary always runs the peer-fetching batch resolver below (Task 9:
	// BuildBatchResolver builds unconditionally from its args now). Unlike
	// cmd/standalone, this binary can never gate that runner on
	// pipeCfg.HasConsumingLoop() — the guard above enforces zero loops here, so
	// that predicate is always false — yet the resolver still runs, draining
	// whatever a peer's StoreVC/RegisterConsumed call registers over the wire.
	// Its peer fetches present this bearer against L1-protected peers
	// regardless of local loops, so an empty bearer would silently starve
	// every fetch at runtime. Fail closed at boot instead, before any
	// evidence-store side effects below.
	if pipeCfg.VCStoreBearer == "" {
		log.Fatalf("network: config %s is required — this binary's batch resolver always runs a peer-fetching client against L1-protected peers", pipelineconfig.VCStoreBearerKey)
	}

	verifier, err := auth.NewVerifier(authCfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}

	// The SSRF guard + DID resolver back this node's chain manager (peer
	// client resolution) and public DID resolution route. Unlike standalone
	// there is no data plane to share them with, but the construction is
	// otherwise identical.
	guard, resolver, err := netcompose.NewDIDResolution(coreCfg, chainCfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}

	// The evidence substrate is DURABLE (spec: evidence-persistence): the
	// evidence stores (credentials, pool, audit queue, verdicts, receipts) are
	// file-backed under data-dir/evidence/; schema and payload stores root
	// under their own data-dir subdirs (schemas/, payloads/) below. An
	// uncreatable evidence dir is a boot error — a node that cannot persist
	// evidence must not pretend to.
	evidenceDir := filepath.Join(coreCfg.DataDir, "evidence")

	// The VC store backs the VCResolverService RPC. Unlike standalone, no
	// data-plane ingress store threads into it here — this node stores only
	// what a peer publishes over the wire.
	credBackend, err := vcfilestore.NewBackend(filepath.Join(evidenceDir, "credentials"))
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	pool, err := vcfilestore.NewPool(filepath.Join(evidenceDir, "pool"))
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	vcSvc := vcresolver.New(vcresolver.NewVariantStore(credBackend), pool)

	// The audit substrate (slice-17h): a registry of consumed heads and a
	// verdict store. With no consuming loop of its own, this node's audit
	// substrate is fed only by whatever a peer's StoreVC / RegisterConsumed
	// call registers over the wire.
	auditQueue, err := auditfilestore.NewQueue(filepath.Join(evidenceDir, "auditqueue"))
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	auditStatus, err := auditfilestore.NewStatusStore(filepath.Join(evidenceDir, "verdicts"))
	if err != nil {
		log.Fatalf("network: %v", err)
	}
	// The emit-time consumed-set receipt store (slice-17o), read by the audit
	// runner's source-commitment step.
	auditReceipts, err := auditfilestore.NewReceiptStore(filepath.Join(evidenceDir, "receipts"))
	if err != nil {
		log.Fatalf("network: %v", err)
	}

	// The chain operator publishes the node account's claims (findings #14) —
	// required for the chain-management RPCs (ChainService) this node
	// exposes, even though it runs no transport loop of its own.
	chainOp, err := netcompose.ChainOperator(chainCfg)
	if err != nil {
		log.Fatalf("network: %v", err)
	}

	// The schema registry backs the control plane's SchemaService RPC and the
	// verifier's schema content-hash resolution. No data-plane boot-time
	// schema-ref resolution here (no producing loop to resolve one for).
	schemaSvc := schemaregistry.New(schemayaml.New(filepath.Join(coreCfg.DataDir, "schemas")))
	schemaBridge := netcompose.SchemaBridge{Svc: schemaSvc} // the one registry->vc.SchemaResolver bridge

	// The by-reference payload serving boundary: BuildHandler mounts a
	// PayloadService serving stored payloads back by content address. With no
	// producing loop of its own, this node serves only what a peer stores
	// (no payload fetch client — that is data-plane wiring this binary does
	// not carry).
	payloadStore, err := payloadfilestore.NewStore(filepath.Join(coreCfg.DataDir, "payloads"))
	if err != nil {
		log.Fatalf("network: build payload store: %v", err)
	}
	payloadSvc := payloadresolver.New(payloadStore)

	// Readiness (/readyz) checks: only what THIS node is configured with — the
	// evidence substrate always, and the external PDP when one is configured
	// (static has no probe). NO nats check: this process holds no data-plane
	// broker connection to probe (the chain operator's own broker connection
	// is a distinct concern from transport-loop health).
	readiness := []netcompose.ReadinessCheck{netcompose.EvidenceStoreCheck(evidenceDir)}
	if check, ok := netcompose.PDPCheck(authCfg); ok {
		readiness = append(readiness, check)
	}

	// ReportEmitHealth's publisher-scoped by-reference advertisement gate
	// (Task 10 D4): this report-mode node has no in-process by-reference
	// producer of its own — unlike cmd/standalone's byRefGate — so
	// advertisement is instead gated per publisher by what that publisher has
	// itself reported here. The store backs BOTH the ReportEmitHealth RPC
	// (mounted via emitHealth below) and chainmanager.WithPublisherHealth's
	// lookup (wired inside BuildHandler).
	emitHealthStore := emithealth.New(chainCfg.EmitHealth.TTL)
	emitHealth := &netcompose.EmitHealthWiring{
		Store:                   emitHealthStore,
		AdvertiseWithoutReports: chainCfg.EmitHealth.AdvertiseWithoutReports,
	}

	// mountIngest and byRefHealthy are both nil: no data plane means no
	// push-ingest routes to mount and no in-process by-reference producer
	// health to gate advertisement on (emitHealth above replaces it for this
	// report-mode binary).
	handler, err := netcompose.BuildHandler(coreCfg, regCfg, chainCfg, chainOp, verifier, guard, resolver, vcSvc, auditStatus, auditReceipts, auditQueue,
		schemaSvc, payloadSvc, payloadStore, map[string]tlog.Log{}, pipeCfg.MaxCredentialSize, pipeCfg.MaxRetainChunkSize, pipeCfg.MaxRetainPayloadSize, nil, readiness, nil, emitHealth)
	if err != nil {
		log.Fatalf("network: build server: %v", err)
	}

	// The async chain-audit resolver drains the pool a peer's StoreVC
	// populates, and the audit runner verifies assembled chains and records
	// verdicts. Both builders build unconditionally now (Task 9), and both
	// ALWAYS run on this binary: it has no local consuming loop to gate on
	// (HasConsumingLoop is always false — it configures none), but a peer's
	// StoreVC/RegisterConsumed call can populate this node's pool/audit-queue
	// over the wire regardless, so both runners must actually run to drain
	// them. The bearer guard above ensures the resolver's peer fetches carry
	// a credential.
	batchRunner, err := netcompose.BuildBatchResolver(pool, vcSvc, guard, resolver, pipeCfg)
	if err != nil {
		log.Fatalf("network: build batch resolver: %v", err)
	}
	auditRunner, err := netcompose.BuildAuditRunner(auditQueue, auditStatus, auditReceipts, vcSvc, pool, resolver, schemaBridge, pipeCfg)
	if err != nil {
		log.Fatalf("network: build audit runner: %v", err)
	}

	// The /metrics bridge composes OUTSIDE BuildHandler, after the audit
	// runner exists (its VerdictCounts is one of the polled sources). Config
	// gated, default off. No loop metrics (nil): this node runs no
	// producing/consuming loop of its own to poll.
	var verdicts func() map[string]uint64
	if auditRunner != nil {
		verdicts = auditRunner.VerdictCounts
	}
	handler, err = netcompose.MaybeMountMetrics(meterScope, coreCfg.MetricsEnabled, handler, nil, verdicts)
	if err != nil {
		log.Fatalf("network: build metrics: %v", err)
	}
	if coreCfg.MetricsEnabled {
		log.Printf("network: metrics exposition mounted at /metrics")
	}

	// Outer raw-body cap: no push-body class on this binary (it mounts no
	// push-ingest routes), so the second argument is 0.
	maxHTTPRequestBytes := netcompose.OuterRequestCapBytes(pipeCfg.MaxCredentialSize, 0, pipeCfg.MaxRetainPayloadSize)
	srv, listen, mode, err := httpserve.BuildServer(coreCfg, tlsConf, handler, maxHTTPRequestBytes)
	if err != nil {
		log.Fatalf("network: build server: %v", err)
	}
	log.Printf("network: serving mode = %s", mode)
	// Endpoint migration matrix (P0-6 #7): a TLS listener does not rewrite what
	// this node ADVERTISES. Advisory, not fail-closed: a migration is allowed
	// to be partway through.
	for _, w := range core.RequireHTTPSEndpoints(coreCfg.TLS, netcompose.EndpointURLs(regCfg, chainCfg)) {
		log.Printf("network: transport posture: %s", w)
	}
	log.Printf("network: listening on %s (registry %q, control plane only)", coreCfg.ListenAddr, regCfg.ID)

	// A failed boot (e.g. the HTTP port is already in use) is NOT a clean
	// stop: exit non-zero so a supervisor restarts the node.
	if err := runNetwork(ctx, srv, listen, batchRunner, auditRunner); err != nil {
		log.Printf("network: %v", err)
		os.Exit(1)
	}
	log.Printf("network: shutdown complete")
}

// runNetwork runs the HTTP server and the two async background runners (the
// batch resolver assembling chains, the audit runner verifying them)
// concurrently under a shared cancellable context, waits for them to drain,
// and returns the first non-shutdown error (nil on a clean shutdown). Mirrors
// standalone's runServices minus the data-plane goroutine: the HTTP server is
// the sole primary service here (its return cancels the context so the
// runners drain — there is no data plane whose failure could independently
// need to bring the node down). Both background runners stay
// degraded-tolerant (log-and-continue, D-17g-9 / D-17h-8): they never cancel
// their siblings and return nil on shutdown. Both are always non-nil for this
// binary (Task 9: main's bearer guard makes BuildBatchResolver/BuildAuditRunner
// always succeed non-nil here); the nil checks below stay defensive so this
// function's contract does not depend on that caller invariant.
func runNetwork(ctx context.Context, srv *http.Server, listen func() error, batchRunner *batchresolver.Runner, auditRunner *auditor.Runner) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := httpserve.ServeHTTP(runCtx, srv, listen); err != nil {
			errs <- fmt.Errorf("http server: %w", err)
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
