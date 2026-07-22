// Command pipeline is the dplaax data-plane deployment root: a
// short-lived, per-execution binary (STL) that loads its HOCON config from a
// single required file (the CONFIG_FILE convention, hoconconfig.LoadFile),
// composes pipeline/runtime — the network-agnostic data plane — against WIRE
// clients to a cmd/network registry, and runs the configured transport
// loops. It carries NO in-process registry: every wire Dep (VC store, audit,
// schema, payload) is a network client pointed at ONE configured registry
// base URL (provin.network.pipeline.vc-store-endpoint) — the "all services
// mount on one node" assumption this file's boot guard documents at its
// mapping site, below.
//
// This binary exists ONLY to run loops: a config with zero
// provin.network.pipeline.loops is a boot error (run cmd/network instead —
// the control-plane-only sibling). It mounts a minimal HTTP surface:
// /healthz (liveness), /readyz (NATS + registry reachability), and the
// configured /ingest/<loop>/... push routes — no ConnectRPC services of its
// own. On SIGINT/SIGTERM the HTTP server shuts down and the data plane
// drains (the shipper hooks around this sequence are PR3b Task 7's job — see
// run, below, structured so that task can slot them in).
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
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
)

// /metrics is deliberately NOT mounted by this binary in PR3b:
// internal/netcompose.MaybeMountMetrics/BuildMetricsHandler are off-limits
// (netcompose is banned here — PR3b Task 8's depsguard pins it), and
// duplicating the ~65-line otel/prometheus bridge is scoped out of this task
// in favor of Deps wiring + guards + HTTP surface + lifecycle correctness.
// PR3c follow-up: build the bridge directly over pipeline/runtime's own
// LoopMetrics (which — unlike cmd/standalone's netcompose.LoopMetrics
// field-copy — this binary would not even need to convert, since it never
// imports netcompose).

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The CONFIG_FILE convention (T1): a short-lived, per-execution binary has
	// no default location to fall back to, unlike cmd/network/cmd/standalone's
	// CONFIG_OVERLAY-over-./config/application.conf layering.
	cfg, err := hoconconfig.LoadFile("CONFIG_FILE")
	if err != nil {
		log.Fatalf("pipeline: load config: %v", err)
	}

	coreCfg, err := core.LoadCoreConfig(cfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	// TLS preflight (P0-6): validate the certificate pair before ANY
	// side-effectful boot work.
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	authCfg, err := auth.LoadAuthConfig(cfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	chainCfg, err := chainconfig.LoadChainConfig(cfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}
	pipeCfg, err := pipelineconfig.LoadPipelineConfig(cfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	// Boot guard 1 (fail-closed, named): this binary exists ONLY to run
	// loops. A zero-loop config is a misconfiguration, not a valid
	// degenerate deployment — that binary is cmd/network. Fires before any
	// side-effectful boot work (no store, no keystore reference, nothing).
	if len(pipeCfg.Loops) == 0 {
		log.Fatalf("pipeline: no loops configured — this binary exists to run loops — configure provin.network.pipeline.loops or run cmd/network")
	}

	// Boot guard 2 (fail-closed, named): loops require the nats transport.
	// rtCfg's construction is pure (no side effects) — safe to compute before
	// any of the guards below, and its own error already names the transport.
	rtCfg, err := pipelineRuntimeConfigFrom(chainCfg, pipeCfg, coreCfg.DataDir)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	// Boot guard 3 (fail-closed, named): any loop requires BOTH
	// vc-store-endpoint and vc-store-bearer. pipelineconfig.LoadPipelineConfig
	// only requires the bearer when an endpoint is set OR a consuming loop is
	// present — it does not require the ENDPOINT itself for a source-only
	// node, since network/pkg/pipelineconfig's own contract treats publication
	// as optional. This binary is stricter: the endpoint doubles as the ONE
	// registry base URL for EVERY wire dependency it composes (VC store,
	// audit, schema, payload — see buildDeps) under the "all services mount
	// on one node" assumption documented here, at the mapping site — without
	// it, nothing this binary does can reach a registry at all, regardless of
	// loop role.
	if pipeCfg.VCStoreEndpoint == "" || pipeCfg.VCStoreBearer == "" {
		log.Fatalf("pipeline: %d loop(s) configured but %s and %s are both required — this binary treats the vc-store endpoint as the ONE registry base URL for every wire dependency (audit, schema, payload) it composes",
			len(pipeCfg.Loops), "provin.network.pipeline.vc-store-endpoint", pipelineconfig.VCStoreBearerKey)
	}

	verifier, err := auth.NewVerifier(authCfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	// Boot guard 4 (fail-closed, named): the DID resolver (sink/chained/
	// aggregate loops verify upstream credentials through it) must be
	// constructible. Built unconditionally (not gated on a consuming loop
	// being present) — pipeline/runtime.Build ALSO fails closed per-loop if
	// Resolver is nil for a consuming role, but naming the failure here, before
	// any side-effectful boot work, gives a clearer boot error (e.g. the F8
	// private-network posture requiring scoped registry resolution).
	guard, didResolver, err := newDIDResolution(coreCfg, chainCfg)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	// nodeDID is this binary's own subscriber/signing identity — guaranteed
	// non-empty here: guard 2 above already required the nats transport
	// whenever any loop is configured (true by guard 1), and
	// chainconfig.LoadChainConfig requires node-did non-empty on that
	// transport.
	nodeDID := chainCfg.NATS.NodeDID

	// The pipeline-local keystore: THIS binary's own DataDir/keys, never the
	// registry's. It must hold the #auth key for nodeDID (AuditRegistrar,
	// PayloadResolver/Retain) and the #signing/#auth keys for every
	// configured loop's issuer identity (source/chained/aggregate issuers,
	// sink receipt issuers) — provisioning them is an operator/CLI concern,
	// out of this task's scope, same convention cmd/standalone follows.
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))

	deps := buildDeps(pipeCfg, keyStore, guard, didResolver, nodeDID)

	dp, err := pipelineruntime.Build(ctx, &rtCfg, keyStore, deps)
	if err != nil {
		log.Fatalf("pipeline: build data plane: %v", err)
	}

	mountIngest := func(mux *http.ServeMux) error {
		return mountPushRoutes(mux, dp.PushBindings(), verifier, pipeCfg.MaxPushBodySize)
	}
	var natsHealthy func() bool
	if dp.Conn() != nil {
		natsHealthy = dp.Conn().Healthy
	}
	handler, err := buildHandler(guard, pipeCfg, mountIngest, natsHealthy)
	if err != nil {
		log.Fatalf("pipeline: build http handler: %v", err)
	}

	maxHTTPRequestBytes := outerRequestCapBytes(pipeCfg.MaxPushBodySize)
	srv, listen, mode, err := httpserve.BuildServer(coreCfg, tlsConf, handler, maxHTTPRequestBytes)
	if err != nil {
		log.Fatalf("pipeline: build server: %v", err)
	}
	log.Printf("pipeline: serving mode = %s", mode)
	log.Printf("pipeline: listening on %s (%d data-plane loop(s), registry %s)", coreCfg.ListenAddr, len(pipeCfg.Loops), hostOnly(pipeCfg.VCStoreEndpoint))

	// A failed boot or a data-plane failure is NOT a clean stop: exit non-zero
	// so a supervisor restarts the node.
	if err := run(ctx, srv, listen, dp); err != nil {
		log.Printf("pipeline: %v", err)
		os.Exit(1)
	}
	log.Printf("pipeline: shutdown complete")
}

// buildHandler mounts this binary's minimal HTTP surface: /healthz
// (liveness), /readyz (NATS + registry reachability), and the configured
// /ingest/<loop>/... push routes via mountIngest. No ConnectRPC services of
// its own — this binary is a wire CLIENT to the registry, never a server for
// it — and no /metrics (see the package doc). natsHealthy is nil for a
// (guard-1-impossible-but-defensive) zero-loop runtime; the readiness
// snapshot then reports no nats check rather than a permanently-failing one.
func buildHandler(guard *core.URLGuard, pipeCfg *pipelineconfig.Config, mountIngest func(*http.ServeMux) error, natsHealthy func() bool) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)

	var checks []readinessCheck
	if natsHealthy != nil {
		checks = append(checks, natsCheck(natsHealthy))
	}
	checks = append(checks, registryCheck(guard.HTTPClient(), pipeCfg.VCStoreEndpoint))
	mux.HandleFunc("/readyz", newCachedReadiness(checks).handler())

	if mountIngest != nil {
		if err := mountIngest(mux); err != nil {
			return nil, err
		}
	}
	return mux, nil
}

// outerRequestCapBytes sizes the outermost raw-request-body limit. This
// binary mounts exactly ONE inbound-body-reading HTTP class of its own — the
// push-ingest route (apipush, bounded by max-push-body-size) — unlike
// cmd/network/cmd/standalone, which each mount a full set of ConnectRPC
// services with their own per-RPC read caps (credential, document, proof,
// retain-chunk classes) that internal/netcompose.OuterRequestCapBytes must
// cover; this binary is a wire CLIENT to those services, never their server,
// so none of those classes apply here. Same inflation formula as that
// function (2x for base64 + JSON overhead, +64 KiB framing/header headroom).
func outerRequestCapBytes(maxPushBodySize int) int {
	return maxPushBodySize*2 + 64<<10
}

// run runs the HTTP server and the data plane concurrently under a shared
// cancellable context, waits for them to drain, and returns the first
// non-shutdown error (nil on a clean shutdown). Mirrors cmd/network's
// runNetwork / cmd/standalone's runServices shape so PR3b Task 7 can slot
// the shipper drain into this exact sequence (start it alongside dp.Run,
// order its shutdown between the HTTP drain and dp.Run's own drain) without
// restructuring main.
func run(ctx context.Context, srv *http.Server, listen func() error, dp *pipelineruntime.Runtime) error {
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
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
