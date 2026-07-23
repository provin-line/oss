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
// own.
//
// On SIGINT/SIGTERM this binary tears down in a FIXED order (tlog-custody
// spec D8), never all at once: (1) the HTTP server stops accepting and
// drains in-flight requests; (2) the data-plane loops/aggregates are told to
// stop and awaited; (3) the mirror shippers' and emit-health reporters'
// periodic goroutines are told to stop and awaited; (4) each mirror shipper
// gets ONE final, FRESH-context flush attempt (never the already-canceled
// signal context — see run, below); (5) the shared NATS connection and every
// durable log's file handle close. See run's own doc for why this requires
// splitting one shared context into several independently-cancelled ones.
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
	"time"

	"github.com/provin-line/oss/hoconconfig"
	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/auth"
	"github.com/provin-line/oss/network/pkg/chainconfig"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/pipelineconfig"
	pipelineruntime "github.com/provin-line/oss/pipeline/runtime"
	"github.com/provin-line/oss/pipeline/transport/tlogship"
)

// /metrics is deliberately NOT mounted by this binary in PR3b:
// internal/netcompose.MaybeMountMetrics/BuildMetricsHandler are off-limits
// (netcompose is banned here — PR3b Task 8's depsguard pins it), and
// duplicating the ~65-line otel/prometheus bridge is scoped out of this task
// in favor of Deps wiring + guards + HTTP surface + lifecycle correctness.
// PR3c follow-up: build the bridge directly over pipeline/runtime's own
// LoopMetrics (this binary would not even need to convert to
// netcompose.LoopMetrics the way cmd/standalone's field-copy once did,
// since it never imports netcompose).

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The CONFIG_FILE convention (T1): a short-lived, per-execution binary has
	// no default location to fall back to, unlike cmd/network's
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
	// registry's. It must hold the #auth key for nodeDID (AuditRegistrar);
	// the #signing/#auth keys for every configured loop's issuer identity
	// (source/chained/aggregate issuers, sink receipt issuers); the #auth key
	// for the checkpoint-signer identity of every durable log (the SAME
	// issuer/receipt keys above — the mirror shipper signs MirrorLogSegment
	// as that same identity, tlog-custody spec D-T3); and the #auth key for
	// every producing loop's OWN pipeline DID (its OutputSubject, distinct
	// from its issuer DID) — the identity BOTH the emit-health reporter
	// signs ReportEmitHealth as (PR3b Task 7 — see emithealthwiring.go's
	// package doc for why it must be the pipeline DID, not the issuer DID)
	// AND, as of D9, the identity by-reference retain (wirePayloadStore's
	// payloadClientFactory, wiring.go) signs RetainPayload as — guard 5,
	// below, checks the latter fails closed at boot rather than silently at
	// first emit. Provisioning them is an operator/CLI concern, out of this
	// task's scope.
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))

	// Boot guard 5 (fail-closed, named, D9): by-reference retain
	// (wirePayloadStore's payloadClientFactory, wiring.go) signs each
	// RetainPayload call as the OWNING producing loop's output subject, never
	// the node identity — network/pkg/services/payloadresolver/storehandler
	// enforces owner_did == the proven signer (the PR2 signer-to-actor
	// binding). A missing key here would otherwise only surface as a runtime
	// retain failure that aborts the whole emission (dataplane.go's
	// payloadWiring — PayloadStore wired ⇒ every producing loop dual-emits,
	// D-6), so this is checked before any loop ever runs.
	if err := preflightPayloadRetainKeys(keyStore, pipeCfg.Loops); err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	deps := buildDeps(pipeCfg, keyStore, guard, didResolver, nodeDID)

	dp, err := pipelineruntime.Build(ctx, &rtCfg, keyStore, deps)
	if err != nil {
		log.Fatalf("pipeline: build data plane: %v", err)
	}

	// Boot guard 6 (fail-closed, named, D9 extension — branch review,
	// Important finding): nodeDID's own signing key (RegisterAuditHead /
	// PayloadResolver) and every durable custody log's checkpoint-signer key
	// — both previously discoverable only at first use, since filelog's own
	// checkpoint arming never probes the key at construction (see
	// preflightWireOnlySignerKeys' own doc, wiring.go, for why this guard
	// must run AFTER Build, unlike guard 5 above). dp.Close() releases the
	// NATS connection and log handles Build already opened before this
	// binary exits — nothing has run yet (dp.Run has not been called).
	if err := preflightWireOnlySignerKeys(keyStore, nodeDID, dp.CustodyLogs()); err != nil {
		_ = dp.Close()
		log.Fatalf("pipeline: %v", err)
	}

	// Mirror shippers (D-T6): one per durable custody log, signed as that
	// log's own checkpoint-signer identity.
	mirrorFactory := newMirrorClientFactory(keyStore, pipeCfg.VCStoreEndpoint, pipeCfg.VCStoreBearer, guard.HTTPClient())
	shippers, err := buildShippers(dp.CustodyLogs(), mirrorFactory.forClient, pipeCfg.TlogMirror)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	// EmitHealth reporters (Task 10 D4): one per by-reference publisher
	// (every producing loop — buildDeps always wires a PayloadStore, so
	// every producing loop dual-emits, D-6), signed/reported as that loop's
	// pipeline DID, each bound to ITS OWN producer's CURRENT stripped-publish
	// health (P1 fix, branch review — every report used to hardcode
	// healthy=true regardless of the producer's actual state; see
	// emitHealthReporterSpecsFor's doc).
	reportFactory := newReportClientFactory(keyStore, pipeCfg.VCStoreEndpoint, pipeCfg.VCStoreBearer, guard.HTTPClient())
	emitHealthSpecs := emitHealthReporterSpecsFor(pipeCfg.Loops, dp.Metrics())
	reporters := buildEmitHealthReporters(emitHealthSpecs, reportFactory.forClient, emitHealthCadence(chainCfg.EmitHealth.TTL))

	mountIngest := func(mux *http.ServeMux) error {
		return mountPushRoutes(mux, dp.PushBindings(), verifier, pipeCfg.MaxPushBodySize)
	}
	var natsHealthy func() bool
	if dp.Conn() != nil {
		natsHealthy = dp.Conn().Healthy
	}
	handler, err := buildHandler(guard, pipeCfg, authCfg, mountIngest, natsHealthy, len(dp.PushBindings()) > 0)
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
	if err := run(ctx, srv, listen, dp, shippers, reporters, DefaultDrainBudget); err != nil {
		log.Printf("pipeline: %v", err)
		os.Exit(1)
	}
	log.Printf("pipeline: shutdown complete")
}

// buildHandler mounts this binary's minimal HTTP surface: /healthz
// (liveness), /readyz (NATS + registry reachability + the external PDP when
// relevant — see below), and the configured /ingest/<loop>/... push routes
// via mountIngest. No ConnectRPC services of its own — this binary is a wire
// CLIENT to the registry, never a server for it — and no /metrics (see the
// package doc). natsHealthy is nil for a (guard-1-impossible-but-defensive)
// zero-loop runtime; the readiness snapshot then reports no nats check
// rather than a permanently-failing one.
//
// hasPushIngress (branch review, P2 Codex fix) gates an added PDP
// reachability check: this binary mounts no ConnectRPC services of its own
// to be ready FOR (unlike cmd/network, which unconditionally
// probes the PDP whenever the backend is external — it always mounts
// PDP-gated RPC surfaces), but a push-ingress route IS PDP-guarded (push.go's
// pushRoutes calls verifier.Verify, the SAME L1 seam an external PDP
// backs) — so the check is added only when BOTH at least one loop mounts a
// push route AND the configured auth backend is external/probeable (pdpCheck,
// readiness.go, mirrors internal/netcompose.PDPCheck's own backend switch;
// this binary must not import netcompose). A static backend, or a node with
// no push-ingress loop, adds nothing.
func buildHandler(guard *core.URLGuard, pipeCfg *pipelineconfig.Config, authCfg *auth.AuthConfig, mountIngest func(*http.ServeMux) error, natsHealthy func() bool, hasPushIngress bool) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)

	var checks []readinessCheck
	if natsHealthy != nil {
		checks = append(checks, natsCheck(natsHealthy))
	}
	checks = append(checks, registryCheck(guard.HTTPClient(), pipeCfg.VCStoreEndpoint))
	if hasPushIngress {
		if check, ok := pdpCheck(authCfg); ok {
			checks = append(checks, check)
		}
	}
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
// cmd/network, which mounts a full set of ConnectRPC
// services with their own per-RPC read caps (credential, document, proof,
// retain-chunk classes) that internal/netcompose.OuterRequestCapBytes must
// cover; this binary is a wire CLIENT to those services, never their server,
// so none of those classes apply here. Same inflation formula as that
// function (2x for base64 + JSON overhead, +64 KiB framing/header headroom).
func outerRequestCapBytes(maxPushBodySize int) int {
	return maxPushBodySize*2 + 64<<10
}

// DefaultDrainBudget bounds step 4's final mirror-shipper flush (tlog-custody
// spec D8): each shipper gets this long, on a FRESH context independent of
// the already-canceled signal context, to ship its local tail before this
// binary closes the underlying log/NATS handles. A shipper that cannot fully
// catch up within the budget (registry down, or an unusually large backlog)
// is NOT a shutdown failure — the unmirrored tail is still durable on the
// LOCAL log and gets re-shipped the moment this node starts again
// (tlogship.Shipper.Drain always resumes from the registry's own acked
// cursor, never a locally cached one) — see drainShippers' doc.
const DefaultDrainBudget = 10 * time.Second

// dataPlane is run's narrow dependency on pipeline/runtime.Runtime: Run
// drains every loop/aggregate on ctx cancellation; Close (called only after
// Run returns) releases the shared NATS connection and every durable custody
// log's file handle — see pipeline/runtime.Runtime.Close's own doc for why
// these are two separate calls as of PR3b Task 7. A local interface (rather
// than the concrete *pipelineruntime.Runtime) lets the ordering test drive
// run's shutdown sequence without booting a real NATS broker.
type dataPlane interface {
	Run(ctx context.Context) error
	Close() error
}

// run executes this binary's D8 ordered shutdown. Unlike the concurrent
// single-shared-context shape this function used to have (every stage
// cancelled at once), an ORDERED sequence needs a CONTEXT SPLIT: the
// data-plane loops (loopCtx) and the mirror shippers/emit-health reporters
// (shipCtx) each get their OWN cancellable context, independent of ctx (the
// signal context) and of each other, so cancelling one stage never also
// cancels a later stage that has not been told to stop yet. All three run
// concurrently the whole time this binary is up — what is ordered is only
// the SHUTDOWN, driven step by step below:
//
//  1. HTTP stops accepting and drains in-flight requests
//     (httpserve.ServeHTTP already gives its own drain a fresh bounded
//     context internally; see its doc).
//  2. loopCtx is cancelled and dp.Run is awaited (every loop/aggregate
//     drains).
//  3. shipCtx is cancelled and every shipper's Run / reporter's run goroutine
//     is awaited (their periodic ticking stops).
//  4. Each shipper gets ONE final flush attempt on a FRESH context
//     (drainShippers — never loopCtx/shipCtx/ctx, all already cancelled by
//     this point: reusing one of them would make Drain's very first attempt
//     fail instantly, defeating the whole point of a final flush at
//     shutdown).
//  5. dp.Close() releases the shared NATS connection and every durable log's
//     file handle, now that the shippers are done reading from them.
//
// An unprompted data-plane failure (dp.Run returning a non-nil error before
// any external signal — e.g. a boot-time Subscribe error) cancels httpCtx
// early, bringing the HTTP surface down too and proceeding through the same
// ordered teardown below it; mirrors the old single-context run()'s "first
// error cancels everyone" posture, just re-anchored at the front of the
// sequence instead of firing every stage at once. Likewise, if ServeHTTP
// itself returns for a reason OTHER than the signal (e.g. a bind failure),
// the sequence still proceeds through steps 2-5 — whatever HTTP stopped for,
// whatever was started still gets torn down in order.
func run(ctx context.Context, srv *http.Server, listen func() error, dp dataPlane, shippers []*tlogship.Shipper, reporters []*emitHealthReporter, drainBudget time.Duration) error {
	loopCtx, cancelLoops := context.WithCancel(context.Background())
	defer cancelLoops()
	shipCtx, cancelShip := context.WithCancel(context.Background())
	defer cancelShip()
	httpCtx, cancelHTTP := context.WithCancel(ctx)
	defer cancelHTTP()

	loopErrCh := make(chan error, 1)
	go func() {
		err := dp.Run(loopCtx)
		if err != nil {
			cancelHTTP()
		}
		loopErrCh <- err
	}()

	var bgWG sync.WaitGroup
	for _, sh := range shippers {
		bgWG.Add(1)
		go func(sh *tlogship.Shipper) {
			defer bgWG.Done()
			_ = sh.Run(shipCtx) // never returns a real error; see tlogship.Shipper.Run's doc
		}(sh)
	}
	for _, rp := range reporters {
		bgWG.Add(1)
		go func(rp *emitHealthReporter) {
			defer bgWG.Done()
			rp.run(shipCtx)
		}(rp)
	}

	// Step 1.
	httpErr := httpserve.ServeHTTP(httpCtx, srv, listen)

	// Step 2.
	cancelLoops()
	loopErr := <-loopErrCh

	// Step 3.
	cancelShip()
	bgWG.Wait()

	// Step 4.
	drainShippers(shippers, drainBudget)

	// Step 5.
	closeErr := dp.Close()

	// Precedence is httpErr > loopErr > closeErr (the switch below): only the
	// highest-priority non-nil error is returned. A lower-priority error is
	// still real (a leaked conn, an unflushed log) — it must not vanish
	// silently just because a higher one is reported first, so log any
	// masked error here before the switch decides what to return.
	if httpErr != nil {
		if loopErr != nil {
			log.Printf("pipeline: data plane error masked by http server error: %v", loopErr)
		}
		if closeErr != nil {
			log.Printf("pipeline: data plane close error masked by http server error: %v", closeErr)
		}
	} else if loopErr != nil && closeErr != nil {
		log.Printf("pipeline: data plane close error masked by data plane error: %v", closeErr)
	}

	switch {
	case httpErr != nil:
		return fmt.Errorf("http server: %w", httpErr)
	case loopErr != nil:
		return fmt.Errorf("data plane: %w", loopErr)
	case closeErr != nil:
		return fmt.Errorf("data plane: close: %w", closeErr)
	}
	return nil
}

// drainShippers gives every mirror shipper one FRESH, bounded (budget)
// attempt to flush its local tail to the registry (D8 step 4) —
// concurrently, so N shippers cost at most ~budget total, not N×budget. A
// shipper that cannot finish within budget is logged, never treated as a
// shutdown failure: the tail stays durable on the local log and the next
// boot's shipper resumes it from the registry's own acked cursor (see
// DefaultDrainBudget's doc) — this binary still exits zero.
func drainShippers(shippers []*tlogship.Shipper, budget time.Duration) {
	var wg sync.WaitGroup
	for _, sh := range shippers {
		wg.Add(1)
		go func(sh *tlogship.Shipper) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			if err := sh.Drain(ctx); err != nil {
				log.Printf("pipeline: local durable tail remains unmirrored (resume re-ships it): %v", err)
			}
		}(sh)
	}
	wg.Wait()
}
