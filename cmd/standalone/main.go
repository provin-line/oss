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
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/provin-line/oss/hoconconfig"
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
)

// httpShutdownTimeout bounds the graceful HTTP drain on shutdown.
const httpShutdownTimeout = 15 * time.Second

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
	// BuildHandler mounts it under the VCResolverService RPC; buildDataPlane threads it
	// into consuming loops' ingress store so every verified ingress credential is
	// immediately resolvable and its predecessor is enqueued in the one shared pool. The
	// pool is a named var so the batch resolver drains exactly the pool StoreVC feeds (D-17g-1).
	credStore, err := vcfilestore.NewStore(filepath.Join(evidenceDir, "credentials"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	pool, err := vcfilestore.NewPool(filepath.Join(evidenceDir, "pool"))
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}
	vcSvc := vcresolver.New(credStore, pool)

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
	schemaBridge := schemaResolver{svc: schemaSvc} // the one registry->vc.SchemaResolver bridge, shared by both verifiers
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
	dp, err := buildDataPlane(ctx, chainCfg, pipeCfg, keyStore, dataPlaneDeps{
		Resolver:        resolver,
		VCStore:         vcSvc,
		AuditQueue:      auditQueue,
		Receipts:        auditReceipts,
		TlogDir:         filepath.Join(coreCfg.DataDir, "tlog"),
		RejectLogDir:    filepath.Join(evidenceDir, "sink-rejects"),
		SchemaResolver:  schemaBridge,
		SchemaGetter:    schemaSvc,
		PayloadStore:    payloadSvc,
		PayloadResolver: payloadClient,
	})
	if err != nil {
		log.Fatalf("standalone: build data plane: %v", err)
	}

	// Readiness (/readyz) checks: only what THIS node is configured with — the
	// evidence substrate always, the shared broker connection when a data plane
	// runs, and the external PDP when one is configured (static has no probe).
	readiness := []readinessCheck{evidenceStoreCheck(evidenceDir)}
	if dp.conn != nil {
		readiness = append(readiness, natsCheck(dp.conn.Healthy))
	}
	if check, ok := pdpCheck(authCfg); ok {
		readiness = append(readiness, check)
	}

	// The by-reference advertisement health gate: every producing loop and
	// aggregate is a stripped-publish health source, so the control-plane
	// advertiser degrades by-reference when any of them is failing (D-5).
	var byRefSources []strippedPublishHealthSource
	for _, lp := range dp.loops {
		byRefSources = append(byRefSources, lp)
	}
	for _, ag := range dp.aggregates {
		byRefSources = append(byRefSources, ag)
	}
	byRefGate := newByRefHealthGate(byRefSources)

	handler, err := BuildHandler(coreCfg, regCfg, chainCfg, chainOp, verifier, guard, resolver, vcSvc, auditStatus, auditReceipts,
		schemaSvc, payloadSvc, dp.tlogs, pipeCfg.MaxCredentialSize, ingestMounts{bindings: dp.pushBindings, maxBodySize: pipeCfg.MaxPushBodySize}, readiness, byRefGate.healthy)
	if err != nil {
		log.Fatalf("standalone: build server: %v", err)
	}

	// The async chain-audit resolver drains the pool the consuming loops populate. It is
	// nil for a source-only node (no consuming loop → no holes to drain).
	batchRunner, err := buildBatchResolver(pool, vcSvc, guard, resolver, pipeCfg)
	if err != nil {
		log.Fatalf("standalone: build batch resolver: %v", err)
	}

	// The async audit runner verifies the assembled chains and records per-head verdicts.
	// Also nil for a source-only node (no consumed heads register).
	auditRunner, err := buildAuditRunner(auditQueue, auditStatus, auditReceipts, vcSvc, pool, resolver, schemaBridge, pipeCfg)
	if err != nil {
		log.Fatalf("standalone: build audit runner: %v", err)
	}

	// The /metrics bridge composes OUTSIDE BuildHandler, after the audit
	// runner exists (its VerdictCounts is one of the polled sources). Config
	// gated, default off — the listener is not loopback-bound and metrics
	// expose more than /healthz (see core reference.conf).
	var verdicts func() map[string]uint64
	if auditRunner != nil {
		verdicts = auditRunner.VerdictCounts
	}
	handler, err = maybeMountMetrics(coreCfg.MetricsEnabled, handler, dp.metrics, verdicts)
	if err != nil {
		log.Fatalf("standalone: build metrics: %v", err)
	}
	if coreCfg.MetricsEnabled {
		log.Printf("standalone: metrics exposition mounted at /metrics")
	}

	// Outer raw-body cap: h2c.NewHandler reads an HTTP/1 upgrade request's body
	// in full before the inner Connect handler (and its per-RPC read cap) runs,
	// so a single generous outer bound closes that pre-auth path. Sized to the
	// largest legitimate request (a stored credential or a pushed body) plus
	// headroom; per-RPC caps stay tight below it.
	maxHTTPRequestBytes := outerRequestCapBytes(pipeCfg.MaxCredentialSize, pipeCfg.MaxPushBodySize)
	srv, listen, mode, err := buildServer(coreCfg, tlsConf, handler, maxHTTPRequestBytes)
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

// runServices runs the HTTP server, the data plane, and the two async background runners
// (the batch resolver assembling chains, the audit runner verifying them) concurrently
// under a shared cancellable context, waits for them to drain, and returns the first
// non-shutdown error (nil on a clean shutdown). The HTTP server is the primary service: if
// it returns, the context is cancelled so the others drain. A data-plane ERROR also cancels
// (the node cannot do its job); a clean data-plane return (zero loops) does not bring the
// HTTP server down. Both background runners are degraded-tolerant (log-and-continue,
// D-17g-9 / D-17h-8): they never cancel their siblings and return nil on shutdown; each is
// nil for a source-only node (no consuming loop).
func runServices(ctx context.Context, srv *http.Server, listen func() error, dp *dataPlane, batchRunner *batchresolver.Runner, auditRunner *auditor.Runner) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := serveHTTP(runCtx, srv, listen); err != nil {
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

// outerRequestCapBytes sizes the outermost raw-request-body limit so it is
// never smaller than any legitimate request under a per-RPC read cap. It must
// cover EVERY message class — the per-RPC read caps bound the DECODED message,
// but a Connect JSON request base64-encodes a bytes field (~4/3 inflation), so
// the raw body is larger than the decoded cap. It is deliberately generous —
// the tight bounds are the per-RPC caps below it; this only closes the
// pre-Connect (h2c-upgrade) path that no interceptor guards.
func outerRequestCapBytes(maxCredentialSize, maxPushBodySize int) int {
	largest := maxCredentialSize
	for _, v := range []int{maxPushBodySize, maxDocumentRequestBytes, maxProofRequestBytes} {
		if v > largest {
			largest = v
		}
	}
	// 2x covers base64 (~4/3) plus JSON field-name/escaping overhead with
	// margin; +64 KiB is framing/header headroom.
	return largest*2 + 64<<10
}

// buildServer assembles the HTTP server, its listen function, and a serving-mode
// label from the transport posture (F6). It serves TLS directly when
// cert-file/key-file are configured (h2 over TLS via ALPN), else cleartext h2c.
// The boot guard (core.LoadCoreConfig) has already ensured any non-loopback
// cleartext listener was explicitly acknowledged. The outer MaxBytesHandler
// (F0 pre-Connect bound) is the outermost handler on BOTH paths; the shared
// http2Server timeouts apply on both.
func buildServer(coreCfg *core.CoreConfig, tlsConf *tls.Config, handler http.Handler, maxHTTPRequestBytes int) (*http.Server, func() error, string, error) {
	srv := &http.Server{
		Addr: coreCfg.ListenAddr,
		// Slowloris defense on the HTTP/1 side. ReadTimeout/WriteTimeout are
		// deliberately unset: a legitimate ResolvePayload streams a large body,
		// and an absolute read/write deadline would abort it. IdleTimeout bounds
		// kept-alive-but-idle connections; HTTP/2 stalls are bounded by
		// http2Server's own timeouts.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if coreCfg.TLS.ServesTLS() {
		if tlsConf == nil {
			// The preflight is not optional on the TLS posture: reaching here
			// without its output means a caller skipped it, and serving would
			// silently re-read the files the preflight exists to pin.
			return nil, nil, "", fmt.Errorf("TLS posture without a preflighted config (core.LoadServerTLS was not run)")
		}
		srv.Handler = http.MaxBytesHandler(handler, int64(maxHTTPRequestBytes))
		srv.TLSConfig = tlsConf
		if err := http2.ConfigureServer(srv, http2Server()); err != nil {
			return nil, nil, "", fmt.Errorf("configure http/2 over TLS: %w", err)
		}
		// Empty paths: serve from the preflighted, preloaded pair in TLSConfig —
		// never re-read the files (TOCTOU; P0-6 closure #3).
		return srv, func() error { return srv.ListenAndServeTLS("", "") }, "direct-tls", nil
	}
	srv.Handler = http.MaxBytesHandler(h2c.NewHandler(handler, http2Server()), int64(maxHTTPRequestBytes))
	mode := "cleartext-acknowledged"
	if core.ListenerIsLoopback(coreCfg.ListenAddr) {
		mode = "loopback-cleartext"
	}
	return srv, srv.ListenAndServe, mode, nil
}

// http2Server builds the HTTP/2 server used by both transport paths — h2c
// hijacks connections into it, and http2.ConfigureServer attaches it to the
// TLS server. http.Server's timeouts do not reach these streams, so the stall
// defenses are set here: IdleTimeout bounds an idle connection, and
// ReadIdleTimeout + PingTimeout make the server probe a silent peer and drop
// it if unanswered. WriteByteTimeout bounds per-write stalls WITHOUT imposing
// an absolute stream duration, so a legitimate large ResolvePayload stream is
// unaffected.
func http2Server() *http2.Server {
	return &http2.Server{
		IdleTimeout:      120 * time.Second,
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}
}

// serveHTTP runs listen (srv.ListenAndServe or ListenAndServeTLS) and shuts it down gracefully when ctx is
// cancelled, using a fresh bounded context (the cancelled ctx must not abort the
// drain). http.ErrServerClosed is the graceful path, not an error.
func serveHTTP(ctx context.Context, srv *http.Server, listen func() error) error {
	errCh := make(chan error, 1)
	go func() {
		err := listen()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		// ListenAndServe failed before any shutdown was requested (e.g. bind error).
		return err
	}
}
