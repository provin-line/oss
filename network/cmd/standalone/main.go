// Command standalone is the dplaax network registry server: a single binary that
// loads its HOCON config, constructs the DID / Schema / Signer services over
// file-backed stores, and serves them via ConnectRPC (h2c) behind the L1
// authorization interceptors, plus the public W3C DID resolution route and
// /healthz. Every config value is validated at boot — a misconfigured binary
// dies at startup, never on first request.
//
// Alongside the HTTP control plane it runs the data plane: the pipeline transport
// loops declared in the pipeline config (slice-17b). Both run concurrently under one
// signal-cancelled context; on SIGINT/SIGTERM the loops drain and the HTTP server
// shuts down gracefully before the process exits.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
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

	verifier, err := auth.NewVerifier(authCfg.PolicyVerifierURL)
	if err != nil {
		log.Fatalf("standalone: %v", err)
	}

	handler, err := BuildHandler(coreCfg, regCfg, chainCfg, verifier)
	if err != nil {
		log.Fatalf("standalone: build server: %v", err)
	}

	// The data plane signs with the same file-backed keystore the control plane uses
	// (dataDir/keys). With zero loops configured this dials nothing.
	keyStore := filestore.New(filepath.Join(coreCfg.DataDir, "keys"))
	dp, err := buildDataPlane(chainCfg, pipeCfg, keyStore)
	if err != nil {
		log.Fatalf("standalone: build data plane: %v", err)
	}

	srv := &http.Server{
		Addr:    coreCfg.ListenAddr,
		Handler: h2c.NewHandler(handler, &http2.Server{}),
	}

	// Run the HTTP server and the data plane concurrently under a shared cancellable
	// context. The HTTP server is the primary service: if it returns, cancel so the
	// data plane drains. A data-plane ERROR also cancels (the node cannot do its job);
	// a clean data-plane return (zero loops) does not bring the HTTP server down.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer cancel()
		if err := serveHTTP(runCtx, srv); err != nil {
			log.Printf("standalone: http server: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := dp.Run(runCtx); err != nil {
			log.Printf("standalone: data plane: %v", err)
			cancel()
		}
	}()

	log.Printf("standalone: listening on %s (registry %q, %d data-plane loop(s))",
		coreCfg.ListenAddr, regCfg.ID, len(pipeCfg.Loops))
	wg.Wait()
	log.Printf("standalone: shutdown complete")
}

// serveHTTP runs srv.ListenAndServe and shuts it down gracefully when ctx is
// cancelled, using a fresh bounded context (the cancelled ctx must not abort the
// drain). http.ErrServerClosed is the graceful path, not an error.
func serveHTTP(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
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
