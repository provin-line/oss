// Package httpserve is the shared HTTP/2 serving plumbing for the node
// binaries (TLS/h2c posture, graceful drain).
package httpserve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/provin-line/oss/network/pkg/core"
)

// shutdownTimeout bounds the graceful HTTP drain on shutdown.
const shutdownTimeout = 15 * time.Second

// BuildServer assembles the HTTP server, its listen function, and a serving-mode
// label from the transport posture (F6). It serves TLS directly when
// cert-file/key-file are configured (h2 over TLS via ALPN), else cleartext h2c.
// The boot guard (core.LoadCoreConfig) has already ensured any non-loopback
// cleartext listener was explicitly acknowledged. The outer MaxBytesHandler
// (F0 pre-Connect bound) is the outermost handler on BOTH paths; the shared
// HTTP2Server timeouts apply on both.
func BuildServer(coreCfg *core.CoreConfig, tlsConf *tls.Config, handler http.Handler, maxHTTPRequestBytes int) (*http.Server, func() error, string, error) {
	srv := &http.Server{
		Addr: coreCfg.ListenAddr,
		// Slowloris defense on the HTTP/1 side. ReadTimeout/WriteTimeout are
		// deliberately unset: a legitimate ResolvePayload streams a large body,
		// and an absolute read/write deadline would abort it. IdleTimeout bounds
		// kept-alive-but-idle connections; HTTP/2 stalls are bounded by
		// HTTP2Server's own timeouts.
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
		if err := http2.ConfigureServer(srv, HTTP2Server()); err != nil {
			return nil, nil, "", fmt.Errorf("configure http/2 over TLS: %w", err)
		}
		// Empty paths: serve from the preflighted, preloaded pair in TLSConfig —
		// never re-read the files (TOCTOU; P0-6 closure #3).
		return srv, func() error { return srv.ListenAndServeTLS("", "") }, "direct-tls", nil
	}
	srv.Handler = http.MaxBytesHandler(h2c.NewHandler(handler, HTTP2Server()), int64(maxHTTPRequestBytes))
	mode := "cleartext-acknowledged"
	if core.ListenerIsLoopback(coreCfg.ListenAddr) {
		mode = "loopback-cleartext"
	}
	return srv, srv.ListenAndServe, mode, nil
}

// HTTP2Server builds the HTTP/2 server used by both transport paths — h2c
// hijacks connections into it, and http2.ConfigureServer attaches it to the
// TLS server. http.Server's timeouts do not reach these streams, so the stall
// defenses are set here: IdleTimeout bounds an idle connection, and
// ReadIdleTimeout + PingTimeout make the server probe a silent peer and drop
// it if unanswered. WriteByteTimeout bounds per-write stalls WITHOUT imposing
// an absolute stream duration, so a legitimate large ResolvePayload stream is
// unaffected.
func HTTP2Server() *http2.Server {
	return &http2.Server{
		IdleTimeout:      120 * time.Second,
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}
}

// ServeHTTP runs listen (srv.ListenAndServe or ListenAndServeTLS) and shuts it down gracefully when ctx is
// cancelled, using a fresh bounded context (the cancelled ctx must not abort the
// drain). http.ErrServerClosed is the graceful path, not an error.
func ServeHTTP(ctx context.Context, srv *http.Server, listen func() error) error {
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
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		// ListenAndServe failed before any shutdown was requested (e.g. bind error).
		return err
	}
}
