// Package httpserve is the shared HTTP/2 serving plumbing for the node
// binaries (TLS/h2c posture, graceful drain).
package httpserve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/provin-line/oss/network/pkg/core"
)

// shutdownTimeout bounds the graceful HTTP drain on shutdown.
const shutdownTimeout = 15 * time.Second

// The bounds on what a request makes the server read before any handler
// decides on it: maxHeaderBytes of headers (net/http's default is 1 MiB), and
// bodyStallTimeout for each read of at most stallReadBytes of the body. So a
// body that stalls is dropped: one that delivers nothing for bodyStallTimeout,
// or, chunked on HTTP/1, fewer than stallReadBytes. As with HTTP2Server's
// WriteByteTimeout, the bound is on progress, not on rate: a body trickled a
// byte at a time is not dropped. The body has no deadline between reads, so a
// large body sent at a steady pace, or a long response streamed after the
// body, is not cut.
const (
	maxHeaderBytes = 64 << 10
	stallReadBytes = 16 << 10
)

var bodyStallTimeout = 30 * time.Second

// BuildServer assembles the HTTP server, its listen function, and a serving-mode
// label from the transport posture (F6). It serves TLS directly when
// cert-file/key-file are configured (h2 over TLS via ALPN), else cleartext h2c.
// The boot guard (core.LoadCoreConfig) has already ensured any non-loopback
// cleartext listener was explicitly acknowledged. On both paths, and for HTTP/1
// requests (also one asking to upgrade to h2c) and HTTP/2 streams alike, every
// request passes boundReads (the F0 pre-Connect size bound and the body stall
// bound) before handler; the shared HTTP2Server timeouts and maxHeaderBytes
// apply on both.
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
		MaxHeaderBytes:    maxHeaderBytes,
	}
	if coreCfg.TLS.ServesTLS() {
		if tlsConf == nil {
			// The preflight is not optional on the TLS posture: reaching here
			// without its output means a caller skipped it, and serving would
			// silently re-read the files the preflight exists to pin.
			return nil, nil, "", fmt.Errorf("TLS posture without a preflighted config (core.LoadServerTLS was not run)")
		}
		srv.Handler = boundReads(handler, maxHTTPRequestBytes)
		srv.TLSConfig = tlsConf
		if err := http2.ConfigureServer(srv, HTTP2Server()); err != nil {
			return nil, nil, "", fmt.Errorf("configure http/2 over TLS: %w", err)
		}
		// Empty paths: serve from the preflighted, preloaded pair in TLSConfig —
		// never re-read the files (TOCTOU; P0-6 closure #3).
		return srv, func() error { return srv.ListenAndServeTLS("", "") }, "direct-tls", nil
	}
	// Around h2c and inside it: h2c reads the body of an HTTP/1 request that
	// asks to upgrade to h2c itself, and serves an HTTP/2 connection's streams
	// with the handler it wraps, so each bound reaches one of them.
	srv.Handler = boundReads(h2c.NewHandler(boundReads(handler, maxHTTPRequestBytes), HTTP2Server()), maxHTTPRequestBytes)
	mode := "cleartext-acknowledged"
	if core.ListenerIsLoopback(coreCfg.ListenAddr) {
		mode = "loopback-cleartext"
	}
	return srv, srv.ListenAndServe, mode, nil
}

// boundReads bounds a request body to maxBytes (http.MaxBytesReader) and each
// read of it to bodyStallTimeout. A body the handler leaves unread, which
// net/http then discards on HTTP/1 before the next request, gets one stall
// window for that too.
func boundReads(handler http.Handler, maxBytes int) http.Handler {
	stall := bodyStallTimeout
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasBody := r.Body != nil && r.Body != http.NoBody
		rc := http.NewResponseController(w)
		bounded := *r
		var body *stallBoundedBody
		if hasBody {
			body = &stallBoundedBody{ReadCloser: http.MaxBytesReader(w, r.Body, int64(maxBytes)), rc: rc, timeout: stall}
			bounded.Body = body
		} else {
			bounded.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
		}
		handler.ServeHTTP(w, &bounded)
		if body != nil && !body.ended && r.ProtoMajor == 1 {
			_ = rc.SetReadDeadline(time.Now().Add(stall))
		}
	})
}

// stallBoundedBody sets a read deadline only while a read of the body is in
// progress, and reads at most stallReadBytes at a time: a read of a chunked
// HTTP/1 body fills what it is given across many reads of the connection.
// Between reads there is no deadline (http.Server's ReadTimeout is unset, so
// none is cleared), and once the body has ended it no longer touches the
// deadline, which HTTP/1 then uses to watch the connection while a response
// streams.
type stallBoundedBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
	ended   bool
}

func (b *stallBoundedBody) Read(p []byte) (int, error) {
	if b.ended {
		return b.ReadCloser.Read(p)
	}
	if len(p) > stallReadBytes {
		p = p[:stallReadBytes]
	}
	_ = b.rc.SetReadDeadline(time.Now().Add(b.timeout))
	n, err := b.ReadCloser.Read(p)
	_ = b.rc.SetReadDeadline(time.Time{})
	if err != nil {
		b.ended = true
	}
	return n, err
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
