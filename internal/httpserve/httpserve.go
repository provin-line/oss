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
	"slices"
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
// long response streamed after the body is not cut.
//
// Besides, the body must be read to its end within bodyReadTimeout of the
// request's start, whatever its pace, so the server spends a bounded time
// reading one request's body. A handler wrapped in StreamingBody, one that
// reads a long body as it arrives, may lift that limit (LiftBodyReadLimit)
// and keep the stall bound only.
const (
	maxHeaderBytes = 64 << 10
	stallReadBytes = 16 << 10
)

var (
	bodyStallTimeout = 30 * time.Second
	bodyReadTimeout  = 60 * time.Second
)

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

// boundReads bounds a request body to maxBytes (http.MaxBytesReader), each
// read of it to bodyStallTimeout, and the whole of it to bodyReadTimeout. A
// body the handler leaves unread, which net/http then discards on HTTP/1
// before the next request, gets the stall window or the time left of the
// whole-body limit, whichever is shorter, for that too.
func boundReads(handler http.Handler, maxBytes int) http.Handler {
	stall, whole := bodyStallTimeout, bodyReadTimeout
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasBody := r.Body != nil && r.Body != http.NoBody
		rc := http.NewResponseController(w)
		var body *stallBoundedBody
		bounded := r
		if hasBody {
			body = &stallBoundedBody{ReadCloser: http.MaxBytesReader(w, r.Body, int64(maxBytes)), rc: rc, timeout: stall, end: time.Now().Add(whole)}
			// Inherit the bodies already bounded only when this request's body
			// is the last of them (the cleartext path's HTTP/1 request, bounded
			// around h2c and inside it). An upgraded h2c connection serves its
			// streams under the upgrade request's context, whose body is not
			// theirs.
			outer := boundBodies(r.Context())
			if n := len(outer); n > 0 && io.ReadCloser(outer[n-1]) != r.Body {
				outer = nil
			}
			bounded = r.WithContext(context.WithValue(r.Context(), boundBodiesKey{}, append(slices.Clone(outer), body)))
			bounded.Body = body
		} else {
			shallow := *r
			bounded = &shallow
			bounded.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
		}
		handler.ServeHTTP(w, bounded)
		if body != nil && !body.ended && r.ProtoMajor == 1 {
			_ = rc.SetReadDeadline(body.deadline(time.Now()))
		}
	})
}

// StreamingBody marks handler as one that reads a long request body as it
// arrives (a client-streaming RPC): once the handler calls LiftBodyReadLimit,
// its body is held to the stall bound only, not to bodyReadTimeout. Which
// routes stream, and when their caller is trusted enough for the lift, is for
// the code that assembles them to say; httpserve knows neither.
func StreamingBody(handler http.Handler) http.Handler {
	return streamingBody{handler}
}

// IsStreamingBody reports whether handler is a value StreamingBody returned
// (a handler wrapped further reports false).
func IsStreamingBody(handler http.Handler) bool {
	_, ok := handler.(streamingBody)
	return ok
}

// LiftBodyReadLimit lifts the whole-body read limit of the request ctx belongs
// to, if its route was marked by StreamingBody; otherwise it does nothing. It
// is meant for the handler's goroutine, which reads the body.
func LiftBodyReadLimit(ctx context.Context) {
	if lift, _ := ctx.Value(liftableKey{}).(bool); !lift {
		return
	}
	for _, b := range boundBodies(ctx) {
		b.end = time.Time{}
	}
}

type streamingBody struct{ http.Handler }

func (s streamingBody) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), liftableKey{}, true)))
}

// liftableKey marks, in a request's context, a route StreamingBody wraps.
type liftableKey struct{}

// boundBodiesKey holds, in a request's context, the bodies boundReads bounds
// (one, or two on the cleartext path's HTTP/1 requests), so
// LiftBodyReadLimit can lift their whole-body limit.
type boundBodiesKey struct{}

func boundBodies(ctx context.Context) []*stallBoundedBody {
	b, _ := ctx.Value(boundBodiesKey{}).([]*stallBoundedBody)
	return b
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
	end     time.Time // the whole-body limit; zero for a Streaming handler
	ended   bool
}

// deadline is the read deadline for a read starting at now: the stall bound,
// or the whole-body limit if that comes first.
func (b *stallBoundedBody) deadline(now time.Time) time.Time {
	d := now.Add(b.timeout)
	if !b.end.IsZero() && b.end.Before(d) {
		return b.end
	}
	return d
}

func (b *stallBoundedBody) Read(p []byte) (int, error) {
	if b.ended {
		return b.ReadCloser.Read(p)
	}
	if len(p) > stallReadBytes {
		p = p[:stallReadBytes]
	}
	_ = b.rc.SetReadDeadline(b.deadline(time.Now()))
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
