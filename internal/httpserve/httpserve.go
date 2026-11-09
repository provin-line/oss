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

	"github.com/provin-line/oss/internal/excerpt"
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
// byte at a time is not dropped. On HTTP/1, net/http also reads the body
// itself, to discard what is left when a handler closes it, answers before
// reading it to its end, or returns; what it reads there is held to the
// stall bound counted from the end of the handler's last read of the body.
// Once the body has ended or been closed the server sets no read deadline of
// its own, so a long response streamed after the body is not cut.
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

// readErrorLimit is the most bytes the text of a failed read or close of a
// body takes (package excerpt cuts it): net/http quotes what it read in some
// of these errors, such as a malformed trailer line of a chunked body, and a
// handler writes the text into its answer or a log. 512 bytes hold any of
// net/http's own texts whole and leave a handler room for its words within
// 1 KiB.
const readErrorLimit = 512

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
// read of it to bodyStallTimeout, and the whole of it to bodyReadTimeout. On
// HTTP/1 net/http discards what a handler leaves of a body: when the handler
// closes it, answers before reading it to its end, or returns. What it reads
// there is held to the deadline the body keeps on the connection between
// reads (stallBoundedBody), and a body whose read failed is not read further.
func boundReads(handler http.Handler, maxBytes int) http.Handler {
	stall, whole := bodyStallTimeout, bodyReadTimeout
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasBody := r.Body != nil && r.Body != http.NoBody
		rc := http.NewResponseController(w)
		var body *stallBoundedBody
		bounded := r
		if hasBody {
			body = &stallBoundedBody{ReadCloser: http.MaxBytesReader(w, r.Body, int64(maxBytes)), rc: rc, timeout: stall, end: time.Now().Add(whole), http1: r.ProtoMajor == 1}
			body.rest()
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
// to, if its route was marked by StreamingBody; otherwise it does nothing.
// The next reads of the body, and the deadline between them, keep the stall
// bound only; until the next read the connection keeps the deadline it had,
// which comes no later. It sets no read deadline itself. It is meant for the
// handler's goroutine, which reads the body.
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

// stallBoundedBody sets a read deadline for each read of the body, and reads
// at most stallReadBytes at a time: a read of a chunked HTTP/1 body fills what
// it is given across many reads of the connection.
//
// On HTTP/1, net/http reads the body itself too, to discard what a handler
// leaves of it (when the handler closes it, answers before reading it to its
// end, or returns), so the connection keeps a read deadline between reads as
// well (rest), by the body's state:
//
//	state   from                                       deadline between reads
//	open    the body's wrapping                        that of a read starting when the last one ended
//	                                                   (or at the wrapping): the stall bound, or the
//	                                                   whole-body limit if that comes first
//	ended   a read reaching the body's end             none
//	failed  a read failing (the stall bound, the size  now: nothing more is read of the body, and
//	        bound, the peer)                           net/http closes the connection after the answer
//	closed  its Close; a read that finds net/http      none: net/http reads the connection itself from
//	        closed it (http.ErrBodyReadAfterClose)     then on, with no deadline, or closes it after
//	                                                   the answer
//
// So each discard net/http makes gets one window, counted from the end of the
// handler's last read of the body: a handler that works past it and leaves
// the body unread has its connection closed after the answer, not reused.
// The body sets no deadline once it has ended or been closed: net/http then
// watches the connection itself, while a response streams. When one read both
// reaches the body's end and passes the size bound, net/http has begun to
// watch the connection, and the deadline of the failed read ends that,
// cancelling the request's context while the handler answers; the connection
// is closed after the answer either way. On HTTP/2 there is
// no deadline between reads: net/http does not read the body itself, and
// closing it ends the stream. http1 is also true of the HTTP/1.1 request an
// h2c upgrade serves as its first stream, which has no body of its own. The
// body is read and closed from one goroutine at a time, the handler's.
type stallBoundedBody struct {
	io.ReadCloser
	rc      *http.ResponseController
	timeout time.Duration
	end     time.Time // the whole-body limit; zero for a lifted body
	state   bodyState
	http1   bool // the request is HTTP/1, so net/http reads the body itself too
}

type bodyState int

const (
	bodyOpen bodyState = iota
	bodyEnded
	bodyFailed
	bodyClosed
)

// rest sets the read deadline an HTTP/1 connection keeps between reads of the
// body, by its state (the table in stallBoundedBody's doc).
func (b *stallBoundedBody) rest() {
	if !b.http1 {
		return
	}
	switch b.state {
	case bodyOpen:
		_ = b.rc.SetReadDeadline(b.deadline(time.Now()))
	case bodyFailed:
		_ = b.rc.SetReadDeadline(time.Now())
	case bodyEnded, bodyClosed:
		_ = b.rc.SetReadDeadline(time.Time{})
	}
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

// Read returns the error of a failed read with its text within readErrorLimit
// bytes: an error whose text is UTF-8 within the limit as it is, any other cut
// and wrapped, so errors.Is and errors.As still find it.
func (b *stallBoundedBody) Read(p []byte) (int, error) {
	if b.state != bodyOpen {
		n, err := b.ReadCloser.Read(p)
		return n, excerpt.OfError(err, readErrorLimit)
	}
	if len(p) > stallReadBytes {
		p = p[:stallReadBytes]
	}
	_ = b.rc.SetReadDeadline(b.deadline(time.Now()))
	n, err := b.ReadCloser.Read(p)
	switch {
	case err == nil:
	case err == io.EOF:
		b.state = bodyEnded
	case errors.Is(err, http.ErrBodyReadAfterClose):
		b.state = bodyClosed
	default:
		b.state = bodyFailed
	}
	if b.http1 {
		b.rest()
	} else {
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, excerpt.OfError(err, readErrorLimit)
}

// Close closes the body and returns its error with the text bounded as Read's
// is. On HTTP/1, closing a body not read to its end reads what is left of it,
// under the deadline rest keeps on the connection; on HTTP/2 closing ends the
// stream without reading. The body sets no deadline after it.
func (b *stallBoundedBody) Close() error {
	err := b.ReadCloser.Close()
	b.state = bodyClosed
	return excerpt.OfError(err, readErrorLimit)
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
