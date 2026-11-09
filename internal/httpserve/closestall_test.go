package httpserve_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/provin-line/oss/internal/httpserve"
)

// stalledHTTP1 is a chunked request to path that announces a 16-byte chunk
// and sends 2 bytes of it.
func stalledHTTP1(path, contentType string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: " + contentType + "\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nab"
}

// readTwoThenClose reads 2 bytes of the body, closes it, and reports how long
// the handler took.
func readTwoThenClose(took chan<- time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		_, _ = io.ReadFull(r.Body, make([]byte, 2))
		_ = r.Body.Close()
		took <- time.Since(start)
	}
}

// timed reports how long h took to serve each request.
func timed(h http.Handler, took chan<- time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		took <- time.Since(start)
	}
}

// waitWithin fails unless the handler reported within limit.
func waitWithin(t *testing.T, what string, took <-chan time.Duration, limit time.Duration) {
	t.Helper()
	select {
	case d := <-took:
		if d > limit {
			t.Errorf("%s: handler took %v, want at most %v", what, d, limit)
		}
	case <-time.After(limit + time.Second):
		t.Errorf("%s: handler still serving after %v", what, limit+time.Second)
	}
}

// A handler that closes, on HTTP/1, a body it has not read to its end is held
// to the stall bound while net/http discards the rest, as a read is: a stalled
// body cannot hold it.
func TestBuildServer_HoldsTheCloseOfAStalledBodyToTheStallBound(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(200 * time.Millisecond)()
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, readTwoThenClose(took), 1<<20)(stalledHTTP1("/", "application/octet-stream"))
			waitWithin(t, "Close", took, 2*time.Second)
		})
	}
}

// The discard while closing a body is held to the whole-body read limit too: a
// body that arrives steadily, never stalling, cannot hold the handler past it.
func TestBuildServer_HoldsTheCloseOfASteadyBodyToTheReadLimit(t *testing.T) {
	defer httpserve.SetBodyReadTimeout(300 * time.Millisecond)()
	took := make(chan time.Duration, 1)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		_, _ = io.ReadFull(r.Body, make([]byte, 1<<10))
		_ = r.Body.Close()
		took <- time.Since(start)
	}), 1<<20)
	trickle(t, addr, 256, 10*time.Millisecond)
	waitWithin(t, "Close", took, 1500*time.Millisecond)
}

// trickle sends to addr one chunked HTTP/1 body of n KiB, 1 KiB every gap.
func trickle(t *testing.T, addr string, n int, gap time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	piece := strings.Repeat("x", 1<<10)
	go func() {
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", n<<10)
		for range n {
			if _, err := io.WriteString(conn, piece); err != nil {
				return
			}
			time.Sleep(gap)
		}
		_, _ = io.WriteString(conn, "\r\n0\r\n\r\n")
	}()
}

// denyBeforeReading answers every stream unauthenticated before reading its
// body, as L1 does.
type denyBeforeReading struct{}

func (denyBeforeReading) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc { return next }

func (denyBeforeReading) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (denyBeforeReading) WrapStreamingHandler(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(context.Context, connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("unauthenticated"))
	}
}

// clientStream is a connect client-streaming handler behind an interceptor that
// refuses each stream before its body is read.
func clientStream() http.Handler {
	return connect.NewClientStreamHandler("/test.v1.Echo/Stream",
		func(context.Context, *connect.ClientStream[structpb.Struct]) (*connect.Response[structpb.Struct], error) {
			return connect.NewResponse(&structpb.Struct{}), nil
		}, connect.WithInterceptors(denyBeforeReading{}))
}

// connect closes the body of a stream it refuses before reading it; on HTTP/1
// that close is held to the stall bound, so a stalled stream cannot hold the
// handler.
func TestBuildServer_HoldsAConnectStreamRefusedBeforeItsBodyToTheStallBound(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(200 * time.Millisecond)()
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, timed(clientStream(), took), 1<<20)(stalledHTTP1("/test.v1.Echo/Stream", "application/connect+proto"))
			waitWithin(t, "refused stream", took, 2*time.Second)
		})
	}
}

// On HTTP/2, over h2c and TLS, closing a body not read to its end closes the
// stream without reading the rest: neither a handler nor a refused connect
// stream waits for a stalled body, with the stall bound far longer than the
// wait allowed.
func TestBuildServer_ClosingAnHTTP2BodyDoesNotWaitForIt(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(30 * time.Second)()
	for _, p := range paths {
		for _, c := range []struct {
			name, path, contentType string
			handler                 func(chan<- time.Duration) http.Handler
		}{
			{"handler", "/", "application/octet-stream", func(took chan<- time.Duration) http.Handler { return readTwoThenClose(took) }},
			{"refused stream", "/test.v1.Echo/Stream", "application/connect+proto", func(took chan<- time.Duration) http.Handler { return timed(clientStream(), took) }},
		} {
			t.Run(p.name+" "+c.name, func(t *testing.T) {
				took := make(chan time.Duration, 1)
				mux := http.NewServeMux()
				mux.Handle(c.path, c.handler(took))
				var client *http.Client
				var base string
				if p.tls {
					s := serveTLS(t, mux, 1<<20)
					client = &http.Client{Transport: &http2.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1"}}}
					base = "https://" + s.addr
				} else {
					client = h2cClient()
					base = "http://" + serve(t, mux, 1<<20)
				}
				body, pw := io.Pipe()
				t.Cleanup(func() { _ = pw.Close() })
				go func() { _, _ = pw.Write([]byte("ab")) }()
				go func() {
					if resp, err := client.Post(base+c.path, c.contentType, body); err == nil {
						resp.Body.Close()
					}
				}()
				waitWithin(t, c.name, took, time.Second)
			})
		}
	}
}

// A response streamed after a handler closes a body it has not read to its end
// is not cut.
func TestBuildServer_DoesNotCutAStreamAfterClosingAnUnreadBody(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadFull(r.Body, make([]byte, 2))
		if err := r.Body.Close(); err != nil {
			t.Errorf("Close: %v", err)
			return
		}
		for i := range 6 {
			select {
			case <-r.Context().Done():
				t.Errorf("request context cancelled after %d chunks: %v", i, context.Cause(r.Context()))
				return
			case <-time.After(60 * time.Millisecond):
			}
			fmt.Fprintf(w, "chunk %d\n", i)
			w.(http.Flusher).Flush()
		}
	}), 1<<20)
	resp, err := http.Post("http://"+addr+"/", "text/plain", strings.NewReader(strings.Repeat("x", 4<<10)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	n := 0
	for s := bufio.NewScanner(resp.Body); s.Scan(); n++ {
	}
	if n != 6 {
		t.Errorf("received %d chunks, want 6", n)
	}
}

// stalledLength is a request to path that promises a 100-byte body and sends
// 2 bytes of it.
func stalledLength(path, contentType string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: x\r\nContent-Type: " + contentType + "\r\nContent-Length: 100\r\n\r\n{}"
}

// A handler that closes a body whose read failed at the stall bound is not
// held by the close: the server reads nothing more of a body whose read
// failed. connect's unary RPCs read the body and then close it.
func TestBuildServer_DoesNotHoldTheCloseOfABodyWhoseReadFailed(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(200 * time.Millisecond)()
	unary := connect.NewUnaryHandler("/test.v1.Echo/Unary",
		func(_ context.Context, r *connect.Request[structpb.Struct]) (*connect.Response[structpb.Struct], error) {
			return connect.NewResponse(r.Msg), nil
		})
	for _, p := range paths {
		t.Run(p.name+" handler", func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				_, _ = io.ReadAll(r.Body)
				_ = r.Body.Close()
				took <- time.Since(start)
			}), 1<<20)(stalledLength("/", "application/octet-stream"))
			waitWithin(t, "Close after a failed read", took, 2*time.Second)
		})
		t.Run(p.name+" connect unary", func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, timed(unary, took), 1<<20)(stalledLength("/test.v1.Echo/Unary", "application/json"))
			waitWithin(t, "unary", took, 2*time.Second)
		})
	}
}

// After a read of its body failed (at the stall bound, or past the size
// bound), the handler's answer reaches the client and the connection is
// closed at once: nothing more is read of the body, and the connection is not
// reused. Past the size bound the stall bound is left at its default, so the
// connection closing at once is not the stall bound's doing.
func TestBuildServer_ClosesTheConnectionOfABodyWhoseReadFailed(t *testing.T) {
	answer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
		}
	})
	for _, c := range []struct {
		name, raw string
		stall     time.Duration
	}{
		{"stalled", stalledLength("/", "application/octet-stream"), 200 * time.Millisecond},
		{"over the size bound", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n" + strings.Repeat("x", 64) + "\r\n10\r\nab", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.stall > 0 {
				defer httpserve.SetBodyStallTimeout(c.stall)()
			}
			conn, err := net.Dial("tcp", serve(t, answer, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, c.raw); err != nil {
				t.Fatal(err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(conn)
			res, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("no answer: %v", err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			start := time.Now()
			if _, err := br.ReadByte(); err != io.EOF {
				t.Errorf("after the answer: %v, want the connection closed", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("connection closed %v after the answer, want at once", d)
			}
		})
	}
}

// A handler that answers before reading its body to its end makes net/http
// discard the body first on HTTP/1; that discard is held to the stall bound:
// a stalled body cannot hold the handler. connect's gRPC and gRPC-Web
// protocols answer a stream they refuse before closing its body.
func TestBuildServer_HoldsAnAnswerBeforeTheBodyToTheStallBound(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(200 * time.Millisecond)()
	for _, p := range paths {
		t.Run(p.name+" handler", func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				w.WriteHeader(http.StatusAccepted)
				w.(http.Flusher).Flush()
				took <- time.Since(start)
			}), 1<<20)(stalledHTTP1("/", "application/octet-stream"))
			waitWithin(t, "answer", took, 2*time.Second)
		})
		for _, contentType := range []string{"application/grpc-web+proto", "application/grpc+proto"} {
			t.Run(p.name+" refused "+contentType, func(t *testing.T) {
				took := make(chan time.Duration, 1)
				serveOn(t, p.tls, timed(clientStream(), took), 1<<20)(stalledHTTP1("/test.v1.Echo/Stream", contentType))
				waitWithin(t, "refused stream", took, 2*time.Second)
			})
		}
	}
}

// With a whole-body limit of 300 ms and a stall bound of 3 s, a handler that
// lifts the limit, waits past the whole-body limit, and answers before
// reading a stalled body has net/http's discard held to the deadline the
// connection kept from before the lift, which had passed: the lift sets no
// deadline itself, so the answer is written at once. Only the answer is
// timed, not the wait; a deadline set again at the lift would hold it until
// the stall bound from the lift ran out, some 2.5 s after the wait. A wait
// so late that such a deadline would have run out by the answer tells
// neither apart, and skips. A read after the lift is held to the stall bound
// only (TestBuildServer_StreamingBodyKeepsTheStallBound).
func TestBuildServer_HoldsALiftedBodyToTheDeadlineFromBeforeTheLiftOutsideReads(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(3 * time.Second)()
	defer httpserve.SetBodyReadTimeout(300 * time.Millisecond)()
	type timing struct{ waited, took time.Duration }
	got := make(chan timing, 1)
	addr := serve(t, httpserve.StreamingBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpserve.LiftBodyReadLimit(r.Context())
		lifted := time.Now()
		time.Sleep(500 * time.Millisecond)
		start := time.Now()
		w.WriteHeader(http.StatusAccepted)
		w.(http.Flusher).Flush()
		got <- timing{waited: start.Sub(lifted), took: time.Since(start)}
	})), 1<<20)
	send(t, addr, stalledHTTP1("/", "application/octet-stream"))
	select {
	case g := <-got:
		if g.waited >= 2*time.Second {
			t.Skipf("the wait took %v: a deadline set again at the lift would have run out by the answer too", g.waited)
		}
		if d := g.took; d > time.Second {
			t.Errorf("answer after the lift took %v, want at once (the deadline from before the lift had passed)", d)
		}
	case <-time.After(5 * time.Second):
		t.Error("answer after the lift: handler still serving after 5s")
	}
}

// A response streamed after the handler read part of its body, the rest of
// which arrived, is not cut on HTTP/1: net/http discards the rest, and the
// end of the body clears the deadline.
func TestBuildServer_DoesNotCutAStreamAfterAPartialRead(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadFull(r.Body, make([]byte, 2))
		for i := range 6 {
			select {
			case <-r.Context().Done():
				t.Errorf("request context cancelled after %d chunks: %v", i, context.Cause(r.Context()))
				return
			case <-time.After(60 * time.Millisecond):
			}
			fmt.Fprintf(w, "chunk %d\n", i)
			w.(http.Flusher).Flush()
		}
	}), 1<<20)
	resp, err := http.Post("http://"+addr+"/", "text/plain", strings.NewReader(strings.Repeat("x", 4<<10)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	n := 0
	for s := bufio.NewScanner(resp.Body); s.Scan(); n++ {
	}
	if n != 6 {
		t.Errorf("received %d chunks, want 6", n)
	}
}
