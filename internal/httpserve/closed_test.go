package httpserve_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/provin-line/oss/internal/httpserve"
)

// twoOnOneConnection sends first and then, after its answer, second on one
// connection to addr, and returns the second's answer body, or "" and the
// error when the connection gave none.
func twoOnOneConnection(t *testing.T, addr, first, second string) (string, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	if _, err := io.WriteString(conn, first); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("first answer: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if _, err := io.WriteString(conn, second); err != nil {
		return "", err
	}
	res, err = http.ReadResponse(br, nil)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

const secondRequest = "GET /2 HTTP/1.1\r\nHost: x\r\n\r\n"

// secondAnswersItsContext serves first for the first request and, for the
// next, answers whether its context was cancelled; it reports, past the stall
// bound, whether the first request's context was.
func secondAnswersItsContext(first http.HandlerFunc, firstCtx chan<- error) http.HandlerFunc {
	var n atomic.Int32
	return func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			first(w, r)
			time.Sleep(200 * time.Millisecond)
			firstCtx <- r.Context().Err()
			return
		}
		fmt.Fprintf(w, "ctx=%v", r.Context().Err())
	}
}

// A handler that reads its body after net/http has read it to its end and
// closed it (when the handler answered first, or closed it itself) leaves the
// connection as net/http keeps it: neither its request's context nor the
// next request's on the same connection is cancelled.
func TestBuildServer_AReadOfABodyNetHTTPClosedLeavesTheConnection(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	for _, c := range []struct {
		name  string
		first http.HandlerFunc
	}{
		{"after an answer", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			w.(http.Flusher).Flush()
			_, _ = r.Body.Read(make([]byte, 4))
		}},
		{"after a close", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadFull(r.Body, make([]byte, 2))
			_ = r.Body.Close()
			_, _ = r.Body.Read(make([]byte, 4))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			firstCtx := make(chan error, 1)
			addr := serve(t, secondAnswersItsContext(c.first, firstCtx), 1<<20)
			got, err := twoOnOneConnection(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", secondRequest)
			if ctxErr := <-firstCtx; ctxErr != nil {
				t.Errorf("first request's context: %v", ctxErr)
			}
			if got != "ctx=<nil>" {
				t.Errorf("second request on the connection: %q (%v), want its context live", got, err)
			}
		})
	}
}

// A response streamed after the whole-body limit is lifted from a body
// already closed (by the handler, or by net/http after an answer) is not cut:
// the lift sets no read deadline on the connection.
func TestBuildServer_DoesNotCutAStreamAfterALiftOfAClosedBody(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	for _, c := range []struct {
		name   string
		before func(w http.ResponseWriter, r *http.Request)
	}{
		{"closed by the handler", func(_ http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadFull(r.Body, make([]byte, 2))
			_ = r.Body.Close()
		}},
		{"closed by net/http after an answer", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := serve(t, httpserve.StreamingBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.before(w, r)
				httpserve.LiftBodyReadLimit(r.Context())
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
			})), 1<<20)
			res, err := http.Post("http://"+addr+"/", "text/plain", strings.NewReader("hello"))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			n := 0
			for s := bufio.NewScanner(res.Body); s.Scan(); n++ {
			}
			if n != 6 {
				t.Errorf("received %d chunks, want 6", n)
			}
		})
	}
}

// A handler that closes a body awaiting a 100 Continue it never asks for
// returns within the stall bound, on both paths.
func TestBuildServer_BoundsTheCloseOfABodyAwaitingContinue(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(200 * time.Millisecond)()
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			took := make(chan time.Duration, 1)
			serveOn(t, p.tls, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				start := time.Now()
				_ = r.Body.Close()
				took <- time.Since(start)
			}), 1<<20)("POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 100\r\n\r\n")
			select {
			case d := <-took:
				if d > time.Second {
					t.Errorf("close took %v, want within the stall bound", d)
				}
			case <-time.After(3 * time.Second):
				t.Error("close still blocked after 3s")
			}
		})
	}
}

// What net/http discards of a body after the handler returns is held to the
// window counted from the handler's last read, like its other discards: a
// handler that works past the stall bound and returns without writing, a
// body left of 64 KiB, closes the connection, and the next request is served
// on a new one.
func TestBuildServer_ClosesTheConnectionOfABodyLeftPastItsWindow(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	var n atomic.Int32
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			_, _ = io.ReadFull(r.Body, make([]byte, 2))
			time.Sleep(300 * time.Millisecond)
			return
		}
		fmt.Fprint(w, "served")
	}), 1<<20)
	body := strings.Repeat("x", 64<<10)
	if got, err := twoOnOneConnection(t, addr, fmt.Sprintf("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(body), body), secondRequest); err == nil {
		t.Errorf("second request on the same connection answered %q, want the connection closed", got)
	}
	res, err := http.Get("http://" + addr + "/2")
	if err != nil {
		t.Fatalf("on a new connection: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if string(b) != "served" {
		t.Errorf("on a new connection: %q", b)
	}
}
