package httpserve_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/network/pkg/core"
)

// serve builds the cleartext server around h and serves it on a loopback
// port, returning its address.
func serve(t *testing.T, h http.Handler, maxBody int) string {
	t.Helper()
	srv, _, _, err := httpserve.BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:0"}, nil, h, maxBody)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// h2cClient speaks HTTP/2 with prior knowledge over cleartext.
func h2cClient() *http.Client {
	return &http.Client{Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

// readBody answers 200 after reading the whole body, 413 if reading it fails.
func readBody(w http.ResponseWriter, r *http.Request) {
	if _, err := io.ReadAll(r.Body); err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Request headers are bounded: net/http's default would take 1 MiB of them
// before any handler runs.
func TestBuildServer_BoundsRequestHeaders(t *testing.T) {
	addr := serve(t, http.HandlerFunc(readBody), 1<<20)
	for size, want := range map[int]int{100 << 10: http.StatusRequestHeaderFieldsTooLarge, 16 << 10: http.StatusOK} {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
		req.Header.Set("X-Pad", strings.Repeat("x", size))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%d-byte header: %v", size, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%d-byte header: status %d, want %d", size, resp.StatusCode, want)
		}
	}
}

// The request-size bound covers HTTP/2 streams on the cleartext path too,
// not only HTTP/1 requests.
func TestBuildServer_BoundsTheBodyOfACleartextHTTP2Stream(t *testing.T) {
	addr := serve(t, http.HandlerFunc(readBody), 1<<10)
	resp, err := h2cClient().Post("http://"+addr+"/", "application/octet-stream", strings.NewReader(strings.Repeat("x", 4<<10)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("4 KiB body over a 1 KiB bound: HTTP/%d status %d, want HTTP/2 413", resp.ProtoMajor, resp.StatusCode)
	}
}

// A request body that stops arriving is dropped after the stall timeout, on
// HTTP/1 and on cleartext HTTP/2: a stalled sender cannot hold the handler.
func TestBuildServer_DropsAStalledRequestBody(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	read := make(chan error, 2)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		read <- err
	}), 1<<20)

	// HTTP/1: the headers promise 100 bytes, 3 arrive.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
	waitReadError(t, "HTTP/1", read)

	// HTTP/2: the stream's body never ends.
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() {
		_, _ = pw.Write([]byte("abc"))
	}()
	go func() {
		resp, err := h2cClient().Post("http://"+addr+"/", "application/octet-stream", pr)
		if err == nil {
			resp.Body.Close()
		}
	}()
	waitReadError(t, "HTTP/2", read)
}

func waitReadError(t *testing.T, proto string, read <-chan error) {
	t.Helper()
	select {
	case err := <-read:
		if err == nil {
			t.Errorf("%s: stalled body read to the end", proto)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: handler still reading a stalled body after 5s", proto)
	}
}

// A response streamed long after the body was read is not cut: the stall
// timeout applies only while the handler waits for the body.
func TestBuildServer_DoesNotCutALongStreamedResponse(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("body: %v", err)
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
	resp, err := http.Post("http://"+addr+"/", "text/plain", strings.NewReader("hello"))
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

// An HTTP/1 request asking to upgrade to h2c, whose body h2c reads itself, is
// held to the request-size bound too.
func TestBuildServer_BoundsTheBodyOfAnH2CUpgradeRequest(t *testing.T) {
	got := make(chan int, 1)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- len(b)
	}), 1<<10)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := strings.Repeat("x", 4<<10)
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if strings.Contains(status, " 101 ") {
		t.Errorf("4 KiB upgrade body over a 1 KiB bound: switched protocols (%q)", strings.TrimSpace(status))
	}
	select {
	case n := <-got:
		if n > 1<<10 {
			t.Errorf("handler read %d bytes past a 1 KiB bound", n)
		}
	default:
	}
}

// A body arriving at a steady pace in one large chunk is read to the end
// although it takes longer than the stall timeout.
func TestBuildServer_ReadsASteadyChunkedBodyLongerThanTheStallTimeout(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(300 * time.Millisecond)()
	read := make(chan error, 1)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err == nil && len(b) != 256<<10 {
			err = fmt.Errorf("read %d bytes", len(b))
		}
		read <- err
	}), 1<<20)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n", 256<<10)
	piece := strings.Repeat("x", 1<<10)
	for range 256 { // 1 KiB every 5 ms: about 1.3 s in all
		if _, err := io.WriteString(conn, piece); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	io.WriteString(conn, "\r\n0\r\n\r\n")
	select {
	case err := <-read:
		if err != nil {
			t.Errorf("steady chunked body: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler still reading after 10s")
	}
}

// A handler may pause between reads of an HTTP/2 body, while flow control
// holds the client back, for longer than the stall timeout: there is no
// deadline between reads.
func TestBuildServer_SetsNoDeadlineBetweenReadsOfAnHTTP2Body(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	read := make(chan error, 1)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			read <- err
			return
		}
		time.Sleep(400 * time.Millisecond)
		_, err := io.Copy(io.Discard, r.Body)
		read <- err
	}), 8<<20)
	go func() {
		resp, err := h2cClient().Post("http://"+addr+"/", "application/octet-stream", strings.NewReader(strings.Repeat("x", 4<<20)))
		if err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case err := <-read:
		if err != nil {
			t.Errorf("body read after a pause: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler still reading after 10s")
	}
}

// A response streamed after the body, on HTTP/1 and HTTP/2, is not cut, also
// when the handler reads once more past the body's end (as connect does when
// it discards the rest).
func TestBuildServer_DoesNotCutAStreamAfterAReadPastTheBodysEnd(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("body: %v", err)
			return
		}
		_, _ = r.Body.Read(make([]byte, 1))
		for i := range 6 {
			select {
			case <-r.Context().Done():
				t.Errorf("HTTP/%d: request context cancelled after %d chunks: %v", r.ProtoMajor, i, context.Cause(r.Context()))
				return
			case <-time.After(60 * time.Millisecond):
			}
			fmt.Fprintf(w, "chunk %d\n", i)
			w.(http.Flusher).Flush()
		}
	}), 1<<20)
	for name, c := range map[string]*http.Client{"HTTP/1": http.DefaultClient, "HTTP/2": h2cClient()} {
		resp, err := c.Post("http://"+addr+"/", "text/plain", strings.NewReader("hello"))
		if err != nil {
			t.Fatalf("%s: POST: %v", name, err)
		}
		n := 0
		for s := bufio.NewScanner(resp.Body); s.Scan(); n++ {
		}
		resp.Body.Close()
		if n != 6 {
			t.Errorf("%s: received %d chunks, want 6", name, n)
		}
	}
}

// A body the handler answers without reading, which net/http then discards
// before the next request, is held to the stall bound too.
func TestBuildServer_BoundsTheDiscardOfAnUnreadBody(t *testing.T) {
	defer httpserve.SetBodyStallTimeout(100 * time.Millisecond)()
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), 1<<20)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(conn)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("connection still held: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection still held after 5s")
	}
}
