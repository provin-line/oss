package httpserve

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/provin-line/oss/network/pkg/core"
)

// After an HTTP/1 request with a body upgrades to h2c, every later stream on
// the connection is served under the upgrade request's context. Each stream
// still sees only its own bounded body, so concurrent streams share none (run
// with -race).
func TestBoundReads_AnUpgradedConnectionsStreamsShareNoBody(t *testing.T) {
	var mu sync.Mutex
	counts := map[uint32]int{}
	var wg sync.WaitGroup
	wg.Add(3)
	var entered sync.WaitGroup
	entered.Add(3)
	h := StreamingBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		entered.Done()
		entered.Wait()
		LiftBodyReadLimit(r.Context())
		_, _ = io.ReadAll(r.Body)
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		counts[uint32(len(counts))] = len(boundBodies(r.Context()))
		mu.Unlock()
	}))
	srv, _, _, err := BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:0"}, nil, h, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\nContent-Length: 3\r\n\r\nabc")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, " 101 ") {
		t.Fatalf("no upgrade: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	io.WriteString(conn, http2.ClientPreface)
	fr := http2.NewFramer(conn, br)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{3, 5} {
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		for _, f := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":authority", "x"}, {":path", "/"}} {
			_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
			t.Fatal(err)
		}
		if err := fr.WriteData(id, true, []byte("hello")); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handlers did not all run")
	}
	mu.Lock()
	defer mu.Unlock()
	for stream, n := range counts {
		if n != 1 {
			t.Errorf("stream %d sees %d bound bodies, want its own only", stream, n)
		}
	}
}

// An HTTP/1 request with a body that upgrades to h2c leaves no read deadline
// on the connection h2c takes over: h2c reads the body to its end and then
// hijacks the connection, which clears its deadlines, and a stream sent on the
// connection after the stall bound is still served.
func TestBoundReads_AnUpgradedConnectionOutlivesTheStallBound(t *testing.T) {
	old := bodyStallTimeout
	bodyStallTimeout = 100 * time.Millisecond
	defer func() { bodyStallTimeout = old }()
	served := make(chan string, 4)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		served <- r.URL.Path
	})
	srv, _, _, err := BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:0"}, nil, h, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\nContent-Length: 3\r\n\r\nabc")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, " 101 ") {
		t.Fatalf("no upgrade: %q", status)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "" {
			break
		}
	}
	io.WriteString(conn, http2.ClientPreface)
	fr := http2.NewFramer(conn, br)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	wait := func(path string) {
		t.Helper()
		select {
		case got := <-served:
			if got != path {
				t.Fatalf("served %q, want %q", got, path)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s not served", path)
		}
	}
	wait("/upgrade")
	time.Sleep(4 * bodyStallTimeout)
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range [][2]string{{":method", "POST"}, {":scheme", "http"}, {":authority", "x"}, {":path", "/later"}} {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hb.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteData(3, true, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	wait("/later")
}
