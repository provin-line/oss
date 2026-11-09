package httpserve_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/network/pkg/core"
)

// readOnce reports the errors of reading a body until a read fails, and of
// reading once more after that.
func readOnce(read chan<- [2]error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		var first error
		for first == nil {
			_, first = r.Body.Read(buf)
		}
		_, again := r.Body.Read(buf)
		read <- [2]error{first, again}
	}
}

// send writes raw to a new connection to addr and leaves it open.
func send(t *testing.T, addr, raw string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
}

// paths are the two ways the server is built: cleartext h2c, which bounds an
// HTTP/1 request's body twice (around h2c and inside it), and TLS, once.
var paths = []struct {
	name string
	tls  bool
}{{"cleartext", false}, {"TLS", true}}

// serveOn serves h on a server built the path's way and returns a function
// that sends raw to it over HTTP/1.1 on a new connection.
func serveOn(t *testing.T, tlsPath bool, h http.Handler, maxBody int) func(raw string) {
	t.Helper()
	if tlsPath {
		s := serveTLS(t, h, maxBody)
		return func(raw string) { sendTLS(t, s, raw) }
	}
	addr := serve(t, h, maxBody)
	return func(raw string) { send(t, addr, raw) }
}

// malformedTrailer is a chunked request to path whose trailer line net/http
// quotes whole in its error, its bytes escaped: about 9.5 KB of text.
func malformedTrailer(path string, header string) string {
	return "POST " + path + " HTTP/1.1\r\nHost: x\r\n" + header + "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n" + strings.Repeat("\xffA", 1900) + "\r\n\r\n"
}

// A read of a body fails with a text within ReadErrorLimit bytes of UTF-8,
// however much of the body the reader quotes: net/http quotes a malformed
// trailer line of a chunked body whole. The text is the head of the reader's
// and its length, and the reader's error is still found by errors.As; so is
// it on a read after the failed one.
func TestBuildServer_BoundsTheTextOfABodyReadError(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			read := make(chan [2]error, 1)
			serveOn(t, p.tls, readOnce(read), 1<<20)(malformedTrailer("/", ""))
			got := waitPair(t, "trailer", read)
			checkBodyReadError(t, "the failed read", got[0])
			checkBodyReadError(t, "the read after it", got[1])
		})
	}
}

// Closing a body not read to its end reads what is left of it on HTTP/1, and
// fails with a text within ReadErrorLimit bytes, as a read does.
func TestBuildServer_BoundsTheTextOfABodyCloseError(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			closed := make(chan [2]error, 1)
			closeUnread := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				closed <- [2]error{r.Body.Close()}
			})
			serveOn(t, p.tls, closeUnread, 1<<20)(malformedTrailer("/", ""))
			checkBodyReadError(t, "Close", waitPair(t, "close", closed)[0])
		})
	}
}

// checkBodyReadError fails unless err is net/http's malformed-trailer error,
// its text cut within ReadErrorLimit bytes of UTF-8 and the whole error found
// by errors.As.
func checkBodyReadError(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error", what)
	}
	text := err.Error()
	if len(text) > httpserve.ReadErrorLimit || !utf8.ValidString(text) {
		t.Errorf("%s: %d bytes of text (UTF-8: %v): %.120q", what, len(text), utf8.ValidString(text), text)
	}
	if !strings.Contains(text, "malformed MIME header") || !strings.HasSuffix(text, " bytes)") {
		t.Errorf("%s: text %.120q is not the head of net/http's error", what, text)
	}
	var whole textproto.ProtocolError
	if !errors.As(err, &whole) || len(whole) <= httpserve.ReadErrorLimit {
		t.Errorf("%s: errors.As does not find net/http's whole error (%d bytes)", what, len(whole))
	}
}

// serveTLS builds the TLS server around h and serves it on a loopback port,
// returning its address and a pool that trusts its certificate.
func serveTLS(t *testing.T, h http.Handler, maxBody int) tlsServer {
	t.Helper()
	certFile, keyFile := writeSelfSignedCert(t)
	coreCfg := &core.CoreConfig{ListenAddr: "127.0.0.1:0", TLS: core.TLSConfig{CertFile: certFile, KeyFile: keyFile}}
	tlsConf, err := coreCfg.TLS.LoadServerTLS()
	if err != nil {
		t.Fatalf("LoadServerTLS: %v", err)
	}
	srv, _, _, err := httpserve.BuildServer(coreCfg, tlsConf, h, maxBody)
	if err != nil {
		t.Fatalf("BuildServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	return tlsServer{addr: ln.Addr().String(), roots: pool}
}

type tlsServer struct {
	addr  string
	roots *x509.CertPool
}

// sendTLS writes raw over HTTP/1.1 on a new TLS connection to s and leaves it
// open.
func sendTLS(t *testing.T, s tlsServer, raw string) {
	t.Helper()
	conn, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: s.roots, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
}

// waitPair returns what readOnce reported.
func waitPair(t *testing.T, name string, read <-chan [2]error) [2]error {
	t.Helper()
	select {
	case got := <-read:
		return got
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: handler still reading after 10s", name)
		return [2]error{}
	}
}

// A read error whose text is UTF-8 within the limit is returned as it is: the
// end of a body is io.EOF itself, on the read that meets it and the one after,
// and a body over the read limit fails with net/http's *http.MaxBytesError.
func TestBuildServer_KeepsAReadErrorThatFits(t *testing.T) {
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			read := make(chan [2]error, 1)
			send := serveOn(t, p.tls, readOnce(read), 16)
			send("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
			for i, err := range waitPair(t, "end", read) {
				if err != io.EOF {
					t.Errorf("the end of a body, read %d: %v, want io.EOF itself", i, err)
				}
			}
			send("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n" + strings.Repeat("a", 64))
			for i, err := range waitPair(t, "limit", read) {
				var tooLarge *http.MaxBytesError
				if !errors.As(err, &tooLarge) {
					t.Errorf("a body over the limit, read %d: %v, want *http.MaxBytesError", i, err)
				}
			}
		})
	}
}

// A connect handler behind the server answers a body whose read fails, over
// HTTP/1 and with a malformed trailer line, with that read's text: within
// ReadErrorLimit bytes and the words connect puts before it.
func TestBuildServer_AConnectHandlerAnswersABodyReadErrorWithinTheLimit(t *testing.T) {
	// connectWords is room for the words connect puts before the read's text
	// ("read message: ", 14 bytes).
	const connectWords = 64
	mux := http.NewServeMux()
	mux.Handle("/test.v1.Echo/Unary", connect.NewUnaryHandler("/test.v1.Echo/Unary",
		func(_ context.Context, r *connect.Request[structpb.Struct]) (*connect.Response[structpb.Struct], error) {
			return connect.NewResponse(r.Msg), nil
		}))
	addr := serve(t, mux, 1<<20)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, malformedTrailer("/test.v1.Echo/Unary", "Content-Type: application/json\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var answer struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&answer); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if !strings.Contains(answer.Message, "malformed MIME header") {
		t.Fatalf("answer %.120q is not the read's error", answer.Message)
	}
	if max := httpserve.ReadErrorLimit + connectWords; len(answer.Message) > max {
		t.Errorf("answer of %d bytes, want at most %d: %.120q", len(answer.Message), max, answer.Message)
	}
}
