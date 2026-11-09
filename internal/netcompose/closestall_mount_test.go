package netcompose

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	payloadpbconnect "github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"

	"github.com/provin-line/oss/internal/httpserve"
	"github.com/provin-line/oss/network/pkg/core"
)

// deadlineListener accepts connections that report each read deadline set on
// them.
type deadlineListener struct {
	net.Listener
	set chan<- time.Time
}

func (l deadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return deadlineConn{Conn: c, set: l.set}, nil
}

type deadlineConn struct {
	net.Conn
	set chan<- time.Time
}

func (c deadlineConn) SetReadDeadline(t time.Time) error {
	select {
	case c.set <- t:
	default:
	}
	return c.Conn.SetReadDeadline(t)
}

// RetainPayload, which L1 refuses before its body is read, does not let a
// stalled HTTP/1 body hold its handler, in each protocol: connect closes the
// body (Connect) or answers before closing it (gRPC, gRPC-Web), and net/http
// then discards the body, under a read deadline at the stall bound that the
// server sets on the connection while the handler is still serving. The
// server's bounds are package httpserve's to shorten, so this checks the
// deadline it sets and that no answer has come yet, rather than waiting the
// 30 s.
func TestBuildServer_RetainPayloadRefusedByL1HoldsItsBodyToTheStallBound(t *testing.T) {
	h, _, _ := assembledHandler(t)
	for _, contentType := range []string{"application/connect+proto", "application/grpc-web+proto", "application/grpc+proto"} {
		t.Run(contentType, func(t *testing.T) {
			srv, _, _, err := httpserve.BuildServer(&core.CoreConfig{ListenAddr: "127.0.0.1:0"}, nil, h, 1<<20)
			if err != nil {
				t.Fatalf("BuildServer: %v", err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			set := make(chan time.Time, 64)
			go func() { _ = srv.Serve(deadlineListener{Listener: ln, set: set}) }()
			t.Cleanup(func() { _ = srv.Close() })

			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			sent := time.Now()
			if _, err := io.WriteString(conn, "POST "+payloadpbconnect.PayloadStoreServiceRetainPayloadProcedure+" HTTP/1.1\r\nHost: x\r\nContent-Type: "+contentType+"\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nab"); err != nil {
				t.Fatal(err)
			}
			// The server first bounds the request's headers (10 s) and clears
			// that deadline; the body's is the stall bound (30 s).
			wait := time.After(3 * time.Second)
			for found := false; !found; {
				select {
				case d := <-set:
					found = d.After(sent.Add(20*time.Second)) && d.Before(time.Now().Add(31*time.Second))
				case <-wait:
					t.Fatal("no read deadline within the stall bound was set while the refused stream's body was discarded")
				}
			}
			// The handler is still discarding the body: it has not answered.
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := conn.Read(make([]byte, 1)); n > 0 || !isTimeout(err) {
				t.Errorf("answered (%d bytes, %v) before the body was discarded: the deadline seen was not the discard's", n, err)
			}
		})
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
