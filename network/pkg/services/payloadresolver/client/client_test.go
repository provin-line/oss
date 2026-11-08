package client_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
)

const clientDID = "did:dplaax:poc.dplaax.dev:org:consumer"

// fakeServer is a minimal PayloadService that streams a fixed frame list (or a
// fixed error). It ignores the AuthProof — this test drives the CLIENT's
// streaming assembly and caps, not the serving-side auth (covered by the handler
// e2e). gotAuth captures whatever Authorization header the request arrived
// with (empty if none), for the anti-leak test below.
type fakeServer struct {
	frames  [][]byte
	err     error
	gotAuth string
}

func (f *fakeServer) ResolvePayload(_ context.Context, req *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	f.gotAuth = req.Header().Get("Authorization")
	if f.err != nil {
		return f.err
	}
	for _, fr := range f.frames {
		if err := stream.Send(&payloadpb.ResolvePayloadResponse{Chunk: fr}); err != nil {
			return err
		}
	}
	return nil
}

func newClient(t *testing.T, srv *fakeServer, maxBytes int) (*client.Resolver, string) {
	t.Helper()
	path, h := payloadpbconnect.NewPayloadServiceHandler(srv)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)

	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(clientDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	return client.New(client.Config{Signer: ks, SignerDID: clientDID, HTTPClient: httpSrv.Client(), MaxBytes: maxBytes}), httpSrv.URL
}

// newClientCfg is newClient with an explicit Config (short fetch/idle budgets for
// the stall tests), returning the resolver and the server URL.
func newClientCfg(t *testing.T, srv payloadpbconnect.PayloadServiceHandler, cfg client.Config) (*client.Resolver, string) {
	t.Helper()
	path, h := payloadpbconnect.NewPayloadServiceHandler(srv)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)

	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(clientDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	cfg.Signer = ks
	cfg.SignerDID = clientDID
	cfg.HTTPClient = httpSrv.Client()
	return client.New(cfg), httpSrv.URL
}

// Multi-chunk assembly: the client concatenates ordered frames into the whole
// payload — the entire reason server-streaming was chosen.
func TestResolvePayload_MultiChunkAssembly(t *testing.T) {
	frames := [][]byte{[]byte("alpha-"), []byte("beta-"), []byte("gamma")}
	c, url := newClient(t, &fakeServer{frames: frames}, 0)
	got, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if string(got) != "alpha-beta-gamma" {
		t.Errorf("assembled = %q, want %q", got, "alpha-beta-gamma")
	}
}

// An empty chunk is rejected (a protocol violation) — the backstop against an
// untrusted upstream streaming endless zero-length frames to hang the consumer.
func TestResolvePayload_EmptyChunkRejected(t *testing.T) {
	frames := [][]byte{[]byte("data"), {}, []byte("more")}
	c, url := newClient(t, &fakeServer{frames: frames}, 0)
	_, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err == nil {
		t.Fatal("empty chunk: want error, got nil")
	}
}

// The assembled size is capped: frames each within the cap but summing over it
// abort with the max-bytes error.
func TestResolvePayload_MaxBytesExceeded(t *testing.T) {
	frames := [][]byte{bytes.Repeat([]byte("x"), 600), bytes.Repeat([]byte("y"), 600)}
	c, url := newClient(t, &fakeServer{frames: frames}, 1000)
	_, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err == nil || !strings.Contains(err.Error(), "exceeds max-bytes 1000") {
		t.Fatalf("over cap: err = %v, want the max-bytes error", err)
	}
}

// A payload of exactly the cap, in one frame, is accepted.
func TestResolvePayload_AcceptsAPayloadOfExactlyTheCapInOneFrame(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 1000)
	c, url := newClient(t, &fakeServer{frames: [][]byte{want}}, 1000)
	got, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("payload of exactly the cap: %d bytes, err %v", len(got), err)
	}
}

// One frame larger than the cap is refused by the transport without the client
// holding it in memory: the upstream is another organization's server.
func TestResolvePayload_RefusesAFrameOverTheCapWithoutHoldingIt(t *testing.T) {
	c, url := newClient(t, &fakeServer{frames: [][]byte{bytes.Repeat([]byte("x"), 1100)}}, 1000)
	_, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("frame over the cap: err = %v, want resource_exhausted", err)
	}
}

// The client accepts no compression from an upstream, so a frame takes in
// memory what it takes on the wire.
func TestResolvePayload_AcceptsNoCompression(t *testing.T) {
	var accept string
	srv := &fakeServer{frames: [][]byte{[]byte("data")}}
	path, h := payloadpbconnect.NewPayloadServiceHandler(srv)
	mux := http.NewServeMux()
	mux.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Connect-Accept-Encoding") + "|" + r.Header.Get("Grpc-Accept-Encoding")
		h.ServeHTTP(w, r)
	}))
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)
	c, _ := newClient(t, &fakeServer{}, 0)
	if _, err := c.ResolvePayload(context.Background(), httpSrv.URL, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if strings.Contains(accept, "gzip") {
		t.Errorf("client accepts compression: %q", accept)
	}
}

// A remote NotFound maps to client.ErrNotFound (distinguished for observability).
func TestResolvePayload_NotFound(t *testing.T) {
	srv := &fakeServer{err: connect.NewError(connect.CodeNotFound, errors.New("no such payload"))}
	c, url := newClient(t, srv, 0)
	_, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if !errors.Is(err, client.ErrNotFound) {
		t.Errorf("err = %v, want client.ErrNotFound", err)
	}
}

// TestResolvePayload_NeverPresentsBearer is the P1-C anti-leak proof: even
// when Config.Bearer is set (for Retain, whose target is THIS node's own
// fixed StoreEndpoint), ResolvePayload — which dials whichever endpoint a
// caller passes, an arbitrary and potentially untrusted publisher — must
// never present it. bearerInterceptor is attached ONLY to retainClient, a
// separate client instance built once in New and bound to StoreEndpoint;
// ResolvePayload builds its own per-call client from the bare HTTPClient and
// never touches retainClient, so this is a structural guarantee, not
// incidental — this test is the empirical check for it (a regression here
// would leak this node's L1 credential to every publisher ResolvePayload
// ever fetches from).
func TestResolvePayload_NeverPresentsBearer(t *testing.T) {
	frames := [][]byte{[]byte("data")}
	srv := &fakeServer{frames: frames}
	c, url := newClientCfg(t, srv, client.Config{Bearer: "leak-if-broken", StoreEndpoint: "http://unused.invalid"})
	if _, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if srv.gotAuth != "" {
		t.Errorf("ResolvePayload leaked the Retain bearer: Authorization = %q, want empty", srv.gotAuth)
	}
}

// --- F10: per-fetch total + idle deadlines (independent of caller ctx) ---

const fetchTestHash = "sha256:" +
	"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// stallServer sends firstFrames, then blocks until the request context is
// cancelled (the client's idle/total budget) — the malicious "trickle then
// stall" / "never respond" upstream.
type stallServer struct{ firstFrames [][]byte }

func (s *stallServer) ResolvePayload(ctx context.Context, _ *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	for _, fr := range s.firstFrames {
		if err := stream.Send(&payloadpb.ResolvePayloadResponse{Chunk: fr}); err != nil {
			return err
		}
	}
	<-ctx.Done() // stall until the client's budget cancels the request
	return ctx.Err()
}

// trickleServer sends a 1-byte frame every interval until the request context is
// cancelled — steady progress that never trips the idle budget, so only the
// TOTAL budget can stop it.
type trickleServer struct{ interval time.Duration }

func (s *trickleServer) ResolvePayload(ctx context.Context, _ *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := stream.Send(&payloadpb.ResolvePayloadResponse{Chunk: []byte{'x'}}); err != nil {
				return err
			}
		}
	}
}

// A server that sends one chunk then stalls trips the IDLE budget (not the byte
// cap, not the total budget) and returns ErrFetchStalled.
func TestResolvePayload_IdleStall(t *testing.T) {
	c, url := newClientCfg(t, &stallServer{firstFrames: [][]byte{[]byte("first-")}}, client.Config{
		IdleTimeout:  50 * time.Millisecond,
		FetchTimeout: 10 * time.Second, // generous — idle must be what fires
	})
	_, err := c.ResolvePayload(context.Background(), url, fetchTestHash)
	if !errors.Is(err, client.ErrFetchStalled) {
		t.Fatalf("err = %v, want ErrFetchStalled", err)
	}
}

// A server that opens the stream but never sends a byte trips the idle budget
// before the first chunk (idle armed before the first Receive).
func TestResolvePayload_NoFirstByte(t *testing.T) {
	c, url := newClientCfg(t, &stallServer{}, client.Config{
		IdleTimeout:  50 * time.Millisecond,
		FetchTimeout: 10 * time.Second,
	})
	_, err := c.ResolvePayload(context.Background(), url, fetchTestHash)
	if !errors.Is(err, client.ErrFetchStalled) {
		t.Fatalf("err = %v, want ErrFetchStalled (no first byte)", err)
	}
}

// A server that trickles steadily within the idle window but past the total
// budget trips the TOTAL budget and returns ErrFetchTimeout.
func TestResolvePayload_TotalBudget(t *testing.T) {
	c, url := newClientCfg(t, &trickleServer{interval: 20 * time.Millisecond}, client.Config{
		IdleTimeout:  10 * time.Second,       // never fires (steady 20ms progress)
		FetchTimeout: 120 * time.Millisecond, // the total budget is the bound
	})
	_, err := c.ResolvePayload(context.Background(), url, fetchTestHash)
	if !errors.Is(err, client.ErrFetchTimeout) {
		t.Fatalf("err = %v, want ErrFetchTimeout", err)
	}
}

// A caller-context cancellation is NOT reported as a budget sentinel — the
// budgets are the client's own policy, distinct from the caller aborting.
func TestResolvePayload_CallerCancelIsNotBudget(t *testing.T) {
	c, url := newClientCfg(t, &stallServer{firstFrames: [][]byte{[]byte("x")}}, client.Config{
		IdleTimeout:  10 * time.Second,
		FetchTimeout: 10 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, err := c.ResolvePayload(ctx, url, fetchTestHash)
	if err == nil {
		t.Fatal("want an error on caller cancel")
	}
	if errors.Is(err, client.ErrFetchStalled) || errors.Is(err, client.ErrFetchTimeout) {
		t.Errorf("caller cancel misreported as a budget sentinel: %v", err)
	}
}

// --- Retain: early-rejection error path ---

// rejectBeforeReceive simulates an L1 authorization interceptor rejecting a
// streaming RPC before the handler ever calls Receive — e.g. a policy check
// failing on the caller's credential ahead of the first application frame
// being read. It never invokes next, so the wrapped handler body (and its
// Receive calls) never runs.
type rejectBeforeReceive struct{ err error }

func (rejectBeforeReceive) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc { return next }

func (rejectBeforeReceive) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (r rejectBeforeReceive) WrapStreamingHandler(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(context.Context, connect.StreamingHandlerConn) error {
		return r.err
	}
}

// newH2CServer mounts h over cleartext HTTP/2 (h2c) with an http2.Transport
// client dialing it. A true HTTP/2 stream is required to reproduce the
// early-rejection race deterministically: the server can RST the stream the
// instant the interceptor rejects it, ahead of the client ever writing a
// frame — over HTTP/1.1 the client's Send merely hands bytes to a local pipe
// that the Transport drains independently of what the server has read, so the
// metadata Send never observes the rejection.
func newH2CServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(h2c.NewHandler(h, &http2.Server{}))
	t.Cleanup(srv.Close)
	c := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	return srv, c
}

// TestRetain_EarlyRejection_ReturnsRealCode proves Retain surfaces the
// server's real Connect error even when the rejection happens before the
// metadata frame is consumed — an L1 interceptor issuing PermissionDenied (or
// Unauthenticated) ahead of the first Receive. The metadata Send call must
// not treat the resulting io.EOF (the server having already returned) as a
// fatal transport error and swallow the real code, mirroring the chunk-send
// handling below it.
func TestRetain_EarlyRejection_ReturnsRealCode(t *testing.T) {
	wantErr := connect.NewError(connect.CodePermissionDenied, errors.New("rejected before any frame is read"))
	path, h := payloadpbconnect.NewPayloadStoreServiceHandler(
		payloadpbconnect.UnimplementedPayloadStoreServiceHandler{},
		connect.WithInterceptors(rejectBeforeReceive{err: wantErr}),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	httpSrv, httpc := newH2CServer(t, mux)

	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(clientDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := client.New(client.Config{Signer: ks, SignerDID: clientDID, HTTPClient: httpc, StoreEndpoint: httpSrv.URL})

	// The metadata frame's owner_did is padded well past the default HTTP/2
	// stream flow-control window (64KiB): the interceptor never reads the
	// body (no WINDOW_UPDATE is ever sent), so the metadata Send call is
	// forced to block on flow control until the stream is torn down — making
	// it observe the server's RST deterministically instead of racing it.
	hugeOwnerDID := clientDID + "?pad=" + string(bytes.Repeat([]byte("x"), 4<<20))
	_, err = c.Retain(context.Background(), bytes.NewReader(nil), hugeOwnerDID, 0)
	if err == nil {
		t.Fatal("early rejection: want error, got nil")
	}
	var connErr *connect.Error
	if !errors.As(err, &connErr) {
		t.Fatalf("Retain error = %v (%T), want a *connect.Error carrying the real server code, not a swallowed transport error", err, err)
	}
	if connErr.Code() != connect.CodePermissionDenied {
		t.Errorf("code = %v, want CodePermissionDenied", connErr.Code())
	}
}

// The store client carries the bearer, so it follows no redirect: a store that
// redirects does not pass the bearer on.
func TestRetain_ShowsTheBearerToNoServerTheStoreRedirectsTo(t *testing.T) {
	var sawBearer atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawBearer.Store(true)
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	t.Cleanup(other.Close)
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	httpSrv, httpc := newH2CServer(t, mux)

	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(clientDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := client.New(client.Config{Signer: ks, SignerDID: clientDID, HTTPClient: httpc, StoreEndpoint: httpSrv.URL, Bearer: "node-token"})
	if _, err := c.Retain(context.Background(), bytes.NewReader([]byte("payload")), clientDID, 7); err == nil {
		t.Error("a redirected retain succeeded")
	}
	if sawBearer.Load() {
		t.Error("the server the store redirected to saw the bearer")
	}
}
