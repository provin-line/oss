package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

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
// e2e).
type fakeServer struct {
	frames [][]byte
	err    error
}

func (f *fakeServer) ResolvePayload(_ context.Context, _ *connect.Request[payloadpb.ResolvePayloadRequest], stream *connect.ServerStream[payloadpb.ResolvePayloadResponse]) error {
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

// The assembled size is capped: frames summing over the cap abort.
func TestResolvePayload_MaxBytesExceeded(t *testing.T) {
	frames := [][]byte{make([]byte, 10), make([]byte, 10)} // 20 bytes total
	for i := range frames {
		for j := range frames[i] {
			frames[i][j] = byte('x')
		}
	}
	c, url := newClient(t, &fakeServer{frames: frames}, 16) // 16-byte cap
	_, err := c.ResolvePayload(context.Background(), url, "sha256:"+
		"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err == nil {
		t.Fatal("over cap: want error, got nil")
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
