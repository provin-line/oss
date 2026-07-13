package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
	return client.New(ks, clientDID, httpSrv.Client(), maxBytes), httpSrv.URL
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
