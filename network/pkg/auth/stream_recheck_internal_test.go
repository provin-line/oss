package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	payloadpb "github.com/provin-line/oss/gen/go/dplaax/payload/v1"
	"github.com/provin-line/oss/gen/go/dplaax/payload/v1/payloadpbconnect"
)

// countingVerifier allows every check and counts them.
type countingVerifier struct{ calls atomic.Int32 }

func (v *countingVerifier) Verify(context.Context, string, string) error {
	v.calls.Add(1)
	return nil
}

// retains reads a RetainPayload client stream to its end; the RPC declares a
// policy, so the chain checks it.
type retains struct {
	payloadpbconnect.UnimplementedPayloadStoreServiceHandler
}

func (retains) RetainPayload(_ context.Context, s *connect.ClientStream[payloadpb.RetainPayloadRequest]) (*connect.Response[payloadpb.RetainPayloadResponse], error) {
	for s.Receive() {
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&payloadpb.RetainPayloadResponse{}), nil
}

// upload sends messages on one client stream through chain, waiting gap
// between them, and returns how many checks the verifier made.
func upload(t *testing.T, chain func(Verifier) []connect.Interceptor, messages int, gap time.Duration) int32 {
	t.Helper()
	v := &countingVerifier{}
	path, h := payloadpbconnect.NewPayloadStoreServiceHandler(retains{}, connect.WithInterceptors(chain(v)...))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	stream := payloadpbconnect.NewPayloadStoreServiceClient(srv.Client(), srv.URL).RetainPayload(context.Background())
	stream.RequestHeader().Set("Authorization", "Bearer token")
	for i := 0; i < messages; i++ {
		if i > 0 {
			time.Sleep(gap)
		}
		if err := stream.Send(&payloadpb.RetainPayloadRequest{Frame: &payloadpb.RetainPayloadRequest_Chunk{Chunk: []byte("x")}}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err := stream.CloseAndReceive(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return v.calls.Load()
}

// A stream is checked when it opens; messages that follow within the
// interval are not checked again, so a payload of many frames costs one
// check, not one per frame.
func TestInterceptors_AStreamWithinTheIntervalIsCheckedOnce(t *testing.T) {
	if got := upload(t, Interceptors, 5, 0); got != 1 {
		t.Errorf("checks = %d for five messages sent at once, want 1 (when the stream opens)", got)
	}
}

// A message that comes after the interval is checked again.
func TestInterceptors_AStreamIsCheckedAgainAfterTheInterval(t *testing.T) {
	const interval = 100 * time.Millisecond
	chain := func(v Verifier) []connect.Interceptor { return interceptorsRecheckingEvery(v, interval) }
	if got := upload(t, chain, 2, 3*interval/2); got < 2 {
		t.Errorf("checks = %d, want at least 2: the open and a re-check of the message sent after the interval", got)
	}
}

// The interval is five seconds: long against a payload's frames, short
// against a token's lifetime.
func TestStreamRecheckInterval_IsFiveSeconds(t *testing.T) {
	if streamRecheckInterval != 5*time.Second {
		t.Errorf("streamRecheckInterval = %v, want 5s", streamRecheckInterval)
	}
}
