package peerclient

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
)

type stubSigner struct{}

func (stubSigner) Sign(_, _ string, _ []byte) ([]byte, error) { return []byte("sig"), nil }

// silent never answers, and ignores the deadline the client sends: each call
// waits until the test ends.
type silent struct {
	chainpbconnect.UnimplementedChainPeerServiceHandler
	release chan struct{}
}

func (s silent) GetPublisherInfo(context.Context, *connect.Request[chainpb.GetPublisherInfoRequest]) (*connect.Response[chainpb.GetPublisherInfoResponse], error) {
	<-s.release
	return nil, errors.New("released")
}

func (s silent) RegisterSubscription(context.Context, *connect.Request[chainpb.RegisterSubscriptionRequest]) (*connect.Response[chainpb.RegisterSubscriptionResponse], error) {
	<-s.release
	return nil, errors.New("released")
}

func (s silent) Disconnect(context.Context, *connect.Request[chainpb.DisconnectRequest]) (*connect.Response[chainpb.DisconnectResponse], error) {
	<-s.release
	return nil, errors.New("released")
}

// Every call to a publisher ends within the client's call timeout, even under a
// context that is never cancelled (the subscriber's compensating Disconnect
// runs under context.WithoutCancel).
func TestClient_EveryCallEndsWithinTheCallTimeout(t *testing.T) {
	release := make(chan struct{})
	_, h := chainpbconnect.NewChainPeerServiceHandler(silent{release: release})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	cli := New(stubSigner{}, "did:dplaax:reg:org:sub", core.NewURLGuard(core.WithAllowLoopback(true)).HTTPClient())
	cli.callTimeout = 50 * time.Millisecond
	ctx := context.WithoutCancel(context.Background())

	for name, call := range map[string]func() error{
		"GetPublisherInfo": func() error {
			_, _, err := cli.GetPublisherInfo(ctx, srv.URL, "did:dplaax:reg:org:sub", "did:dplaax:reg:org:pub")
			return err
		},
		"RegisterSubscription": func() error {
			_, _, _, _, err := cli.RegisterSubscription(ctx, srv.URL, "did:dplaax:reg:org:sub", "did:dplaax:reg:org:pub", "")
			return err
		},
		"Disconnect": func() error { return cli.Disconnect(ctx, srv.URL, "remote-1") },
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if connect.CodeOf(err) != connect.CodeDeadlineExceeded && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s: err = %v, want deadline exceeded", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: still waiting after 5s", name)
		}
	}
}

// New sets the call timeout every caller gets.
func TestNew_SetsTheCallTimeout(t *testing.T) {
	if got := New(stubSigner{}, "did:x", nil).callTimeout; got != callTimeout {
		t.Errorf("callTimeout = %s, want %s", got, callTimeout)
	}
}
