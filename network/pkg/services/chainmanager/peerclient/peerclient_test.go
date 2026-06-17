package peerclient_test

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
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

const (
	subDID = "did:dplaax:reg:org:sub"
	pubDID = "did:dplaax:reg:org:acme:pipeline:p1"
)

// fakeSigner returns a fixed signature; the byte-equality of the signed view is
// proven end-to-end against the real verifier in Phase E, not here. This phase
// pins the CLIENT's request/proof construction.
type fakeSigner struct{}

func (fakeSigner) Sign(_, _ string, _ []byte) ([]byte, error) { return []byte("test-sig"), nil }

// capture is a ChainPeerService handler that records the request it received and
// returns canned responses (or an injected error code on Disconnect).
type capture struct {
	chainpbconnect.UnimplementedChainPeerServiceHandler
	gi             *chainpb.GetPublisherInfoRequest
	rs             *chainpb.RegisterSubscriptionRequest
	dc             *chainpb.DisconnectRequest
	disconnectCode connect.Code
}

func (c *capture) GetPublisherInfo(_ context.Context, req *connect.Request[chainpb.GetPublisherInfoRequest]) (*connect.Response[chainpb.GetPublisherInfoResponse], error) {
	c.gi = req.Msg
	return connect.NewResponse(&chainpb.GetPublisherInfoResponse{
		PublishType: "noop", SupportedPayloadDelivery: []string{"by-reference", "inline"},
	}), nil
}

func (c *capture) RegisterSubscription(_ context.Context, req *connect.Request[chainpb.RegisterSubscriptionRequest]) (*connect.Response[chainpb.RegisterSubscriptionResponse], error) {
	c.rs = req.Msg
	return connect.NewResponse(&chainpb.RegisterSubscriptionResponse{
		SubscriptionId:  "remote-9",
		ConnectionInfo:  map[string]string{"subject": "subject-x"},
		PublishType:     "noop",
		PayloadDelivery: req.Msg.GetPayloadDelivery(), // echo verbatim
	}), nil
}

func (c *capture) Disconnect(_ context.Context, req *connect.Request[chainpb.DisconnectRequest]) (*connect.Response[chainpb.DisconnectResponse], error) {
	c.dc = req.Msg
	if c.disconnectCode != 0 {
		return nil, connect.NewError(c.disconnectCode, errors.New("injected"))
	}
	return connect.NewResponse(&chainpb.DisconnectResponse{}), nil
}

func setup(t *testing.T) (*peerclient.Client, *capture, string) {
	t.Helper()
	cap := &capture{}
	_, h := chainpbconnect.NewChainPeerServiceHandler(cap)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	guard := core.NewURLGuard(core.WithAllowLoopback(true)) // httptest is 127.0.0.1
	cli := peerclient.New(fakeSigner{}, subDID, guard.HTTPClient())
	return cli, cap, srv.URL
}

func assertProof(t *testing.T, ap *chainpb.AuthProof) {
	t.Helper()
	if ap == nil {
		t.Fatal("no AuthProof on request")
	}
	if ap.GetSignerDid() != subDID {
		t.Errorf("signer_did = %q, want %q", ap.GetSignerDid(), subDID)
	}
	if ap.GetNonce() == "" {
		t.Error("empty nonce")
	}
	if len(ap.GetSignature()) == 0 {
		t.Error("empty signature")
	}
	// issued_at must be canonical second-precision UTC RFC3339.
	parsed, err := time.Parse(time.RFC3339, ap.GetIssuedAt())
	if err != nil {
		t.Errorf("issued_at %q not RFC3339: %v", ap.GetIssuedAt(), err)
	} else if ap.GetIssuedAt() != parsed.UTC().Format(time.RFC3339) {
		t.Errorf("issued_at %q is not canonical UTC second-precision", ap.GetIssuedAt())
	}
}

func TestClient_GetPublisherInfo(t *testing.T) {
	cli, cap, url := setup(t)
	pt, modes, err := cli.GetPublisherInfo(context.Background(), url, subDID, pubDID)
	if err != nil {
		t.Fatalf("GetPublisherInfo: %v", err)
	}
	if pt != "noop" || len(modes) != 2 {
		t.Errorf("resp = (%q, %v)", pt, modes)
	}
	if cap.gi.GetPublisherDid() != pubDID {
		t.Errorf("publisher_did = %q", cap.gi.GetPublisherDid())
	}
	assertProof(t, cap.gi.GetAuthProof())
}

func TestClient_RegisterSubscription(t *testing.T) {
	cli, cap, url := setup(t)
	remoteID, connInfo, pt, agreed, err := cli.RegisterSubscription(context.Background(), url, subDID, pubDID, "inline")
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if remoteID != "remote-9" || connInfo["subject"] != "subject-x" || pt != "noop" || agreed != "inline" {
		t.Errorf("resp = (%q, %v, %q, %q)", remoteID, connInfo, pt, agreed)
	}
	if cap.rs.GetSubscriberDid() != subDID || cap.rs.GetPublisherDid() != pubDID || cap.rs.GetPayloadDelivery() != "inline" {
		t.Errorf("request = %+v", cap.rs)
	}
	assertProof(t, cap.rs.GetAuthProof())
}

// Empty requested mode must travel VERBATIM (not pre-normalized to by-reference);
// the publisher normalizes post-Verify, so pre-normalizing would diverge the
// signed bytes from the request.
func TestClient_RegisterSubscription_EmptyModeVerbatim(t *testing.T) {
	cli, cap, url := setup(t)
	if _, _, _, _, err := cli.RegisterSubscription(context.Background(), url, subDID, pubDID, ""); err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if cap.rs.GetPayloadDelivery() != "" {
		t.Errorf("payload_delivery = %q, want empty (verbatim)", cap.rs.GetPayloadDelivery())
	}
}

func TestClient_Disconnect(t *testing.T) {
	cli, cap, url := setup(t)
	if err := cli.Disconnect(context.Background(), url, "remote-9"); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if cap.dc.GetSubscriptionId() != "remote-9" {
		t.Errorf("subscription_id = %q", cap.dc.GetSubscriptionId())
	}
	assertProof(t, cap.dc.GetAuthProof())
}

// A remote NotFound is surfaced as store.ErrNotFound so the domain's idempotent
// teardown (D-s5) can treat it as already-disconnected.
func TestClient_Disconnect_RemoteNotFound(t *testing.T) {
	cli, cap, url := setup(t)
	cap.disconnectCode = connect.CodeNotFound
	err := cli.Disconnect(context.Background(), url, "gone")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want store.ErrNotFound", err)
	}
}
