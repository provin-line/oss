package handler

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

// Compile-time guards: the concrete domain service satisfies BOTH the unwidened
// read/admin Service and the new SubscriberService (D-s9), and the 1-arg
// NewOperator call still compiles.
var (
	_ Service           = (*chainmanager.Service)(nil)
	_ SubscriberService = (*chainmanager.Service)(nil)
	_                   = NewOperator((*chainmanager.Service)(nil)) // 1-arg form unchanged
)

type fakeSub struct {
	id        string
	subErr    error
	unsubErr  error
	gotSub    string
	gotPub    string
	gotMode   string
	gotUnsub  string
	subCalled bool
}

func (f *fakeSub) Subscribe(_ context.Context, subscriberDID, publisherDID, mode string) (string, error) {
	f.subCalled = true
	f.gotSub, f.gotPub, f.gotMode = subscriberDID, publisherDID, mode
	return f.id, f.subErr
}

func (f *fakeSub) Unsubscribe(_ context.Context, id string) error {
	f.gotUnsub = id
	return f.unsubErr
}

func TestOperatorHandler_Subscribe_Success(t *testing.T) {
	svc, _, _ := newSvc(t)
	fs := &fakeSub{id: "local-1"}
	h := NewOperator(svc, WithSubscriber(fs))
	resp, err := h.Subscribe(context.Background(), connect.NewRequest(&chainpb.SubscribeRequest{
		SubscriberDid: "did:dplaax:reg:org:sub", PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1", PayloadDelivery: "inline",
	}))
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if resp.Msg.GetSubscriptionId() != "local-1" {
		t.Errorf("subscription_id = %q", resp.Msg.GetSubscriptionId())
	}
	if fs.gotSub != "did:dplaax:reg:org:sub" || fs.gotPub != "did:dplaax:reg:org:acme:pipeline:p1" || fs.gotMode != "inline" {
		t.Errorf("domain args = (%q, %q, %q)", fs.gotSub, fs.gotPub, fs.gotMode)
	}
}

func TestOperatorHandler_Unsubscribe_Success(t *testing.T) {
	svc, _, _ := newSvc(t)
	fs := &fakeSub{}
	h := NewOperator(svc, WithSubscriber(fs))
	if _, err := h.Unsubscribe(context.Background(), connect.NewRequest(&chainpb.UnsubscribeRequest{SubscriptionId: "local-1"})); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if fs.gotUnsub != "local-1" {
		t.Errorf("domain got id %q", fs.gotUnsub)
	}
}

// Without WithSubscriber, the two connection-flow RPCs return CodeUnimplemented
// (the embedded stub) — the operator-local RPCs still work.
func TestOperatorHandler_Subscribe_Unconfigured(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc) // no subscriber
	_, err := h.Subscribe(context.Background(), connect.NewRequest(&chainpb.SubscribeRequest{
		PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
	}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("Subscribe code = %v, want Unimplemented", connect.CodeOf(err))
	}
	if _, err := h.Unsubscribe(context.Background(), connect.NewRequest(&chainpb.UnsubscribeRequest{SubscriptionId: "x"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("Unsubscribe code = %v, want Unimplemented", connect.CodeOf(err))
	}
}

func TestOperatorHandler_Subscribe_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"invalid pipeline", chainmanager.ErrInvalidPipelineDID, connect.CodeInvalidArgument},
		{"no endpoint", chainmanager.ErrNoChainManagerEndpoint, connect.CodeFailedPrecondition},
		{"unsafe endpoint", chainmanager.ErrEndpointNotAllowed, connect.CodeInvalidArgument},
		{"unsupported mode", chainmanager.ErrPayloadModeUnsupported, connect.CodeInvalidArgument},
		{"unconfigured", chainmanager.ErrSubscriberUnconfigured, connect.CodeInternal},
		{"remote peer", chainmanager.ErrRemotePeer, connect.CodeUnavailable},
		{"not found", store.ErrNotFound, connect.CodeNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newSvc(t)
			h := NewOperator(svc, WithSubscriber(&fakeSub{subErr: tc.err, unsubErr: tc.err}))
			_, err := h.Subscribe(context.Background(), connect.NewRequest(&chainpb.SubscribeRequest{
				PublisherDid: "did:dplaax:reg:org:acme:pipeline:p1",
			}))
			if connect.CodeOf(err) != tc.want {
				t.Errorf("Subscribe(%s) code = %v, want %v", tc.name, connect.CodeOf(err), tc.want)
			}
		})
	}
}

// mapError passes a wrapped remote ConnectRPC code through (D-s8): a remote
// PermissionDenied surfaces as PermissionDenied, not a misleading Unavailable;
// an opaque (non-connect) remote failure falls back to Unavailable.
func TestMapError_RemotePeerPassthrough(t *testing.T) {
	remote := connect.NewError(connect.CodePermissionDenied, errors.New("denied"))
	wrapped := fmt.Errorf("%w: get publisher info: %w", chainmanager.ErrRemotePeer, remote)
	if got := connect.CodeOf(mapError(wrapped)); got != connect.CodePermissionDenied {
		t.Errorf("passthrough code = %v, want PermissionDenied", got)
	}
	opaque := fmt.Errorf("%w: resolve: %v", chainmanager.ErrRemotePeer, errors.New("dns failure"))
	if got := connect.CodeOf(mapError(opaque)); got != connect.CodeUnavailable {
		t.Errorf("opaque remote code = %v, want Unavailable", got)
	}
}

func TestOperatorHandler_Unsubscribe_NotFound(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc, WithSubscriber(&fakeSub{unsubErr: store.ErrNotFound}))
	_, err := h.Unsubscribe(context.Background(), connect.NewRequest(&chainpb.UnsubscribeRequest{SubscriptionId: "x"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("code = %v, want NotFound", connect.CodeOf(err))
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want wraps store.ErrNotFound", err)
	}
}
