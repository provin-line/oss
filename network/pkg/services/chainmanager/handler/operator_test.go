package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	chainpb "github.com/provin-line/oss/gen/go/dplaax/chain/v1"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

func newSvc(t *testing.T) (*chainmanager.Service, store.SubscriptionStore, store.AllowListStore) {
	t.Helper()
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	return chainmanager.New(subs, allows), subs, allows
}

func TestOperatorHandler_ListSubscriptions(t *testing.T) {
	svc, subs, _ := newSvc(t)
	if err := subs.Save(&store.Subscription{
		ID:           "sub-1",
		PublisherDID: "did:dplaax:reg:org:pub",
		PublishType:  "nats",
		Created:      time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	h := NewOperator(svc)
	resp, err := h.ListSubscriptions(context.Background(), connect.NewRequest(&chainpb.ListSubscriptionsRequest{}))
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	got := resp.Msg.GetSubscriptions()
	if len(got) != 1 {
		t.Fatalf("got %d subscriptions, want 1", len(got))
	}
	if got[0].GetId() != "sub-1" || got[0].GetPublisherDid() != "did:dplaax:reg:org:pub" {
		t.Errorf("subscription = %+v", got[0])
	}
	if got[0].GetCreated() != "2026-06-17T12:00:00Z" {
		t.Errorf("created = %q, want RFC3339 second-precision UTC", got[0].GetCreated())
	}
}

func TestOperatorHandler_ListSubscriptions_Empty(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc)
	resp, err := h.ListSubscriptions(context.Background(), connect.NewRequest(&chainpb.ListSubscriptionsRequest{}))
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(resp.Msg.GetSubscriptions()) != 0 {
		t.Errorf("empty store returned %d subscriptions", len(resp.Msg.GetSubscriptions()))
	}
}

func TestOperatorHandler_UpdateAllowList_Success(t *testing.T) {
	svc, _, allows := newSvc(t)
	h := NewOperator(svc)
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	_, err := h.UpdateAllowList(context.Background(), connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: pid,
		Rules:       []*chainpb.AllowRule{{Pattern: "did:dplaax:*:org:acme:*"}},
	}))
	if err != nil {
		t.Fatalf("UpdateAllowList: %v", err)
	}
	stored, _ := allows.Get(pid)
	if len(stored) != 1 || stored[0].Pattern != "did:dplaax:*:org:acme:*" {
		t.Errorf("stored = %+v, want the one pattern", stored)
	}
}

func TestOperatorHandler_UpdateAllowList_InvalidPattern(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc)
	_, err := h.UpdateAllowList(context.Background(), connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: "did:dplaax:reg:org:acme:pipeline:p1",
		Rules:       []*chainpb.AllowRule{{Pattern: "did:dplaax:reg:org:ac*me"}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

func TestOperatorHandler_UpdateAllowList_InvalidPipelineDID(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc)
	_, err := h.UpdateAllowList(context.Background(), connect.NewRequest(&chainpb.UpdateAllowListRequest{
		PipelineDid: "did:dplaax:reg:org:acme", // owner, not a pipeline
		Rules:       []*chainpb.AllowRule{{Pattern: "did:dplaax:*"}},
	}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", connect.CodeOf(err))
	}
}

// The two connection-flow RPCs are deferred to the last slice; the embedded
// Unimplemented stub must keep returning CodeUnimplemented so the deferral is
// explicit, not an accidental silent success.
func TestOperatorHandler_ConnectionFlowUnimplemented(t *testing.T) {
	svc, _, _ := newSvc(t)
	h := NewOperator(svc)
	if _, err := h.Subscribe(context.Background(), connect.NewRequest(&chainpb.SubscribeRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("Subscribe code = %v, want Unimplemented", connect.CodeOf(err))
	}
	if _, err := h.Unsubscribe(context.Background(), connect.NewRequest(&chainpb.UnsubscribeRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("Unsubscribe code = %v, want Unimplemented", connect.CodeOf(err))
	}
}
