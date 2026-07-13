package chainmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// spyAllowStore records whether Save was called, to prove the domain validates
// before any write (all-or-nothing).
type spyAllowStore struct {
	saved bool
}

func (s *spyAllowStore) Save(pipelineDID string, rules []store.AllowRule) error {
	s.saved = true
	return nil
}
func (s *spyAllowStore) Get(pipelineDID string) ([]store.AllowRule, error) { return nil, nil }

func TestService_ListSubscriptions_Empty(t *testing.T) {
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore())
	subs, err := svc.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("empty store returned %d subscriptions, want 0", len(subs))
	}
}

// ListSubscriptions returns the operator's subscriber-direction records only
// ("what am I subscribed to" — slice-12 D-s6 option a); publisher-direction
// records (who subscribed to me) are excluded.
func TestService_ListSubscriptions_Returns(t *testing.T) {
	subStore := memstore.NewSubscriptionStore()
	if err := subStore.Save(&store.Subscription{ID: "sub-1", PublisherDID: "did:dplaax:reg:org:pub", Direction: "subscriber"}); err != nil {
		t.Fatal(err)
	}
	// a publisher-direction record (default-empty Direction) must be excluded
	if err := subStore.Save(&store.Subscription{ID: "pub-1", PublisherDID: "did:dplaax:reg:org:pub"}); err != nil {
		t.Fatal(err)
	}
	svc := New(subStore, memstore.NewAllowListStore())
	subs, err := svc.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != "sub-1" {
		t.Errorf("ListSubscriptions = %+v, want one sub-1 (subscriber-direction only)", subs)
	}
}

func TestService_UpdateAllowList_Valid(t *testing.T) {
	allowStore := memstore.NewAllowListStore()
	svc := New(memstore.NewSubscriptionStore(), allowStore)
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	err := svc.UpdateAllowList(context.Background(), pid, []string{"did:dplaax:*:org:acme:*", "did:dplaax:reg:org:sub"})
	if err != nil {
		t.Fatalf("UpdateAllowList: %v", err)
	}
	got, _ := allowStore.Get(pid)
	if len(got) != 2 || got[0].Pattern != "did:dplaax:*:org:acme:*" || got[1].Pattern != "did:dplaax:reg:org:sub" {
		t.Errorf("stored rules = %+v, want the two patterns in order", got)
	}
}

func TestService_UpdateAllowList_InvalidPipelineDID(t *testing.T) {
	cases := []struct {
		name string
		pid  string
	}{
		{"unparseable", "not-a-did"},
		{"owner not pipeline", "did:dplaax:reg:org:acme"},
		{"process not pipeline", "did:dplaax:reg:org:acme:pipeline:p1:process:x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spy := &spyAllowStore{}
			svc := New(memstore.NewSubscriptionStore(), spy)
			err := svc.UpdateAllowList(context.Background(), c.pid, []string{"did:dplaax:*"})
			if !errors.Is(err, ErrInvalidPipelineDID) {
				t.Fatalf("err = %v, want ErrInvalidPipelineDID", err)
			}
			if spy.saved {
				t.Error("Save was called on an invalid pipelineDID (write before validation)")
			}
		})
	}
}

// A mutating call on an already-canceled context must not touch the store — the
// codebase idiom (signer/schema/did/vc all guard ctx.Err() at entry).
func TestService_UpdateAllowList_ContextCanceled(t *testing.T) {
	spy := &spyAllowStore{}
	svc := New(memstore.NewSubscriptionStore(), spy)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.UpdateAllowList(ctx, "did:dplaax:reg:org:acme:pipeline:p1", []string{"did:dplaax:*"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if spy.saved {
		t.Error("Save was called on a canceled context")
	}
}

func TestService_ListSubscriptions_ContextCanceled(t *testing.T) {
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.ListSubscriptions(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestService_UpdateAllowList_InvalidPattern(t *testing.T) {
	spy := &spyAllowStore{}
	svc := New(memstore.NewSubscriptionStore(), spy)
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	// second pattern is malformed → whole update rejected, store untouched
	err := svc.UpdateAllowList(context.Background(), pid, []string{"did:dplaax:*", "did:dplaax:reg:org:ac*me"})
	if err == nil {
		t.Fatal("UpdateAllowList accepted a malformed pattern")
	}
	if spy.saved {
		t.Error("Save was called despite a malformed pattern (not all-or-nothing)")
	}
}

// GetAllowList is the read-before-replace companion to UpdateAllowList: an
// absent list is empty (not an error), a saved list comes back in order, and the
// key is validated like the write path.
func TestService_GetAllowList(t *testing.T) {
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore())
	const pid = "did:dplaax:reg:org:acme:pipeline:p1"

	// Absent list → empty, not an error (default-distrust; store does not
	// distinguish never-configured from configured-empty).
	rules, err := svc.GetAllowList(context.Background(), pid)
	if err != nil || len(rules) != 0 {
		t.Fatalf("absent allow-list: rules=%v err=%v, want empty/nil", rules, err)
	}

	// After a save, the rules come back in stored order.
	if err := svc.UpdateAllowList(context.Background(), pid, []string{"did:dplaax:*:org:a:*", "did:dplaax:*:org:b:*"}); err != nil {
		t.Fatalf("UpdateAllowList: %v", err)
	}
	rules, err = svc.GetAllowList(context.Background(), pid)
	if err != nil {
		t.Fatalf("GetAllowList: %v", err)
	}
	if len(rules) != 2 || rules[0].Pattern != "did:dplaax:*:org:a:*" || rules[1].Pattern != "did:dplaax:*:org:b:*" {
		t.Errorf("rules = %+v, want the two saved patterns in order", rules)
	}

	// An unparseable pipeline DID is rejected, like the write path.
	if _, err := svc.GetAllowList(context.Background(), "not-a-pipeline-did"); !errors.Is(err, ErrInvalidPipelineDID) {
		t.Errorf("invalid pipeline DID: want ErrInvalidPipelineDID, got %v", err)
	}

	// A canceled context is honored before any read.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.GetAllowList(cctx, pid); err == nil {
		t.Error("canceled context: want error")
	}
}
