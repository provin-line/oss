package memstore

import (
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
)

func sampleSub() *store.Subscription {
	return &store.Subscription{
		ID:              "sub-1",
		SubscriberDID:   "did:dplaax:reg:org:sub",
		PublisherDID:    "did:dplaax:reg:org:pub",
		PublishType:     "nats",
		PayloadDelivery: "by-reference",
		ConnectionInfo:  map[string]string{"url": "nats://host:4222"},
	}
}

func TestSubscriptionStore_RoundTrip(t *testing.T) {
	s := NewSubscriptionStore()
	if err := s.Save(sampleSub()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get("sub-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PublisherDID != "did:dplaax:reg:org:pub" || got.ConnectionInfo["url"] != "nats://host:4222" {
		t.Errorf("Get returned %+v", got)
	}
}

func TestSubscriptionStore_GetAbsent(t *testing.T) {
	s := NewSubscriptionStore()
	if _, err := s.Get("nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get absent err = %v, want ErrNotFound", err)
	}
}

func TestSubscriptionStore_Delete(t *testing.T) {
	s := NewSubscriptionStore()
	if err := s.Save(sampleSub()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.Delete("sub-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("sub-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrNotFound", err)
	}
	if err := s.Delete("sub-1"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Delete absent err = %v, want ErrNotFound", err)
	}
}

func TestSubscriptionStore_List(t *testing.T) {
	s := NewSubscriptionStore()
	a := sampleSub()
	b := sampleSub()
	b.ID = "sub-2"
	if err := s.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(b); err != nil {
		t.Fatal(err)
	}
	all, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("List len = %d, want 2", len(all))
	}
}

// A caller must not be able to mutate stored state through the map it handed to
// Save, nor through a map returned by Get/List (defensive copies — Codex Medium).
func TestSubscriptionStore_DefensiveCopy(t *testing.T) {
	s := NewSubscriptionStore()
	in := sampleSub()
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's map after Save must not reach stored state.
	in.ConnectionInfo["url"] = "nats://EVIL:4222"
	got, _ := s.Get("sub-1")
	if got.ConnectionInfo["url"] != "nats://host:4222" {
		t.Errorf("Save did not copy: stored url = %q", got.ConnectionInfo["url"])
	}
	// Mutating a map returned by Get must not reach stored state.
	got.ConnectionInfo["url"] = "nats://EVIL2:4222"
	again, _ := s.Get("sub-1")
	if again.ConnectionInfo["url"] != "nats://host:4222" {
		t.Errorf("Get did not copy: stored url = %q", again.ConnectionInfo["url"])
	}
	// Mutating a sub returned by List must not reach stored state.
	list, _ := s.List()
	list[0].ConnectionInfo["url"] = "nats://EVIL3:4222"
	final, _ := s.Get("sub-1")
	if final.ConnectionInfo["url"] != "nats://host:4222" {
		t.Errorf("List did not copy: stored url = %q", final.ConnectionInfo["url"])
	}
}

func TestAllowListStore_RoundTrip(t *testing.T) {
	s := NewAllowListStore()
	rules := []store.AllowRule{{Pattern: "did:dplaax:*:org:acme:*"}}
	if err := s.Save("did:dplaax:reg:org:acme:pipeline:p1", rules); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get("did:dplaax:reg:org:acme:pipeline:p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 1 || got[0].Pattern != "did:dplaax:*:org:acme:*" {
		t.Errorf("Get returned %+v", got)
	}
}

// Default-distrust: an absent allow-list is empty, never an error.
func TestAllowListStore_GetAbsentEmpty(t *testing.T) {
	s := NewAllowListStore()
	got, err := s.Get("did:dplaax:reg:org:acme:pipeline:p1")
	if err != nil {
		t.Fatalf("Get absent err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Get absent = %+v, want empty", got)
	}
}

func TestAllowListStore_FullReplacement(t *testing.T) {
	s := NewAllowListStore()
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	if err := s.Save(pid, []store.AllowRule{{Pattern: "a"}, {Pattern: "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(pid, []store.AllowRule{{Pattern: "c"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(pid)
	if len(got) != 1 || got[0].Pattern != "c" {
		t.Errorf("after replacement Get = %+v, want [{c}]", got)
	}
}

func TestAllowListStore_DefensiveCopy(t *testing.T) {
	s := NewAllowListStore()
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	in := []store.AllowRule{{Pattern: "did:dplaax:*"}}
	if err := s.Save(pid, in); err != nil {
		t.Fatal(err)
	}
	// Mutating the caller's slice after Save must not reach stored state.
	in[0].Pattern = "EVIL"
	got, _ := s.Get(pid)
	if got[0].Pattern != "did:dplaax:*" {
		t.Errorf("Save did not copy: stored = %q", got[0].Pattern)
	}
	// Mutating a slice returned by Get must not reach stored state.
	got[0].Pattern = "EVIL2"
	again, _ := s.Get(pid)
	if again[0].Pattern != "did:dplaax:*" {
		t.Errorf("Get did not copy: stored = %q", again[0].Pattern)
	}
}
