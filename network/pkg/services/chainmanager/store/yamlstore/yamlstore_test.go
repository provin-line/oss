package yamlstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		Created:         time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC),
	}
}

// corrupt overwrites the single persisted file under root with bytes that are
// not a valid record, simulating on-disk damage.
func corrupt(t *testing.T, root string) {
	t.Helper()
	var target string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(p) == ".yaml" {
			target = p
		}
		return nil
	})
	if err != nil || target == "" {
		t.Fatalf("locating file to corrupt: err=%v target=%q", err, target)
	}
	if err := os.WriteFile(target, []byte("!!! not a record, a bare scalar !!!"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionStore_RoundTrip(t *testing.T) {
	s := NewSubscriptionStore(t.TempDir())
	in := sampleSub()
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get("sub-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PublisherDID != in.PublisherDID || got.ConnectionInfo["url"] != in.ConnectionInfo["url"] {
		t.Errorf("Get returned %+v", got)
	}
	if !got.Created.Equal(in.Created) {
		t.Errorf("Created = %v, want %v", got.Created, in.Created)
	}
}

func TestSubscriptionStore_GetAbsent(t *testing.T) {
	s := NewSubscriptionStore(t.TempDir())
	if _, err := s.Get("nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get absent err = %v, want ErrNotFound", err)
	}
}

func TestSubscriptionStore_Delete(t *testing.T) {
	s := NewSubscriptionStore(t.TempDir())
	if err := s.Save(sampleSub()); err != nil {
		t.Fatal(err)
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
	s := NewSubscriptionStore(t.TempDir())
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

func TestSubscriptionStore_UnsafeID(t *testing.T) {
	root := t.TempDir()
	s := NewSubscriptionStore(root)
	bad := sampleSub()
	bad.ID = "../escape"
	if err := s.Save(bad); err == nil {
		t.Fatal("Save with traversing id returned nil, want error")
	}
	// Nothing must have been written outside the subscriptions dir.
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.yaml")); err == nil {
		t.Error("traversing id escaped the store root")
	}
}

// A corrupt/unparseable file is a real error, never silently collapsed to
// ErrNotFound (which would silently drop a subscription — Codex Medium).
func TestSubscriptionStore_CorruptIsError(t *testing.T) {
	root := t.TempDir()
	s := NewSubscriptionStore(root)
	if err := s.Save(sampleSub()); err != nil {
		t.Fatal(err)
	}
	corrupt(t, root)
	_, err := s.Get("sub-1")
	if err == nil {
		t.Fatal("Get on a corrupt file returned nil error")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get on a corrupt file = ErrNotFound, want a real error")
	}
}

func TestAllowListStore_RoundTrip(t *testing.T) {
	s := NewAllowListStore(t.TempDir())
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	rules := []store.AllowRule{{Pattern: "did:dplaax:*:org:acme:*"}}
	if err := s.Save(pid, rules); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Get(pid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 1 || got[0].Pattern != rules[0].Pattern {
		t.Errorf("Get returned %+v", got)
	}
}

// The on-disk path includes the registry, so two registries' identical
// accountType/accountID/pipeline do not collide (Codex Medium).
func TestAllowListStore_RegistryInPath(t *testing.T) {
	root := t.TempDir()
	s := NewAllowListStore(root)
	pid1 := "did:dplaax:reg1:org:acme:pipeline:p1"
	pid2 := "did:dplaax:reg2:org:acme:pipeline:p1"
	if err := s.Save(pid1, []store.AllowRule{{Pattern: "one"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(pid2, []store.AllowRule{{Pattern: "two"}}); err != nil {
		t.Fatal(err)
	}
	got1, _ := s.Get(pid1)
	got2, _ := s.Get(pid2)
	if len(got1) != 1 || got1[0].Pattern != "one" {
		t.Errorf("reg1 = %+v, want [{one}]", got1)
	}
	if len(got2) != 1 || got2[0].Pattern != "two" {
		t.Errorf("reg2 = %+v, want [{two}] (registry collision?)", got2)
	}
	if _, err := os.Stat(filepath.Join(root, "allowlists", "reg1")); err != nil {
		t.Errorf("registry segment missing from path: %v", err)
	}
}

func TestAllowListStore_NonPipelineRejected(t *testing.T) {
	s := NewAllowListStore(t.TempDir())
	// owner DID (not a pipeline)
	if err := s.Save("did:dplaax:reg:org:acme", []store.AllowRule{{Pattern: "x"}}); err == nil {
		t.Error("Save with owner DID returned nil, want error")
	}
	if _, err := s.Get("did:dplaax:reg:org:acme"); err == nil {
		t.Error("Get with owner DID returned nil, want error")
	}
	// unparseable
	if err := s.Save("not-a-did", []store.AllowRule{{Pattern: "x"}}); err == nil {
		t.Error("Save with unparseable DID returned nil, want error")
	}
}

func TestAllowListStore_FullReplacement(t *testing.T) {
	s := NewAllowListStore(t.TempDir())
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	if err := s.Save(pid, []store.AllowRule{{Pattern: "a"}, {Pattern: "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(pid, []store.AllowRule{{Pattern: "c"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(pid)
	if len(got) != 1 || got[0].Pattern != "c" {
		t.Errorf("after replacement = %+v, want [{c}]", got)
	}
}

// Default-distrust: an absent allow-list is empty, not an error.
func TestAllowListStore_GetAbsentEmpty(t *testing.T) {
	s := NewAllowListStore(t.TempDir())
	got, err := s.Get("did:dplaax:reg:org:acme:pipeline:p1")
	if err != nil {
		t.Fatalf("Get absent err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("Get absent = %+v, want empty", got)
	}
}

// A corrupt allow-list file is a real error, never silently collapsed to empty
// (which would silently drop trust config — Codex Medium).
func TestAllowListStore_CorruptIsError(t *testing.T) {
	root := t.TempDir()
	s := NewAllowListStore(root)
	pid := "did:dplaax:reg:org:acme:pipeline:p1"
	if err := s.Save(pid, []store.AllowRule{{Pattern: "x"}}); err != nil {
		t.Fatal(err)
	}
	corrupt(t, root)
	got, err := s.Get(pid)
	if err == nil {
		t.Fatalf("Get on a corrupt file returned nil error (got %+v)", got)
	}
	if len(got) != 0 {
		t.Errorf("Get on a corrupt file returned rules %+v, want none", got)
	}
}
