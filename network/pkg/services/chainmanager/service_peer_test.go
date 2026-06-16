package chainmanager

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

const (
	pubPipeline = "did:dplaax:reg:org:acme:pipeline:p1"
	subOwner    = "did:dplaax:reg:org:sub"
)

// fakeInfra records AddExport/RemoveExport so tests can assert the export
// lifecycle (and inject an AddExport failure).
type fakeInfra struct {
	added   []string
	removed []string
	addErr  error
}

func (f *fakeInfra) PublishType() string { return "noop" }
func (f *fakeInfra) AddExport(s string) (map[string]string, error) {
	if f.addErr != nil {
		return nil, f.addErr
	}
	f.added = append(f.added, s)
	return map[string]string{"subject": s}, nil
}
func (f *fakeInfra) RemoveExport(s string) error          { f.removed = append(f.removed, s); return nil }
func (f *fakeInfra) AddImport(_, _, _ string) error       { return nil }
func (f *fakeInfra) RemoveImport(_, _ string) error       { return nil }

// failingSubStore wraps a real store but forces Save to fail.
type failingSubStore struct {
	store.SubscriptionStore
	saveErr error
}

func (f *failingSubStore) Save(*store.Subscription) error { return f.saveErr }

// svcWith builds a Service with an admitting allow-list for pubPipeline → subOwner,
// the given infra, and returns the infra + allow store for assertions.
func svcWith(t *testing.T, inf *fakeInfra) (*Service, store.SubscriptionStore) {
	t.Helper()
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	if err := allows.Save(pubPipeline, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	return New(subs, allows, WithInfraOperator(inf)), subs
}

func TestPeer_PublisherInfo_Admitted(t *testing.T) {
	svc, _ := svcWith(t, &fakeInfra{})
	pt, modes, err := svc.PublisherInfo(context.Background(), pubPipeline, subOwner)
	if err != nil {
		t.Fatalf("PublisherInfo: %v", err)
	}
	if pt != "noop" || len(modes) == 0 {
		t.Errorf("PublisherInfo = (%q, %v)", pt, modes)
	}
}

func TestPeer_PublisherInfo_NotAdmitted(t *testing.T) {
	svc, _ := svcWith(t, &fakeInfra{})
	_, _, err := svc.PublisherInfo(context.Background(), pubPipeline, "did:dplaax:reg:org:stranger")
	if !errors.Is(err, ErrNotAdmitted) {
		t.Errorf("err = %v, want ErrNotAdmitted", err)
	}
}

func TestPeer_PublisherInfo_InvalidPublisher(t *testing.T) {
	svc, _ := svcWith(t, &fakeInfra{})
	_, _, err := svc.PublisherInfo(context.Background(), "did:dplaax:reg:org:acme", subOwner) // owner, not pipeline
	if !errors.Is(err, ErrInvalidPipelineDID) {
		t.Errorf("err = %v, want ErrInvalidPipelineDID", err)
	}
}

func TestPeer_NoInfra_Unavailable(t *testing.T) {
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	svc := New(subs, allows) // no WithInfraOperator
	if _, _, err := svc.PublisherInfo(context.Background(), pubPipeline, subOwner); !errors.Is(err, ErrInfraUnavailable) {
		t.Errorf("PublisherInfo err = %v, want ErrInfraUnavailable", err)
	}
	if _, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, ""); !errors.Is(err, ErrInfraUnavailable) {
		t.Errorf("RegisterSubscription err = %v, want ErrInfraUnavailable", err)
	}
	if err := svc.Disconnect(context.Background(), "id", subOwner); !errors.Is(err, ErrInfraUnavailable) {
		t.Errorf("Disconnect err = %v, want ErrInfraUnavailable", err)
	}
}

func TestPeer_RegisterSubscription_Success(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "inline")
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if sub.ID == "" || sub.PayloadDelivery != "inline" || sub.PublishType != "noop" {
		t.Errorf("subscription = %+v", sub)
	}
	if sub.ConnectionInfo["subject"] != pubPipeline {
		t.Errorf("connection_info = %+v", sub.ConnectionInfo)
	}
	if len(inf.added) != 1 || inf.added[0] != pubPipeline {
		t.Errorf("AddExport calls = %v, want [%s]", inf.added, pubPipeline)
	}
	if got, _ := subs.Get(sub.ID); got == nil {
		t.Error("subscription not persisted")
	}
}

func TestPeer_RegisterSubscription_EmptyModeDefaults(t *testing.T) {
	svc, _ := svcWith(t, &fakeInfra{})
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatalf("RegisterSubscription: %v", err)
	}
	if sub.PayloadDelivery != "by-reference" {
		t.Errorf("empty mode → %q, want by-reference", sub.PayloadDelivery)
	}
}

func TestPeer_RegisterSubscription_UnsupportedMode(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	_, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "carrier-pigeon")
	if !errors.Is(err, ErrPayloadModeUnsupported) {
		t.Fatalf("err = %v, want ErrPayloadModeUnsupported", err)
	}
	if len(inf.added) != 0 {
		t.Error("AddExport called on unsupported mode")
	}
	if all, _ := subs.List(); len(all) != 0 {
		t.Error("subscription persisted on unsupported mode")
	}
}

func TestPeer_RegisterSubscription_NotAdmitted(t *testing.T) {
	inf := &fakeInfra{}
	svc, _ := svcWith(t, inf)
	_, err := svc.RegisterSubscription(context.Background(), "did:dplaax:reg:org:stranger", pubPipeline, "")
	if !errors.Is(err, ErrNotAdmitted) {
		t.Fatalf("err = %v, want ErrNotAdmitted", err)
	}
	if len(inf.added) != 0 {
		t.Error("AddExport called for a non-admitted subscriber")
	}
}

// A Save failure for the first subscription must compensate by removing the
// export it just created, so no orphan export survives (D-p8).
func TestPeer_RegisterSubscription_SaveFailureCompensates(t *testing.T) {
	inf := &fakeInfra{}
	allows := memstore.NewAllowListStore()
	if err := allows.Save(pubPipeline, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	failing := &failingSubStore{SubscriptionStore: memstore.NewSubscriptionStore(), saveErr: errors.New("disk full")}
	svc := New(failing, allows, WithInfraOperator(inf))
	_, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "")
	if err == nil {
		t.Fatal("RegisterSubscription succeeded despite Save failure")
	}
	if len(inf.added) != 1 || len(inf.removed) != 1 || inf.removed[0] != pubPipeline {
		t.Errorf("expected compensating RemoveExport: added=%v removed=%v", inf.added, inf.removed)
	}
}

func TestPeer_Disconnect_Owner_LastSubscription(t *testing.T) {
	inf := &fakeInfra{}
	svc, _ := svcWith(t, inf)
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Disconnect(context.Background(), sub.ID, subOwner); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(inf.removed) != 1 || inf.removed[0] != pubPipeline {
		t.Errorf("last subscription: expected RemoveExport, removed=%v", inf.removed)
	}
}

// Disconnecting one subscriber must NOT tear down the export while a sibling
// subscriber of the same publisher remains (D-p8 ref-count).
func TestPeer_Disconnect_SiblingRemains(t *testing.T) {
	inf := &fakeInfra{}
	svc, _ := svcWith(t, inf)
	// admit a second subscriber too
	subTwo := "did:dplaax:reg:org:sub2"
	allows := memstore.NewAllowListStore()
	_ = allows // (svcWith already admits via "*:org:sub"; broaden by re-saving)
	// Re-save the allow-list to admit both org:sub and org:sub2.
	if err := svc.allows.Save(pubPipeline, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}, {Pattern: "did:dplaax:*:org:sub2"}}); err != nil {
		t.Fatal(err)
	}
	s1, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterSubscription(context.Background(), subTwo, pubPipeline, ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.Disconnect(context.Background(), s1.ID, subOwner); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if len(inf.removed) != 0 {
		t.Errorf("sibling remains: RemoveExport must not be called, removed=%v", inf.removed)
	}
}

func TestPeer_Disconnect_NotFound(t *testing.T) {
	svc, _ := svcWith(t, &fakeInfra{})
	if err := svc.Disconnect(context.Background(), "no-such-id", subOwner); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPeer_Disconnect_NotOwner(t *testing.T) {
	inf := &fakeInfra{}
	svc, subs := svcWith(t, inf)
	sub, err := svc.RegisterSubscription(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Disconnect(context.Background(), sub.ID, "did:dplaax:reg:org:intruder"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("err = %v, want ErrNotOwner", err)
	}
	if len(inf.removed) != 0 {
		t.Error("RemoveExport called on a non-owner disconnect")
	}
	if got, _ := subs.Get(sub.ID); got == nil {
		t.Error("subscription deleted on a non-owner disconnect")
	}
}
