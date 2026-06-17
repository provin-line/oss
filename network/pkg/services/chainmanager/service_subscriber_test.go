package chainmanager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

const subEndpoint = "https://cm.example/chain"

// fakeResolver returns a fixed document (or error) for any DID.
type fakeResolver struct {
	doc *did.DIDDocument
	err error
}

func (f *fakeResolver) Resolve(context.Context, string) (*did.DIDDocument, error) {
	return f.doc, f.err
}

// fakePeer records outbound calls and returns scripted responses / errors.
type fakePeer struct {
	publishType  string
	modes        []string
	remoteID     string
	connInfo     map[string]string
	agreedMode   string // "" → echo the requested mode
	getErr       error
	registerErr  error
	disconnErr   error
	registered   int
	disconnected []string
}

func (f *fakePeer) GetPublisherInfo(context.Context, string, string, string) (string, []string, error) {
	if f.getErr != nil {
		return "", nil, f.getErr
	}
	return f.publishType, f.modes, nil
}

func (f *fakePeer) RegisterSubscription(_ context.Context, _, _, _, requestedMode string) (string, map[string]string, string, string, error) {
	if f.registerErr != nil {
		return "", nil, "", "", f.registerErr
	}
	f.registered++
	agreed := f.agreedMode
	if agreed == "" {
		agreed = requestedMode
		if agreed == "" {
			agreed = "by-reference"
		}
	}
	return f.remoteID, f.connInfo, f.publishType, agreed, nil
}

func (f *fakePeer) Disconnect(_ context.Context, _, remoteID string) error {
	if f.disconnErr != nil {
		return f.disconnErr
	}
	f.disconnected = append(f.disconnected, remoteID)
	return nil
}

// publicGuard resolves any host to a public address so the endpoint passes SSRF.
func publicGuard() *core.URLGuard {
	return core.NewURLGuard(core.WithResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}))
}

// privateGuard resolves any host to a private address → SSRF must block.
func privateGuard() *core.URLGuard {
	return core.NewURLGuard(core.WithResolver(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}))
}

func pubDoc() *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: pubPipeline,
		Service: []did.ServiceEndpoint{{
			ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: subEndpoint,
		}},
	})
}

// subSvc builds a subscriber-configured Service over the given peer + infra.
func subSvc(inf *fakeInfra, peer *fakePeer, g *core.URLGuard) (*Service, store.SubscriptionStore) {
	subs := memstore.NewSubscriptionStore()
	allows := memstore.NewAllowListStore()
	svc := New(subs, allows,
		WithInfraOperator(inf),
		WithDIDResolver(&fakeResolver{doc: pubDoc()}),
		WithPeerClient(peer),
		WithEndpointGuard(g),
	)
	return svc, subs
}

func defaultPeer() *fakePeer {
	return &fakePeer{
		publishType: "noop",
		modes:       []string{"by-reference", "inline"},
		remoteID:    "remote-123",
		connInfo:    map[string]string{"subject": pubPipeline},
	}
}

func TestSubscribe_Success(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())

	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if id == "" {
		t.Fatal("empty subscription id")
	}
	got, _ := subs.Get(id)
	if got == nil {
		t.Fatal("subscription not persisted")
	}
	if got.Direction != "subscriber" || got.RemoteID != "remote-123" {
		t.Errorf("record = %+v, want Direction=subscriber RemoteID=remote-123", got)
	}
	if got.PayloadDelivery != "inline" || got.PublishType != "noop" {
		t.Errorf("record = %+v", got)
	}
	if len(inf.imported) != 1 || inf.imported[0] != pubPipeline {
		t.Errorf("AddImport calls = %v, want [%s]", inf.imported, pubPipeline)
	}
}

func TestSubscribe_EmptyModeDefaults(t *testing.T) {
	svc, subs := subSvc(&fakeInfra{}, defaultPeer(), publicGuard())
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	got, _ := subs.Get(id)
	if got.PayloadDelivery != "by-reference" {
		t.Errorf("empty mode → %q, want by-reference", got.PayloadDelivery)
	}
}

func TestSubscribe_Unconfigured(t *testing.T) {
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore()) // no subscriber deps
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); !errors.Is(err, ErrSubscriberUnconfigured) {
		t.Errorf("err = %v, want ErrSubscriberUnconfigured", err)
	}
}

func TestSubscribe_InvalidPublisher(t *testing.T) {
	svc, _ := subSvc(&fakeInfra{}, defaultPeer(), publicGuard())
	_, err := svc.Subscribe(context.Background(), subOwner, "did:dplaax:reg:org:acme", "") // owner, not pipeline
	if !errors.Is(err, ErrInvalidPipelineDID) {
		t.Errorf("err = %v, want ErrInvalidPipelineDID", err)
	}
}

func TestSubscribe_NoEndpoint(t *testing.T) {
	subs := memstore.NewSubscriptionStore()
	emptyDoc := did.New(did.DocumentFields{ID: pubPipeline})
	svc := New(subs, memstore.NewAllowListStore(),
		WithInfraOperator(&fakeInfra{}),
		WithDIDResolver(&fakeResolver{doc: emptyDoc}),
		WithPeerClient(defaultPeer()),
		WithEndpointGuard(publicGuard()),
	)
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); !errors.Is(err, ErrNoChainManagerEndpoint) {
		t.Errorf("err = %v, want ErrNoChainManagerEndpoint", err)
	}
}

func TestSubscribe_UnsafeEndpoint(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, privateGuard())
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if !errors.Is(err, ErrEndpointNotAllowed) {
		t.Fatalf("err = %v, want ErrEndpointNotAllowed", err)
	}
	if peer.registered != 0 || len(inf.imported) != 0 {
		t.Error("outbound register / import happened for an unsafe endpoint")
	}
}

func TestSubscribe_UnsupportedMode(t *testing.T) {
	inf := &fakeInfra{}
	peer := defaultPeer()
	peer.modes = []string{"by-reference"} // inline not offered
	svc, subs := subSvc(inf, peer, publicGuard())
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline")
	if !errors.Is(err, ErrPayloadModeUnsupported) {
		t.Fatalf("err = %v, want ErrPayloadModeUnsupported", err)
	}
	if peer.registered != 0 || len(inf.imported) != 0 {
		t.Error("register/import happened for an unsupported mode")
	}
	if all, _ := subs.List(); len(all) != 0 {
		t.Error("subscription persisted for an unsupported mode")
	}
}

func TestSubscribe_AddImportFailure_Compensates(t *testing.T) {
	inf := &fakeInfra{importErr: errors.New("nats down")}
	peer := defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err == nil {
		t.Fatal("Subscribe succeeded despite AddImport failure")
	}
	// the remote already registered → compensate with a remote Disconnect
	if len(peer.disconnected) != 1 || peer.disconnected[0] != "remote-123" {
		t.Errorf("expected compensating remote Disconnect, got %v", peer.disconnected)
	}
	if all, _ := subs.List(); len(all) != 0 {
		t.Error("subscription persisted despite AddImport failure")
	}
}

func TestSubscribe_PersistFailure_Compensates(t *testing.T) {
	inf := &fakeInfra{}
	peer := defaultPeer()
	allows := memstore.NewAllowListStore()
	failing := &failingSubStore{SubscriptionStore: memstore.NewSubscriptionStore(), saveErr: errors.New("disk full")}
	svc := New(failing, allows,
		WithInfraOperator(inf),
		WithDIDResolver(&fakeResolver{doc: pubDoc()}),
		WithPeerClient(peer),
		WithEndpointGuard(publicGuard()),
	)
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err == nil {
		t.Fatal("Subscribe succeeded despite persist failure")
	}
	if len(inf.removedImports) != 1 {
		t.Errorf("expected compensating RemoveImport, got %v", inf.removedImports)
	}
	if len(peer.disconnected) != 1 {
		t.Errorf("expected compensating remote Disconnect, got %v", peer.disconnected)
	}
}

func TestUnsubscribe_Success(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Unsubscribe(context.Background(), id); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if len(peer.disconnected) != 1 || peer.disconnected[0] != "remote-123" {
		t.Errorf("remote Disconnect = %v, want [remote-123]", peer.disconnected)
	}
	if len(inf.removedImports) != 1 {
		t.Errorf("RemoveImport = %v, want one", inf.removedImports)
	}
	if got, _ := subs.Get(id); got != nil {
		t.Error("subscription not deleted")
	}
}

func TestUnsubscribe_NotFound(t *testing.T) {
	svc, _ := subSvc(&fakeInfra{}, defaultPeer(), publicGuard())
	if err := svc.Unsubscribe(context.Background(), "no-such-id"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUnsubscribe_WrongDirection(t *testing.T) {
	// A publisher-direction record must not be reachable via Unsubscribe.
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	if err := subs.Save(&store.Subscription{ID: "pub-rec", PublisherDID: pubPipeline, Direction: "publisher"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Unsubscribe(context.Background(), "pub-rec"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound (direction-gated)", err)
	}
	if len(peer.disconnected) != 0 {
		t.Error("remote Disconnect called on a publisher-direction record")
	}
}

func TestUnsubscribe_RemoteNotFoundIsIdempotent(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	peer.disconnErr = store.ErrNotFound // remote already tore its record down
	if err := svc.Unsubscribe(context.Background(), id); err != nil {
		t.Fatalf("Unsubscribe should treat remote NotFound as success: %v", err)
	}
	if len(inf.removedImports) != 1 {
		t.Error("RemoveImport must still run after a remote NotFound")
	}
	if got, _ := subs.Get(id); got != nil {
		t.Error("local record must still be deleted after a remote NotFound")
	}
}

func TestUnsubscribe_RemoveImportFailure_KeepsRecord(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	inf.removeImportErr = errors.New("nats down")
	if err := svc.Unsubscribe(context.Background(), id); err == nil {
		t.Fatal("Unsubscribe succeeded despite RemoveImport failure")
	}
	if got, _ := subs.Get(id); got == nil {
		t.Error("record deleted even though RemoveImport failed (not retryable)")
	}
}

func TestListSubscriptions_SubscriberDirectionOnly(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	// one subscriber record (via Subscribe) and one publisher record (direct save)
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); err != nil {
		t.Fatal(err)
	}
	if err := subs.Save(&store.Subscription{ID: "pub-rec", PublisherDID: pubPipeline, Direction: "publisher"}); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListSubscriptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Direction != "subscriber" {
		t.Errorf("ListSubscriptions = %+v, want one subscriber-direction record", list)
	}
}

// countForPublisher must ignore subscriber-direction records so a publisher
// Disconnect tears down its export based on publisher records alone.
func TestCountForPublisher_IgnoresSubscriberDirection(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, publicGuard())
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); err != nil {
		t.Fatal(err)
	}
	n, err := svc.countForPublisher(pubPipeline)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("countForPublisher = %d, want 0 (subscriber record must not count)", n)
	}
}
