package chainmanager

import (
	"context"
	"errors"
	"net/netip"
	"strings"
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
	publishType      string
	modes            []string
	remoteID         string
	connInfo         map[string]string
	agreedMode       string // "" → echo the requested mode
	getErr           error
	registerErr      error
	disconnErr       error
	registered       int
	disconnected     []string
	cancelOnRegister context.CancelFunc // if set, cancels the caller ctx mid-flight
	onRegister       func()             // if set, runs after the remote side-effect commits (races a concurrent winner)
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
	if f.cancelOnRegister != nil {
		f.cancelOnRegister() // simulate the caller's ctx being canceled after the remote side-effect
	}
	if f.onRegister != nil {
		f.onRegister() // simulate a concurrent Subscribe winning between the unlocked check and the lock
	}
	f.registered++
	agreed := f.agreedMode
	if agreed == "" {
		agreed = requestedMode
		if agreed == "" {
			agreed = "by-reference"
		}
	}
	// Mirror a real publisher's subjectForMode: a by-reference agreement
	// exports (and reports) the prefixed subject. A test that scripts an
	// already-prefixed or deliberately-foreign subject is passed through
	// verbatim (the mismatch test relies on that).
	connInfo := f.connInfo
	if agreed == "by-reference" && connInfo != nil && connInfo["subject"] != "" &&
		!strings.HasPrefix(connInfo["subject"], ByReferenceSubjectPrefix) {
		derived := make(map[string]string, len(connInfo))
		for k, v := range connInfo {
			derived[k] = v
		}
		derived["subject"] = ByReferenceSubjectPrefix + derived["subject"]
		connInfo = derived
	}
	return f.remoteID, connInfo, f.publishType, agreed, nil
}

func (f *fakePeer) Disconnect(ctx context.Context, _, remoteID string) error {
	if err := ctx.Err(); err != nil {
		return err // a real client respects ctx; compensation must use a fresh one
	}
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

func TestSubscribe_InvalidSubscriberDID(t *testing.T) {
	svc, _ := subSvc(&fakeInfra{}, defaultPeer(), publicGuard())
	_, err := svc.Subscribe(context.Background(), "not-a-did", pubPipeline, "")
	if !errors.Is(err, ErrInvalidSubscriberDID) {
		t.Errorf("err = %v, want ErrInvalidSubscriberDID", err)
	}
}

// Unsubscribing one subscriber must NOT tear down the shared import while a
// sibling subscriber-direction record on the same remote subject remains
// (Codex P2 ref-count). Under D-4's mixed-mode invariant, Subscribe itself no
// longer produces two subscriber-direction records for the SAME publisherDID
// (ErrDuplicateSubscription rejects the second regardless of subscriberDID —
// the local infra account has exactly one import target per publisherDID, so
// two live subscriber records for one publisher would collide on it). The
// sibling state is therefore constructed directly against the store here,
// keeping the ref-count teardown logic itself covered as the still-real,
// defensive code it is (e.g. a legacy/migrated store could hold it).
func TestUnsubscribe_SiblingKeepsImport(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, subs := subSvc(inf, peer, publicGuard())
	id1, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	sub1, err := subs.Get(id1)
	if err != nil {
		t.Fatal(err)
	}
	sibling := &store.Subscription{
		ID:              "sibling",
		SubscriberDID:   "did:dplaax:reg:org:sub2",
		PublisherDID:    pubPipeline,
		PayloadDelivery: sub1.PayloadDelivery,
		ConnectionInfo:  sub1.ConnectionInfo,
		Direction:       directionSubscriber,
		RemoteID:        "remote-sibling",
	}
	if err := subs.Save(sibling); err != nil {
		t.Fatal(err)
	}
	if err := svc.Unsubscribe(context.Background(), id1); err != nil {
		t.Fatal(err)
	}
	if len(inf.removedImports) != 0 {
		t.Errorf("sibling remains: RemoveImport must not fire, got %v", inf.removedImports)
	}
	if err := svc.Unsubscribe(context.Background(), sibling.ID); err != nil {
		t.Fatal(err)
	}
	if len(inf.removedImports) != 1 {
		t.Errorf("last subscriber: RemoveImport must fire once, got %v", inf.removedImports)
	}
}

// When the caller's context is canceled after the remote registration but before
// persist, the compensating Disconnect must still reach the publisher — it runs
// on a context detached from the caller's cancellation (Codex P2). The fake peer
// honors ctx, so without the detach the compensation would silently no-op.
func TestSubscribe_CompensationSurvivesCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inf := &fakeInfra{}
	peer := defaultPeer()
	peer.cancelOnRegister = cancel
	allows := memstore.NewAllowListStore()
	failing := &failingSubStore{SubscriptionStore: memstore.NewSubscriptionStore(), saveErr: errors.New("disk full")}
	svc := New(failing, allows,
		WithInfraOperator(inf),
		WithDIDResolver(&fakeResolver{doc: pubDoc()}),
		WithPeerClient(peer),
		WithEndpointGuard(publicGuard()),
	)
	if _, err := svc.Subscribe(ctx, subOwner, pubPipeline, ""); err == nil {
		t.Fatal("expected persist failure")
	}
	if len(peer.disconnected) != 1 {
		t.Errorf("compensation Disconnect not delivered under a canceled caller ctx: %v", peer.disconnected)
	}
}

// countForSubject must ignore subscriber-direction records so a publisher
// Disconnect tears down its export based on publisher records alone.
func TestCountForSubject_IgnoresSubscriberDirection(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc, _ := subSvc(inf, peer, publicGuard())
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); err != nil {
		t.Fatal(err)
	}
	n, err := svc.countForSubject(pubPipeline)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("countForSubject = %d, want 0 (subscriber record must not count)", n)
	}
}
