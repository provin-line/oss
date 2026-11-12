package chainmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// otherPipeline is another publisher's DID, whose document advertises its own
// #chain-manager endpoint.
const otherPipeline = "did:dplaax:reg:org:other:pipeline:p1"

func otherPubDoc() *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: otherPipeline,
		Service: []did.ServiceEndpoint{{
			ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: "https://other.example/chain",
		}},
	})
}

// Subscribe refuses a publisher whose resolved document is another DID's, as
// a failure to resolve the publisher, and calls no peer.
func TestSubscribe_RefusesTheDocumentOfAnotherDID(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		WithInfraOperator(inf),
		WithDIDResolver(&fakeResolver{doc: otherPubDoc()}),
		WithPeerClient(peer),
		WithEndpointGuard(publicGuard()),
	)
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if !errors.Is(err, ErrRemotePeer) || !strings.Contains(err.Error(), otherPipeline) {
		t.Errorf("err = %v, want ErrRemotePeer naming the document's DID", err)
	}
	if len(peer.targets) != 0 || len(inf.imported) != 0 {
		t.Errorf("calls %v and imports %v, want none", peer.targets, inf.imported)
	}
}

// Unsubscribe refuses a publisher whose resolved document is another DID's,
// and sends no Disconnect to that document's endpoint.
func TestUnsubscribe_RefusesTheDocumentOfAnotherDID(t *testing.T) {
	inf, peer := &fakeInfra{}, defaultPeer()
	res := &fakeResolver{doc: pubDoc()}
	subs := memstore.NewSubscriptionStore()
	svc := New(subs, memstore.NewAllowListStore(),
		WithInfraOperator(inf),
		WithDIDResolver(res),
		WithPeerClient(peer),
		WithEndpointGuard(publicGuard()),
	)
	id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if err != nil {
		t.Fatal(err)
	}
	res.doc = otherPubDoc()
	if err := svc.Unsubscribe(context.Background(), id); !errors.Is(err, ErrRemotePeer) {
		t.Errorf("Unsubscribe: %v, want ErrRemotePeer", err)
	}
	if len(peer.disconnected) != 0 {
		t.Errorf("Disconnect sent: %v, want none", peer.disconnected)
	}
	if got, _ := subs.Get(id); got == nil || len(inf.removedImports) != 0 {
		t.Errorf("subscription kept: %t, imports removed: %v; want it kept, and none removed, for a retry", got != nil, inf.removedImports)
	}
}

// The id of a document of another DID is named within a bound, however long.
func TestSubscribe_NamesAnotherDIDsDocumentWithinABound(t *testing.T) {
	long := "did:dplaax:reg:org:" + strings.Repeat("x", 64<<10) + ":pipeline:p1"
	svc := New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		WithInfraOperator(&fakeInfra{}),
		WithDIDResolver(&fakeResolver{doc: did.New(did.DocumentFields{ID: long})}),
		WithPeerClient(defaultPeer()),
		WithEndpointGuard(publicGuard()),
	)
	_, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
	if !errors.Is(err, ErrRemotePeer) || len(err.Error()) > 1024 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(long))) {
		t.Errorf("err = %.200v (%d bytes), want ErrRemotePeer naming the id's head and length within 1 KiB", err, len(fmt.Sprint(err)))
	}
}
