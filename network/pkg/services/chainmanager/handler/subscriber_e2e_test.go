package handler_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/noop"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// pubEndpointDoc is the publisher's DID document as the SUBSCRIBER resolves it:
// it advertises the #chain-manager endpoint (the httptest peer server).
func pubEndpointDoc(pub, endpoint string) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID: pub,
		Service: []did.ServiceEndpoint{{
			ID: "#chain-manager", Type: "ChainManager", ServiceEndpoint: endpoint,
		}},
	})
}

// subscriberE2E wires a real publisher peer server (wireauth-verified, noop infra,
// allow-list rules) and a real subscriber Service whose peer client signs with a
// real key and dials through a loopback-permitting SSRF guard. The subscriber's
// resolver maps the publisher DID to its #chain-manager endpoint (the server).
func subscriberE2E(t *testing.T, rules []store.AllowRule) (*chainmanager.Service, store.SubscriptionStore) {
	t.Helper()
	srvURL, subSigner, pubSubs := publisherPeerServer(t, rules)
	guard := core.NewURLGuard(core.WithAllowLoopback(true)) // httptest is 127.0.0.1
	pc := peerclient.New(subSigner, e2eSub, guard.HTTPClient())
	subSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(noop.New()),
		chainmanager.WithDIDResolver(e2eResolver{e2ePub: pubEndpointDoc(e2ePub, srvURL)}),
		chainmanager.WithPeerClient(pc),
		chainmanager.WithEndpointGuard(guard),
	)
	return subSvc, pubSubs
}

// publisherPeerServer stands up the publisher peer server (wireauth-verified, noop
// infra, given allow-list) over httptest and returns its URL, the subscriber's
// signer (whose #auth key the verifier can resolve), and the publisher's store.
func publisherPeerServer(t *testing.T, rules []store.AllowRule) (string, crypto.Signer, store.SubscriptionStore) {
	t.Helper()
	subSigner, subPub := e2eSigner(t, e2eSub)
	pubResolver := e2eResolver{e2eSub: e2eAuthDoc(e2eSub, subPub)}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: pubResolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
		Epoch: time.Now().Add(-time.Hour), // real clock; client signs at time.Now()
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	allows := memstore.NewAllowListStore()
	if err := allows.Save(e2ePub, rules); err != nil {
		t.Fatal(err)
	}
	pubSubs := memstore.NewSubscriptionStore()
	pubSvc := chainmanager.New(pubSubs, allows, chainmanager.WithInfraOperator(noop.New()))
	_, h := chainpbconnect.NewChainPeerServiceHandler(handler.NewPeer(pubSvc, v))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, subSigner, pubSubs
}

// The WithSubscriberSigner convenience path (slice-13 D-r5): the Service builds
// its own peer client from the signer, and the full round-trip still succeeds.
func TestSubscriberE2E_ViaWithSubscriberSigner(t *testing.T) {
	ctx := context.Background()
	srvURL, subSigner, _ := publisherPeerServer(t, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}})
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	subSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(noop.New()),
		chainmanager.WithDIDResolver(e2eResolver{e2ePub: pubEndpointDoc(e2ePub, srvURL)}),
		chainmanager.WithSubscriberSigner(subSigner, e2eSub), // convenience: Service builds the client
		chainmanager.WithEndpointGuard(guard),
	)
	id, err := subSvc.Subscribe(ctx, e2eSub, e2ePub, "inline")
	if err != nil {
		t.Fatalf("Subscribe via WithSubscriberSigner: %v", err)
	}
	if err := subSvc.Unsubscribe(ctx, id); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
}

// The full subscriber-initiated round-trip over a real signature/verify exchange:
// Subscribe (GetPublisherInfo + RegisterSubscription) → ListSubscriptions →
// Unsubscribe (Disconnect). This proves the D-p4 signed-view byte contract from
// the SENDING side — the peer client reproduces exactly what the publisher's
// verifier rebuilds and checks.
func TestSubscriberE2E_RoundTrip(t *testing.T) {
	ctx := context.Background()
	subSvc, pubSubs := subscriberE2E(t, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}})

	id, err := subSvc.Subscribe(ctx, e2eSub, e2ePub, "inline")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if id == "" {
		t.Fatal("empty subscription id")
	}

	// the operator sees its own subscription (subscriber-direction)
	list, err := subSvc.ListSubscriptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Direction != "subscriber" || list[0].PayloadDelivery != "inline" {
		t.Errorf("ListSubscriptions = %+v", list)
	}

	// the publisher recorded the matching publisher-direction edge
	if all, _ := pubSubs.List(); len(all) != 1 || all[0].PublisherDID != e2ePub {
		t.Errorf("publisher records = %+v, want one for %s", all, e2ePub)
	}

	if err := subSvc.Unsubscribe(ctx, id); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if list, _ := subSvc.ListSubscriptions(ctx); len(list) != 0 {
		t.Errorf("after Unsubscribe, ListSubscriptions = %+v, want empty", list)
	}
	// the publisher tore its edge down too
	if all, _ := pubSubs.List(); len(all) != 0 {
		t.Errorf("after Unsubscribe, publisher records = %+v, want empty", all)
	}
}

// Empty requested mode rides verbatim and the publisher normalizes it to
// by-reference — proving the empty→default normalization is the publisher's
// post-Verify step (the subscriber's signed bytes match what it sent).
func TestSubscriberE2E_EmptyModeNegotiated(t *testing.T) {
	ctx := context.Background()
	subSvc, _ := subscriberE2E(t, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}})
	id, err := subSvc.Subscribe(ctx, e2eSub, e2ePub, "")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	list, _ := subSvc.ListSubscriptions(ctx)
	if len(list) != 1 || list[0].ID != id || list[0].PayloadDelivery != "by-reference" {
		t.Errorf("negotiated mode = %+v, want by-reference", list)
	}
}

// A subscriber the publisher does not admit is denied remotely; the failure
// surfaces as ErrRemotePeer and nothing is persisted locally.
func TestSubscriberE2E_RemoteDenied(t *testing.T) {
	ctx := context.Background()
	subSvc, _ := subscriberE2E(t, nil) // empty allow-list → default-distrust
	_, err := subSvc.Subscribe(ctx, e2eSub, e2ePub, "inline")
	if !errors.Is(err, chainmanager.ErrRemotePeer) {
		t.Fatalf("err = %v, want ErrRemotePeer", err)
	}
	if list, _ := subSvc.ListSubscriptions(ctx); len(list) != 0 {
		t.Errorf("persisted despite remote denial = %+v", list)
	}
}
