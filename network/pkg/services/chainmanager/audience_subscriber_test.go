package chainmanager

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// pubPipeline's registry segment is "reg": the registry whose DID document
// publishes the #chain-manager endpoint the peer calls go to.
const pubRegistry = "reg"

func TestSubscribeSignsForPublisherRegistry(t *testing.T) {
	peer := defaultPeer()
	svc, _ := subSvc(&fakeInfra{}, peer, publicGuard())
	if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "inline"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	want := []string{
		"GetPublisherInfo " + subEndpoint + " " + pubRegistry,
		"RegisterSubscription " + subEndpoint + " " + pubRegistry,
	}
	if !slices.Equal(peer.targets, want) {
		t.Errorf("peer calls = %q, want %q", peer.targets, want)
	}
}

func TestDisconnectSignsForPublisherRegistry(t *testing.T) {
	t.Run("unsubscribe", func(t *testing.T) {
		peer := defaultPeer()
		svc, _ := subSvc(&fakeInfra{}, peer, publicGuard())
		id, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, "")
		if err != nil {
			t.Fatal(err)
		}
		peer.targets = nil
		if err := svc.Unsubscribe(context.Background(), id); err != nil {
			t.Fatalf("Unsubscribe: %v", err)
		}
		if want := []string{"Disconnect " + subEndpoint + " " + pubRegistry}; !slices.Equal(peer.targets, want) {
			t.Errorf("peer calls = %q, want %q", peer.targets, want)
		}
	})
	t.Run("compensation", func(t *testing.T) {
		peer := defaultPeer()
		svc, _ := subSvc(&fakeInfra{importErr: errors.New("nats down")}, peer, publicGuard())
		if _, err := svc.Subscribe(context.Background(), subOwner, pubPipeline, ""); err == nil {
			t.Fatal("Subscribe succeeded despite AddImport failure")
		}
		if last := peer.targets[len(peer.targets)-1]; last != "Disconnect "+subEndpoint+" "+pubRegistry {
			t.Errorf("compensating call = %q, want a Disconnect for %q", last, pubRegistry)
		}
	})
}
