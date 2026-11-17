package handler_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/infra/noop"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
)

// A publisher's DID document that points #chain-manager at a node of another
// registry: that node's verifier refuses the subscriber's proofs, which are
// for the publisher's registry, and Subscribe says why.
func TestSubscribeToForeignChainManagerFailsWithWrongAudience(t *testing.T) {
	srvURL, subSigner, pubSubs := publisherPeerServerOpts(t, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}, false, "other.example")
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	subSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(noop.New()),
		chainmanager.WithDIDResolver(e2eResolver{e2ePub: pubEndpointDoc(e2ePub, srvURL)}),
		chainmanager.WithPeerClient(peerclient.New(subSigner, e2eSub, guard.HTTPClient())),
		chainmanager.WithEndpointGuard(guard),
	)
	_, err := subSvc.Subscribe(context.Background(), e2eSub, e2ePub, "inline")
	if !errors.Is(err, chainmanager.ErrRemotePeer) || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("Subscribe through another registry's node: %v, want ErrRemotePeer naming the audience", err)
	}
	if all, _ := pubSubs.List(); len(all) != 0 {
		t.Errorf("the other registry's node registered %d subscriptions", len(all))
	}
}
