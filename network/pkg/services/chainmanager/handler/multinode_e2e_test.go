package handler_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/gen/go/dplaax/chain/v1/chainpbconnect"
	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/services/chainmanager"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/handler"
	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/peerclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/store/memstore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// bridgeDirToResolver copies every <accountPub>.jwt the operators wrote into a
// MemAccResolver, so the embedded server enforces the SAME grants the real
// DirPublisher produced (the DirPublisher<->DirAccResolver file contract is proven
// in slice-15 Phase A; this avoids the DirAccResolver system-account machinery the
// deferred $SYS live-update needs).
func bridgeDirToResolver(t *testing.T, dir string) *server.MemAccResolver {
	t.Helper()
	mr := &server.MemAccResolver{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read shared dir: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".jwt") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		pub := strings.TrimSuffix(e.Name(), ".jwt")
		if err := mr.Store(pub, string(b)); err != nil {
			t.Fatalf("resolver store %s: %v", pub, err)
		}
	}
	return mr
}

// natsClient connects to url as accKP's account (a freshly minted user JWT) —
// stands in for the pipeline data plane (cmd/pipeline, wired over NATS
// transport since PR3c's separated topology; this fixture predates that and
// was never migrated to a real cmd/pipeline instance).
func natsClient(t *testing.T, url string, accKP nkeys.KeyPair) *natsclient.Conn {
	t.Helper()
	u, _ := nkeys.CreateUser()
	uPub, _ := u.PublicKey()
	uSeed, _ := u.Seed()
	ujwt, err := jwt.NewUserClaims(uPub).Encode(accKP)
	if err != nil {
		t.Fatalf("encode user JWT: %v", err)
	}
	nc, err := natsclient.Connect(url, natsclient.UserJWTAndSeed(ujwt, string(uSeed)))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return nc
}

// TestMultiNodeDelivery is the chainmanager capstone: two nodes (a publisher peer
// server + a subscriber Service), each with a REAL nats operator writing grants
// via the production DirPublisher to a shared dir, negotiate a subscription over
// the real wireauth peer round-trip; a real nats-server then enforces those
// operator-written grants so a publish on the publisher account is delivered to
// the subscriber account cross-account (positive), while a subject the publisher
// did not export is not (structurally-routable negative).
func TestMultiNodeDelivery(t *testing.T) {
	ctx := context.Background()

	// Shared single-operator trust root + a shared resolver directory.
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	opPub, _ := op.PublicKey()
	sharedDir := t.TempDir()

	// Two account identities, one per node. We keep the seeds to mint data-plane
	// users; the operators are built over the same seeds.
	pubAcc, _ := nkeys.CreateAccount()
	pubAccSeed, _ := pubAcc.Seed()
	pubAccPub, _ := pubAcc.PublicKey()
	subAcc, _ := nkeys.CreateAccount()
	subAccSeed, _ := subAcc.Seed()

	pubOp := mustOperator(t, pubAccSeed, opSeed, sharedDir)
	subOp := mustOperator(t, subAccSeed, opSeed, sharedDir)

	// --- publisher node (peer server, real wireauth, real nats operator) ---
	subSigner, subAuthPub := e2eSigner(t, e2eSub)
	pubResolver := e2eResolver{e2eSub: e2eAuthDoc(e2eSub, subAuthPub)}
	v, err := wireauth.NewVerifier(wireauth.VerifierConfig{
		Resolver: pubResolver, Crypto: ed25519.Verifier{}, Nonces: wireauth.NewMemoryNonceStore(),
		Epoch: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	allows := memstore.NewAllowListStore()
	if err := allows.Save(e2ePub, []store.AllowRule{{Pattern: "did:dplaax:*:org:sub"}}); err != nil {
		t.Fatal(err)
	}
	pubSvc := chainmanager.New(memstore.NewSubscriptionStore(), allows, chainmanager.WithInfraOperator(pubOp))
	_, ph := chainpbconnect.NewChainPeerServiceHandler(handler.NewPeer(pubSvc, v))
	pubSrv := httptest.NewServer(ph)
	t.Cleanup(pubSrv.Close)

	// --- subscriber node (Service, real nats operator, peer client) ---
	guard := core.NewURLGuard(core.WithAllowLoopback(true))
	pc := peerclient.New(subSigner, e2eSub, guard.HTTPClient())
	subSvc := chainmanager.New(memstore.NewSubscriptionStore(), memstore.NewAllowListStore(),
		chainmanager.WithInfraOperator(subOp),
		chainmanager.WithDIDResolver(e2eResolver{e2ePub: pubEndpointDoc(e2ePub, pubSrv.URL)}),
		chainmanager.WithPeerClient(pc),
		chainmanager.WithEndpointGuard(guard),
	)

	// Negotiate the subscription over the real peer round-trip → both operators
	// write their account-claims JWTs (export e2ePub on the publisher account;
	// import e2ePub from the publisher account on the subscriber account).
	if _, err := subSvc.Subscribe(ctx, e2eSub, e2ePub, "inline"); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// For a structurally-routable negative: the subscriber account also imports a
	// subject the publisher account never exports.
	const denied = "chain.denied"
	if err := subOp.AddImport(denied, pubAccPub, denied); err != nil {
		t.Fatalf("AddImport(denied): %v", err)
	}

	// All grants established BEFORE any data-plane client connects (cold-account /
	// first-lookup semantics — D-x5). Bridge them into the broker's resolver.
	mr := bridgeDirToResolver(t, sharedDir)
	natsSrv := natstest.RunServer(&server.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedKeys: []string{opPub}, AccountResolver: mr,
	})
	defer natsSrv.Shutdown()

	pubClient := natsClient(t, natsSrv.ClientURL(), pubAcc)
	defer pubClient.Close()
	subClient := natsClient(t, natsSrv.ClientURL(), subAcc)
	defer subClient.Close()

	gotMsg := make(chan struct{}, 1)
	gotDenied := make(chan struct{}, 1)
	if _, err := subClient.Subscribe(e2ePub, func(*natsclient.Msg) { gotMsg <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if _, err := subClient.Subscribe(denied, func(*natsclient.Msg) { gotDenied <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := subClient.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := pubClient.Publish(e2ePub, []byte("event")); err != nil {
		t.Fatal(err)
	}
	if err := pubClient.Publish(denied, []byte("nope")); err != nil {
		t.Fatal(err)
	}
	if err := pubClient.Flush(); err != nil {
		t.Fatal(err)
	}

	// positive: the negotiated grant delivers the publisher's stream cross-account.
	select {
	case <-gotMsg:
	case <-time.After(3 * time.Second):
		t.Fatal("positive: subscribed publisher stream NOT delivered cross-node")
	}
	// negative: a subject the publisher account never exported is not delivered,
	// even though the subscriber imports it — broker-enforced export authorization.
	select {
	case <-gotDenied:
		t.Fatal("negative: a non-exported subject WAS delivered cross-node")
	case <-time.After(time.Second):
	}
}

func mustOperator(t *testing.T, accSeed, trustSeed []byte, dir string) *natsop.Operator {
	t.Helper()
	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(trustSeed),
		URL:           "nats://unused-in-e2e:4222",
		Publisher:     natsop.NewDirPublisher(dir),
	})
	if err != nil {
		t.Fatalf("nats.New: %v", err)
	}
	return o
}
