package nats_test

import (
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	natstest "github.com/nats-io/nats-server/v2/test"
	natsclient "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

// memPub is a test-only JWTPublisher backed by the embedded server's in-memory
// account resolver (the production push to a live resolver is C2b-2). It is a
// helper, NOT a production export of infra/nats (D-n3): it references the
// nats-server, which must stay out of the production import graph.
type memPub struct{ mr *server.MemAccResolver }

func (m memPub) Publish(accountPub, accountJWT string) error {
	return m.mr.Store(accountPub, accountJWT)
}

// Load is unused by the e2e (operators are created once) but required by the
// JWTPublisher interface.
func (m memPub) Load(string) (string, error) { return "", natsop.ErrNotPublished }

// newE2EOperator builds a nats.Operator over a fresh account, all signed by the
// shared trust-root (single-operator deployment), publishing into mr. It returns
// the operator, the account key pair (to mint client user JWTs), and the account
// public key.
func newE2EOperator(t *testing.T, trustRootSeed []byte, mr *server.MemAccResolver) (*natsop.Operator, nkeys.KeyPair, string) {
	t.Helper()
	acc, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	accSeed, _ := acc.Seed()
	accPub, _ := acc.PublicKey()
	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(trustRootSeed),
		URL:           "nats://unused-in-e2e",
		Publisher:     memPub{mr},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o, acc, accPub
}

// connectAs mints a user JWT signed by accKP and connects a client as that
// account (test scaffolding for the data-plane — not infra.Operator's job).
func connectAs(t *testing.T, url string, accKP nkeys.KeyPair) *natsclient.Conn {
	t.Helper()
	u, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
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

// TestIsolationE2E proves broker-enforced cross-account isolation (D-n5): the nats
// operator's account claims are evaluated by a real nats-server, so an exported→
// imported subject crosses accounts (positive) while a subject the subscriber is
// structurally ready to receive but the publisher did NOT export does not
// (negative). The negative is routable on the sub side (it imports `denied`), so
// the ONLY reason it is blocked is the missing export authorization.
func TestIsolationE2E(t *testing.T) {
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opSeed, _ := op.Seed()
	opPub, _ := op.PublicKey()

	const allowed = "chain.pub.allowed"
	const denied = "chain.pub.denied"

	// Establish the FINAL claim set in the resolver BEFORE any client connects
	// (D-n5 timing: MemAccResolver.Store does not update an already-loaded account).
	mr := &server.MemAccResolver{}
	pubOp, pubAcc, pubPub := newE2EOperator(t, opSeed, mr)
	subOp, subAcc, _ := newE2EOperator(t, opSeed, mr)

	if _, err := pubOp.AddExport(allowed); err != nil { // pub exports ONLY allowed
		t.Fatalf("AddExport: %v", err)
	}
	// sub imports BOTH allowed and denied → structurally routable for denied.
	if err := subOp.AddImport(allowed, pubPub, "in.allowed"); err != nil {
		t.Fatalf("AddImport allowed: %v", err)
	}
	if err := subOp.AddImport(denied, pubPub, "in.denied"); err != nil {
		t.Fatalf("AddImport denied: %v", err)
	}

	s := natstest.RunServer(&server.Options{
		Host:            "127.0.0.1",
		Port:            -1,
		NoLog:           true,
		NoSigs:          true,
		TrustedKeys:     []string{opPub},
		AccountResolver: mr,
	})
	defer s.Shutdown()
	url := s.ClientURL()

	subNC := connectAs(t, url, subAcc)
	defer subNC.Close()
	pubNC := connectAs(t, url, pubAcc)
	defer pubNC.Close()

	gotAllowed := make(chan struct{}, 1)
	gotDenied := make(chan struct{}, 1)
	if _, err := subNC.Subscribe("in.allowed", func(*natsclient.Msg) { gotAllowed <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if _, err := subNC.Subscribe("in.denied", func(*natsclient.Msg) { gotDenied <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := subNC.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := pubNC.Publish(allowed, []byte("yes")); err != nil {
		t.Fatal(err)
	}
	if err := pubNC.Publish(denied, []byte("no")); err != nil {
		t.Fatal(err)
	}
	if err := pubNC.Flush(); err != nil {
		t.Fatal(err)
	}

	// positive: the exported→imported subject is delivered across accounts.
	select {
	case <-gotAllowed:
	case <-time.After(3 * time.Second):
		t.Fatal("positive: exported subject was NOT delivered across accounts")
	}
	// negative: the non-exported subject is NOT delivered, even though the sub
	// imports it — proving nats-server enforces export authorization at the
	// account boundary (isolation), independent of the peer-layer gate.
	select {
	case <-gotDenied:
		t.Fatal("negative: a non-exported subject WAS delivered — broker did not enforce account isolation")
	case <-time.After(time.Second):
		// good: blocked by the missing export authorization.
	}
}
