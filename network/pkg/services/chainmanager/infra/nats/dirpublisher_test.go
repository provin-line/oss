package nats_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	natsop "github.com/provin-line/oss/network/pkg/services/chainmanager/infra/nats"
)

var _ natsop.JWTPublisher = (*natsop.DirPublisher)(nil)

func TestDirPublisher_WritesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	p := natsop.NewDirPublisher(dir)

	if err := p.Publish(accPub, "jwt-v1"); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	path := filepath.Join(dir, accPub+".jwt")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != "jwt-v1" {
		t.Errorf("content = %q, want jwt-v1", got)
	}
	// a second publish overwrites in place (no stale temp files left behind).
	if err := p.Publish(accPub, "jwt-v2"); err != nil {
		t.Fatalf("Publish (overwrite): %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "jwt-v2" {
		t.Errorf("content after overwrite = %q, want jwt-v2", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (atomic rename leaves no temp)", len(entries))
	}
}

func TestDirPublisher_LoadRoundTripAndNotPublished(t *testing.T) {
	dir := t.TempDir()
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	p := natsop.NewDirPublisher(dir)

	// not yet published -> typed ErrNotPublished (first boot), not a generic error.
	if _, err := p.Load(accPub); !errors.Is(err, natsop.ErrNotPublished) {
		t.Errorf("Load before publish: err = %v, want ErrNotPublished", err)
	}
	if err := p.Publish(accPub, "jwt-body"); err != nil {
		t.Fatal(err)
	}
	got, err := p.Load(accPub)
	if err != nil {
		t.Fatalf("Load after publish: %v", err)
	}
	if got != "jwt-body" {
		t.Errorf("Load = %q, want jwt-body", got)
	}
}

func TestDirPublisher_RejectsMalformedAccountKey(t *testing.T) {
	dir := t.TempDir()
	p := natsop.NewDirPublisher(dir)
	if err := p.Publish("not-an-account-key", "jwt"); err == nil {
		t.Error("malformed account key accepted")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Error("a file was written for a malformed key")
	}
}

// TestDirPublisher_LoadableByDirResolver proves the file layout matches the
// nats-server directory account resolver contract: the JWT the publisher writes is
// read back by the SAME store type the running resolver uses
// (server.DirJWTStore.LoadAcc — exactly what DirAccResolver.Fetch calls on a
// first lookup), unsharded under <dir>/<pub>.jwt. This pins the publisher↔resolver
// contract without the system-account wiring a full running server needs (the
// running-server isolation proof is TestIsolationE2E over MemAccResolver).
func TestDirPublisher_LoadableByDirResolver(t *testing.T) {
	dir := t.TempDir()
	op, _ := nkeys.CreateOperator()
	opSeed, _ := op.Seed()
	acc, _ := nkeys.CreateAccount()
	accSeed, _ := acc.Seed()
	accPub, _ := acc.PublicKey()

	o, err := natsop.New(natsop.Config{
		AccountSeed:   string(accSeed),
		TrustRootSeed: string(opSeed),
		URL:           "nats://unused:4222",
		Publisher:     natsop.NewDirPublisher(dir),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// any mutation publishes the account JWT to <dir>/<accPub>.jwt
	if _, err := o.AddExport("chain.x"); err != nil {
		t.Fatalf("AddExport: %v", err)
	}

	// shard=false matches NewDirAccResolver's NewExpiringDirJWTStore(path, false, …).
	store, err := server.NewImmutableDirJWTStore(dir, false)
	if err != nil {
		t.Fatalf("NewImmutableDirJWTStore: %v", err)
	}
	defer store.Close()
	loaded, err := store.LoadAcc(accPub)
	if err != nil {
		t.Fatalf("LoadAcc(%s): %v", accPub, err)
	}
	ac, err := jwt.DecodeAccountClaims(loaded)
	if err != nil {
		t.Fatalf("DecodeAccountClaims: %v", err)
	}
	if ac.Subject != accPub {
		t.Errorf("loaded account subject = %q, want %q", ac.Subject, accPub)
	}
	if len(ac.Exports) != 1 || string(ac.Exports[0].Subject) != "chain.x" {
		t.Errorf("loaded exports = %+v, want one for chain.x", ac.Exports)
	}
}
