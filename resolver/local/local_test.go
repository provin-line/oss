package local_test

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/local"
)

var _ resolver.Resolver = (*local.Resolver)(nil)

const testDID = "did:dplaax:poc.dplaax.dev:org:acme"

func TestResolve_RoundTrip(t *testing.T) {
	r := local.New()
	doc := did.New(did.DocumentFields{ID: testDID, Controller: testDID})
	r.Add(doc)

	got, err := r.Resolve(context.Background(), testDID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID() != testDID {
		t.Errorf("resolved ID=%q, want %q", got.ID(), testDID)
	}
}

func TestResolve_NotFound(t *testing.T) {
	r := local.New()
	_, err := r.Resolve(context.Background(), "did:dplaax:poc.dplaax.dev:org:absent")
	if err == nil {
		t.Fatal("resolving an unregistered DID: want error")
	}
	// A local miss is definitive — the store authoritatively holds no document —
	// so the error must carry the resolver.ErrNotFound classification.
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is(err, resolver.ErrNotFound)", err)
	}
}

func TestAdd_Overwrite(t *testing.T) {
	r := local.New()
	r.Add(did.New(did.DocumentFields{ID: testDID, Controller: "old"}))
	r.Add(did.New(did.DocumentFields{ID: testDID, Controller: "new"}))
	got, err := r.Resolve(context.Background(), testDID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Controller() != "new" {
		t.Errorf("Controller=%q, want the overwriting value %q", got.Controller(), "new")
	}
}
