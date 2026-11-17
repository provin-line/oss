package didregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store"
	"github.com/provin-line/oss/network/pkg/services/didregistry/store/yamlstore"
	"github.com/provin-line/oss/resolver"
)

// storeResolver adapts the registry's own store to resolver.Resolver, and this
// registry is authoritative for its namespace — so a store miss is a definitive
// absence and must carry the resolver.ErrNotFound classification (the
// resolver.Resolver error-taxonomy contract), with the store's own sentinel
// preserved for registry-internal consumers.
func TestStoreResolver_Miss_WrapsErrNotFound(t *testing.T) {
	r := storeResolver{st: yamlstore.New(t.TempDir())}
	_, err := r.Resolve(context.Background(), "did:dplaax:reg.example:org:absent")
	if err == nil {
		t.Fatal("resolving an unregistered DID: want error")
	}
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, want errors.Is(err, resolver.ErrNotFound)", err)
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want the store sentinel preserved", err)
	}
}

// Over the registry's store, storeResolver answers with a document or an
// error, never with neither (resolver.Resolver).
func TestStoreResolver_ReturnsADocumentOrAnError(t *testing.T) {
	const owner = "did:dplaax:reg.example:org:acme"
	st := yamlstore.New(t.TempDir())
	d, err := dplaax.Parse(owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveOwner(d, did.New(did.DocumentFields{ID: owner, Controller: owner})); err != nil {
		t.Fatal(err)
	}
	for _, r := range []storeResolver{{st: st}, {st: failingStore{st}}} {
		for _, s := range []string{owner, "did:dplaax:reg.example:org:absent", "did:dplaax:"} {
			if doc, err := r.Resolve(context.Background(), s); doc == nil && err == nil {
				t.Errorf("Resolve(%q): neither a document nor an error", s)
			}
		}
	}
}

// failingStore is a store whose Resolve fails with an error that is not a
// miss.
type failingStore struct{ store.DIDStore }

func (failingStore) Resolve(*dplaax.DID) (*did.DIDDocument, error) {
	return nil, errors.New("store unreadable")
}
