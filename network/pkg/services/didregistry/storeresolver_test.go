package didregistry

import (
	"context"
	"errors"
	"testing"

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
