package filestore_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/internal/storecontract"
)

// The shared behavioral contract, run against the file implementations — the
// mem siblings run the SAME suite, so semantics cannot drift apart silently.
func TestContract_Store(t *testing.T) {
	storecontract.Store(t, func(t *testing.T) vcresolver.Store {
		s, err := filestore.NewStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestContract_Pool(t *testing.T) {
	storecontract.Pool(t, func(t *testing.T) vcresolver.Pool {
		p, err := filestore.NewPool(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return p
	})
}

func TestContract_VariantBackend(t *testing.T) {
	storecontract.Backend(t, func(t *testing.T) vcresolver.VariantBackend {
		b, err := filestore.NewBackend(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return b
	})
}
