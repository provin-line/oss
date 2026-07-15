package filestore_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/filestore"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/internal/storecontract"
)

// The shared behavioral contracts, run against the file implementations — the
// mem siblings run the SAME suites, so semantics cannot drift apart silently.
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
