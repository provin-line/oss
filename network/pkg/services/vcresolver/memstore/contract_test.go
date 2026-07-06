package memstore_test

import (
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/internal/storecontract"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
)

// The shared behavioral contract, run against the mem implementations — the
// file siblings run the SAME suite, so semantics cannot drift apart silently.
func TestContract_Store(t *testing.T) {
	storecontract.Store(t, func(t *testing.T) vcresolver.Store { return memstore.NewStore() })
}

func TestContract_Pool(t *testing.T) {
	storecontract.Pool(t, func(t *testing.T) vcresolver.Pool { return memstore.NewPool() })
}
