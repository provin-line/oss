package vcresolver_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/network/pkg/services/vcresolver"
	"github.com/provin-line/oss/network/pkg/services/vcresolver/memstore"
)

// Same setup as TestRollbackWrittenFlatIsNotLost, but a single Get() (the
// ResolveVC read path) happens between the rollback write and the fetch.
func TestProbeRollbackFlatLostByRead(t *testing.T) {
	for _, pv := range []string{"zB", "zC", "zD", "zE", "zF", "zG"} {
		t.Run(pv, func(t *testing.T) {
			backend := memstore.NewBackend()
			store := vcresolver.NewVariantStore(backend)
			first := credWithProof(t, "s1", "zA")
			body, variantA := mustPut(t, store, first)
			bodyHex := strings.TrimPrefix(body, "sha256:")

			rolledBack := credWithProof(t, "s1", pv)
			variantB, err := rolledBack.WireVariantID()
			if err != nil {
				t.Fatal(err)
			}
			if err := backend.WriteProjection(bodyHex, canonicalOf(t, rolledBack)); err != nil {
				t.Fatal(err)
			}

			// Sanity: before any read, the rollback bytes ARE fetchable.
			if _, err := store.GetVariant(body, variantB); err != nil {
				t.Fatalf("precondition: rollback variant not fetchable: %v", err)
			}

			// A plain read of the legacy projection. ResolveVC does exactly this.
			if _, err := store.Get(body); err != nil {
				t.Fatalf("Get: %v", err)
			}

			ord := "flat(B) < set-min(A)"
			if variantA < variantB {
				ord = "set-min(A) < flat(B)"
			}
			if _, err := store.GetVariant(body, variantB); err != nil {
				t.Errorf("[%s] a READ destroyed the rollback-written variant: %v", ord, err)
			}
			ids, err := store.ListVariantIDs(body, "", 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 2 {
				t.Errorf("[%s] variant set after a read = %v (want 2 ids)", ord, ids)
			}
		})
	}
}
