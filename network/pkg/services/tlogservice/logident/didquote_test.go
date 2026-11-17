package logident_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/logident"
)

type controllerResolver struct{ controller string }

func (r controllerResolver) ResolveDID(_ context.Context, didStr string) (*did.DIDDocument, error) {
	return did.New(did.DocumentFields{ID: didStr, Controller: r.controller}), nil
}

// A DID refused for its kind is named within a bound, however long it is: an
// emission log id that is not a pipeline's, a sink log's suffix that is not a
// process's, a process's controller that is not a pipeline's.
func TestDIDRefusedForItsKindIsNamedWithinABound(t *testing.T) {
	owner := "did:dplaax:poc.dplaax.dev:org:" + strings.Repeat("x", 64<<10)
	_, emissionErr := logident.OwnerDID(owner)
	_, receiptErr := logident.OwnerDID("sink-receipt:" + owner)
	_, rejectErr := logident.OwnerDID("sink-reject:" + owner)
	_, controllerErr := logident.NewDIDRegistryAncestry(controllerResolver{owner}).AncestorPipeline(context.Background(), processDID)
	for name, err := range map[string]error{
		"an emission log id":     emissionErr,
		"a sink-receipt suffix":  receiptErr,
		"a sink-reject suffix":   rejectErr,
		"a process's controller": controllerErr,
	} {
		if err == nil || len(err.Error()) > 500 || !strings.Contains(err.Error(), fmt.Sprintf("(%d bytes)", len(owner))) {
			t.Errorf("%s: %.200v (%d bytes), want an error naming the DID's head and length", name, err, len(fmt.Sprint(err)))
		}
	}
}
