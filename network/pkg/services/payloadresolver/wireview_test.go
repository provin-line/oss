package payloadresolver_test

import (
	"reflect"
	"testing"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/wirecontract"
)

// RetainPayloadFields builds the same fields as the wire contract's builder.
func TestRetainPayloadFields_AreTheWireContracts(t *testing.T) {
	addr := contentaddress.Of([]byte("payload"))
	got := payloadresolver.RetainPayloadFields("did:example:owner", 7, addr)
	want := wirecontract.RetainPayloadFields("did:example:owner", 7, addr)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RetainPayloadFields = %v, want the wire contract's %v", got, want)
	}
}
