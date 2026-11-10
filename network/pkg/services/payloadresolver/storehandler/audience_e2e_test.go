package storehandler_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
)

// The Retain proof names the configured store audience: the store's verifier
// accepts a client configured with its audience and refuses one configured
// with another.
func TestRetainProofNamesStoreAudience(t *testing.T) {
	h := newHarness(t, 1<<20)
	payload := []byte("retained for this node")
	if _, err := h.client.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload))); err != nil {
		t.Fatalf("configured for the store's audience: %v", err)
	}
	other := client.New(client.Config{Signer: h.signer, SignerDID: nodeDID, HTTPClient: h.httpc, StoreEndpoint: h.url, StoreAudience: "other.example"})
	_, err := other.Retain(context.Background(), bytes.NewReader(payload), nodeDID, uint64(len(payload)))
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("configured for another audience: %v (code %v), want Unauthenticated naming the audience", err, connect.CodeOf(err))
	}
}
