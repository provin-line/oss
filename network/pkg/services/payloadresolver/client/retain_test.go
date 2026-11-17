package client_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/provin-line/oss/contentaddress"
	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
)

// Retain refuses a zero content address before it sends anything.
func TestRetainWithoutContentAddressFailsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	ks := ksfilestore.New(t.TempDir())
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ks.SaveKeyPair(clientDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDAuth: kp}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := client.New(client.Config{Signer: ks, SignerDID: clientDID, HTTPClient: srv.Client(), StoreEndpoint: srv.URL, StoreAudience: "store.example"})
	if _, err := c.Retain(context.Background(), bytes.NewReader([]byte("payload")), clientDID, 7, contentaddress.Address{}); err == nil {
		t.Fatal("Retain with a zero content address: nil error, want a refusal")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests reached the server, want 0", n)
	}
}
