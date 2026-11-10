package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	ksfilestore "github.com/provin-line/oss/keystore/filestore"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/payloadresolver/client"
)

func TestResolvePayloadProofNamesUpstreamAudience(t *testing.T) {
	fake := &fakeServer{frames: [][]byte{[]byte("ab")}}
	c, url := newClient(t, fake, 0)
	if _, err := c.ResolvePayload(context.Background(), url, "upstream.example", fetchTestHash); err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if fake.gotAudience != "upstream.example" {
		t.Errorf("the proof names %q, want %q", fake.gotAudience, "upstream.example")
	}
}

func TestResolvePayloadWithoutAudienceFailsBeforeSending(t *testing.T) {
	fake := &fakeServer{frames: [][]byte{[]byte("ab")}}
	c, url := newClient(t, fake, 0)
	if _, err := c.ResolvePayload(context.Background(), url, "", fetchTestHash); !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no audience: %v, want ErrMalformedProof", err)
	}
	if fake.calls != 0 {
		t.Errorf("no audience: %d requests reached the server, want 0", fake.calls)
	}
}

func TestRetainWithoutStoreAudienceFailsBeforeSending(t *testing.T) {
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
	c := client.New(client.Config{Signer: ks, SignerDID: clientDID, HTTPClient: srv.Client(), StoreEndpoint: srv.URL})
	if _, err := c.Retain(context.Background(), bytes.NewReader([]byte("payload")), clientDID, 7); !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no store audience: %v, want ErrMalformedProof", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("no store audience: %d requests reached the server, want 0", n)
	}
}
