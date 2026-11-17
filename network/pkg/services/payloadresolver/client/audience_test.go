package client_test

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// A fetch's proof names the audience Config.UpstreamAudiences gives its
// endpoint.
func TestResolvePayloadProofNamesUpstreamAudience(t *testing.T) {
	fake := &fakeServer{frames: [][]byte{[]byte("ab")}}
	c, url := newClient(t, fake, 0)
	if _, err := c.ResolvePayload(context.Background(), url, fetchTestHash); err != nil {
		t.Fatalf("ResolvePayload: %v", err)
	}
	if fake.gotAudience != upstreamAudience {
		t.Errorf("the proof names %q, want %q", fake.gotAudience, upstreamAudience)
	}
}

// The client fetches nothing from an endpoint whose audience it does not
// know: one not in Config.UpstreamAudiences, or given there no audience. It
// fails with ErrUnknownUpstream before anything is sent.
func TestResolvePayloadFromAnEndpointWithoutAudienceFailsBeforeSending(t *testing.T) {
	fake := &fakeServer{frames: [][]byte{[]byte("ab")}}
	_, url := newClient(t, fake, 0)
	for name, audiences := range map[string]map[string]string{
		"not in the map": {"http://other.example": upstreamAudience},
		"no audience":    {url: ""},
		"an empty map":   {},
	} {
		c, _ := newClientCfg(t, fake, client.Config{UpstreamAudiences: audiences})
		if _, err := c.ResolvePayload(context.Background(), url, fetchTestHash); !errors.Is(err, client.ErrUnknownUpstream) {
			t.Errorf("%s: %v, want ErrUnknownUpstream", name, err)
		}
	}
	if fake.calls != 0 {
		t.Errorf("%d requests reached the server, want 0", fake.calls)
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
	if _, err := c.Retain(context.Background(), bytes.NewReader([]byte("payload")), clientDID, 7, contentaddress.Of([]byte("payload"))); !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no store audience: %v, want ErrMalformedProof", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("no store audience: %d requests reached the server, want 0", n)
	}
}
