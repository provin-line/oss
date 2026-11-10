package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
	"github.com/provin-line/oss/network/pkg/services/tlogservice/client"
)

// The proof names the configured audience: the harness's verifier accepts a
// client configured with its audience and refuses one configured with another.
func TestProofNamesConfiguredAudience(t *testing.T) {
	h := newHarness(t, 256, 4<<20)
	ctx := context.Background()
	seg := recPayloads(1)
	cp := h.appendAndCheckpoint(t, ctx, seg)
	other := client.New(client.Config{
		Audience: "other.example", Signer: h.signer, SignerDID: clientProcessA1, BaseURL: h.url, HTTPClient: http.DefaultClient,
	})
	_, err := other.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp)
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("configured for another audience: %v (code %v), want Unauthenticated naming the audience", err, connect.CodeOf(err))
	}
	if _, err := h.client.MirrorLogSegment(ctx, clientPipeline, 0, seg, cp); err != nil {
		t.Fatalf("configured for the verifier's audience: %v", err)
	}
}

func TestMissingAudienceFailsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	h := newHarness(t, 256, 4<<20)
	seg := recPayloads(1)
	cp := h.appendAndCheckpoint(t, context.Background(), seg)
	c := client.New(client.Config{Signer: h.signer, SignerDID: clientProcessA1, BaseURL: srv.URL, HTTPClient: srv.Client()})
	_, err := c.MirrorLogSegment(context.Background(), clientPipeline, 0, seg, cp)
	if !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no audience: %v, want ErrMalformedProof", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("no audience: %d requests reached the server, want 0", n)
	}
}
