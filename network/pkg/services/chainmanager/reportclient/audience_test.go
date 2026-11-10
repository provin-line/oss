package reportclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	"github.com/provin-line/oss/network/pkg/services/chainmanager/reportclient"
	"github.com/provin-line/oss/network/pkg/services/chainmanager/wireauth"
)

// The proof names the configured audience: the harness's verifier accepts a
// client configured with its audience and refuses one configured with another.
func TestProofNamesConfiguredAudience(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.ReportEmitHealth(context.Background(), publisherDID, true); err != nil {
		t.Fatalf("configured for the verifier's audience: %v", err)
	}
	other := reportclient.New(reportclient.Config{
		Audience: "other.example", Signer: h.signer, SignerDID: publisherDID, BaseURL: h.url, HTTPClient: http.DefaultClient,
	})
	_, err := other.ReportEmitHealth(context.Background(), publisherDID, true)
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("configured for another audience: %v (code %v), want Unauthenticated naming the audience", err, connect.CodeOf(err))
	}
}

func TestMissingAudienceFailsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	sgn, _ := signer(t, publisherDID)
	c := reportclient.New(reportclient.Config{Signer: sgn, SignerDID: publisherDID, BaseURL: srv.URL, HTTPClient: srv.Client()})
	if _, err := c.ReportEmitHealth(context.Background(), publisherDID, true); !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no audience: %v, want ErrMalformedProof", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("no audience: %d requests reached the server, want 0", n)
	}
}
