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

	auditclient "github.com/provin-line/oss/network/pkg/services/auditor/client"
	"github.com/provin-line/oss/network/pkg/wireauth"
)

// The proof names the configured audience: the harness's verifier refuses a
// client configured for another audience before the head is looked up.
func TestProofNamesConfiguredAudience(t *testing.T) {
	h := newHarness(t)
	if err := h.client.RegisterAuditHead(context.Background(), variantAddr("9")); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("configured for the verifier's audience: %v, want the admission check's FailedPrecondition", err)
	}
	other := auditclient.New(auditclient.Config{
		Audience: "other.example", Signer: h.signer, SignerDID: nodeDID, BaseURL: h.url, HTTPClient: h.httpc,
	})
	err := other.RegisterAuditHead(context.Background(), variantAddr("9"))
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
	sgn, _ := signer(t, nodeDID)
	c := auditclient.New(auditclient.Config{Signer: sgn, SignerDID: nodeDID, BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err := c.RegisterAuditHead(context.Background(), variantAddr("9")); !errors.Is(err, wireauth.ErrMalformedProof) {
		t.Fatalf("no audience: %v, want ErrMalformedProof", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("no audience: %d requests reached the server, want 0", n)
	}
}
