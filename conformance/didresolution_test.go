// The did-resolution family: auth.resolve.* vectors driven against the real
// outbound resolver (network/pkg/didresolver — the cross-registry HTTP client
// wireauth and chainmanager consume). The rules primarily bind the L1 grant
// path's resolver (provin-line/auth, whose conformance harness runs the same
// vectors); this repo's resolver makes the same verdicts at its own seam, so
// the vectors drive it too — a second implementation surface, pinned to the
// same bytes.
//
// Each vector serves its registry_response verbatim from an httptest server
// and asserts the error classification its expect block names:
//
//	FAILED / id-mismatch: resolution errors with the distinct
//	  ErrDIDIdentityMismatch class and the document is never honoured. The
//	  vector's FAILED verdict binds the L1 grant resolver (no token may
//	  mint); in THIS repo only a registry 404 (resolver.ErrNotFound) is a
//	  definitive absence — the confidence layer deliberately classifies an
//	  identity mismatch indeterminate, never verified (didresolver.go's
//	  error-taxonomy note). The driver asserts the error class at the
//	  resolver seam, not a downstream verdict.
//	INDETERMINATE / registry-5xx: transient — neither resolver.ErrNotFound
//	  (definitive absence) nor an identity verdict; the consumer retries
//	  rather than concluding.
package conformance_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/provin-line/oss/network/pkg/core"
	"github.com/provin-line/oss/network/pkg/didresolver"
	"github.com/provin-line/oss/resolver"
)

func runDidResolutionHTTP(t *testing.T, v dplaaxVector) {
	var input struct {
		DID              string `json:"did"`
		RegistryResponse struct {
			Status int             `json:"status"`
			Body   json.RawMessage `json:"body"`
		} `json:"registry_response"`
	}
	mustParse(t, v.Input, &input)
	var expect struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	}
	mustParse(t, v.Expect, &expect)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		w.WriteHeader(input.RegistryResponse.Status)
		w.Write(input.RegistryResponse.Body)
	}))
	t.Cleanup(srv.Close)

	r := didresolver.New(core.NewURLGuard(core.WithAllowLoopback(true)),
		didresolver.WithRegistryBaseURL(func(string) (string, error) { return srv.URL, nil }))
	_, err := r.Resolve(context.Background(), input.DID)
	if err == nil {
		t.Fatalf("%s: resolution succeeded, want %s (%s)", v.ID, expect.Result, expect.Reason)
	}
	switch expect.Reason {
	case "id-mismatch":
		if expect.Result != "FAILED" {
			t.Fatalf("%s: expect.result = %q for id-mismatch, want FAILED (vector shape changed?)", v.ID, expect.Result)
		}
		if !errors.Is(err, didresolver.ErrDIDIdentityMismatch) {
			t.Errorf("%s: err = %v, want ErrDIDIdentityMismatch", v.ID, err)
		}
	case "registry-5xx":
		if expect.Result != "INDETERMINATE" {
			t.Fatalf("%s: expect.result = %q for registry-5xx, want INDETERMINATE (vector shape changed?)", v.ID, expect.Result)
		}
		// INDETERMINATE means the failure must carry the typed transient
		// class (wireauth maps it to a retryable code — the production
		// classifier's contract, pinned by TestVerify_TransientResolverError)
		// and must not be mistaken for a definitive verdict of either kind.
		if !errors.Is(err, didresolver.ErrRegistryUnavailable) {
			t.Errorf("%s: 5xx err = %v, want ErrRegistryUnavailable (typed transient)", v.ID, err)
		}
		if errors.Is(err, resolver.ErrNotFound) {
			t.Errorf("%s: 5xx classified as definitive not-found: %v", v.ID, err)
		}
		if errors.Is(err, didresolver.ErrDIDIdentityMismatch) {
			t.Errorf("%s: 5xx classified as identity mismatch: %v", v.ID, err)
		}
	default:
		t.Fatalf("%s: unhandled expect.reason %q", v.ID, expect.Reason)
	}
}
