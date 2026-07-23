package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/provin-line/oss/delegation"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/network/pkg/services/didregistry/handler"
)

func resolutionServer(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()
	svc, signer, pub := newSvc(t)
	if _, err := svc.RegisterOwner(ctx, mustUnmarshalDoc(t, signedOwnerDocBytes(t, signer, pub)), nil); err != nil {
		t.Fatalf("RegisterOwner: %v", err)
	}
	// Also issue a pipeline so the deeper segment-join path is exercised.
	dlg, err := mustDelegation(t, signer, pipelineDID)
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}
	if _, _, err := svc.IssuePipeline(ctx, pipelineDID, dlg, nil); err != nil {
		t.Fatalf("IssuePipeline: %v", err)
	}
	srv := httptest.NewServer(handler.NewResolutionHandler(svc, registry))
	t.Cleanup(srv.Close)
	return srv
}

func mustDelegation(t *testing.T, signer interface {
	Sign(did, keyID string, data []byte) ([]byte, error)
}, subject string) (*delegation.DelegationCredential, error) {
	t.Helper()
	return delegation.Build(signer, ownerDID, delegation.DelegationSubject{ID: subject, DelegatedBy: ownerDID})
}

func mustUnmarshalDoc(t *testing.T, b []byte) *did.DIDDocument {
	t.Helper()
	var doc did.DIDDocument
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal doc: %v", err)
	}
	return &doc
}

func TestResolution_RoundTrip(t *testing.T) {
	srv := resolutionServer(t)
	resp, err := http.Get(srv.URL + "/did/org/acme/did.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/did+json" {
		t.Errorf("content-type=%q, want application/did+json", ct)
	}
	var doc did.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.ID() != ownerDID {
		t.Errorf("resolved id=%q, want %q", doc.ID(), ownerDID)
	}
}

// A deeper DID (pipeline) exercises the multi-segment path join
// (/did/org/acme/pipeline/p1/did.json → :org:acme:pipeline:p1).
func TestResolution_Pipeline(t *testing.T) {
	srv := resolutionServer(t)
	resp, err := http.Get(srv.URL + "/did/org/acme/pipeline/p1/did.json")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var doc did.DIDDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID() != pipelineDID {
		t.Errorf("resolved id=%q, want %q", doc.ID(), pipelineDID)
	}
}

func TestResolution_NotFound(t *testing.T) {
	srv := resolutionServer(t)
	resp, err := http.Get(srv.URL + "/did/org/absent/did.json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("absent DID: status=%d, want 404", resp.StatusCode)
	}
}

func TestResolution_BadDID(t *testing.T) {
	srv := resolutionServer(t)
	// A traversal segment fails the did:dplaax safe-segment parse → 400.
	resp, err := http.Get(srv.URL + "/did/org/../did.json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// net/http may normalize "/org/../" — accept either a 400 (parsed, rejected)
	// or a 404 (path collapsed to a non-existent DID), but never a 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("traversal path returned 200, want rejection")
	}
}

func TestResolution_MethodNotAllowed(t *testing.T) {
	srv := resolutionServer(t)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/did/org/acme/did.json", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: status=%d, want 405", resp.StatusCode)
	}
}
