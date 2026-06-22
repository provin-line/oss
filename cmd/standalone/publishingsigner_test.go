package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/provin-line/oss/vc"
)

// fakeFullSigner returns a fixed credential for both sign methods, recording which
// was called.
type fakeFullSigner struct {
	cred         *vc.PipelinePassCredential
	firstDropHit int
	chainHit     int
}

func (f *fakeFullSigner) SignFirstDrop(_ context.Context, _ []byte, _, _ string) (*vc.PipelinePassCredential, error) {
	f.firstDropHit++
	return f.cred, nil
}

func (f *fakeFullSigner) SignChainPreserving(_ context.Context, _ []byte, _, _ string, _ *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	f.chainHit++
	return f.cred, nil
}

// fakePublisher records StoreCredential calls and returns a configurable result.
type fakePublisher struct {
	calls   int
	gotEnd  string
	retAddr string // "" => echo the credential's own Hash()
	retErr  error
}

func (p *fakePublisher) StoreCredential(_ context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (string, error) {
	p.calls++
	p.gotEnd = upstreamEndpoint
	if p.retErr != nil {
		return "", p.retErr
	}
	if p.retAddr != "" {
		return p.retAddr, nil
	}
	h, _ := cred.Hash()
	return h, nil
}

func testCred(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:reg:org:acme:pipeline:pipe:process:src",
		"credentialSubject": map[string]any{"pipelineId": "pipe", "processId": "src"},
	})
	var c vc.PipelinePassCredential
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

// A successful publish: SignFirstDrop tees the credential to the store with the
// configured upstream hint and returns the signed credential unchanged.
func TestPublishingSigner_FirstDrop_PublishesAndReturns(t *testing.T) {
	cred := testCred(t)
	inner := &fakeFullSigner{cred: cred}
	pub := &fakePublisher{}
	ps := &publishingSigner{inner: inner, publisher: pub, upstreamEndpoint: ""}

	got, err := ps.SignFirstDrop(context.Background(), []byte("x"), "ih", "oh")
	if err != nil {
		t.Fatalf("SignFirstDrop: %v", err)
	}
	if got != cred {
		t.Fatal("returned credential is not the signed one")
	}
	if pub.calls != 1 {
		t.Fatalf("StoreCredential calls = %d, want 1", pub.calls)
	}
}

// A chained sign passes the loop's upstream endpoint as the predecessor-fetch hint.
func TestPublishingSigner_ChainPreserving_PassesUpstreamHint(t *testing.T) {
	cred := testCred(t)
	inner := &fakeFullSigner{cred: cred}
	pub := &fakePublisher{}
	ps := &publishingSigner{inner: inner, publisher: pub, upstreamEndpoint: "https://up.example/"}

	if _, err := ps.SignChainPreserving(context.Background(), []byte("x"), "ih", "oh", nil); err != nil {
		t.Fatalf("SignChainPreserving: %v", err)
	}
	if pub.gotEnd != "https://up.example/" {
		t.Fatalf("upstream hint = %q, want %q", pub.gotEnd, "https://up.example/")
	}
}

// Fail-closed: a StoreCredential transport error fails the sign (the event is dropped
// before NATS emit by the processor->transport contract).
func TestPublishingSigner_PublishError_FailsClosed(t *testing.T) {
	inner := &fakeFullSigner{cred: testCred(t)}
	pub := &fakePublisher{retErr: errors.New("store down")}
	ps := &publishingSigner{inner: inner, publisher: pub}

	if _, err := ps.SignFirstDrop(context.Background(), []byte("x"), "ih", "oh"); err == nil {
		t.Fatal("publish error: want sign to fail closed, got nil")
	}
}

// Fail-closed: a server-returned content address that differs from the credential's
// own Hash() means the store did not store what was signed — fail the sign.
func TestPublishingSigner_HashMismatch_FailsClosed(t *testing.T) {
	inner := &fakeFullSigner{cred: testCred(t)}
	pub := &fakePublisher{retAddr: "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"}
	ps := &publishingSigner{inner: inner, publisher: pub}

	if _, err := ps.SignFirstDrop(context.Background(), []byte("x"), "ih", "oh"); err == nil {
		t.Fatal("hash mismatch: want sign to fail closed, got nil")
	}
}
