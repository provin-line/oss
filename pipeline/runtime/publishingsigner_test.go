package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	vcresolverclient "github.com/provin-line/oss/network/pkg/services/vcresolver/client"
	"github.com/provin-line/oss/vc"
)

// fakeFullSigner returns a fixed credential for both sign methods, recording which
// was called.
type fakeFullSigner struct {
	cred         *vc.PipelinePassCredential
	firstDropHit int
	chainHit     int
	aggregateHit int
}

func (f *fakeFullSigner) SignFirstDrop(_ context.Context, _ []byte, _, _ string) (*vc.PipelinePassCredential, error) {
	f.firstDropHit++
	return f.cred, nil
}

func (f *fakeFullSigner) SignChainPreserving(_ context.Context, _ []byte, _, _ string, _ *vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	f.chainHit++
	return f.cred, nil
}

func (f *fakeFullSigner) SignAggregateFirstDrop(_ context.Context, _ []byte, _ string, _ []*vc.PipelinePassCredential) (*vc.PipelinePassCredential, error) {
	f.aggregateHit++
	return f.cred, nil
}

// fakePublisher records StoreCredential calls and returns a configurable result.
type fakePublisher struct {
	calls      int
	gotEnd     string
	retAddr    string // "" => echo the credential's own Hash()
	retVariant string // "" => echo the credential's own WireVariantID()
	retErr     error
}

func (p *fakePublisher) StoreCredential(_ context.Context, cred *vc.PipelinePassCredential, upstreamEndpoint string) (vcresolverclient.StoredCredential, error) {
	p.calls++
	p.gotEnd = upstreamEndpoint
	if p.retErr != nil {
		return vcresolverclient.StoredCredential{}, p.retErr
	}
	out := vcresolverclient.StoredCredential{BodyAddress: p.retAddr, WireVariantID: p.retVariant}
	if out.BodyAddress == "" {
		out.BodyAddress, _ = cred.Hash()
	}
	if out.WireVariantID == "" {
		out.WireVariantID, _ = cred.WireVariantID()
	}
	return out, nil
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

// An aggregate sign tees the issued credential to the store like the other paths, so
// an aggregate FirstDrop is published before emit (D-17k-6).
func TestPublishingSigner_AggregateFirstDrop_PublishesAndReturns(t *testing.T) {
	cred := testCred(t)
	inner := &fakeFullSigner{cred: cred}
	pub := &fakePublisher{}
	ps := &publishingSigner{inner: inner, publisher: pub}

	got, err := ps.SignAggregateFirstDrop(context.Background(), []byte("x"), "oh", nil)
	if err != nil {
		t.Fatalf("SignAggregateFirstDrop: %v", err)
	}
	if got != cred {
		t.Fatal("returned credential is not the signed one")
	}
	if inner.aggregateHit != 1 {
		t.Fatalf("inner aggregate calls = %d, want 1", inner.aggregateHit)
	}
	if pub.calls != 1 {
		t.Fatalf("StoreCredential calls = %d, want 1", pub.calls)
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

// TestPublishRejectsAStoreThatKeptADifferentSignedForm is the case the content
// address alone cannot see.
//
// The store returns the RIGHT body address — it holds the same claims — but a
// different variant: a different signed form of that body. The old check
// compared addresses and passed, so a store could hold a document other than
// the one that was signed while reporting success, which is exactly what this
// check exists to prevent.
func TestPublishRejectsAStoreThatKeptADifferentSignedForm(t *testing.T) {
	cred := publishTestCred(t)
	pub := &fakePublisher{
		// Body address echoed (retAddr == "" means "echo the credential's own"),
		// variant deliberately not the credential's.
		retVariant: vc.WireVariantIDFromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	err := publishIssuedCredential(context.Background(), pub, cred, "")
	if err == nil {
		t.Fatal("publish accepted a store holding a different signed form of the body")
	}
	if !strings.Contains(err.Error(), "variant") {
		t.Errorf("the error does not name what disagreed: %v", err)
	}
}

// TestPublishAcceptsAFaithfulStore: the happy path still passes, so the check
// above is not simply refusing everything.
func TestPublishAcceptsAFaithfulStore(t *testing.T) {
	cred := publishTestCred(t)
	if err := publishIssuedCredential(context.Background(), &fakePublisher{}, cred, ""); err != nil {
		t.Fatalf("publish rejected a faithful store: %v", err)
	}
}

func publishTestCred(t *testing.T) *vc.PipelinePassCredential {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:s1",
		"credentialSubject": map[string]any{"pipelineId": "p1", "processId": "s1"},
		"proof": map[string]any{
			"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
			"verificationMethod": "did:dplaax:poc.dplaax.dev:org:acme#signing",
			"proofPurpose":       "assertionMethod", "created": "2026-07-01T00:00:01Z",
			"proofValue": "zA",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return &c
}
