package vc_test

import (
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

func sampleSubject() vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID:          "p1",
		ProcessID:           "proc1",
		TransformationClaim: vc.ClaimConvert,
		InputHash:           "sha256:in",
		OutputHash:          "sha256:out",
	}
}

func TestBuilder_BuildFirstDrop_SignsAndVerifies(t *testing.T) {
	signer, pub, _ := fixture(t)
	b := vc.NewBuilder(signer)

	cred, err := b.BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	if cred.Proof() == nil {
		t.Fatal("built credential is unsigned (Proof() nil)")
	}
	if cred.PreviousCredential() != "" {
		t.Errorf("FirstDrop must carry no previousCredential, got %q", cred.PreviousCredential())
	}
	// The issued proof verifies against the issuer's public key.
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, cred.Proof(), cred.Body()); err != nil {
		t.Errorf("issued FirstDrop proof does not verify: %v", err)
	}
}

func TestBuilder_BuildChainPreserving_SignsAndLinks(t *testing.T) {
	signer, pub, _ := fixture(t)
	b := vc.NewBuilder(signer)

	previous, err := b.BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil)
	if err != nil {
		t.Fatalf("build predecessor: %v", err)
	}
	prevHash, _ := previous.Hash()

	cred, err := b.BuildChainPreserving(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), previous, nil)
	if err != nil {
		t.Fatalf("BuildChainPreserving: %v", err)
	}
	if cred.PreviousCredential() != prevHash {
		t.Errorf("previousCredential=%q, want predecessor hash %q", cred.PreviousCredential(), prevHash)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, cred.Proof(), cred.Body()); err != nil {
		t.Errorf("issued chain-preserving proof does not verify: %v", err)
	}
}

func TestBuilder_BuildChainPreserving_NilPredecessor(t *testing.T) {
	signer, _, _ := fixture(t)
	b := vc.NewBuilder(signer)
	if _, err := b.BuildChainPreserving(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil, nil); err == nil {
		t.Error("BuildChainPreserving(nil predecessor): want error")
	}
}

func TestBuilder_WithCryptosuite_Unregistered(t *testing.T) {
	signer, _, _ := fixture(t)
	b := vc.NewBuilder(signer, vc.WithCryptosuite("eddsa-rdfc-2022"))
	if _, err := b.BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil); err == nil {
		t.Error("building with an unregistered cryptosuite: want error")
	}
}

func TestBuilder_InvalidClaimRejected(t *testing.T) {
	signer, _, _ := fixture(t)
	b := vc.NewBuilder(signer)
	subject := sampleSubject()
	subject.TransformationClaim = "" // claim MUST: presence
	if _, err := b.BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, subject, nil); err == nil {
		t.Error("building with an absent transformationClaim: want error (claim MUST)")
	}
}

func TestBuilder_Commitment_AllConsumed(t *testing.T) {
	signer, _, _ := fixture(t)
	b := vc.NewBuilder(signer)

	const upstreamDID = "did:dplaax:poc.dplaax.dev:org:upstream:pipeline:p1:process:up"
	previous, err := vc.New(vc.CredentialFields{
		Issuer:    upstreamDID,
		ValidFrom: time.Now(),
		Subject:   sampleSubject(),
	})
	if err != nil {
		t.Fatalf("build predecessor: %v", err)
	}

	// A commitment omitting the predecessor's issuer is an emit-time misuse.
	bad := &vc.SourceCommitment{
		DerivedFrom:         []string{"did:dplaax:poc.dplaax.dev:org:someone-else"},
		SourceRoot:          "sha256:root",
		SourceRootCanonical: "f00",
	}
	if _, err := b.BuildChainPreserving(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), previous, bad); err == nil {
		t.Error("commitment omitting the predecessor's issuer: want error (all-consumed)")
	}

	// Including the predecessor's issuer is accepted.
	good := &vc.SourceCommitment{
		DerivedFrom:         []string{upstreamDID},
		SourceRoot:          "sha256:root",
		SourceRootCanonical: "f00",
	}
	if _, err := b.BuildChainPreserving(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), previous, good); err != nil {
		t.Errorf("commitment including the predecessor's issuer: unexpected error %v", err)
	}
}

// A signed credential survives a wire round-trip with its proof intact and
// still verifies.
func TestBuilder_RoundTripWire(t *testing.T) {
	signer, pub, _ := fixture(t)
	b := vc.NewBuilder(signer)

	cred, err := b.BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	wire, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON(wire); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	h1, _ := cred.Hash()
	h2, _ := rt.Hash()
	if h1 != h2 {
		t.Errorf("content address changed across round-trip: %q vs %q", h1, h2)
	}
	if rt.Proof() == nil {
		t.Fatal("proof lost across round-trip")
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, rt.Proof(), rt.Body()); err != nil {
		t.Errorf("round-tripped proof does not verify: %v", err)
	}
}
