package vc_test

import (
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// provinDocument builds a real-shape provin credential body (the frozen
// 3-context wire form) without a proof — the document eddsa-rdfc-2022 must
// handle end to end.
func provinDocument(t *testing.T) map[string]any {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuerDID,
		ValidFrom: time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "proc1",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           "sha256:" + repeatHex("ab"),
			OutputHash:          "sha256:" + repeatHex("cd"),
		},
		PreviousCredential: "sha256:" + repeatHex("ef"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cred.Body()
}

func repeatHex(pair string) string {
	out := ""
	for i := 0; i < 32; i++ {
		out += pair
	}
	return out
}

// eddsa-rdfc-2022 signs and verifies a real provin credential — the suite is
// registered, canonicalizes through URDNA2015, and the proof round-trips.
func TestRDFC_CreateVerifyProof_RoundTrip(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)

	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof(eddsa-rdfc-2022): %v", err)
	}
	if proof.Cryptosuite != vc.CryptosuiteEdDSARDFC2022 {
		t.Errorf("proof.Cryptosuite = %q", proof.Cryptosuite)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err != nil {
		t.Errorf("VerifyProof on a genuine rdfc proof: %v", err)
	}
}

// The signature covers the proof configuration: tampering any typed proof
// field breaks verification (same shape as the JCS suite's guarantee).
func TestRDFC_VerifyProof_TamperedProofConfig(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *vc.DataIntegrityProof)
	}{
		{"created", func(p *vc.DataIntegrityProof) { p.Created = "2020-01-01T00:00:00Z" }},
		{"verificationMethod", func(p *vc.DataIntegrityProof) { p.VerificationMethod = issuerDID + "#other" }},
		{"proofPurpose", func(p *vc.DataIntegrityProof) { p.ProofPurpose = "authentication" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *proof
			tc.mutate(&tampered)
			if err := vc.VerifyProof(ed25519.Verifier{}, pub, &tampered, doc); err == nil {
				t.Error("VerifyProof must fail when a signed proof field is tampered")
			}
		})
	}
}

// Tampering the document body after signing breaks verification.
func TestRDFC_VerifyProof_TamperedDocument(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	doc["credentialSubject"].(map[string]any)["outputHash"] = "sha256:" + repeatHex("00")
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof must fail on a tampered document")
	}
}

// The H1 fail-closed defense is reachable through the public signing API: a
// document member no frozen context defines refuses to SIGN (it would ride
// the credential outside the signature), and the same shape refuses to
// VERIFY. Under eddsa-jcs-2022 the identical document signs fine — JCS signs
// every member, so the defense is RDFC-specific by design.
func TestRDFC_UndefinedMember_RefusedBothSides(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["smuggledField"] = "unsigned rider"

	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil {
		t.Error("CreateProof(rdfc) must refuse a member no frozen context defines")
	}

	jcsProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof(jcs) on the same document: %v", err)
	}
	rdfcShaped := *jcsProof
	rdfcShaped.Cryptosuite = vc.CryptosuiteEdDSARDFC2022
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, &rdfcShaped, doc); err == nil {
		t.Error("VerifyProof(rdfc) must refuse a member no frozen context defines")
	}
}

// The H3 fail-closed defense through the public API: a numeric member
// refuses to sign on the RDFC path.
func TestRDFC_NumericMember_Refused(t *testing.T) {
	signer, _, _ := fixture(t)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["schema"] = map[string]any{"version": float64(2)}
	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil {
		t.Error("CreateProof(rdfc) must refuse a numeric member")
	}
}
