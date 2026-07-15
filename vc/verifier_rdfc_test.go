package vc_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// The regression both ForkW-1 reviewers converged on: wiring the exact
// classifier into the Verifier rejected every eddsa-rdfc-2022 credential,
// because the dispatch knew only the jcs contracts. No test caught it — every
// rdfc test called VerifyProof directly and never drove the production
// Verifier. This one does.
func TestVerify_RDFCCredential_VerifiesWithItsOwnContract(t *testing.T) {
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	cred, err := vc.NewBuilder(ks, vc.WithCryptosuite(vc.CryptosuiteEdDSARDFC2022)).BuildFirstDrop(
		issuerDID, string(keystore.KeyIDSigning), vmID,
		vc.CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "proc1",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           "sha256:" + repeatHex("ab"),
			OutputHash:          "sha256:" + repeatHex("cd"),
		}, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop(rdfc): %v", err)
	}

	r := local.New()
	r.Add(didDoc(issuerDID, ownerDID, vmID, kp.PublicKey))
	r.Add(didDoc(ownerDID, ownerDID, "", nil))
	v := vc.NewVerifier(r, ed25519.Verifier{})

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Fatalf("SignerAuthenticity = %v, want Verified — the rdfc suite must survive the exact dispatch", res.Axes.SignerAuthenticity)
	}
	if res.SuiteContract != vc.ContractW3CEdDSARDFC2022 {
		t.Errorf("SuiteContract = %q, want %q", res.SuiteContract, vc.ContractW3CEdDSARDFC2022)
	}
}
