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

// Wiring the exact classifier into the Verifier must not reject
// eddsa-rdfc-2022 credentials: the dispatch has to know the rdfc contract as
// well as the jcs contracts. Tests that call VerifyProof directly never drive
// the production Verifier; this one does.
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
