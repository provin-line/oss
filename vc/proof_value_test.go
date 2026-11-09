package vc_test

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// A proofValue that does not decode is refused before the document is
// canonicalized. The document here does not canonicalize either, so the
// error tells which check ran first.
func TestVerifyProof_DecodesProofValueBeforeCanonicalizing(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	// RDFC refuses a numeric member when it canonicalizes.
	doc["credentialSubject"].(map[string]any)["schema"] = map[string]any{"version": float64(2)}
	bad := *proof
	bad.ProofValue = "not base58btc"

	entryPoints := []struct {
		name   string
		verify func(*vc.DataIntegrityProof) error
	}{
		{"VerifyProof", func(p *vc.DataIntegrityProof) error {
			return vc.VerifyProof(ed25519.Verifier{}, pub, p, doc)
		}},
		{"VerifyProofWithContract", func(p *vc.DataIntegrityProof) error {
			_, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, p, doc)
			return err
		}},
		{"VerifyProofUnderContract", func(p *vc.DataIntegrityProof) error {
			return vc.VerifyProofUnderContract(ed25519.Verifier{}, pub, p, doc, vc.ContractW3CEdDSARDFC2022)
		}},
	}
	const canonicalize = "vc: canonicalize document: "
	const decode = "vc: decode proofValue: "
	for _, ep := range entryPoints {
		// With the genuine proofValue, the document is what each refuses.
		if err := ep.verify(proof); err == nil || !strings.HasPrefix(err.Error(), canonicalize) {
			t.Fatalf("%s with the genuine proofValue: err = %v, want %q", ep.name, err, canonicalize)
		}
		if err := ep.verify(&bad); err == nil || !strings.HasPrefix(err.Error(), decode) {
			t.Errorf("%s: err = %v, want %q first", ep.name, err, decode)
		}
	}
}

// An undecodable proofValue costs what reading it costs, not a
// canonicalization of its document.
func BenchmarkVerifyProof_UndecodableProofValue(b *testing.B) {
	signer, pub, _ := fixture(b)
	doc := provinDocument(b)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		b.Fatal(err)
	}
	bad := *proof
	bad.ProofValue = "not base58btc"
	for b.Loop() {
		if err := vc.VerifyProof(ed25519.Verifier{}, pub, &bad, doc); err == nil {
			b.Fatal("an undecodable proofValue verified")
		}
	}
}
