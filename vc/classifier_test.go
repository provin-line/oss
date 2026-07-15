package vc_test

import (
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// One suite identifier, two contracts. eddsa-jcs-2022 means the W3C shape
// (proof-local @context + Multikey + jcs-rfc8785); the same identifier over the
// six-member proof and a JWK key is what provin issued before Fork W, and it
// canonicalizes with the int64-verbatim deviation. Same name, different bytes —
// the hazard P0-4 called Critical.
//
// ClassifyProof is the whole defense: it reads the suite id, then the raw proof
// shape, then the key encoding, and every combination outside the two known
// contracts fails. It never tries a canonicalizer to see if the signature
// happens to check out — that would make the signature an oracle for "which
// contract is this?", which is exactly the algorithm-guessing the exact-dispatch
// rule forbids.

func TestClassifyProof_Matrix(t *testing.T) {
	tests := []struct {
		name       string
		suite      string
		hasContext bool
		encoding   did.KeyEncoding
		want       vc.SuiteContract
		wantErr    bool
	}{
		{
			name:  "W3C: context + Multikey",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: true, encoding: did.EncodingMultikey,
			want: vc.ContractW3CEdDSAJCS2022,
		},
		{
			name:  "legacy: no context + JWK",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: false, encoding: did.EncodingJWK,
			want: vc.ContractLegacyProvinEdDSAJCSInt64,
		},
		{
			// A W3C-shaped proof over a JWK key names a contract it does not
			// satisfy: the suite requires Multikey.
			name:  "mismatch: context + JWK",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: true, encoding: did.EncodingJWK,
			wantErr: true,
		},
		{
			// A Multikey key does not upgrade a six-member proof. Accepting this
			// would let a pre-cutover proof be read as W3C-conformant the moment
			// its DID document was re-issued with a Multikey — promoting evidence
			// on the strength of a change made after it was signed.
			name:  "mismatch: no context + Multikey",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: false, encoding: did.EncodingMultikey,
			wantErr: true,
		},
		{
			name:  "unknown suite fails closed",
			suite: "eddsa-2022-totally-real", hasContext: true, encoding: did.EncodingMultikey,
			wantErr: true,
		},
		{
			name:  "empty suite fails closed",
			suite: "", hasContext: false, encoding: did.EncodingJWK,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vc.ClassifyProof(tc.suite, tc.hasContext, tc.encoding)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ClassifyProof accepted an unlisted combination, returning %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyProof: %v", err)
			}
			if got != tc.want {
				t.Errorf("contract = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSuiteContract_CanonicalizerBinding(t *testing.T) {
	// A contract names its canonicalizer; the two are not chosen independently.
	// This is the binding that stops the same suite identifier from meaning two
	// different byte streams depending on which reader looked.
	if got := vc.ContractW3CEdDSAJCS2022.CanonicalizerID(); got != "jcs-rfc8785" {
		t.Errorf("W3C contract canonicalizer = %q, want jcs-rfc8785", got)
	}
	if got := vc.ContractLegacyProvinEdDSAJCSInt64.CanonicalizerID(); got != "jcs" {
		t.Errorf("legacy contract canonicalizer = %q, want jcs (int64-verbatim)", got)
	}
}

func TestSuiteContract_IDsAreTheCatalogNames(t *testing.T) {
	// These strings reach consumers as claim contract ids (claims.suite.contract-id).
	// They are frozen by the scope catalog, so a rename here is a protocol change.
	if got := string(vc.ContractW3CEdDSAJCS2022); got != "W3C_EDDSA_JCS_2022_REC_20250515@1" {
		t.Errorf("W3C contract id = %q", got)
	}
	if got := string(vc.ContractLegacyProvinEdDSAJCSInt64); got != "LEGACY_PROVIN_EDDSA_JCS_INT64@1" {
		t.Errorf("legacy contract id = %q", got)
	}
}

func TestVerify_LegacyMultikeyProofIsNotPromoted(t *testing.T) {
	// The dispatch has to be wired into verification, not merely available: a
	// six-member proof whose issuer document now carries a Multikey must not
	// verify as W3C. Before the classifier, the key encoding alone decided the
	// canonicalizer, so re-issuing a DID document could silently reclassify old
	// evidence.
	if _, err := vc.ClassifyProof(vc.CryptosuiteEdDSAJCS2022, false, did.EncodingMultikey); err == nil {
		t.Fatal("classifier accepts the promotion shape")
	}
}

func TestVerifyProofWithContract_RejectsSwappedProofContext(t *testing.T) {
	// The wire proof.@context is the one member this verify path's signature
	// reconstruction does not cover (the config is rebuilt from the DOCUMENT's
	// context). Without the mirror check, provin would accept an artifact whose
	// proof.@context was swapped after signing — while a W3C verifier, which
	// canonicalizes the wire proof options as-is, would reject it. Same bytes,
	// two verdicts: the interop failure Fork W exists to end.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	proof.Context = []any{"https://attacker.example/context/v2"}

	// Multikey encoding puts this on the W3C row, where the mirror is enforced.
	if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, proof, doc); err == nil {
		t.Error("a swapped wire proof.@context was accepted — the member is malleable on this verify path")
	}
}
