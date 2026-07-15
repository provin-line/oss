package vc

import (
	stded25519 "crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
	ed25519lib "github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/multibase"
)

// What we ISSUE under eddsa-jcs-2022 must be canonicalized by the
// canonicalizer that suite names. This is unobservable from outside — the
// admission gate rejects the only inputs on which the two canonicalizers
// disagree, so every signable document produces identical bytes either way —
// which is exactly why it needs pinning here. An artifact that claims W3C
// conformance while being canonicalized under the int64-verbatim deviation is
// the same-name-different-bytes hazard, just latent.
func TestIssuanceSuiteUsesRFC8785(t *testing.T) {
	c, err := canonicalizerFor(CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("canonicalizerFor(%s): %v", CryptosuiteEdDSAJCS2022, err)
	}
	if got := c.Name(); got != jcs.NameRFC8785 {
		t.Errorf("issuance canonicalizer = %q, want %q — a W3C-shaped proof signed with the legacy deviation claims a conformance it does not have",
			got, jcs.NameRFC8785)
	}
}

// The legacy contract keeps its own canonicalizer, reached through the contract
// rather than the registry: the registry answers "what do we issue?", the
// contract answers "what was this signed under?". Collapsing the two would make
// old evidence unverifiable the moment issuance moved on.
func TestLegacyContractKeepsTheDeviation(t *testing.T) {
	c, err := ContractLegacyProvinEdDSAJCSInt64.canonicalizer()
	if err != nil {
		t.Fatalf("legacy contract canonicalizer: %v", err)
	}
	got, err := c(map[string]any{"n": json.Number("9007199254740993")})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(got) != `{"n":9007199254740993}` {
		t.Errorf("legacy contract lost the int64-verbatim deviation: %s", got)
	}
}

// The legacy contract's reason to exist, exercised end to end over a document
// where the two canonicalizers actually DISAGREE. Every other legacy test in
// the suite uses numeric-free bodies, where int64-verbatim and RFC 8785 emit
// identical bytes — meaning the one property legacy preservation is FOR was
// never checked. This signs a >2^53 document the way a pre-Fork-W issuer did
// and pins both directions of the divergence.
func TestLegacyContract_VerifiesADocumentTheSuitesDisagreeOn(t *testing.T) {
	kp, err := (ed25519lib.Generator{}).Generate()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	doc := map[string]any{
		"id": "urn:uuid:legacy-big-int",
		"n":  json.Number("9007199254740993"),
	}
	created := "2026-01-01T00:00:00Z"
	vm := "did:dplaax:o:p#signing"
	cfg := proofConfigMap(proofType, CryptosuiteEdDSAJCS2022, vm, proofPurposeSign, created, nil, false)
	hd, err := proofHashData(jcs.Canonicalizer{}, cfg, doc)
	if err != nil {
		t.Fatalf("legacy hashData: %v", err)
	}
	sig := stded25519.Sign(stded25519.NewKeyFromSeed(kp.PrivateKey[:32]), hd)
	proof := &DataIntegrityProof{
		Type:               proofType,
		Cryptosuite:        CryptosuiteEdDSAJCS2022,
		VerificationMethod: vm,
		ProofPurpose:       proofPurposeSign,
		Created:            created,
		ProofValue:         multibase.EncodeBase58Btc(sig),
	}

	if err := VerifyProofUnderContract(ed25519lib.Verifier{}, kp.PublicKey, proof, doc, ContractLegacyProvinEdDSAJCSInt64); err != nil {
		t.Errorf("legacy contract rejected a genuine legacy artifact: %v", err)
	}
	if err := VerifyProofUnderContract(ed25519lib.Verifier{}, kp.PublicKey, proof, doc, ContractW3CEdDSAJCS2022); err == nil {
		t.Error("the W3C contract verified an int64-verbatim signature — the two canonicalizations did not diverge where they must")
	}
}
