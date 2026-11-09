package vc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/internal/jsondepth"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

func deepArrays(depth int) any {
	var v any = "x"
	for i := range depth {
		if i%2 == 0 {
			v = []any{v}
		} else {
			v = map[string]any{"k": v}
		}
	}
	return v
}

// A document built in Go two million objects and arrays deep, far past
// what encoding/json decodes, is refused rather than exhausting the goroutine
// stack in the walks that run before a suite canonicalizes it: CreateProof
// admits its numbers first, and the verify functions canonicalize the proof's
// and the document's @context to compare them.
func TestProofs_RefuseADocumentNestedPastTheBound(t *testing.T) {
	signer, pub, _ := fixture(t)
	deep := deepArrays(2000000)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["evidence"] = deep
	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("CreateProof: %v, want the nesting refused", err)
	}
	ctx := []any{"https://www.w3.org/ns/credentials/v2", deep}
	shallow := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, shallow, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatal(err)
	}
	deepDoc := provinDocument(t)
	deepDoc["@context"] = ctx
	proof.Context = ctx
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, deepDoc); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("VerifyProof: %v, want the nesting refused", err)
	}
	if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, proof, deepDoc); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("VerifyProofWithContract: %v, want the nesting refused", err)
	}
	if err := vc.VerifyProofUnderContract(ed25519.Verifier{}, pub, proof, deepDoc, vc.ContractW3CEdDSAJCS2022); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("VerifyProofUnderContract: %v, want the nesting refused", err)
	}
	// The deep value in the body, the @context as the proof's: the suite's
	// canonicalization refuses it.
	bodyProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, provinDocument(t), vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatal(err)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, bodyProof, doc); err == nil || !strings.Contains(err.Error(), "nested deeper than") {
		t.Errorf("VerifyProof, the body deep: %v, want the nesting refused", err)
	}
}

// Under eddsa-rdfc-2022, CreateProof refuses a document nested past the bound
// at its number check, before the suite canonicalizes it: the error is
// canon's, and does not wrap urdna2015.ErrTooComplex, which the suite's
// canonicalization wraps.
func TestCreateProof_RefusesNestingAtTheNumberCheckUnderRDFC(t *testing.T) {
	signer, _, _ := fixture(t)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["evidence"] = deepArrays(jsondepth.Max)
	_, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err == nil || !strings.HasPrefix(err.Error(), "canon: value nested deeper than") || errors.Is(err, urdna2015.ErrTooComplex) {
		t.Errorf("CreateProof: %v, want canon's refusal of the nesting", err)
	}
}
