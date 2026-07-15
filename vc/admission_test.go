package vc_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// New artifacts pass the safe-number gate before they are signed
// (canon.number.safe-integer). The gate lives on the CREATE side only: an
// artifact carrying an unsafe integer is exactly what the int64-verbatim
// projection exists to verify, so gating the verify path would break the legacy
// contract it is meant to preserve.

func TestCreateProof_RefusesToSignUnsafeIntegers(t *testing.T) {
	// Signing an unsafe integer mints an artifact that a strict-ES6 verifier
	// (any TypeScript one) canonicalizes differently — the signature forks
	// across implementations. The honest moment to fail is before the signature
	// exists, not when a peer cannot reproduce it.
	signer, _, doc := fixture(t)
	doc["credentialSubject"].(map[string]any)["count"] = json.Number("9007199254740993")

	_, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err == nil {
		t.Fatal("CreateProof signed an artifact carrying an unsafe integer")
	}
	var unsafeErr *canon.UnsafeNumberError
	if !errors.As(err, &unsafeErr) {
		t.Errorf("error is not *canon.UnsafeNumberError: %T (%v)", err, err)
	}
}

func TestCreateProof_RefusesUnsafeIntegersInAnySpelling(t *testing.T) {
	// The gate keys on the value, not the spelling: an issuer cannot slip an
	// unsafe integer past it by writing it as an exponent or with a .0 tail.
	for _, lit := range []string{"1e30", "9007199254740993e0", "9007199254740992.0", "-9007199254740993"} {
		signer, _, doc := fixture(t)
		doc["n"] = json.Number(lit)
		if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022); err == nil {
			t.Errorf("CreateProof signed %s", lit)
		}
	}
}

func TestCreateProof_SignsSafeDocuments(t *testing.T) {
	// The gate must not become a tax on ordinary artifacts: real bodies are
	// numeric-free or safe-range, and they sign as before.
	for _, extra := range []map[string]any{
		nil,
		{"n": json.Number("9007199254740991")},
		{"v": 1},
		{"f": json.Number("4.50")},
		{"neg": json.Number("-9007199254740991")},
	} {
		signer, _, doc := fixture(t)
		for k, v := range extra {
			doc[k] = v
		}
		if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022); err != nil {
			t.Errorf("CreateProof rejected a safe document %v: %v", extra, err)
		}
	}
}

func TestVerifyProof_DoesNotApplyTheAdmissionGate(t *testing.T) {
	// Verification of an unsafe-integer document must fail (if at all) on the
	// signature, never on admission: legacy artifacts legitimately carry
	// integers above 2^53, and the int64-verbatim projection exists to verify
	// exactly them. An UnsafeNumberError here would mean the create-side gate
	// leaked onto the verify side and made historical evidence unverifiable.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	doc["n"] = json.Number("9007199254740993") // mutate after signing

	err = vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc)
	if err == nil {
		t.Fatal("expected the mutated document to fail verification")
	}
	var unsafeErr *canon.UnsafeNumberError
	if errors.As(err, &unsafeErr) {
		t.Errorf("verify path applied the admission gate: %v", err)
	}
}
