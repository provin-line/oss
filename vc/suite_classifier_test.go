package vc_test

import (
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// Fork W makes eddsa-jcs-2022 mean what W3C says it means: jcs-rfc8785
// canonicalization, Multikey verification methods, and a proof-local @context
// copied from the document (vc-di-eddsa §3.3.1 step 2, Example 39). The legacy
// artifacts provin already issued use the same suite identifier with a
// six-member proof and a JWK key — the same name over different bytes.
//
// The classifier is what keeps those two apart. It reads the suite id, then the
// raw proof shape, then the verification method's encoding, and every
// combination outside the two known contracts fails. No fallback, no try-all:
// an implementation that retried the other canonicalizer on a signature failure
// would turn "which contract is this?" into an oracle.

func TestCreateProof_W3CShapeCarriesProofLocalContext(t *testing.T) {
	// §3.3.1 step 2: the proof's @context is the document's @context. A proof
	// without it is not eddsa-jcs-2022, whatever its cryptosuite member says.
	signer, _, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal proof: %v", err)
	}
	got, present := m["@context"]
	if !present {
		t.Fatalf("wire proof carries no @context: %s", raw)
	}
	want := doc["@context"]
	if !jsonEqual(t, got, want) {
		t.Errorf("proof @context = %v, want the document's %v", got, want)
	}
}

func TestCreateProof_OmitsContextWhenTheDocumentHasNone(t *testing.T) {
	// "If unsecuredDocument.@context is present" — absence stays absence. An
	// invented context would sign a term the issuer never asserted.
	signer, _, doc := fixture(t)
	delete(doc, "@context")
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	raw, _ := json.Marshal(proof)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["@context"]; present {
		t.Errorf("proof invented an @context for a context-free document: %s", raw)
	}
}

func TestVerifyProof_AcceptsTheProofItJustCreated(t *testing.T) {
	// The round trip has to survive the new member: the proof config is built
	// from the same helper on both sides, so adding @context to the wire must
	// not fork create from verify.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err != nil {
		t.Errorf("VerifyProof rejected a proof it just created: %v", err)
	}
}

func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(ab) == string(bb)
}

func TestVerifyProof_ContextIsInsideTheSignature(t *testing.T) {
	// @context is admitted into the proof only because the proof config commits
	// to it. If it ever rode outside the signature, an attacker could swap the
	// context — and with it the meaning of every term in the document — while
	// the proof still verified. Tampering must break the check.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	doc["@context"] = []any{"https://attacker.example/context/v2"}

	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("a swapped @context still verified — the context is not covered by the signature")
	}
}
