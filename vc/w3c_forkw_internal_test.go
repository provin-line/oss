package vc

import (
	"strings"
	"testing"

	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
)

// Fork W's interop anchor. The legacy vector test (TestW3CVector_EdDSAJCS2022
// in rdfc_internal_test.go) pins the official Example 29–38 chain under the
// int64-verbatim canonicalizer — sound on these inputs only because the vector
// carries no unsafe integers. What Fork W actually claims is stronger: the
// CONFORMANT canonicalizer reproduces the official bytes, and the whole
// classifier path — Multikey resolution, exact dispatch, context mirror,
// RFC 8785 hashing — accepts the signature W3C's own example published.

// The W3C test key's did:key form (vc-di-eddsa test vectors): the public key
// whose secretKeyMultibase seed w3cSigningKey decodes.
const w3cDIDKey = "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"

func TestW3CVector_EdDSAJCS2022_RFC8785(t *testing.T) {
	// The official canonical JSON, byte for byte, from the conformant
	// canonicalizer — not the legacy one whose agreement is an accident of the
	// vector's numeric content.
	c := jcs.RFC8785{}
	canonCred, err := c.Canonicalize(readTestdataJSON(t, "w3c-jcs-credential.json"))
	if err != nil {
		t.Fatalf("Canonicalize credential: %v", err)
	}
	if want := strings.TrimSpace(string(readTestdata(t, "w3c-jcs-canonical-credential.txt"))); string(canonCred) != want {
		t.Errorf("canonical credential:\n got %s\nwant %s", canonCred, want)
	}
	canonPO, err := c.Canonicalize(readTestdataJSON(t, "w3c-jcs-proof-options.json"))
	if err != nil {
		t.Fatalf("Canonicalize proof options: %v", err)
	}
	if want := strings.TrimSpace(string(readTestdata(t, "w3c-jcs-canonical-proof-options.txt"))); string(canonPO) != want {
		t.Errorf("canonical proof options:\n got %s\nwant %s", canonPO, want)
	}

	assertVectorChain(t, c,
		"w3c-jcs-credential.json", "w3c-jcs-proof-options.json",
		w3cJCSCredHashHex, w3cJCSPOHashHex, w3cJCSSignatureHex, w3cJCSProofValue)
}

// w3cVectorProof assembles the wire proof of the signed example (Example 39):
// the published proof options plus the published proofValue.
func w3cVectorProof(t *testing.T) *DataIntegrityProof {
	t.Helper()
	po := readTestdataJSON(t, "w3c-jcs-proof-options.json")
	return &DataIntegrityProof{
		Context:            po[keyContext],
		Type:               po["type"].(string),
		Cryptosuite:        po["cryptosuite"].(string),
		VerificationMethod: po["verificationMethod"].(string),
		ProofPurpose:       po["proofPurpose"].(string),
		Created:            po["created"].(string),
		ProofValue:         w3cJCSProofValue,
	}
}

// w3cVectorDoc builds the did:key document the vector's verificationMethod
// resolves to: the Multikey method, listed under assertionMethod, controlled
// by the subject — the exact preconditions ExtractPublicKeyAndEncoding gates on.
func w3cVectorDoc(t *testing.T, vmID string) *did.DIDDocument {
	t.Helper()
	fragment := strings.TrimPrefix(vmID, w3cDIDKey+"#")
	vm := did.VerificationMethod{
		ID:                 vmID,
		Type:               "Multikey",
		Controller:         w3cDIDKey,
		PublicKeyMultibase: fragment, // did:key: the fragment IS the multikey value
	}
	return did.New(did.DocumentFields{
		Context:            did.IssuedDocumentContexts(),
		ID:                 w3cDIDKey,
		Controller:         w3cDIDKey,
		VerificationMethod: []did.VerificationMethod{vm},
		AssertionMethod:    []string{vmID},
	})
}

func TestW3CVector_EndToEnd_ClassifierAcceptsTheOfficialProof(t *testing.T) {
	// The artifact W3C published, verified through the production path: key and
	// encoding from one DID resolution, contract from the exact classifier,
	// bytes from RFC 8785. Passing means an external W3C verifier and this
	// implementation agree about the same signature — the interop claim
	// (signer.suite.w3c-interop-gate's in-repo half).
	proof := w3cVectorProof(t)
	doc := w3cVectorDoc(t, proof.VerificationMethod)

	pub, encoding, err := did.ExtractPublicKeyAndEncoding(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
	}
	if encoding != did.EncodingMultikey {
		t.Fatalf("encoding = %v, want Multikey", encoding)
	}

	credential := readTestdataJSON(t, "w3c-jcs-credential.json")
	contract, err := VerifyProofWithContract(ed25519.Verifier{}, pub, encoding, proof, credential)
	if err != nil {
		t.Fatalf("VerifyProofWithContract: %v", err)
	}
	if contract != ContractW3CEdDSAJCS2022 {
		t.Errorf("contract = %q, want %q", contract, ContractW3CEdDSAJCS2022)
	}
}

func TestW3CVector_EndToEnd_SixMemberShapeIsNotPromoted(t *testing.T) {
	// The same key, the same signature bytes, minus the proof-local @context:
	// the shape provin issued before Fork W. It must not ride the Multikey
	// document into the W3C contract — and it must not verify at all, because
	// no contract matches (signer.suite.legacy-projection).
	proof := w3cVectorProof(t)
	proof.Context = nil
	doc := w3cVectorDoc(t, proof.VerificationMethod)

	pub, encoding, err := did.ExtractPublicKeyAndEncoding(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
	}
	credential := readTestdataJSON(t, "w3c-jcs-credential.json")
	if _, err := VerifyProofWithContract(ed25519.Verifier{}, pub, encoding, proof, credential); err == nil {
		t.Error("a six-member proof over a Multikey document was accepted — promotion the classifier exists to refuse")
	}
}

func TestW3CVector_EndToEnd_SwappedContextIsRejected(t *testing.T) {
	// The published signature with a swapped proof-local @context: the mirror
	// check must refuse it, because this verify path's signature reconstruction
	// reads the document's context and would otherwise never notice.
	proof := w3cVectorProof(t)
	proof.Context = []any{"https://attacker.example/context/v2"}
	doc := w3cVectorDoc(t, proof.VerificationMethod)

	pub, encoding, err := did.ExtractPublicKeyAndEncoding(doc, proof.VerificationMethod, did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
	}
	credential := readTestdataJSON(t, "w3c-jcs-credential.json")
	if _, err := VerifyProofWithContract(ed25519.Verifier{}, pub, encoding, proof, credential); err == nil {
		t.Error("a swapped proof-local @context was accepted")
	}
}
