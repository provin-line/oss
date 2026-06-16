package vc_test

import (
	stded25519 "crypto/ed25519"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// in-memory keystore for the signer.
type memKeyStore struct {
	keys map[string][]byte
}

func newMemKeyStore() *memKeyStore { return &memKeyStore{keys: map[string][]byte{}} }

func (m *memKeyStore) SaveKeyPair(did string, keys map[keystore.KeyID]*crypto.KeyPair) error {
	for id, kp := range keys {
		m.keys[did+"#"+string(id)] = kp.PrivateKey
	}
	return nil
}
func (m *memKeyStore) GetPrivateKey(did string, keyID keystore.KeyID) ([]byte, error) {
	k, ok := m.keys[did+"#"+string(keyID)]
	if !ok {
		return nil, errNotFound
	}
	return k, nil
}
func (m *memKeyStore) DeleteKeys(did string) error { return nil }

var errNotFound = errStr("key not found")

type errStr string

func (e errStr) Error() string { return string(e) }

const (
	issuerDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"
	vmID      = issuerDID + "#signing"
)

// fixture wires a real Ed25519 signer/verifier and a document, returning the
// signer, the public key, and the unsigned document body.
func fixture(t *testing.T) (crypto.Signer, []byte, map[string]any) {
	t.Helper()
	kp, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(issuerDID, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kp}); err != nil {
		t.Fatalf("SaveKeyPair: %v", err)
	}
	doc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"issuer":   issuerDID,
		"credentialSubject": map[string]any{
			"pipelineId": "p1",
			"outputHash": "sha256:abc",
		},
	}
	return ed25519.NewSigner(ks), kp.PublicKey, doc
}

func TestCreateVerifyProof_RoundTrip(t *testing.T) {
	signer, pub, doc := fixture(t)

	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	if proof.Type != "DataIntegrityProof" {
		t.Errorf("proof.Type=%q", proof.Type)
	}
	if proof.Cryptosuite != vc.CryptosuiteEdDSAJCS2022 {
		t.Errorf("proof.Cryptosuite=%q", proof.Cryptosuite)
	}
	if proof.ProofPurpose != "assertionMethod" {
		t.Errorf("proof.ProofPurpose=%q", proof.ProofPurpose)
	}
	if proof.Created == "" {
		t.Error("proof.Created empty")
	}
	if len(proof.ProofValue) < 2 || proof.ProofValue[0] != 'z' {
		t.Errorf("proofValue=%q must be multibase base58btc ('z' prefix)", proof.ProofValue)
	}

	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err != nil {
		t.Errorf("VerifyProof on a genuine proof: %v", err)
	}
}

func TestVerifyProof_TamperedDocument(t *testing.T) {
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	// Mutate the document after signing.
	doc["credentialSubject"].(map[string]any)["outputHash"] = "sha256:TAMPERED"
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof must fail on a tampered document")
	}
}

func TestVerifyProof_TamperedProofField(t *testing.T) {
	signer, pub, doc := fixture(t)
	proof, _ := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	// Changing any proof-config field must break verification, since the
	// signature covers the whole proof config.
	proof.Created = "2000-01-01T00:00:00Z"
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof must fail when proof.Created is altered post-signing")
	}
}

func TestVerifyProof_TamperedProofValue(t *testing.T) {
	signer, pub, doc := fixture(t)
	proof, _ := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)

	// Splice in a GENUINE 64-byte signature over a DIFFERENT document — a
	// same-length forgery attempt. This must fail on signature mismatch, not on
	// the verifier's size check, exercising the real verification path.
	otherDoc := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"issuer":            issuerDID,
		"credentialSubject": map[string]any{"outputHash": "sha256:different"},
	}
	otherProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, otherDoc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof(otherDoc): %v", err)
	}
	proof.ProofValue = otherProof.ProofValue // valid, well-formed, but over different data
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof must reject a valid-shape signature made over different data")
	}
}

func TestVerifyProof_WrongKey(t *testing.T) {
	signer, _, doc := fixture(t)
	proof, _ := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	otherPub, _, _ := stded25519.GenerateKey(nil)
	if err := vc.VerifyProof(ed25519.Verifier{}, otherPub, proof, doc); err == nil {
		t.Error("VerifyProof must fail under the wrong public key")
	}
}

func TestCreateProof_UnknownCryptosuite(t *testing.T) {
	signer, _, doc := fixture(t)
	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, "eddsa-rdfc-2022"); err == nil {
		t.Error("CreateProof with an unregistered cryptosuite: want error")
	}
}

func TestCreateProof_NoOpCryptosuiteRejected(t *testing.T) {
	signer, _, doc := fixture(t)
	for _, name := range []string{"", "none", "null", "identity"} {
		if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, name); err == nil {
			t.Errorf("CreateProof with no-op cryptosuite %q: want error (alg:none defense)", name)
		}
	}
}

func TestVerifyProof_NoOpCryptosuiteRejected(t *testing.T) {
	signer, pub, doc := fixture(t)
	proof, _ := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	proof.Cryptosuite = "none"
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof with cryptosuite 'none': want error (alg:none defense)")
	}
}
