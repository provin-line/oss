package did_test

import (
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/provin-line/oss/did"
)

const subjectDID = "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:proc1"

// docWithSigningKey builds a DID document whose #signing key (assertionMethod)
// carries an Ed25519 JWK for pub.
func docWithSigningKey(t *testing.T, pub []byte) *did.DIDDocument {
	t.Helper()
	return &did.DIDDocument{
		ID:         subjectDID,
		Controller: subjectDID,
		VerificationMethod: []did.VerificationMethod{{
			ID:         subjectDID + "#signing",
			Type:       "JsonWebKey2020",
			Controller: subjectDID,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		AssertionMethod: []string{subjectDID + "#signing"},
		Authentication:  []string{},
	}
}

func TestExtractPublicKey_RoundTrip(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, pub)

	// Absolute reference.
	got, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey (absolute): %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("extracted key != original public key")
	}

	// Fragment-relative reference resolves to the same key.
	got2, err := did.ExtractPublicKey(doc, "#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey (relative): %v", err)
	}
	if string(got2) != string(pub) {
		t.Errorf("relative reference extracted a different key")
	}
}

func TestExtractPublicKey_WrongRelationship(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, pub)
	// The signing key is under assertionMethod, NOT authentication.
	if _, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAuthentication); err == nil {
		t.Error("extracting a key not listed under the required relationship: want error")
	}
}

func TestExtractPublicKey_UnknownKey(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, pub)
	if _, err := did.ExtractPublicKey(doc, subjectDID+"#absent", did.RelationshipAssertionMethod); err == nil {
		t.Error("extracting an absent key: want error")
	}
}

func TestExtractPublicKey_ControllerMismatch(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, pub)
	// A verification method whose controller is some other DID must be rejected
	// (key-confusion / cross-document injection defense).
	doc.VerificationMethod[0].Controller = "did:dplaax:poc.dplaax.io:org:evil"
	if _, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("verification-method controller != document: want error")
	}
}

func TestExtractPublicKey_BadJWK(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)

	// Wrong key type.
	d1 := docWithSigningKey(t, pub)
	d1.VerificationMethod[0].PublicKeyJWK["kty"] = "RSA"
	if _, err := did.ExtractPublicKey(d1, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("non-OKP key type: want error")
	}

	// Wrong curve.
	d2 := docWithSigningKey(t, pub)
	d2.VerificationMethod[0].PublicKeyJWK["crv"] = "X25519"
	if _, err := did.ExtractPublicKey(d2, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("non-Ed25519 curve: want error")
	}

	// Malformed base64 in x.
	d3 := docWithSigningKey(t, pub)
	d3.VerificationMethod[0].PublicKeyJWK["x"] = "!!!not base64!!!"
	if _, err := did.ExtractPublicKey(d3, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("malformed base64url x: want error")
	}

	// Wrong key length (not 32 bytes).
	d4 := docWithSigningKey(t, pub)
	d4.VerificationMethod[0].PublicKeyJWK["x"] = base64.RawURLEncoding.EncodeToString([]byte("too short"))
	if _, err := did.ExtractPublicKey(d4, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("wrong public-key length: want error")
	}
}

// A verification method with a DIFFERENT DID id but the SAME fragment as the
// requested key, placed first and spoofing the document's controller, must not
// be selected: the named key is matched by absolute id, not by fragment alone
// (key-confusion / fragment-collision injection defense).
func TestExtractPublicKey_FragmentCollisionInjection_Rejected(t *testing.T) {
	realPub, _, _ := stded25519.GenerateKey(nil)
	attackerPub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, realPub)
	attacker := did.VerificationMethod{
		ID:         "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:attacker#signing",
		Type:       "JsonWebKey2020",
		Controller: subjectDID, // spoofed to the document subject
		PublicKeyJWK: map[string]any{
			"kty": "OKP", "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(attackerPub),
		},
	}
	doc.VerificationMethod = append([]did.VerificationMethod{attacker}, doc.VerificationMethod...)

	got, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey: %v", err)
	}
	if string(got) != string(realPub) {
		t.Error("a fragment-colliding attacker key was selected instead of the named key")
	}
}

// Two verification methods with the identical absolute id are ambiguous and
// must be rejected rather than silently resolving to the first.
func TestExtractPublicKey_DuplicateMethodID_Rejected(t *testing.T) {
	realPub, _, _ := stded25519.GenerateKey(nil)
	attackerPub, _, _ := stded25519.GenerateKey(nil)
	doc := docWithSigningKey(t, realPub)
	dup := did.VerificationMethod{
		ID:         subjectDID + "#signing",
		Type:       "JsonWebKey2020",
		Controller: subjectDID,
		PublicKeyJWK: map[string]any{
			"kty": "OKP", "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(attackerPub),
		},
	}
	doc.VerificationMethod = append([]did.VerificationMethod{dup}, doc.VerificationMethod...)

	if _, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("duplicate verification-method id: want error (ambiguous key)")
	}
}
