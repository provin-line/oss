package did_test

import (
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/multibase"
)

// Published Multikey test vector from W3C vc-di-eddsa (Example 1): an Ed25519
// public key encoded as a Multikey. The decoded bytes are pinned so the
// multicodec-strip path is anchored to a cross-implementation vector, not a
// self-produced one.
const (
	w3cMultikeyVM    = "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	w3cMultikeyVMHex = "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44"
	w3cSigningKey    = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
	w3cSigningKeyHex = "b00d8d938e7f773d51565aad36a623f5344f7f5d1960f9cf3e8e12620ea2810f"
	ed25519PubVarint = "ed01" // multicodec ed25519-pub varint prefix
	vmTypeMultikey   = "Multikey"
	vmTypeJSONWebKey = "JsonWebKey2020"
)

// multikeyVM builds a #signing Multikey verification method for the document
// fixture used across these tests.
func multikeyVM(publicKeyMultibase string) did.VerificationMethod {
	return did.VerificationMethod{
		ID:                 subjectDID + "#signing",
		Type:               vmTypeMultikey,
		Controller:         subjectDID,
		PublicKeyMultibase: publicKeyMultibase,
	}
}

// encodeMultikey wraps raw Ed25519 public key bytes as a Multikey value
// (multicodec ed25519-pub prefix, base58btc multibase).
func encodeMultikey(t *testing.T, pub []byte) string {
	t.Helper()
	prefix, err := hex.DecodeString(ed25519PubVarint)
	if err != nil {
		t.Fatal(err)
	}
	return multibase.EncodeBase58Btc(append(prefix, pub...))
}

// ExtractPublicKey recovers the pinned raw key bytes from the published W3C
// Multikey vector.
func TestExtractPublicKey_Multikey_W3CVector(t *testing.T) {
	doc := docWith([]did.VerificationMethod{multikeyVM(w3cMultikeyVM)})
	got, err := did.ExtractPublicKey(doc, "#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey(Multikey): %v", err)
	}
	if hex.EncodeToString(got) != w3cMultikeyVMHex {
		t.Errorf("extracted key = %x, want %s", got, w3cMultikeyVMHex)
	}
}

// The same Ed25519 key expressed as a JWK and as a Multikey extracts to the
// same raw bytes — the two encodings cannot partition key identity.
func TestExtractPublicKey_JWKAndMultikeyAgree(t *testing.T) {
	pub, err := hex.DecodeString(w3cSigningKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	viaMultikey, err := did.ExtractPublicKey(
		docWith([]did.VerificationMethod{multikeyVM(w3cSigningKey)}),
		"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey(Multikey): %v", err)
	}
	viaJWK, err := did.ExtractPublicKey(
		docWith([]did.VerificationMethod{{
			ID:         subjectDID + "#signing",
			Type:       vmTypeJSONWebKey,
			Controller: subjectDID,
			PublicKeyJWK: map[string]any{
				"kty": "OKP", "crv": "Ed25519",
				"x": base64.RawURLEncoding.EncodeToString(pub),
			},
		}}),
		"#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey(JWK): %v", err)
	}
	if string(viaMultikey) != string(viaJWK) || string(viaMultikey) != string(pub) {
		t.Errorf("Multikey %x and JWK %x must both equal %x", viaMultikey, viaJWK, pub)
	}
}

// A Multikey read from a resolved (unmarshalled) document works end to end —
// publicKeyMultibase survives the wire parse.
func TestExtractPublicKey_Multikey_FromWire(t *testing.T) {
	wire, err := json.Marshal(docWith([]did.VerificationMethod{multikeyVM(w3cMultikeyVM)}))
	if err != nil {
		t.Fatal(err)
	}
	var doc did.DIDDocument
	if err := json.Unmarshal(wire, &doc); err != nil {
		t.Fatal(err)
	}
	got, err := did.ExtractPublicKey(&doc, "#signing", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKey after round-trip: %v", err)
	}
	if hex.EncodeToString(got) != w3cMultikeyVMHex {
		t.Errorf("extracted key = %x, want %s", got, w3cMultikeyVMHex)
	}
}

// VM type and key encoding are mutually exclusive: a method carrying both
// encodings, an encoding that contradicts its type, or neither encoding is
// rejected — never resolved by silently picking one (no alternate wire shape
// gets frozen by accident).
func TestExtractPublicKey_TypeEncodingExclusive(t *testing.T) {
	pub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{
		"kty": "OKP", "crv": "Ed25519",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}
	mk := encodeMultikey(t, pub)

	cases := []struct {
		name string
		vm   did.VerificationMethod
	}{
		{"Multikey with JWK alongside", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: vmTypeMultikey, Controller: subjectDID,
			PublicKeyMultibase: mk, PublicKeyJWK: jwk,
		}},
		{"JsonWebKey2020 with multibase alongside", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: vmTypeJSONWebKey, Controller: subjectDID,
			PublicKeyJWK: jwk, PublicKeyMultibase: mk,
		}},
		{"Multikey with only JWK", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: vmTypeMultikey, Controller: subjectDID,
			PublicKeyJWK: jwk,
		}},
		{"JsonWebKey2020 with only multibase", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: vmTypeJSONWebKey, Controller: subjectDID,
			PublicKeyMultibase: mk,
		}},
		{"Multikey with neither encoding", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: vmTypeMultikey, Controller: subjectDID,
		}},
		{"unsupported type with valid JWK", did.VerificationMethod{
			ID: subjectDID + "#signing", Type: "Ed25519VerificationKey2020", Controller: subjectDID,
			PublicKeyJWK: jwk,
		}},
		{"empty type with valid JWK", did.VerificationMethod{
			ID: subjectDID + "#signing", Controller: subjectDID,
			PublicKeyJWK: jwk,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := did.ExtractPublicKey(docWith([]did.VerificationMethod{tc.vm}), "#signing", did.RelationshipAssertionMethod); err == nil {
				t.Error("want error, got key")
			}
		})
	}
}

// Malformed Multikey values fail closed: wrong multibase base, wrong
// multicodec prefix, wrong key length, invalid base58.
func TestExtractPublicKey_Multikey_Malformed(t *testing.T) {
	pub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 31)
	long := make([]byte, 33)
	copy(short, pub)
	copy(long, pub)

	cases := []struct {
		name  string
		value string
	}{
		{"missing z prefix", encodeMultikey(t, pub)[1:]},
		{"multibase hex not base58btc", "f1220deadbeef"},
		{"invalid base58 character", "z0OIl"},
		{"wrong multicodec prefix", multibase.EncodeBase58Btc(append([]byte{0x12, 0x20}, pub...))},
		{"no multicodec prefix", multibase.EncodeBase58Btc(pub)},
		{"31-byte key", encodeMultikey(t, short)},
		{"33-byte key", encodeMultikey(t, long)},
		{"empty after prefix", multibase.EncodeBase58Btc([]byte{0xed, 0x01})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := did.ExtractPublicKey(docWith([]did.VerificationMethod{multikeyVM(tc.value)}), "#signing", did.RelationshipAssertionMethod); err == nil {
				t.Error("want error, got key")
			}
		})
	}
}
