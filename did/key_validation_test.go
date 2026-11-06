package did_test

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/multibase"
)

// invalidEd25519Keys are 32-byte values that are not usable Ed25519 public
// keys, each with the error ed25519.ValidatePublicKey gives for it.
var invalidEd25519Keys = []struct {
	name string
	hex  string
	want error
}{
	{"identity", "0100000000000000000000000000000000000000000000000000000000000000", ed25519.ErrSmallOrder},
	{"identity with the sign bit", "0100000000000000000000000000000000000000000000000000000000000080", ed25519.ErrSmallOrder},
	{"order 4 (y = 0)", "0000000000000000000000000000000000000000000000000000000000000000", ed25519.ErrSmallOrder},
	{"order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", ed25519.ErrSmallOrder},
	{"order 8, other y", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", ed25519.ErrSmallOrder},
	{"order 2 (y = p - 1)", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ed25519.ErrSmallOrder},
	{"y = p, a non-canonical y = 0", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ed25519.ErrSmallOrder},
	{"y = p + 1, a non-canonical identity", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ed25519.ErrSmallOrder},
	{"off the curve (y = 2)", "0200000000000000000000000000000000000000000000000000000000000000", ed25519.ErrInvalidPoint},
	{"y = p + 3, a non-canonical ordinary point", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", ed25519.ErrInvalidPoint},
	{"31 bytes", "b00d8d938e7f773d51565aad36a623f5344f7f5d1960f9cf3e8e12620ea281", ed25519.ErrPublicKeySize},
	{"33 bytes", "b00d8d938e7f773d51565aad36a623f5344f7f5d1960f9cf3e8e12620ea2810f00", ed25519.ErrPublicKeySize},
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The fixtures agree with the key check they stand for, so the tests below
// exercise the decoders rather than a disagreement about the vectors.
func TestInvalidEd25519KeyFixturesMatchValidatePublicKey(t *testing.T) {
	for _, tc := range invalidEd25519Keys {
		if err := ed25519.ValidatePublicKey(mustDecodeHex(t, tc.hex)); !errors.Is(err, tc.want) {
			t.Errorf("%s: ValidatePublicKey = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// Both key encodings refuse every key ValidatePublicKey refuses, with an error
// that wraps did.ErrInvalidPublicKey and the same ed25519 sentinel, so a caller
// can tell an unusable key from a document that does not list it.
func TestExtractPublicKey_RefusesInvalidEd25519Keys(t *testing.T) {
	for _, tc := range invalidEd25519Keys {
		key := mustDecodeHex(t, tc.hex)
		docs := map[string]*did.DIDDocument{
			"Multikey": docWith([]did.VerificationMethod{multikeyVM(encodeMultikey(t, key))}),
			"JWK":      docWithSigningKey(t, key),
		}
		for enc, doc := range docs {
			got, err := did.ExtractPublicKey(doc, "#signing", did.RelationshipAssertionMethod)
			if !errors.Is(err, tc.want) || !errors.Is(err, did.ErrInvalidPublicKey) {
				t.Errorf("%s via %s: ExtractPublicKey = (%x, %v), want an error wrapping ErrInvalidPublicKey and %v", tc.name, enc, got, err, tc.want)
			}
			if _, _, err := did.ExtractPublicKeyAndEncoding(doc, "#signing", did.RelationshipAssertionMethod); !errors.Is(err, tc.want) {
				t.Errorf("%s via %s: ExtractPublicKeyAndEncoding error = %v, want one wrapping %v", tc.name, enc, err, tc.want)
			}
		}
	}
}

// A generated key still extracts unchanged through both encodings.
func TestExtractPublicKey_AcceptsGeneratedKeys(t *testing.T) {
	for i := 0; i < 32; i++ {
		pub, _, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		docs := map[string]*did.DIDDocument{
			"Multikey": docWith([]did.VerificationMethod{multikeyVM(encodeMultikey(t, pub))}),
			"JWK":      docWithSigningKey(t, pub),
		}
		for enc, doc := range docs {
			got, err := did.ExtractPublicKey(doc, "#signing", did.RelationshipAssertionMethod)
			if err != nil {
				t.Fatalf("via %s: ExtractPublicKey: %v", enc, err)
			}
			if string(got) != string(pub) {
				t.Fatalf("via %s: extracted %x, want %x", enc, got, pub)
			}
		}
	}
}

// The encoder refuses what the decoder refuses: a key it encoded could not be
// read back.
func TestEncodeEd25519Multikey_RefusesInvalidEd25519Keys(t *testing.T) {
	for _, tc := range invalidEd25519Keys {
		key := mustDecodeHex(t, tc.hex)
		if mb, err := did.EncodeEd25519Multikey(key); !errors.Is(err, tc.want) || !errors.Is(err, did.ErrInvalidPublicKey) {
			t.Errorf("%s: EncodeEd25519Multikey = (%q, %v), want an error wrapping ErrInvalidPublicKey and %v", tc.name, mb, err, tc.want)
		}
		if _, err := did.NewMultikeyVerificationMethod(subjectDID+"#signing", subjectDID, key); !errors.Is(err, tc.want) {
			t.Errorf("%s: NewMultikeyVerificationMethod error = %v, want one wrapping %v", tc.name, err, tc.want)
		}
	}
}

// A failure that is not about the key's value — the method is missing,
// unlisted, ambiguous, foreign, or its encoding is malformed — is not
// ErrInvalidPublicKey, so a caller that refuses unusable keys does not mistake
// these for one.
func TestExtractPublicKey_OtherFailuresAreNotInvalidPublicKey(t *testing.T) {
	pub := mustDecodeHex(t, w3cSigningKeyHex)
	jwk := func(kty, x string) did.VerificationMethod {
		return did.VerificationMethod{ID: subjectDID + "#signing", Type: vmTypeJSONWebKey, Controller: subjectDID,
			PublicKeyJWK: map[string]any{"kty": kty, "crv": "Ed25519", "x": x}}
	}
	cases := map[string]struct {
		doc *did.DIDDocument
		key string
		rel did.VerificationRelationship
	}{
		"not listed under the relationship": {docWithSigningKey(t, pub), "#signing", did.RelationshipAuthentication},
		"no such method":                    {docWithSigningKey(t, pub), "#other", did.RelationshipAssertionMethod},
		"duplicate method id": {docWith([]did.VerificationMethod{
			multikeyVM(encodeMultikey(t, pub)), multikeyVM(encodeMultikey(t, pub)),
		}), "#signing", did.RelationshipAssertionMethod},
		"controller is another DID": {docWith([]did.VerificationMethod{{
			ID: subjectDID + "#signing", Type: vmTypeMultikey, Controller: "did:dplaax:poc.dplaax.dev:org:other",
			PublicKeyMultibase: encodeMultikey(t, pub),
		}}), "#signing", did.RelationshipAssertionMethod},
		"wrong multicodec": {docWith([]did.VerificationMethod{multikeyVM(
			multibase.EncodeBase58Btc(append([]byte{0x12, 0x20}, pub...)))}), "#signing", did.RelationshipAssertionMethod},
		"invalid base58":      {docWith([]did.VerificationMethod{multikeyVM("z0OIl")}), "#signing", did.RelationshipAssertionMethod},
		"JWK kty is not OKP":  {docWith([]did.VerificationMethod{jwk("EC", "AAAA")}), "#signing", did.RelationshipAssertionMethod},
		"JWK x is not base64": {docWith([]did.VerificationMethod{jwk("OKP", "!!!")}), "#signing", did.RelationshipAssertionMethod},
		"unknown method type": {docWith([]did.VerificationMethod{{ID: subjectDID + "#signing", Type: "Ed25519VerificationKey2018", Controller: subjectDID}}), "#signing", did.RelationshipAssertionMethod},
	}
	for name, tc := range cases {
		_, err := did.ExtractPublicKey(tc.doc, tc.key, tc.rel)
		if err == nil {
			t.Errorf("%s: extracted a key", name)
			continue
		}
		var keyErr ed25519.Error
		if errors.Is(err, did.ErrInvalidPublicKey) || errors.As(err, &keyErr) {
			t.Errorf("%s: err = %v, reads as an unusable key", name, err)
		}
	}
}

// The JWK x member has one spelling per key: the unpadded base64url encoding
// of its 32 bytes. Non-zero trailing bits and embedded line breaks decode to
// the same bytes in a lenient decoder, and are refused.
func TestExtractPublicKey_JWKRefusesNonCanonicalBase64(t *testing.T) {
	const canonical = "sA2Nk45_dz1RVlqtNqYj9TRPf10ZYPnPPo4SYg6igQ8"
	jwkDoc := func(x string) *did.DIDDocument {
		return docWith([]did.VerificationMethod{{ID: subjectDID + "#signing", Type: vmTypeJSONWebKey, Controller: subjectDID,
			PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x}}})
	}
	got, err := did.ExtractPublicKey(jwkDoc(canonical), "#signing", did.RelationshipAssertionMethod)
	if err != nil || hex.EncodeToString(got) != w3cSigningKeyHex {
		t.Fatalf("canonical x: (%x, %v)", got, err)
	}
	for name, x := range map[string]string{
		"non-zero trailing bits": canonical[:len(canonical)-1] + "9",
		"line break":             canonical[:20] + "\n" + canonical[20:],
		"carriage return":        canonical[:20] + "\r" + canonical[20:],
		"padded":                 canonical + "=",
	} {
		if _, err := did.ExtractPublicKey(jwkDoc(x), "#signing", did.RelationshipAssertionMethod); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
