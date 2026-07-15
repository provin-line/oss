package did_test

import (
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/did"
)

// Type↔encoding exclusivity is a claim about the WIRE, so it has to be checked
// against the wire. Checking it against the typed projection instead lets a
// method carry the other encoding's member as long as the value happens to
// project to a zero value — "publicKeyJwk": null reads as absent, and
// "publicKeyMultibase": "" reads as absent, so the method sails through a check
// that believes it is exclusive.
//
// The bytes still commit to those members (Hash/MarshalJSON keep every member),
// so a reader keying on raw presence and this package keying on the projection
// would disagree about what the document says. The suite classifier (ForkW-1
// §2.2) dispatches on exactly this encoding, so the two must be one operation
// over one raw method, not two independent readings.

const subject = "did:dplaax:owner1:proc1"

func docWithVM(t *testing.T, vm map[string]any) *did.DIDDocument {
	t.Helper()
	body := map[string]any{
		"@context":           []any{"https://www.w3.org/ns/did/v1"},
		"id":                 subject,
		"assertionMethod":    []any{subject + "#k1"},
		"verificationMethod": []any{vm},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// UnmarshalJSON is the resolution path — it preserves every wire member,
	// which is exactly what an exclusivity check has to see.
	var doc did.DIDDocument
	if err := doc.UnmarshalJSON(raw); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	return &doc
}

// A valid Multikey and a valid JWK for the same curve — the two legitimate shapes.
func validMultikey() string { return "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2" }

func validJWK() map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

func TestExtractPublicKey_RejectsForeignEncodingMemberRegardlessOfValue(t *testing.T) {
	// Each case carries the other encoding's member with a value that projects
	// to a zero value. Presence is the violation; the value is irrelevant.
	cases := []struct {
		name string
		vm   map[string]any
	}{
		{"Multikey with null publicKeyJwk", map[string]any{
			"id": subject + "#k1", "type": "Multikey", "controller": subject,
			"publicKeyMultibase": validMultikey(), "publicKeyJwk": nil,
		}},
		{"Multikey with scalar publicKeyJwk", map[string]any{
			"id": subject + "#k1", "type": "Multikey", "controller": subject,
			"publicKeyMultibase": validMultikey(), "publicKeyJwk": "not-an-object",
		}},
		{"JWK with empty publicKeyMultibase", map[string]any{
			"id": subject + "#k1", "type": "JsonWebKey2020", "controller": subject,
			"publicKeyJwk": validJWK(), "publicKeyMultibase": "",
		}},
		{"JWK with null publicKeyMultibase", map[string]any{
			"id": subject + "#k1", "type": "JsonWebKey2020", "controller": subject,
			"publicKeyJwk": validJWK(), "publicKeyMultibase": nil,
		}},
		{"JWK with wrong-typed publicKeyMultibase", map[string]any{
			"id": subject + "#k1", "type": "JsonWebKey2020", "controller": subject,
			"publicKeyJwk": validJWK(), "publicKeyMultibase": 42,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := docWithVM(t, tc.vm)
			if _, err := did.ExtractPublicKey(doc, subject+"#k1", did.RelationshipAssertionMethod); err == nil {
				t.Error("a method carrying both encoding members was accepted")
			}
		})
	}
}

func TestExtractPublicKeyAndEncoding_ReportsTheEncodingItResolved(t *testing.T) {
	// The classifier needs the key and the encoding from ONE reading of ONE
	// method: two separate readings can disagree, and the whole point of the
	// exact dispatch is that they cannot.
	t.Run("Multikey", func(t *testing.T) {
		doc := docWithVM(t, map[string]any{
			"id": subject + "#k1", "type": "Multikey", "controller": subject,
			"publicKeyMultibase": validMultikey(),
		})
		key, enc, err := did.ExtractPublicKeyAndEncoding(doc, subject+"#k1", did.RelationshipAssertionMethod)
		if err != nil {
			t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
		}
		if enc != did.EncodingMultikey {
			t.Errorf("encoding = %v, want %v", enc, did.EncodingMultikey)
		}
		if len(key) == 0 {
			t.Error("no key bytes returned")
		}
	})
	t.Run("JWK", func(t *testing.T) {
		doc := docWithVM(t, map[string]any{
			"id": subject + "#k1", "type": "JsonWebKey2020", "controller": subject,
			"publicKeyJwk": validJWK(),
		})
		key, enc, err := did.ExtractPublicKeyAndEncoding(doc, subject+"#k1", did.RelationshipAssertionMethod)
		if err != nil {
			t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
		}
		if enc != did.EncodingJWK {
			t.Errorf("encoding = %v, want %v", enc, did.EncodingJWK)
		}
		if len(key) == 0 {
			t.Error("no key bytes returned")
		}
	})
}

func TestExtractPublicKey_StillAcceptsTheLegitimateShapes(t *testing.T) {
	// The strictness must not cost the two shapes the profile actually issues.
	for _, vm := range []map[string]any{
		{"id": subject + "#k1", "type": "Multikey", "controller": subject, "publicKeyMultibase": validMultikey()},
		{"id": subject + "#k1", "type": "JsonWebKey2020", "controller": subject, "publicKeyJwk": validJWK()},
	} {
		doc := docWithVM(t, vm)
		if _, err := did.ExtractPublicKey(doc, subject+"#k1", did.RelationshipAssertionMethod); err != nil {
			t.Errorf("legitimate %s method rejected: %v", vm["type"], err)
		}
	}
}
