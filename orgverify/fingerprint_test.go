package orgverify

import (
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/provin-line/oss/did"
)

const fpTestDID = "did:dplaax:poc.dplaax.dev:org:acme.com"

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// docWithSigningKey builds a DID document whose #signing key is listed under
// assertionMethod and controlled by the document subject — the shape
// FingerprintFromDIDDocument expects.
func docWithSigningKey(id string, pub []byte) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID:         id,
		Controller: id,
		VerificationMethod: []did.VerificationMethod{{
			ID:           id + "#signing",
			Type:         "JsonWebKey2020",
			Controller:   id,
			PublicKeyJWK: ed25519JWK(pub),
		}},
		AssertionMethod: []string{id + "#signing"},
	})
}

// Known-answer vector: RFC 8037 Appendix A.2's Ed25519 public key. The
// fingerprint is pinned to the frozen wire definition (spec §7.1/§7.2):
// sha256 over the raw 32-byte Ed25519 public key, "sha256:" + 64 lowercase
// hex — computed independently of FingerprintFromDIDDocument's own SHA256
// call so this test catches a definition drift (e.g. hashing the JWK
// instead of the raw key), not just a self-consistency check.
func TestFingerprintFromDIDDocument_Ed25519KnownAnswer(t *testing.T) {
	const pubKeyB64 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	const wantFingerprint = "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"

	pub, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	if len(pub) != stded25519.PublicKeySize {
		t.Fatalf("test vector length=%d, want %d", len(pub), stded25519.PublicKeySize)
	}
	doc := docWithSigningKey(fpTestDID, pub)

	fp, err := FingerprintFromDIDDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != wantFingerprint {
		t.Errorf("fingerprint=%q, want known-answer %q", fp, wantFingerprint)
	}
}

// Determinism: the same document always yields the same fingerprint.
func TestFingerprintFromDIDDocument_Deterministic(t *testing.T) {
	pub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := docWithSigningKey(fpTestDID, pub)
	fp1, err := FingerprintFromDIDDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fp2, err := FingerprintFromDIDDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp1 != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp1, fp2)
	}
}

func TestFingerprintFromDIDDocument_Nil(t *testing.T) {
	if _, err := FingerprintFromDIDDocument(nil); err == nil {
		t.Error("expected error for nil document")
	}
}

// No #signing key at all under assertionMethod: extraction fails rather than
// falling back to "the first assertionMethod entry" (spec §7.1 — the
// predecessor's fragment-only / first-entry behavior is not ported).
func TestFingerprintFromDIDDocument_NoSigningKey(t *testing.T) {
	doc := did.New(did.DocumentFields{
		ID:         fpTestDID,
		Controller: fpTestDID,
		VerificationMethod: []did.VerificationMethod{{
			ID:           fpTestDID + "#other",
			Type:         "JsonWebKey2020",
			Controller:   fpTestDID,
			PublicKeyJWK: ed25519JWK(mustKey(t)),
		}},
		AssertionMethod: []string{fpTestDID + "#other"},
	})
	if _, err := FingerprintFromDIDDocument(doc); err == nil {
		t.Error("expected error when no #signing key is present")
	}
}

// A key present but listed only under authentication, not assertionMethod,
// must not be picked up (relationship check — spec §7.1).
func TestFingerprintFromDIDDocument_SigningKeyWrongRelationship(t *testing.T) {
	doc := did.New(did.DocumentFields{
		ID:         fpTestDID,
		Controller: fpTestDID,
		VerificationMethod: []did.VerificationMethod{{
			ID:           fpTestDID + "#signing",
			Type:         "JsonWebKey2020",
			Controller:   fpTestDID,
			PublicKeyJWK: ed25519JWK(mustKey(t)),
		}},
		Authentication: []string{fpTestDID + "#signing"},
		// Deliberately NOT listed under AssertionMethod.
	})
	if _, err := FingerprintFromDIDDocument(doc); err == nil {
		t.Error("expected error when #signing is listed under authentication, not assertionMethod")
	}
}

// Two verification methods sharing the #signing absolute id are ambiguous —
// unique resolution is required (spec §7.1 "一意解決"); did.ExtractPublicKey
// rejects rather than silently choosing the first.
func TestFingerprintFromDIDDocument_DuplicateSigningKeyRejected(t *testing.T) {
	pubA := mustKey(t)
	pubB := mustKey(t)
	doc := did.New(did.DocumentFields{
		ID:         fpTestDID,
		Controller: fpTestDID,
		VerificationMethod: []did.VerificationMethod{
			{ID: fpTestDID + "#signing", Type: "JsonWebKey2020", Controller: fpTestDID, PublicKeyJWK: ed25519JWK(pubA)},
			{ID: fpTestDID + "#signing", Type: "JsonWebKey2020", Controller: fpTestDID, PublicKeyJWK: ed25519JWK(pubB)},
		},
		AssertionMethod: []string{fpTestDID + "#signing"},
	})
	if _, err := FingerprintFromDIDDocument(doc); err == nil {
		t.Error("expected error for duplicate #signing verification method id")
	}
}

// A verification method controlled by a different DID must not be selected
// even if its id fragment is #signing (controller check — spec §7.1).
func TestFingerprintFromDIDDocument_ControllerMismatchRejected(t *testing.T) {
	doc := did.New(did.DocumentFields{
		ID:         fpTestDID,
		Controller: fpTestDID,
		VerificationMethod: []did.VerificationMethod{{
			ID:           fpTestDID + "#signing",
			Type:         "JsonWebKey2020",
			Controller:   "did:dplaax:poc.dplaax.dev:org:evil.example",
			PublicKeyJWK: ed25519JWK(mustKey(t)),
		}},
		AssertionMethod: []string{fpTestDID + "#signing"},
	})
	if _, err := FingerprintFromDIDDocument(doc); err == nil {
		t.Error("expected error for verification method controller != document subject")
	}
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
