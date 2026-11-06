package did_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/multibase"
)

func TestAbsoluteKeyID(t *testing.T) {
	for ref, want := range map[string]string{
		"#signing":                 subjectDID + "#signing",
		subjectDID + "#signing":    subjectDID + "#signing",
		"#key-1.v2_b":              subjectDID + "#key-1.v2_b",
		"":                         "",
		"#":                        "",
		"##":                       "",
		"#x#signing":               "",
		subjectDID + "#x#signing":  "",
		"signing":                  "",
		"did:dplaax:other#signing": "",
		subjectDID + "x#signing":   "",
		"#..":                      "",
		"#sign%69ng":               "",
		"#sig\tning":               "",
		"#signing ":                "",
		"#sígning":                 "",
	} {
		got, err := did.AbsoluteKeyID(subjectDID, ref)
		if want == "" {
			if !errors.Is(err, did.ErrInvalidKeyReference) {
				t.Errorf("AbsoluteKeyID(%q) = %q, %v; want ErrInvalidKeyReference", ref, got, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("AbsoluteKeyID(%q) = %q, %v; want %q", ref, got, err, want)
		}
	}
}

// ExtractPublicKey reads a key reference only in a form every reader reads
// alike: "#x#signing" and a bare "signing" no longer stand for "#signing",
// and a method whose id names another DID is not this document's key.
func TestExtractPublicKey_ReadsKeyReferencesInOneForm(t *testing.T) {
	pub := mustDecodeHex(t, w3cSigningKeyHex)
	doc := docWith([]did.VerificationMethod{multikeyVM(encodeMultikey(t, pub))})
	for _, ref := range []string{"#x#signing", "signing", subjectDID + "#x#signing", "#sign%69ng"} {
		if _, err := did.ExtractPublicKey(doc, ref, did.RelationshipAssertionMethod); !errors.Is(err, did.ErrInvalidKeyReference) {
			t.Errorf("ExtractPublicKey(%q) = %v, want ErrInvalidKeyReference", ref, err)
		}
	}
	foreign := did.New(did.DocumentFields{
		ID: subjectDID, Controller: subjectDID,
		VerificationMethod: []did.VerificationMethod{{ID: "did:dplaax:other#signing", Type: "Multikey", Controller: subjectDID, PublicKeyMultibase: encodeMultikey(t, pub)}},
		AssertionMethod:    []string{"did:dplaax:other#signing"},
	})
	if _, err := did.ExtractPublicKey(foreign, "did:dplaax:other#signing", did.RelationshipAssertionMethod); !errors.Is(err, did.ErrInvalidKeyReference) {
		t.Error("extracted a method whose id names another DID as this document's key")
	}
	// A listed reference "#x#signing" no longer lists "#signing".
	tricky := did.New(did.DocumentFields{
		ID: subjectDID, Controller: subjectDID,
		VerificationMethod: []did.VerificationMethod{multikeyVM(encodeMultikey(t, pub))},
		AssertionMethod:    []string{"#x#signing"},
	})
	if _, err := did.ExtractPublicKey(tricky, "#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("a reference #x#signing listed #signing")
	}
}

// A method carries exactly one key member, its type's: another key member
// (publicKeyBase58, publicKeyHex, …) is a second key some readers read first.
func TestExtractPublicKey_RefusesASecondKeyMember(t *testing.T) {
	pub := mustDecodeHex(t, w3cSigningKeyHex)
	for _, typ := range []string{"Multikey", "JsonWebKey2020"} {
		vmOf := func(extra string) map[string]any {
			vm := map[string]any{"id": subject + "#k1", "type": typ, "controller": subject}
			if typ == "Multikey" {
				vm["publicKeyMultibase"] = encodeMultikey(t, pub)
			} else {
				vm["publicKeyJwk"] = ed25519JWK(pub)
			}
			if extra != "" {
				vm[extra] = multibase.EncodeBase58Btc(pub)
			}
			return vm
		}
		if _, err := did.ExtractPublicKey(docWithVM(t, vmOf("")), subject+"#k1", did.RelationshipAssertionMethod); err != nil {
			t.Fatalf("%s method with only its own key: %v", typ, err)
		}
		for _, member := range []string{"publicKeyBase58", "publicKeyBase64", "publicKeyHex", "publicKeyPem", "publicKeyPgp", "publicKeyFuture", "secretKeyMultibase", "secretKeyJwk", "blockchainAccountId", "ethereumAddress"} {
			_, err := did.ExtractPublicKey(docWithVM(t, vmOf(member)), subject+"#k1", did.RelationshipAssertionMethod)
			if err == nil || !strings.Contains(err.Error(), member) {
				t.Errorf("%s method with %s: err = %v, want one naming %s", typ, member, err, member)
			}
		}
	}
}

// A method whose id is not in the one form is refused, not skipped: a reader
// that splits differently might take it for the key asked for.
func TestExtractPublicKey_RefusesAShadowMethod(t *testing.T) {
	pub := mustDecodeHex(t, w3cSigningKeyHex)
	shadow := mustDecodeHex(t, w3cMultikeyVMHex)
	for _, id := range []string{"#x#signing", "signing", subjectDID + "#x#signing", "#sign%69ng", "#signing ", "did:dplaax:other#signing"} {
		doc := did.New(did.DocumentFields{
			ID: subjectDID, Controller: subjectDID,
			VerificationMethod: []did.VerificationMethod{
				{ID: id, Type: "Multikey", Controller: subjectDID, PublicKeyMultibase: encodeMultikey(t, shadow)},
				multikeyVM(encodeMultikey(t, pub)),
			},
			AssertionMethod: []string{"#signing"},
		})
		if got, err := did.ExtractPublicKey(doc, "#signing", did.RelationshipAssertionMethod); !errors.Is(err, did.ErrInvalidKeyReference) {
			t.Errorf("shadow %q: ExtractPublicKey = (%x, %v), want ErrInvalidKeyReference", id, got, err)
		}
	}
}

// The subject is a DID: a document id with a fragment, a query or a path, or
// that is not a DID at all, resolves no reference. A resolved id resolves to
// itself.
func TestAbsoluteKeyID_TheSubjectIsADID(t *testing.T) {
	for _, subj := range []string{"", "did:example:a#old", "did:example:a?q=1", "did:example:a/path", "example:a", "did:EX:a"} {
		if got, err := did.AbsoluteKeyID(subj, "#key"); !errors.Is(err, did.ErrInvalidKeyReference) {
			t.Errorf("AbsoluteKeyID(%q, #key) = %q, %v; want ErrInvalidKeyReference", subj, got, err)
		}
	}
	id, err := did.AbsoluteKeyID(subjectDID, "#key")
	if err != nil {
		t.Fatal(err)
	}
	if again, err := did.AbsoluteKeyID(subjectDID, id); err != nil || again != id {
		t.Errorf("AbsoluteKeyID(%q) = %q, %v; want itself", id, again, err)
	}
}
