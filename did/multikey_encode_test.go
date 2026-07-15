package did_test

import (
	"testing"

	"github.com/provin-line/oss/did"
)

func TestEncodeEd25519Multikey_RoundTrips(t *testing.T) {
	// A key that cannot be read back is a key that was never published. The
	// encoder and the decoder are each other's only real test.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	vm, err := did.NewMultikeyVerificationMethod(subject+"#k1", subject, key)
	if err != nil {
		t.Fatalf("NewMultikeyVerificationMethod: %v", err)
	}
	doc := docWithVM(t, map[string]any{
		"id": vm.ID, "type": vm.Type, "controller": vm.Controller,
		"publicKeyMultibase": vm.PublicKeyMultibase,
	})
	got, enc, err := did.ExtractPublicKeyAndEncoding(doc, subject+"#k1", did.RelationshipAssertionMethod)
	if err != nil {
		t.Fatalf("ExtractPublicKeyAndEncoding: %v", err)
	}
	if enc != did.EncodingMultikey {
		t.Errorf("encoding = %q, want Multikey", enc)
	}
	if string(got) != string(key) {
		t.Errorf("key did not round-trip")
	}
}

func TestEncodeEd25519Multikey_RejectsWrongLength(t *testing.T) {
	if _, err := did.EncodeEd25519Multikey(make([]byte, 31)); err == nil {
		t.Error("encoded a 31-byte key as Ed25519")
	}
}
