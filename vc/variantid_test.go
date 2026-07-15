package vc_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

// The conformance harness pins the ID's VALUE against hashes the catalog
// derived from its own rule text (conformance/vectors/dplaax/identity-001).
// These tests pin its PROPERTIES — the things a value KAT cannot show:
// spelling-insensitivity, domain separation, and what the grammar rejects.

const variantProof = `"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022",` +
	`"verificationMethod":"did:dplaax:poc.dplaax.dev:org:acme#signing",` +
	`"proofPurpose":"assertionMethod","created":"2026-06-10T12:00:00Z","proofValue":"z3FXQ"}`

// signedFixture returns a signed credential's canonical wire bytes.
func signedFixture(t *testing.T) []byte {
	t.Helper()
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	wire, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	signed := strings.Replace(string(wire), "{", "{"+variantProof+",", 1)
	return []byte(signed)
}

func mustParseCred(t *testing.T, wire []byte) *vc.PipelinePassCredential {
	t.Helper()
	var c vc.PipelinePassCredential
	if err := c.UnmarshalJSON(wire); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	return &c
}

// TestWireVariantIDIsIndifferentToSpelling is the property the id exists for:
// it names the canonical projection, so two spellings of one document — the
// difference between two conformant peers' serializers — admit under ONE id.
// Were it over submission octets instead, either peer could mint a second
// identity for the same signed form just by re-serializing it.
func TestWireVariantIDIsIndifferentToSpelling(t *testing.T) {
	wire := signedFixture(t)
	canonical := mustParseCred(t, wire)

	// Same document, non-canonical spelling: whitespace the canonicalizer
	// removes. It must not change the id.
	respelled := mustParseCred(t, []byte(strings.Replace(string(wire), "{", "{  ", 1)))

	want, err := canonical.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	got, err := respelled.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID (respelled): %v", err)
	}
	if got != want {
		t.Errorf("re-spelling the same document changed its variant id:\n got %s\nwant %s", got, want)
	}
}

// TestWireVariantIDSeparatesProofs is the other half: the id must move when
// the signed form does, or one variant could be served for another.
func TestWireVariantIDSeparatesProofs(t *testing.T) {
	a := mustParseCred(t, signedFixture(t))
	b := mustParseCred(t, []byte(strings.Replace(string(signedFixture(t)), `"z3FXQ"`, `"z3FXR"`, 1)))

	idA, err := a.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	idB, err := b.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	if idA == idB {
		t.Fatal("two different proofs share a variant id")
	}
	// ...while the body address — what successors link to — does not move.
	hashA, _ := a.Hash()
	hashB, _ := b.Hash()
	if hashA != hashB {
		t.Errorf("re-issuing a proof moved the body address: %s != %s", hashA, hashB)
	}
}

// TestWireVariantIDIsDomainSeparated proves the domain tag does work rather
// than decorating the input. Without it the digest would be a bare sha256 of
// the wire bytes, so any other role digesting those same bytes would produce
// a colliding id — the ambiguity the tag exists to prevent.
func TestWireVariantIDIsDomainSeparated(t *testing.T) {
	wire := signedFixture(t)
	c := mustParseCred(t, wire)
	id, err := c.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	canonical, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	sum := sha256.Sum256(canonical)
	if untagged := hex.EncodeToString(sum[:]); strings.HasSuffix(id, untagged) {
		t.Error("variant id equals the undomained sha256 of the wire bytes — the domain tag is not being mixed in")
	}
}

// TestWireVariantIDOfMatchesTheCredentialPath pins the two entry points to one
// answer: a store validating bytes it read back must reach the same id as the
// credential that produced them, or a round-trip through storage would rename
// the variant.
func TestWireVariantIDOfMatchesTheCredentialPath(t *testing.T) {
	c := mustParseCred(t, signedFixture(t))
	canonical, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	viaCred, err := c.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	if viaBytes := vc.WireVariantIDOf(canonical); viaBytes != viaCred {
		t.Errorf("WireVariantIDOf = %s, WireVariantID = %s", viaBytes, viaCred)
	}
}

// TestWireVariantIDOfUnsignedCredential pins current behavior rather than
// choosing one: an unsigned credential's wire form IS its body, so the id is
// defined with no special case. Whether an unsigned credential is admissible
// is the store's question (T2), not the id's.
func TestWireVariantIDOfUnsignedCredential(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	if c.Proof() != nil {
		t.Fatal("fixture is signed — this test is about the unsigned path")
	}
	id, err := c.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	if !vc.IsWireVariantID(id) {
		t.Errorf("unsigned credential produced a malformed id: %s", id)
	}
	// The signed form of the same body is a DIFFERENT variant: a signature is
	// part of what the id names.
	signed := mustParseCred(t, signedFixture(t))
	signedID, err := signed.WireVariantID()
	if err != nil {
		t.Fatalf("WireVariantID: %v", err)
	}
	if signedID == id {
		t.Error("signing a credential did not change its variant id")
	}
}

func TestIsWireVariantID(t *testing.T) {
	const validHex = "57c6e5ceaf53648e3e3e175f6e1345790a08522d5689a5460d6435500bf6ff21"
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"canonical", "wire:v1:jcs-rfc8785:sha256:" + validHex, true},
		{"empty", "", false},
		{"bare hex", validHex, false},
		{"content address of the body", "sha256:" + validHex, false},
		// A profile change must claim a new id space rather than reuse this
		// one — the prefix is the claim, so every part of it is checked.
		{"wrong id version", "wire:v2:jcs-rfc8785:sha256:" + validHex, false},
		{"wrong canonicalizer", "wire:v1:jcs:sha256:" + validHex, false},
		{"wrong hash algorithm", "wire:v1:jcs-rfc8785:sha512:" + validHex, false},
		{"no prefix at all", "wire:" + validHex, false},
		// Uppercase is a second spelling of one digest; ids are compared as
		// strings (map keys, file names), so folding would admit two
		// identities for one variant.
		{"uppercase hex", "wire:v1:jcs-rfc8785:sha256:" + strings.ToUpper(validHex), false},
		// validHex[2] is 'c' — a LETTER. Upper-casing a digit position would
		// leave the string identical and quietly assert nothing.
		{"mixed-case hex", "wire:v1:jcs-rfc8785:sha256:" + validHex[:2] + "C" + validHex[3:], false},
		{"hex too short", "wire:v1:jcs-rfc8785:sha256:" + validHex[:63], false},
		{"hex too long", "wire:v1:jcs-rfc8785:sha256:" + validHex + "a", false},
		{"non-hex character", "wire:v1:jcs-rfc8785:sha256:" + validHex[:63] + "g", false},
		{"trailing space", "wire:v1:jcs-rfc8785:sha256:" + validHex + " ", false},
		{"prefix only", "wire:v1:jcs-rfc8785:sha256:", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := vc.IsWireVariantID(tc.in); got != tc.want {
				t.Errorf("IsWireVariantID(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
