package did_test

import (
	stded25519 "crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/did"
)

const subjectDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:proc1"

func ed25519JWK(pub []byte) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// docWith builds a DID document carrying vms, with #signing listed under the
// assertionMethod relationship — the adversarial cases craft vms directly
// (body-as-SoT documents are assembled from typed fields, never mutated).
func docWith(vms []did.VerificationMethod) *did.DIDDocument {
	return did.New(did.DocumentFields{
		ID:                 subjectDID,
		Controller:         subjectDID,
		VerificationMethod: vms,
		AssertionMethod:    []string{subjectDID + "#signing"},
		Authentication:     []string{},
	})
}

// docWithSigningKey builds a DID document whose #signing key (assertionMethod)
// carries an Ed25519 JWK for pub.
func docWithSigningKey(t *testing.T, pub []byte) *did.DIDDocument {
	t.Helper()
	return docWith([]did.VerificationMethod{{
		ID:           subjectDID + "#signing",
		Type:         "JsonWebKey2020",
		Controller:   subjectDID,
		PublicKeyJWK: ed25519JWK(pub),
	}})
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
	// A verification method whose controller is some other DID must be rejected
	// (key-confusion / cross-document injection defense).
	doc := docWith([]did.VerificationMethod{{
		ID:           subjectDID + "#signing",
		Type:         "JsonWebKey2020",
		Controller:   "did:dplaax:poc.dplaax.dev:org:evil",
		PublicKeyJWK: ed25519JWK(pub),
	}})
	if _, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("verification-method controller != document: want error")
	}
}

func TestExtractPublicKey_BadJWK(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)

	badDoc := func(jwk map[string]any) *did.DIDDocument {
		return docWith([]did.VerificationMethod{{
			ID:           subjectDID + "#signing",
			Type:         "JsonWebKey2020",
			Controller:   subjectDID,
			PublicKeyJWK: jwk,
		}})
	}

	// Wrong key type.
	j1 := ed25519JWK(pub)
	j1["kty"] = "RSA"
	if _, err := did.ExtractPublicKey(badDoc(j1), subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("non-OKP key type: want error")
	}

	// Wrong curve.
	j2 := ed25519JWK(pub)
	j2["crv"] = "X25519"
	if _, err := did.ExtractPublicKey(badDoc(j2), subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("non-Ed25519 curve: want error")
	}

	// Malformed base64 in x.
	j3 := ed25519JWK(pub)
	j3["x"] = "!!!not base64!!!"
	if _, err := did.ExtractPublicKey(badDoc(j3), subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("malformed base64url x: want error")
	}

	// Wrong key length (not 32 bytes).
	j4 := ed25519JWK(pub)
	j4["x"] = base64.RawURLEncoding.EncodeToString([]byte("too short"))
	if _, err := did.ExtractPublicKey(badDoc(j4), subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
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
	attacker := did.VerificationMethod{
		ID:           "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:attacker#signing",
		Type:         "JsonWebKey2020",
		Controller:   subjectDID, // spoofed to the document subject
		PublicKeyJWK: ed25519JWK(attackerPub),
	}
	real := did.VerificationMethod{
		ID:           subjectDID + "#signing",
		Type:         "JsonWebKey2020",
		Controller:   subjectDID,
		PublicKeyJWK: ed25519JWK(realPub),
	}
	doc := docWith([]did.VerificationMethod{attacker, real})

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
	dup := did.VerificationMethod{
		ID:           subjectDID + "#signing",
		Type:         "JsonWebKey2020",
		Controller:   subjectDID,
		PublicKeyJWK: ed25519JWK(attackerPub),
	}
	real := did.VerificationMethod{
		ID:           subjectDID + "#signing",
		Type:         "JsonWebKey2020",
		Controller:   subjectDID,
		PublicKeyJWK: ed25519JWK(realPub),
	}
	doc := docWith([]did.VerificationMethod{dup, real})

	if _, err := did.ExtractPublicKey(doc, subjectDID+"#signing", did.RelationshipAssertionMethod); err == nil {
		t.Error("duplicate verification-method id: want error (ambiguous key)")
	}
}

// New assembles a body from typed fields and the accessors read it back; empty
// members are omitted, not surfaced as zero values.
func TestDIDDocument_NewAccessorsRoundTrip(t *testing.T) {
	pub, _, _ := stded25519.GenerateKey(nil)
	doc := did.New(did.DocumentFields{
		Context:     []string{"https://www.w3.org/ns/did/v1"},
		ID:          subjectDID,
		Controller:  "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1",
		AlsoKnownAs: []string{"https://acme.example/p1/proc1"},
		VerificationMethod: []did.VerificationMethod{{
			ID:           subjectDID + "#signing",
			Type:         "JsonWebKey2020",
			Controller:   subjectDID,
			PublicKeyJWK: ed25519JWK(pub),
		}},
		AssertionMethod: []string{subjectDID + "#signing"},
		Service: []did.ServiceEndpoint{{
			ID:              subjectDID + "#vc-resolver",
			Type:            "VCResolver",
			ServiceEndpoint: "https://registry.example/vc",
		}},
	})

	if doc.ID() != subjectDID {
		t.Errorf("ID()=%q, want %q", doc.ID(), subjectDID)
	}
	if doc.Controller() != "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1" {
		t.Errorf("Controller()=%q", doc.Controller())
	}
	if aka := doc.AlsoKnownAs(); len(aka) != 1 || aka[0] != "https://acme.example/p1/proc1" {
		t.Errorf("AlsoKnownAs()=%v", aka)
	}
	if vms := doc.VerificationMethod(); len(vms) != 1 || vms[0].ID != subjectDID+"#signing" {
		t.Errorf("VerificationMethod()=%v", vms)
	}
	if am := doc.AssertionMethod(); len(am) != 1 || am[0] != subjectDID+"#signing" {
		t.Errorf("AssertionMethod()=%v", am)
	}
	if svc := doc.Service(); len(svc) != 1 || svc[0].Type != "VCResolver" {
		t.Errorf("Service()=%v", svc)
	}
	// An owner-style document omits an empty controller rather than surfacing "".
	owner := did.New(did.DocumentFields{ID: "did:dplaax:poc.dplaax.dev:org:acme"})
	if _, present := owner.Body()["controller"]; present {
		t.Error("empty controller must be omitted from the body")
	}
}

// Body returns a defensive copy: mutating it does not change the document.
func TestDIDDocument_BodyDefensiveCopy(t *testing.T) {
	doc := did.New(did.DocumentFields{ID: subjectDID, Controller: subjectDID})
	b := doc.Body()
	b["id"] = "tampered"
	if doc.ID() != subjectDID {
		t.Error("mutating Body() leaked into the document")
	}
}

// Unknown members survive the resolution round-trip and participate in the hash
// — required because the document hash is recorded as a lifecycle snapshot.
func TestDIDDocument_UnknownMembersPreserved(t *testing.T) {
	wire := []byte(`{"id":"` + subjectDID + `","controller":"` + subjectDID + `","futureProperty":{"k":"v"},"keyAgreement":["` + subjectDID + `#kex"]}`)
	var doc did.DIDDocument
	if err := json.Unmarshal(wire, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := doc.Body()["futureProperty"]; !present {
		t.Error("unknown member futureProperty was dropped on round-trip")
	}
	if _, present := doc.Body()["keyAgreement"]; !present {
		t.Error("unmodelled member keyAgreement was dropped on round-trip")
	}
	// Re-marshalling must retain the unknown members.
	out, err := json.Marshal(&doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var reparsed map[string]any
	if err := json.Unmarshal(out, &reparsed); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if _, present := reparsed["futureProperty"]; !present {
		t.Error("futureProperty did not survive Marshal")
	}
}

// A present-but-wrong-typed KNOWN member must fail closed on unmarshal, exactly
// as the former typed decode did: preserving unknown members must not extend to
// tolerating malformed known ones. The dangerous case is a non-string
// controller, which the accessor would otherwise collapse to "" — and "" means
// "self-controlled owner" to the chain walk, so a malformed owner document
// would silently pass chain-consistency (fail-open).
func TestDIDDocument_MalformedKnownMemberRejected(t *testing.T) {
	cases := map[string]string{
		"controller as array":       `{"id":"` + subjectDID + `","controller":["` + subjectDID + `"]}`,
		"controller as object":      `{"id":"` + subjectDID + `","controller":{"id":"x"}}`,
		"id as number":              `{"id":123}`,
		"authentication as string":  `{"id":"` + subjectDID + `","authentication":"` + subjectDID + `#auth"}`,
		"verificationMethod object": `{"id":"` + subjectDID + `","verificationMethod":{"id":"x"}}`,
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			var doc did.DIDDocument
			if err := json.Unmarshal([]byte(wire), &doc); err == nil {
				t.Errorf("malformed known member (%s) was accepted; want fail-closed error", name)
			}
		})
	}

	// Unknown members of any type remain preserved (not validated).
	var ok did.DIDDocument
	if err := json.Unmarshal([]byte(`{"id":"`+subjectDID+`","futureScalar":1,"futureArr":["x"],"futureObj":{"k":"v"}}`), &ok); err != nil {
		t.Fatalf("unknown members must not be validated: %v", err)
	}
}

// Hash is deterministic over the canonical body and changes when any member —
// including an unmodelled one — changes.
func TestDIDDocument_HashDeterministicAndMemberSensitive(t *testing.T) {
	var a, b did.DIDDocument
	if err := json.Unmarshal([]byte(`{"id":"`+subjectDID+`","x":1}`), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"id":"`+subjectDID+`","x":1}`), &b); err != nil {
		t.Fatal(err)
	}
	ha, err := a.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	hb, _ := b.Hash()
	if ha != hb {
		t.Errorf("identical bodies hashed differently: %q vs %q", ha, hb)
	}

	var c did.DIDDocument
	if err := json.Unmarshal([]byte(`{"id":"`+subjectDID+`","x":2}`), &c); err != nil {
		t.Fatal(err)
	}
	hc, _ := c.Hash()
	if ha == hc {
		t.Error("a changed member did not change the hash")
	}
}
