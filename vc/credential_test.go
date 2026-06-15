package vc_test

import (
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/vc"
)

func subjectFields() vc.CredentialSubjectFields {
	return vc.CredentialSubjectFields{
		PipelineID:          "urn:pipeline:analytics:price-report",
		ProcessID:           "urn:process:filter-01",
		TransformationClaim: vc.ClaimFilter,
		Schema: vc.SchemaRef{
			ID:          "urn:schema:price:1",
			Type:        "JsonSchema",
			ContentHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		InputHash:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		OutputHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	}
}

func newCred(t *testing.T, fields vc.CredentialFields) *vc.PipelinePassCredential {
	t.Helper()
	c, err := vc.New(fields)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewAndAccessors(t *testing.T) {
	validFrom := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	c := newCred(t, vc.CredentialFields{
		Issuer:             "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:filter-01",
		ValidFrom:          validFrom,
		Subject:            subjectFields(),
		PreviousCredential: "sha256:" + strings.Repeat("3", 64),
	})

	if got := c.Issuer(); got != "did:dplaax:poc.dplaax.io:org:acme:pipeline:p1:process:filter-01" {
		t.Errorf("Issuer = %q", got)
	}
	vf, err := c.ValidFrom()
	if err != nil {
		t.Fatalf("ValidFrom: %v", err)
	}
	if !vf.Equal(validFrom) {
		t.Errorf("ValidFrom = %v, want %v", vf, validFrom)
	}
	subj, err := c.Subject()
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if subj != subjectFields() {
		t.Errorf("Subject = %+v, want %+v", subj, subjectFields())
	}
	if got := c.PreviousCredential(); got != "sha256:"+strings.Repeat("3", 64) {
		t.Errorf("PreviousCredential = %q", got)
	}
	if c.SourceCommitment() != nil {
		t.Errorf("SourceCommitment = %+v, want nil", c.SourceCommitment())
	}
	if c.Proof() != nil {
		t.Errorf("Proof = %+v, want nil (unsigned)", c.Proof())
	}
}

func TestNewWithSourceCommitment(t *testing.T) {
	commitment := &vc.SourceCommitment{
		DerivedFrom: []string{
			"did:dplaax:poc.dplaax.io:org:mineA:pipeline:m:process:src",
			"did:dplaax:poc.dplaax.io:org:mineB:pipeline:m:process:src",
		},
		SourceRoot:          "f1220" + strings.Repeat("ab", 32),
		SourceRootCanonical: vc.SourceRootCanonicalJCS,
	}
	subj := subjectFields()
	subj.TransformationClaim = vc.ClaimAggregate
	subj.InputHash = "" // absent for aggregation FirstDrops
	c := newCred(t, vc.CredentialFields{
		Issuer:           "did:dplaax:poc.dplaax.io:org:factory:pipeline:agg:process:agg-01",
		ValidFrom:        time.Now(),
		Subject:          subj,
		SourceCommitment: commitment,
	})

	got := c.SourceCommitment()
	if got == nil {
		t.Fatal("SourceCommitment = nil, want commitment")
	}
	if got.SourceRoot != commitment.SourceRoot || got.SourceRootCanonical != commitment.SourceRootCanonical {
		t.Errorf("SourceCommitment = %+v, want %+v", got, commitment)
	}
	if len(got.DerivedFrom) != 2 || got.DerivedFrom[0] != commitment.DerivedFrom[0] {
		t.Errorf("DerivedFrom = %v", got.DerivedFrom)
	}
	// Defensive copy: mutating the returned commitment must not affect the body.
	got.DerivedFrom[0] = "tampered"
	if c.SourceCommitment().DerivedFrom[0] == "tampered" {
		t.Error("SourceCommitment() returned a live reference, want defensive copy")
	}
	if c.PreviousCredential() != "" {
		t.Errorf("PreviousCredential = %q, want empty (FirstDrop)", c.PreviousCredential())
	}
}

func TestHashDeterministicAndDefensiveBody(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	h1, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h1, "sha256:") || len(h1) != len("sha256:")+64 {
		t.Errorf("Hash format: %q", h1)
	}
	// Mutating the Body() copy must not change the credential's hash.
	body := c.Body()
	body["issuer"] = "did:dplaax:evil"
	delete(body, "credentialSubject")
	h2, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h1 != h2 {
		t.Errorf("Hash changed after mutating Body() copy: %s -> %s", h1, h2)
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:             "did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x",
		ValidFrom:          time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:            subjectFields(),
		PreviousCredential: "sha256:" + strings.Repeat("4", 64),
	})
	wire, err := c.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	// The wire key and namespaced value are the contract — pin the literals
	// so a typo in the wire constants cannot round-trip invisibly.
	if !strings.Contains(string(wire), `"transformationClaim":"provin:filter"`) {
		t.Errorf("wire form missing transformationClaim literal: %s", wire)
	}
	// The @context array is the signing-scope contract: protocol context
	// plus the provin profile context that grounds the claim namespace.
	if !strings.Contains(string(wire),
		`"@context":["https://www.w3.org/ns/credentials/v2","https://poc.dplaax.io/vc/v1","https://poc.provin-line.io/vc/v1"]`) {
		t.Errorf("wire form missing expected @context array: %s", wire)
	}
	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON(wire); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	h1, _ := c.Hash()
	h2, err := rt.Hash()
	if err != nil {
		t.Fatalf("Hash after round-trip: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash diverged across round-trip: %s -> %s", h1, h2)
	}
	if rt.Issuer() != c.Issuer() || rt.PreviousCredential() != c.PreviousCredential() {
		t.Error("accessor mismatch after round-trip")
	}
}

func TestUnknownSignedScopeFieldSurvives(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	baseHash, _ := c.Hash()
	wire, _ := c.MarshalJSON()
	// Inject an unknown top-level field the way a future vocabulary would.
	extended := strings.Replace(string(wire), "{", `{"futureField":"x",`, 1)

	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON([]byte(extended)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	rtHash, err := rt.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if rtHash == baseHash {
		t.Error("unknown field did not participate in the hash")
	}
	rewire, err := rt.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if !strings.Contains(string(rewire), `"futureField":"x"`) {
		t.Errorf("unknown field lost on re-marshal: %s", rewire)
	}
}

func TestUnmarshalProofExcludedFromHash(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	unsignedHash, _ := c.Hash()
	wire, _ := c.MarshalJSON()
	withProof := strings.Replace(string(wire), "{",
		`{"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:dplaax:poc.dplaax.io:org:acme#signing","proofPurpose":"assertionMethod","created":"2026-06-10T12:00:00Z","proofValue":"z3FXQ"},`, 1)

	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON([]byte(withProof)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	p := rt.Proof()
	if p == nil || p.Cryptosuite != "eddsa-jcs-2022" || p.ProofValue != "z3FXQ" {
		t.Fatalf("Proof = %+v", p)
	}
	h, err := rt.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h != unsignedHash {
		t.Errorf("proof leaked into the signing scope: %s != %s", h, unsignedHash)
	}
	// Proof survives re-marshal.
	rewire, _ := rt.MarshalJSON()
	if !strings.Contains(string(rewire), `"proofValue":"z3FXQ"`) {
		t.Errorf("proof lost on re-marshal: %s", rewire)
	}
}

func TestUnmarshalRejectsDuplicateKeys(t *testing.T) {
	var rt vc.PipelinePassCredential
	err := rt.UnmarshalJSON([]byte(`{"issuer":"a","issuer":"b"}`))
	if err == nil {
		t.Error("want duplicate-key rejection, got nil")
	}
}

func TestUnmarshalProofUnknownMembersSurvive(t *testing.T) {
	c := newCred(t, vc.CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.io:org:acme:pipeline:p:process:x",
		ValidFrom: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		Subject:   subjectFields(),
	})
	wire, _ := c.MarshalJSON()
	withProof := strings.Replace(string(wire), "{",
		`{"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","proofValue":"zX","domain":"example.com","challenge":"abc123","created":"2026-06-10T12:00:00Z","verificationMethod":"did:x#k","proofPurpose":"assertionMethod"},`, 1)

	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON([]byte(withProof)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	rewire, err := rt.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, member := range []string{`"domain":"example.com"`, `"challenge":"abc123"`} {
		if !strings.Contains(string(rewire), member) {
			t.Errorf("proof member lost on round-trip: %s missing from %s", member, rewire)
		}
	}
	// Round-trip stability: a second unmarshal/marshal is byte-identical.
	var rt2 vc.PipelinePassCredential
	if err := rt2.UnmarshalJSON(rewire); err != nil {
		t.Fatalf("second UnmarshalJSON: %v", err)
	}
	rewire2, _ := rt2.MarshalJSON()
	if string(rewire) != string(rewire2) {
		t.Error("wire form not stable across round-trips")
	}
}

func TestUnmarshalProofSetRejected(t *testing.T) {
	var rt vc.PipelinePassCredential
	err := rt.UnmarshalJSON([]byte(`{"issuer":"did:x","proof":[{"type":"DataIntegrityProof"}]}`))
	if err == nil {
		t.Error("proof set (array): want loud rejection, got nil")
	}
}

func TestUnmarshalEmptyObject(t *testing.T) {
	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON([]byte(`{}`)); err != nil {
		t.Fatalf("UnmarshalJSON({}): %v", err)
	}
	if rt.Issuer() != "" || rt.SourceCommitment() != nil || rt.Proof() != nil {
		t.Error("empty credential should read as zero values")
	}
}
