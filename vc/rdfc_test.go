package vc_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/vc"
)

// provinDocument builds a real-shape provin credential body (the frozen
// 3-context wire form) without a proof — the document eddsa-rdfc-2022 must
// handle end to end.
func provinDocument(t testing.TB) map[string]any {
	t.Helper()
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuerDID,
		ValidFrom: time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC),
		Subject: vc.CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "proc1",
			TransformationClaim: vc.ClaimConvert,
			InputHash:           "sha256:" + repeatHex("ab"),
			OutputHash:          "sha256:" + repeatHex("cd"),
		},
		PreviousCredential: "sha256:" + repeatHex("ef"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cred.Body()
}

func repeatHex(pair string) string {
	out := ""
	for i := 0; i < 32; i++ {
		out += pair
	}
	return out
}

// eddsa-rdfc-2022 signs and verifies a real provin credential — the suite is
// registered, canonicalizes through URDNA2015, and the proof round-trips.
func TestRDFC_CreateVerifyProof_RoundTrip(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)

	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof(eddsa-rdfc-2022): %v", err)
	}
	if proof.Cryptosuite != vc.CryptosuiteEdDSARDFC2022 {
		t.Errorf("proof.Cryptosuite = %q", proof.Cryptosuite)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err != nil {
		t.Errorf("VerifyProof on a genuine rdfc proof: %v", err)
	}
}

// The signature covers the proof configuration: tampering any typed proof
// field breaks verification (same shape as the JCS suite's guarantee).
func TestRDFC_VerifyProof_TamperedProofConfig(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *vc.DataIntegrityProof)
	}{
		{"created", func(p *vc.DataIntegrityProof) { p.Created = "2020-01-01T00:00:00Z" }},
		{"verificationMethod", func(p *vc.DataIntegrityProof) { p.VerificationMethod = issuerDID + "#other" }},
		{"proofPurpose", func(p *vc.DataIntegrityProof) { p.ProofPurpose = "authentication" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *proof
			tc.mutate(&tampered)
			if err := vc.VerifyProof(ed25519.Verifier{}, pub, &tampered, doc); err == nil {
				t.Error("VerifyProof must fail when a signed proof field is tampered")
			}
		})
	}
}

// Tampering the document body after signing breaks verification.
func TestRDFC_VerifyProof_TamperedDocument(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	doc["credentialSubject"].(map[string]any)["outputHash"] = "sha256:" + repeatHex("00")
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof must fail on a tampered document")
	}
}

// The H1 fail-closed defense is reachable through the public signing API: a
// document member no frozen context defines refuses to SIGN (it would ride
// the credential outside the signature), and the same shape refuses to
// VERIFY. Under eddsa-jcs-2022 the identical document signs fine — JCS signs
// every member, so the defense is RDFC-specific by design.
func TestRDFC_UndefinedMember_RefusedBothSides(t *testing.T) {
	signer, pub, _ := fixture(t)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["smuggledField"] = "unsigned rider"

	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil {
		t.Error("CreateProof(rdfc) must refuse a member no frozen context defines")
	}

	jcsProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof(jcs) on the same document: %v", err)
	}
	rdfcShaped := *jcsProof
	rdfcShaped.Cryptosuite = vc.CryptosuiteEdDSARDFC2022
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, &rdfcShaped, doc); err == nil {
		t.Error("VerifyProof(rdfc) must refuse a member no frozen context defines")
	}
}

// The H3 fail-closed defense through the public API: a numeric member
// refuses to sign on the RDFC path.
func TestRDFC_NumericMember_Refused(t *testing.T) {
	signer, _, _ := fixture(t)
	doc := provinDocument(t)
	doc["credentialSubject"].(map[string]any)["schema"] = map[string]any{"version": float64(2)}
	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil {
		t.Error("CreateProof(rdfc) must refuse a numeric member")
	}
}

// listDocument is a credential, of the served contexts alone, whose subject
// carries an @list of n equal strings. Labelling it costs about n³, so a long
// one is too complex.
func listDocument(n int) map[string]any {
	steps := make([]any, n)
	for i := range steps {
		steps[i] = "pass"
	}
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuerDID,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"https://example.org/steps": map[string]any{"@list": steps}},
	}
}

// valuesDocument is a credential, of the served contexts alone, whose subject
// has n distinct strings on one property. json-gold's node map compares each
// with those before it, so a long one is too complex.
func valuesDocument(n int) map[string]any {
	values := make([]any, n)
	for i := range values {
		values[i] = fmt.Sprintf("v%d", i)
	}
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuerDID,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"https://example.org/values": values},
	}
}

// longSubjectDocument is a credential whose subject, of an IRI of length
// bytes, has n properties: each quad of the canonical form writes the IRI,
// so a long one with many properties is too complex.
func longSubjectDocument(n, length int) map[string]any {
	subject := map[string]any{"id": "urn:x:" + strings.Repeat("a", length)}
	for i := range n {
		subject[fmt.Sprintf("urn:p:%d", i)] = "v"
	}
	return map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            issuerDID,
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": subject,
	}
}

// Every primitive that canonicalizes refuses a document too complex to
// canonicalize, in every stage (building its dataset, writing its canonical
// form, labelling it), and errors.Is reaches urdna2015.ErrTooComplex through
// vc's wrapping.
func TestRDFC_TooComplexToCanonicalizeReachesTheCaller(t *testing.T) {
	signer, pub, _ := fixture(t)
	for _, tc := range []struct {
		stage         string
		short, long   map[string]any
		shortN, longN int
	}{
		{"labelling, equal values in a list", listDocument(16), listDocument(64), 16, 64},
		{"node map, distinct values on one property", valuesDocument(20), valuesDocument(3000), 20, 3000},
		{"canonical form, a long subject IRI in every quad", longSubjectDocument(10, 100), longSubjectDocument(1000, 100_000), 10, 1000},
	} {
		proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, tc.short, vc.CryptosuiteEdDSARDFC2022)
		if err != nil {
			t.Fatalf("%s: CreateProof with %d values: %v", tc.stage, tc.shortN, err)
		}
		if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, tc.short); err != nil {
			t.Fatalf("%s: VerifyProof with %d values: %v", tc.stage, tc.shortN, err)
		}

		if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, tc.long, vc.CryptosuiteEdDSARDFC2022); !errors.Is(err, urdna2015.ErrTooComplex) {
			t.Errorf("%s: CreateProof with %d values: err = %v, want urdna2015.ErrTooComplex", tc.stage, tc.longN, err)
		}
		// The genuine proof of the short document, presented with the long
		// one: the proof config is the same, so only the document's
		// canonicalizing refuses it.
		if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, tc.long); !errors.Is(err, urdna2015.ErrTooComplex) {
			t.Errorf("%s: VerifyProof: err = %v, want urdna2015.ErrTooComplex", tc.stage, err)
		}
		if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, proof, tc.long); !errors.Is(err, urdna2015.ErrTooComplex) {
			t.Errorf("%s: VerifyProofWithContract: err = %v, want urdna2015.ErrTooComplex", tc.stage, err)
		}
		if err := vc.VerifyProofUnderContract(ed25519.Verifier{}, pub, proof, tc.long, vc.ContractW3CEdDSARDFC2022); !errors.Is(err, urdna2015.ErrTooComplex) {
			t.Errorf("%s: VerifyProofUnderContract: err = %v, want urdna2015.ErrTooComplex", tc.stage, err)
		}
	}
}

// A credential holding a value its canonical form would not hold is refused
// before its signature is checked, from every primitive: here a proof given
// as an IRI on a subject typed VerifiableCredential, which the W3C context
// puts in a graph of its own, where nothing names it.
func TestRDFC_RefusesAValueItWouldNotSign(t *testing.T) {
	signer, pub, _ := fixture(t)
	credential := func(subject map[string]any) map[string]any {
		return map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
			"type":              []any{"VerifiableCredential"},
			"issuer":            issuerDID,
			"validFrom":         "2026-01-01T00:00:00Z",
			"credentialSubject": subject,
		}
	}
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, credential(map[string]any{"id": "did:example:s"}), vc.CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatal(err)
	}
	doc := credential(map[string]any{"id": "did:example:s", "type": "VerifiableCredential", "proof": "https://example.org/a"})
	const want = "in no quad"
	if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("CreateProof: %v, want the value refused", err)
	}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("VerifyProof: %v, want the value refused", err)
	}
	if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, proof, doc); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("VerifyProofWithContract: %v, want the value refused", err)
	}
	if err := vc.VerifyProofUnderContract(ed25519.Verifier{}, pub, proof, doc, vc.ContractW3CEdDSARDFC2022); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("VerifyProofUnderContract: %v, want the value refused", err)
	}
}

// A credential holding a context written in it, rather than the IRI of one
// the suite serves, is refused before its signature is checked, from every
// primitive: here a context setting @base, and one defining a term. Its
// proof's context mirrors the document's, so the proof is refused first.
func TestRDFC_RefusesAContextWrittenInTheDocument(t *testing.T) {
	signer, pub, _ := fixture(t)
	for name, ctx := range map[string]map[string]any{
		"@base":  {"@base": "https://example.org/"},
		"a term": {"amount": "https://example.org/amount"},
	} {
		doc := map[string]any{
			"@context":          []any{"https://www.w3.org/ns/credentials/v2", ctx},
			"type":              []any{"VerifiableCredential"},
			"issuer":            issuerDID,
			"validFrom":         "2026-01-01T00:00:00Z",
			"credentialSubject": map[string]any{"id": "https://example.org/s"},
		}
		// A proof whose @context mirrors the document's, made under JCS,
		// which signs the bytes and reads no context.
		jcsProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
		if err != nil {
			t.Fatal(err)
		}
		proof := *jcsProof
		proof.Cryptosuite = vc.CryptosuiteEdDSARDFC2022
		const want = "only the IRIs of the contexts it serves"
		if _, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSARDFC2022); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: CreateProof: %v, want the context refused", name, err)
		}
		if err := vc.VerifyProof(ed25519.Verifier{}, pub, &proof, doc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: VerifyProof: %v, want the context refused", name, err)
		}
		if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, &proof, doc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: VerifyProofWithContract: %v, want the context refused", name, err)
		}
		if err := vc.VerifyProofUnderContract(ed25519.Verifier{}, pub, &proof, doc, vc.ContractW3CEdDSARDFC2022); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: VerifyProofUnderContract: %v, want the context refused", name, err)
		}
	}
}
