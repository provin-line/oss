package urdna2015_test

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/urdna2015"
)

// Context IRIs served by the test loader (the W3C vector's context set).
// The w3c-ex*.{json,nq} testdata files are Examples 8/9 (credential /
// canonical credential) and 11/12 (proof options / canonical proof options)
// of https://www.w3.org/TR/vc-di-eddsa/ §3.1 (eddsa-rdfc-2022), extracted
// verbatim; re-verify against the spec URL, not this repo's history.
const (
	ctxCredentialsV2 = "https://www.w3.org/ns/credentials/v2"
	ctxExamplesV2    = "https://www.w3.org/ns/credentials/examples/v2"
)

var _ canon.Canonicalizer = (*urdna2015.Canonicalizer)(nil)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readJSON(t *testing.T, name string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(read(t, name), &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

// w3cCanonicalizer serves exactly the two W3C contexts the official test
// vector's documents reference.
func w3cCanonicalizer(t *testing.T) *urdna2015.Canonicalizer {
	t.Helper()
	return urdna2015.NewCanonicalizer(map[string][]byte{
		ctxCredentialsV2: read(t, "credentials-v2.jsonld"),
		ctxExamplesV2:    read(t, "examples-v2.jsonld"),
	})
}

// canonEquals compares canonical N-Quads output against a pinned vector,
// tolerating only the trailing-newline difference from the HTML extraction.
func canonEquals(t *testing.T, got []byte, wantFile string) {
	t.Helper()
	want := strings.TrimRight(string(read(t, wantFile)), "\n")
	if strings.TrimRight(string(got), "\n") != want {
		t.Errorf("canonical N-Quads mismatch:\n--- got ---\n%s\n--- want (%s) ---\n%s", got, wantFile, want)
	}
}

// The freeze anchor: the official W3C vc-di-eddsa test vector's credential
// (Example 8) canonicalizes to the official canonical N-Quads (Example 9).
// Matching the published vector — not a self-produced golden — is the
// evidence that a non-Go W3C verifier computes the same signing bytes.
func TestCanonicalize_W3CVector_Credential(t *testing.T) {
	got, err := w3cCanonicalizer(t).Canonicalize(readJSON(t, "w3c-ex8-credential.json"))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	canonEquals(t, got, "w3c-ex9-canonical-credential.nq")
}

// The proof-options half of the vector (Example 11 → Example 12): the proof
// config canonicalizes through the same path as the document.
func TestCanonicalize_W3CVector_ProofOptions(t *testing.T) {
	got, err := w3cCanonicalizer(t).Canonicalize(readJSON(t, "w3c-ex11-proof-options.json"))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	canonEquals(t, got, "w3c-ex12-canonical-proof-options.nq")
}

// Canonical output is deterministic across repeated and concurrent calls —
// two peers (or two goroutines) must never compute different signing bytes.
func TestCanonicalize_Deterministic(t *testing.T) {
	c := w3cCanonicalizer(t)
	doc := readJSON(t, "w3c-ex8-credential.json")
	first, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.Canonicalize(readJSON(t, "w3c-ex8-credential.json"))
			if err != nil {
				t.Errorf("Canonicalize: %v", err)
				return
			}
			if string(got) != string(first) {
				t.Error("concurrent canonicalization diverged")
			}
		}()
	}
	wg.Wait()
}

// A context IRI outside the embedded allowlist is an error — never a network
// fetch. (There is no network seam in the implementation at all; this pins
// the error path a hostile credential would take.)
func TestCanonicalize_UnknownContextIRI_Errors(t *testing.T) {
	c := urdna2015.NewCanonicalizer(map[string][]byte{
		ctxCredentialsV2: read(t, "credentials-v2.jsonld"),
	})
	doc := map[string]any{
		"@context": []any{ctxCredentialsV2, "https://evil.example/context/v1"},
		"type":     []any{"VerifiableCredential"},
	}
	if _, err := c.Canonicalize(doc); err == nil {
		t.Fatal("unknown context IRI: want error, got canonical output")
	} else if !strings.Contains(err.Error(), "evil.example") {
		t.Errorf("error should name the refused IRI: %v", err)
	}
}

// A string input is rejected outright: json-gold would treat it as a remote
// document URL to fetch, which must be structurally impossible here.
func TestCanonicalize_NonObjectInput_Errors(t *testing.T) {
	c := w3cCanonicalizer(t)
	for _, in := range []any{"https://evil.example/doc.jsonld", 42, 3.14, true} {
		if _, err := c.Canonicalize(in); err == nil {
			t.Errorf("Canonicalize(%T %v): want error", in, in)
		}
	}
}

// H1 defense (undefined term): a property that no frozen context defines is
// REJECTED, not silently dropped from the signing scope. JSON-LD expansion
// drops undefined terms by default — under JCS every member is signed, so on
// the RDFC path an undefined member would ride the credential unsigned
// (malleable). The credentials/v2 context has no @vocab, so this is a live
// hazard, not a theoretical one.
func TestCanonicalize_UndefinedTerm_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	doc := map[string]any{
		// credentials/v2 only, no examples/v2 (@vocab) — "smuggled" has no
		// definition anywhere.
		"@context":  []any{ctxCredentialsV2},
		"type":      []any{"VerifiableCredential"},
		"issuer":    "https://vc.example/issuers/5678",
		"validFrom": "2023-01-01T00:00:00Z",
		"smuggled":  "rides unsigned if dropped",
	}
	if _, err := c.Canonicalize(doc); err == nil {
		t.Fatal("undefined term: want error, got canonical output (silent drop)")
	}
}

// Same defense one level down: an undefined member inside credentialSubject
// is rejected too — expansion applies per node, not just at the top level.
func TestCanonicalize_UndefinedNestedTerm_Rejected(t *testing.T) {
	doc := readJSON(t, "w3c-ex8-credential.json")
	doc["@context"] = []any{ctxCredentialsV2} // drop examples/v2 so alumniOf is undefined
	if _, err := w3cCanonicalizer(t).Canonicalize(doc); err == nil {
		t.Fatal("undefined nested term: want error, got canonical output")
	}
}

// H3 defense (unsafe numerics): a numeric member is rejected on the RDFC
// path. json-gold truncates integers above 2^53 (float64 transit), so a
// received credential's numeric extension member could be silently altered
// between the bytes received and the bytes signed/verified. The provin wire
// profile carries strings only, so issuance is unaffected; this guards the
// verify side.
func TestCanonicalize_NumericMember_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	base := func() map[string]any {
		return map[string]any{
			"@context": []any{ctxCredentialsV2, ctxExamplesV2},
			"type":     []any{"VerifiableCredential"},
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"float64 member", func(m map[string]any) { m["count"] = float64(3) }},
		{"json.Number member", func(m map[string]any) { m["count"] = json.Number("18446744073709551617") }},
		{"int member", func(m map[string]any) { m["count"] = 7 }},
		{"nested numeric", func(m map[string]any) {
			m["credentialSubject"] = map[string]any{"score": float64(0.5)}
		}},
		{"numeric inside array", func(m map[string]any) {
			m["values"] = []any{"ok", float64(1)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := base()
			tc.mutate(doc)
			if _, err := c.Canonicalize(doc); err == nil {
				t.Error("numeric member: want error, got canonical output")
			}
		})
	}
}

// A top-level array element that is not an object is rejected: JSON-LD
// expansion silently drops free-floating scalars, so [{...}, "rider"] would
// canonicalize identically to [{...}] — an unsigned rider (Codex P1).
func TestCanonicalize_TopLevelArrayScalar_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	node := map[string]any{
		"@context": []any{ctxCredentialsV2, ctxExamplesV2},
		"id":       "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
		"type":     []any{"VerifiableCredential"},
	}
	for _, rider := range []any{"unsigned rider", true, nil, []any{node}} {
		if _, err := c.Canonicalize([]any{node, rider}); err == nil {
			t.Errorf("top-level array with %T element: want error, got canonical output", rider)
		}
	}
	// An all-object top-level array is legitimate JSON-LD input.
	if _, err := c.Canonicalize([]any{node}); err != nil {
		t.Errorf("top-level array of objects: %v", err)
	}
}

// The same rider class inside @graph: expansion drops scalar @graph entries
// silently, so they must be rejected before expansion.
func TestCanonicalize_GraphScalarEntry_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	doc := map[string]any{
		"@context": []any{ctxCredentialsV2, ctxExamplesV2},
		"@graph": []any{
			map[string]any{"id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33", "type": []any{"VerifiableCredential"}},
			"unsigned rider",
		},
	}
	if _, err := c.Canonicalize(doc); err == nil {
		t.Fatal("@graph scalar entry: want error, got canonical output")
	}
}

// A null value anywhere in the document is rejected: expansion drops
// null-valued members (and null array entries) silently, so a member could
// ride the credential outside the signature. JSON-LD's null-equals-omission
// semantic is exactly the malleability this path refuses — omit the member
// instead.
func TestCanonicalize_NullValue_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	base := func() map[string]any {
		return map[string]any{
			"@context": []any{ctxCredentialsV2, ctxExamplesV2},
			"type":     []any{"VerifiableCredential"},
			"issuer":   "https://vc.example/issuers/5678",
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"null member", func(m map[string]any) { m["validFrom"] = nil }},
		{"null nested member", func(m map[string]any) {
			m["credentialSubject"] = map[string]any{"id": "did:example:abcdefgh", "alumniOf": nil}
		}},
		{"null array entry", func(m map[string]any) {
			m["type"] = []any{"VerifiableCredential", nil}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := base()
			tc.mutate(doc)
			if _, err := c.Canonicalize(doc); err == nil {
				t.Error("null value: want error, got canonical output")
			}
		})
	}
}

// Keyword shapes that survive expansion but produce no RDF are rejected:
// @index (index maps emit no quads), @direction (json-gold v0.8.0 does not
// serialize base direction), and a malformed @language (the whole literal is
// dropped by the quad-validity filter). Each would otherwise ride the
// credential outside the signature.
func TestCanonicalize_NonRDFKeywords_Rejected(t *testing.T) {
	c := w3cCanonicalizer(t)
	base := func() map[string]any {
		return map[string]any{
			"@context": []any{ctxCredentialsV2, ctxExamplesV2},
			"type":     []any{"VerifiableCredential"},
			"issuer":   "https://vc.example/issuers/5678",
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
	}{
		{"@index on a node", func(m map[string]any) {
			m["credentialSubject"] = map[string]any{"id": "did:example:abcdefgh", "@index": "rider"}
		}},
		{"@index on a value object", func(m map[string]any) {
			m["description"] = map[string]any{"@value": "x", "@index": "rider"}
		}},
		{"@direction on a value object", func(m map[string]any) {
			m["description"] = map[string]any{"@value": "x", "@language": "en", "@direction": "rtl"}
		}},
		{"malformed @language", func(m map[string]any) {
			m["description"] = map[string]any{"@value": "x", "@language": "not a language !!"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := base()
			tc.mutate(doc)
			if _, err := c.Canonicalize(doc); err == nil {
				t.Error("non-RDF keyword shape: want error, got canonical output")
			}
		})
	}

	// A WELL-FORMED language tag is legitimate RDF and must canonicalize,
	// with the tagged literal present in the output — strictness must not
	// overreach into valid W3C credentials.
	doc := base()
	doc["description"] = map[string]any{"@value": "x", "@language": "en-US"}
	nq, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("valid @language: %v", err)
	}
	if !strings.Contains(string(nq), `"x"@en-us`) {
		t.Errorf("language-tagged literal missing from canonical output:\n%s", nq)
	}
}

// A "type" value that does not expand to an absolute IRI is rejected: toRDF
// silently drops relative-IRI type quads, which would remove the type from
// the signing scope (same malleability class as an undefined term).
func TestCanonicalize_RelativeTypeValue_Rejected(t *testing.T) {
	doc := map[string]any{
		"@context": []any{ctxCredentialsV2}, // no @vocab: bare type names stay relative
		"type":     []any{"VerifiableCredential", "NotDefinedAnywhere"},
		"issuer":   "https://vc.example/issuers/5678",
	}
	if _, err := w3cCanonicalizer(t).Canonicalize(doc); err == nil {
		t.Fatal("relative type value: want error, got canonical output")
	}
}

// An "id" value that is not an absolute IRI is rejected: toRDF silently
// drops the whole node for a relative-IRI subject.
func TestCanonicalize_RelativeIDValue_Rejected(t *testing.T) {
	doc := map[string]any{
		"@context": []any{ctxCredentialsV2, ctxExamplesV2},
		"id":       "not-an-absolute-iri",
		"type":     []any{"VerifiableCredential"},
		"issuer":   "https://vc.example/issuers/5678",
	}
	if _, err := w3cCanonicalizer(t).Canonicalize(doc); err == nil {
		t.Fatal("relative id value: want error, got canonical output")
	}
}

// The contexts map is defensively copied: mutating the caller's bytes after
// construction must not change canonical output (freeze integrity).
func TestNewCanonicalizer_DefensiveCopy(t *testing.T) {
	credCtx := read(t, "credentials-v2.jsonld")
	exCtx := read(t, "examples-v2.jsonld")
	contexts := map[string][]byte{ctxCredentialsV2: credCtx, ctxExamplesV2: exCtx}
	c := urdna2015.NewCanonicalizer(contexts)
	doc := readJSON(t, "w3c-ex8-credential.json")
	before, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range credCtx {
		credCtx[i] = 'X'
	}
	delete(contexts, ctxExamplesV2)
	after, err := c.Canonicalize(readJSON(t, "w3c-ex8-credential.json"))
	if err != nil {
		t.Fatalf("Canonicalize after caller mutation: %v", err)
	}
	if string(before) != string(after) {
		t.Error("caller mutation of the contexts map changed canonical output")
	}
}

func TestName(t *testing.T) {
	if got := w3cCanonicalizer(t).Name(); got != "urdna2015" {
		t.Errorf("Name() = %q, want %q", got, "urdna2015")
	}
}
