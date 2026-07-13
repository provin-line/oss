package vc

// The v0 freeze anchors for the eddsa-rdfc-2022 (and, for symmetry,
// eddsa-jcs-2022) proof algorithm: the official W3C vc-di-eddsa test vectors,
// with every intermediate pinned separately — canonical bytes, both SHA-256
// halves, the concatenated hashData, the deterministic Ed25519 signature,
// and the multibase proofValue. Matching the PUBLISHED vector, not a
// self-produced round-trip, is what evidences that a non-Go W3C verifier
// computes the same signing bytes (a round-trip alone would mask a defect
// shared by create and verify). A provin-shape KAT rides alongside as a
// regression guard for json-gold upgrades and embedded-context edits.

import (
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/canon"
	"github.com/provin-line/oss/canon/jcs"
	"github.com/provin-line/oss/canon/urdna2015"
	"github.com/provin-line/oss/multibase"
)

// Pins from W3C vc-di-eddsa (https://www.w3.org/TR/vc-di-eddsa/, §3 Test
// Vectors), extracted verbatim from the published spec. The eddsa-rdfc-2022
// set is Examples 7–16 (7 keys / 8 credential → testdata
// w3c-rdfc-credential.json / 10 credential hash / 11 proof options →
// w3c-rdfc-proof-options.json / 13 options hash / 14 hashData / 15
// signature / 16 proofValue); the eddsa-jcs-2022 set is Examples 29–38 with
// the same roles (30/33 → w3c-jcs-*.json, 31/34 → canonical JSON pins). The
// signing key is the spec's test key (secretKeyMultibase
// z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq, multicodec-stripped seed
// below). Re-verify any constant against the spec URL, not against this
// file's history.
const (
	w3cSeedHex = "c96ef9ea10c5e414c471723aff9de72c35fa5b70fae97e8832ecac7d2e2b8ed6"

	w3cRDFCCredHashHex  = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
	w3cRDFCPOHashHex    = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"
	w3cRDFCSignatureHex = "4d8e53c2d5b3f2a7891753eb16ca993325bdb0d3cfc5be1093d0a18426f5ef8578cadc0fd4b5f4dd0d1ce0aefd15ab120b7a894d0eb094ffda4e6553cd1ed50d"
	w3cRDFCProofValue   = "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"

	w3cJCSCredHashHex  = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
	w3cJCSPOHashHex    = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db"
	w3cJCSSignatureHex = "407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b80351da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"
	w3cJCSProofValue   = "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readTestdataJSON(t *testing.T, name string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readTestdata(t, name), &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return m
}

func w3cSigningKey(t *testing.T) stded25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(w3cSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	return stded25519.NewKeyFromSeed(seed)
}

// assertVectorChain drives proofHashData over the official vector's document
// and proof options with the given canonicalizer and pins each intermediate:
// both SHA-256 halves, the concatenation order (proof-config hash FIRST),
// the deterministic Ed25519 signature, and the proofValue encoding.
func assertVectorChain(t *testing.T, c canon.Canonicalizer, credFile, poFile, credHashHex, poHashHex, sigHex, proofValue string) {
	t.Helper()
	cred := readTestdataJSON(t, credFile)
	po := readTestdataJSON(t, poFile)

	hd, err := proofHashData(c, po, cred)
	if err != nil {
		t.Fatalf("proofHashData: %v", err)
	}
	if got := hex.EncodeToString(hd[:sha256.Size]); got != poHashHex {
		t.Errorf("proof-config hash = %s, want %s", got, poHashHex)
	}
	if got := hex.EncodeToString(hd[sha256.Size:]); got != credHashHex {
		t.Errorf("credential hash = %s, want %s", got, credHashHex)
	}
	if got := hex.EncodeToString(hd); got != poHashHex+credHashHex {
		t.Errorf("hashData = %s, want proof-config hash ‖ credential hash", got)
	}

	sig := stded25519.Sign(w3cSigningKey(t), hd)
	if got := hex.EncodeToString(sig); got != sigHex {
		t.Errorf("signature = %s, want %s", got, sigHex)
	}
	if got := multibase.EncodeBase58Btc(sig); got != proofValue {
		t.Errorf("proofValue = %s, want %s", got, proofValue)
	}
}

// The eddsa-rdfc-2022 freeze anchor (W3C vc-di-eddsa Examples 8–16). The
// canonicalizer serves the vector's two contexts; the registered production
// suite serves the three frozen provin contexts instead, so the vector runs
// against a test-scoped canonicalizer through the same proofHashData path.
func TestW3CVector_EdDSARDFC2022(t *testing.T) {
	c := urdna2015.NewCanonicalizer(map[string][]byte{
		ContextCredentialsV2:                            contextCredentialsV2Document,
		"https://www.w3.org/ns/credentials/examples/v2": readTestdata(t, "w3c-examples-v2.jsonld"),
	})
	assertVectorChain(t, c,
		"w3c-rdfc-credential.json", "w3c-rdfc-proof-options.json",
		w3cRDFCCredHashHex, w3cRDFCPOHashHex, w3cRDFCSignatureHex, w3cRDFCProofValue)
}

// The eddsa-jcs-2022 anchor (W3C vc-di-eddsa Examples 30–38), pinning the
// already-frozen Phase-1 suite to the official vector too — including the
// canonical JSON bytes themselves, which JCS exposes directly.
func TestW3CVector_EdDSAJCS2022(t *testing.T) {
	c := jcs.Canonicalizer{}

	canonCred, err := c.Canonicalize(readTestdataJSON(t, "w3c-jcs-credential.json"))
	if err != nil {
		t.Fatalf("Canonicalize credential: %v", err)
	}
	if want := strings.TrimSpace(string(readTestdata(t, "w3c-jcs-canonical-credential.txt"))); string(canonCred) != want {
		t.Errorf("canonical credential:\n got %s\nwant %s", canonCred, want)
	}
	canonPO, err := c.Canonicalize(readTestdataJSON(t, "w3c-jcs-proof-options.json"))
	if err != nil {
		t.Fatalf("Canonicalize proof options: %v", err)
	}
	if want := strings.TrimSpace(string(readTestdata(t, "w3c-jcs-canonical-proof-options.txt"))); string(canonPO) != want {
		t.Errorf("canonical proof options:\n got %s\nwant %s", canonPO, want)
	}

	assertVectorChain(t, c,
		"w3c-jcs-credential.json", "w3c-jcs-proof-options.json",
		w3cJCSCredHashHex, w3cJCSPOHashHex, w3cJCSSignatureHex, w3cJCSProofValue)
}

// The registration probe panics when an embedded context is missing — a
// binary whose canonicalization cannot cover the frozen wire vocabulary must
// fail at startup, not at the first proof it touches.
func TestProbeRDFC_MissingContextPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("probeRDFC with a missing context: want panic")
		}
	}()
	probeRDFC(urdna2015.NewCanonicalizer(map[string][]byte{
		// dplaax and provin contexts deliberately absent.
		ContextCredentialsV2: contextCredentialsV2Document,
	}))
}

// katCredential is the fixed full-shape provin credential the KAT pins:
// every wire member populated, deterministic values only.
func katCredential(t *testing.T) map[string]any {
	t.Helper()
	filler := strings.Repeat("ab", 32)
	cred, err := New(CredentialFields{
		Issuer:    "did:dplaax:poc.dplaax.dev:org:kat:pipeline:p1:process:s1",
		ValidFrom: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
		Subject: CredentialSubjectFields{
			PipelineID:          "p1",
			ProcessID:           "s1",
			TransformationClaim: ClaimAggregate,
			Schema:              SchemaRef{ID: SchemaURI("kat", "1.0.0"), Type: "JsonSchema", ContentHash: "sha256:" + filler},
			InputHash:           "sha256:" + filler,
			OutputHash:          "sha256:" + filler,
		},
		PreviousCredential: "sha256:" + filler,
		SourceCommitment: &SourceCommitment{
			DerivedFrom:         []string{"sha256:" + filler},
			SourceRoot:          "f1220" + filler,
			SourceRootCanonical: "rfc6962-sha256",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cred.Body()
}

// The provin-shape KAT: the registered eddsa-rdfc-2022 suite canonicalizes a
// fixed full-shape credential to pinned N-Quads, and the fixed W3C test key
// signs it to a pinned proofValue. Unlike the W3C vector (the cross-
// implementation anchor), this is a self-produced golden — its job is
// regression detection: a json-gold upgrade or an embedded-context edit that
// shifts canonical bytes fails here even if it is internally consistent.
func TestKAT_ProvinCredential_RDFC(t *testing.T) {
	c, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatal(err)
	}
	doc := katCredential(t)

	nq, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if want := string(readTestdata(t, "kat-provin-credential.nq")); string(nq) != want {
		t.Errorf("canonical N-Quads drifted from the pinned KAT:\n--- got ---\n%s--- want ---\n%s", nq, want)
	}

	ctx, hasCtx := doc[keyContext]
	cfg := proofConfigMap(proofType, CryptosuiteEdDSARDFC2022,
		"did:dplaax:poc.dplaax.dev:org:kat:pipeline:p1:process:s1#signing",
		proofPurposeSign, "2026-07-13T00:00:00Z", ctx, hasCtx)
	hd, err := proofHashData(c, cfg, doc)
	if err != nil {
		t.Fatalf("proofHashData: %v", err)
	}
	pv := multibase.EncodeBase58Btc(stded25519.Sign(w3cSigningKey(t), hd))
	if want := strings.TrimSpace(string(readTestdata(t, "kat-provin-proofvalue.txt"))); pv != want {
		t.Errorf("proofValue drifted from the pinned KAT: got %s, want %s", pv, want)
	}
}

// termCoverageIRIs maps every provin wire member (top level and subject) to
// the IRI its term must expand to. The test below requires the mapping to be
// COMPLETE over the credential body: a new wire key without an entry here
// fails the test, so vocabulary additions must extend the frozen contexts
// and this map together.
var termCoverageIRIs = map[string]string{
	"type":                  "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
	"issuer":                "https://www.w3.org/2018/credentials#issuer",
	"validFrom":             "https://www.w3.org/2018/credentials#validFrom",
	"credentialSubject":     "https://www.w3.org/2018/credentials#credentialSubject",
	"pipelineId":            "https://dplaax.dev/vocab#pipelineId",
	"processId":             "https://dplaax.dev/vocab#processId",
	"transformationClaim":   "https://dplaax.dev/vocab#transformationClaim",
	"schema":                "https://dplaax.dev/vocab#schema",
	"contentHash":           "https://dplaax.dev/vocab#contentHash",
	"inputHash":             "https://dplaax.dev/vocab#inputHash",
	"outputHash":            "https://dplaax.dev/vocab#outputHash",
	"previousCredential":    "https://dplaax.dev/vocab#previousCredential",
	"derived_from":          "https://dplaax.dev/vocab#derivedFrom",
	"source_root":           "https://dplaax.dev/vocab#sourceRoot",
	"source_root_canonical": "https://dplaax.dev/vocab#sourceRootCanonical",
	// Inside the schema reference object; id becomes the node IRI itself.
	// NOTE the expansion: the schema URI "dplaax:schema/<name>@<version>" is a
	// compact IRI under the dplaax context prefix ("dplaax" →
	// "https://dplaax.dev/vocab#"), so on the RDFC path the node lands under
	// the vocab namespace. Standard JSON-LD compact-IRI expansion — every
	// conformant processor does the same — and pinned as v0 behavior by the
	// provin KAT. The JCS path signs the literal string, untouched.
	"id": "https://dplaax.dev/vocab#schema/",
}

// H1 term coverage, positive direction: for every credential variant the
// wire profile can emit, every body member survives into the canonical
// N-Quads as its mapped IRI — nothing the issuer signs is silently outside
// the signature. (The negative direction — an undefined member REFUSES to
// canonicalize — is TestRDFC_UndefinedMember_RefusedBothSides.)
func TestTermCoverage_AllVariants(t *testing.T) {
	c, err := canonicalizerFor(CryptosuiteEdDSARDFC2022)
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("cd", 32)

	variants := map[string]CredentialFields{
		"minimal convert": {
			Issuer:    "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:s",
			ValidFrom: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
			Subject: CredentialSubjectFields{
				PipelineID: "p", ProcessID: "s",
				TransformationClaim: ClaimConvert,
				OutputHash:          "sha256:" + filler,
			},
		},
		"full aggregate with commitment": {
			Issuer:    "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:s",
			ValidFrom: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
			Subject: CredentialSubjectFields{
				PipelineID: "p", ProcessID: "s",
				TransformationClaim: ClaimAggregate,
				Schema:              SchemaRef{ID: SchemaURI("cov", "1.0.0"), Type: "JsonSchema", ContentHash: "sha256:" + filler},
				InputHash:           "sha256:" + filler,
				OutputHash:          "sha256:" + filler,
			},
			PreviousCredential: "sha256:" + filler,
			SourceCommitment: &SourceCommitment{
				DerivedFrom:         []string{"sha256:" + filler},
				SourceRoot:          "f1220" + filler,
				SourceRootCanonical: "rfc6962-sha256",
			},
		},
	}
	// Every registered claim value must expand (transformationClaim is
	// @vocab-typed: the VALUE becomes an IRI too).
	for _, claim := range []TransformationClaim{ClaimFilter, ClaimConvert, ClaimFilterConvert, ClaimAggregate, ClaimEnrich, ClaimGenerate} {
		variants["claim "+string(claim)] = CredentialFields{
			Issuer:    "did:dplaax:poc.dplaax.dev:org:x:pipeline:p:process:s",
			ValidFrom: time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
			Subject: CredentialSubjectFields{
				PipelineID: "p", ProcessID: "s",
				TransformationClaim: claim,
				OutputHash:          "sha256:" + filler,
			},
		}
	}

	for name, fields := range variants {
		t.Run(name, func(t *testing.T) {
			cred, err := New(fields)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			doc := cred.Body()
			nq, err := c.Canonicalize(doc)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			out := string(nq)

			var walk func(m map[string]any)
			walk = func(m map[string]any) {
				for k, v := range m {
					if strings.HasPrefix(k, "@") {
						continue
					}
					iri, ok := termCoverageIRIs[k]
					if !ok {
						t.Errorf("wire member %q has no term-coverage mapping — extend termCoverageIRIs and the frozen contexts together", k)
						continue
					}
					if !strings.Contains(out, iri) {
						t.Errorf("member %q: canonical output does not contain %q — the member was silently dropped from the signing scope", k, iri)
					}
					if sub, ok := v.(map[string]any); ok {
						walk(sub)
					}
				}
			}
			walk(doc)

			// The claim VALUE is signed as an IRI (dplaax's @vocab typing).
			claimIRI := "https://provin.dev/vocab#" + strings.TrimPrefix(string(fields.Subject.TransformationClaim), "provin:")
			if !strings.Contains(out, claimIRI) {
				t.Errorf("transformationClaim value: canonical output does not contain %q", claimIRI)
			}
		})
	}
}
