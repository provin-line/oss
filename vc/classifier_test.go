package vc_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// One suite identifier, two contracts. eddsa-jcs-2022 means the W3C shape
// (proof-local @context + Multikey + jcs-rfc8785); the same identifier over the
// six-member proof and a JWK key is what provin issued before Fork W, and it
// canonicalizes with the int64-verbatim deviation. Same name, different bytes —
// the hazard P0-4 called Critical.
//
// ClassifyProof is the whole defense: it reads the suite id, then the raw proof
// shape, then the key encoding, and every combination outside the two known
// contracts fails. It never tries a canonicalizer to see if the signature
// happens to check out — that would make the signature an oracle for "which
// contract is this?", which is exactly the algorithm-guessing the exact-dispatch
// rule forbids.

func TestClassifyProof_Matrix(t *testing.T) {
	tests := []struct {
		name       string
		suite      string
		hasContext bool
		encoding   did.KeyEncoding
		want       vc.SuiteContract
		wantErr    bool
	}{
		{
			name:  "W3C: context + Multikey",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: true, encoding: did.EncodingMultikey,
			want: vc.ContractW3CEdDSAJCS2022,
		},
		{
			name:  "legacy: no context + JWK",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: false, encoding: did.EncodingJWK,
			want: vc.ContractLegacyProvinEdDSAJCSInt64,
		},
		{
			// A W3C-shaped proof over a JWK key names a contract it does not
			// satisfy: the suite requires Multikey.
			name:  "mismatch: context + JWK",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: true, encoding: did.EncodingJWK,
			wantErr: true,
		},
		{
			// A Multikey key does not upgrade a six-member proof. Accepting this
			// would let a pre-cutover proof be read as W3C-conformant the moment
			// its DID document was re-issued with a Multikey — promoting evidence
			// on the strength of a change made after it was signed.
			name:  "mismatch: no context + Multikey",
			suite: vc.CryptosuiteEdDSAJCS2022, hasContext: false, encoding: did.EncodingMultikey,
			wantErr: true,
		},
		{
			name:  "unknown suite fails closed",
			suite: "eddsa-2022-totally-real", hasContext: true, encoding: did.EncodingMultikey,
			wantErr: true,
		},
		{
			name:  "empty suite fails closed",
			suite: "", hasContext: false, encoding: did.EncodingJWK,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vc.ClassifyProof(tc.suite, tc.hasContext, tc.encoding)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ClassifyProof accepted an unlisted combination, returning %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyProof: %v", err)
			}
			if got != tc.want {
				t.Errorf("contract = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSuiteContract_CanonicalizerBinding(t *testing.T) {
	// A contract names its canonicalizer; the two are not chosen independently.
	// This is the binding that stops the same suite identifier from meaning two
	// different byte streams depending on which reader looked.
	if got := vc.ContractW3CEdDSAJCS2022.CanonicalizerID(); got != "jcs-rfc8785" {
		t.Errorf("W3C contract canonicalizer = %q, want jcs-rfc8785", got)
	}
	if got := vc.ContractLegacyProvinEdDSAJCSInt64.CanonicalizerID(); got != "jcs" {
		t.Errorf("legacy contract canonicalizer = %q, want jcs (int64-verbatim)", got)
	}
}

func TestSuiteContract_IDsAreTheCatalogNames(t *testing.T) {
	// These strings reach consumers as claim contract ids (claims.suite.contract-id).
	// They are frozen by the scope catalog, so a rename here is a protocol change.
	if got := string(vc.ContractW3CEdDSAJCS2022); got != "W3C_EDDSA_JCS_2022_REC_20250515@1" {
		t.Errorf("W3C contract id = %q", got)
	}
	if got := string(vc.ContractLegacyProvinEdDSAJCSInt64); got != "LEGACY_PROVIN_EDDSA_JCS_INT64@1" {
		t.Errorf("legacy contract id = %q", got)
	}
}

func TestVerify_LegacyMultikeyProofIsNotPromoted(t *testing.T) {
	// The dispatch has to be wired into verification, not merely available: a
	// six-member proof whose issuer document now carries a Multikey must not
	// verify as W3C. Before the classifier, the key encoding alone decided the
	// canonicalizer, so re-issuing a DID document could silently reclassify old
	// evidence.
	if _, err := vc.ClassifyProof(vc.CryptosuiteEdDSAJCS2022, false, did.EncodingMultikey); err == nil {
		t.Fatal("classifier accepts the promotion shape")
	}
}

func TestVerifyProofWithContract_RejectsSwappedProofContext(t *testing.T) {
	// The wire proof.@context is the one member this verify path's signature
	// reconstruction does not cover (the config is rebuilt from the DOCUMENT's
	// context). Without the mirror check, provin would accept an artifact whose
	// proof.@context was swapped after signing — while a W3C verifier, which
	// canonicalizes the wire proof options as-is, would reject it. Same bytes,
	// two verdicts: the interop failure Fork W exists to end.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	proof.Context = []any{"https://attacker.example/context/v2"}

	// Multikey encoding puts this on the W3C row, where the mirror is enforced.
	if _, err := vc.VerifyProofWithContract(ed25519.Verifier{}, pub, did.EncodingMultikey, proof, doc); err == nil {
		t.Error("a swapped wire proof.@context was accepted — the member is malleable on this verify path")
	}
}

func TestClassifyProof_RDFCRow(t *testing.T) {
	// eddsa-rdfc-2022 is a production suite (v0-mandatory, p0-7/p0-12 ruling);
	// the dispatch must route it, not reject it. Its W3C shape is the same as
	// the jcs sibling's — proof-local @context + Multikey — and RDF expansion
	// needs the context anyway, so nothing else classifies.
	tests := []struct {
		name       string
		hasContext bool
		encoding   did.KeyEncoding
		want       vc.SuiteContract
		wantErr    bool
	}{
		{"W3C shape classifies", true, did.EncodingMultikey, vc.ContractW3CEdDSARDFC2022, false},
		{"no context fails", false, did.EncodingMultikey, "", true},
		{"JWK fails", true, did.EncodingJWK, "", true},
		{"neither fails", false, did.EncodingJWK, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vc.ClassifyProof(vc.CryptosuiteEdDSARDFC2022, tc.hasContext, tc.encoding)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted, returning %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyProof: %v", err)
			}
			if got != tc.want {
				t.Errorf("contract = %q, want %q", got, tc.want)
			}
		})
	}
	if got := vc.ContractW3CEdDSARDFC2022.CanonicalizerID(); got != "urdna2015" {
		t.Errorf("rdfc contract canonicalizer = %q, want urdna2015", got)
	}
	if got := string(vc.ContractW3CEdDSARDFC2022); got != "W3C_EDDSA_RDFC_2022_REC_20250515@1" {
		t.Errorf("rdfc contract id = %q — frozen by the scope catalog", got)
	}
}

func TestVerify_PresentNullContextIsRejected(t *testing.T) {
	// "@context": null is present-but-nil: presence-carry maps it to a nil
	// Context, which reads as "no context" and classifies as the legacy row —
	// where the mirror check does not run. Since the member name is allowlisted
	// and the proof sits outside the body hash, appending it to a stored legacy
	// proof would change the wire bytes without changing the content address or
	// breaking the signature: a malleable member, on the one row that cannot
	// pin it. Both ForkW-1 reviewers converged on this; the fix is to refuse
	// the shape outright — null is not absence, and no contract accepts it.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	raw, err := json.Marshal(map[string]any{"p": proof})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	pm := m["p"].(map[string]any)
	pm["@context"] = nil
	nullified, err := json.Marshal(pm)
	if err != nil {
		t.Fatal(err)
	}
	var reparsed vc.DataIntegrityProof
	if err := json.Unmarshal(nullified, &reparsed); err == nil {
		// The typed unmarshal is the delegation / external-consumer path: it
		// must refuse the shape at parse, because after parsing the null is
		// indistinguishable from absence.
		t.Error("DataIntegrityProof.UnmarshalJSON accepted a present-but-null @context")
	}
	_ = pub
}

func TestVerify_RawProofNullContextFailsVerification(t *testing.T) {
	// The raw-map path: a stored credential whose proof map carries
	// "@context": null must fail signer authenticity, not classify as legacy.
	// The wire is crafted by hand because no builder emits the shape — which is
	// the point: only an attacker appends it.
	cred, pub := signedCred(t)
	wire, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatal(err)
	}
	m["proof"].(map[string]any)["@context"] = nil
	tamperedWire, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var tampered vc.PipelinePassCredential
	if err := json.Unmarshal(tamperedWire, &tampered); err != nil {
		t.Fatalf("unmarshal tampered wire: %v", err)
	}

	r := local.New()
	r.Add(didDoc(issuerDID, ownerDID, vmID, pub))
	r.Add(didDoc(ownerDID, ownerDID, "", nil))
	v := vc.NewVerifier(r, ed25519.Verifier{})
	res, err := v.Verify(context.Background(), &tampered)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity == vc.ConfidenceVerified {
		t.Error("a present-but-null proof @context verified")
	}
}

func TestVerifyChain_ReportsTheHeadSuiteContract(t *testing.T) {
	// The field's own doc promises it: "For a chain, this is the contract of
	// the head credential." A chain result with an empty contract would leave
	// consumers unable to tell W3C from legacy verification — the compression
	// claims.headline.suite-contract forbids.
	cred, pub := signedCred(t)
	r := local.New()
	r.Add(didDoc(issuerDID, ownerDID, vmID, pub))
	r.Add(didDoc(ownerDID, ownerDID, "", nil))
	v := vc.NewVerifier(r, ed25519.Verifier{})

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{cred})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Fatalf("SignerAuthenticity = %v, want Verified", res.Axes.SignerAuthenticity)
	}
	if res.SuiteContract != vc.ContractW3CEdDSAJCS2022 {
		t.Errorf("chain SuiteContract = %q, want the head credential's %q", res.SuiteContract, vc.ContractW3CEdDSAJCS2022)
	}
}

func TestVerifyProof_EnforcesTheMirrorToo(t *testing.T) {
	// VerifyProof stays exported as the registry-suite path (rdfc, and any
	// external consumer of this OSS API). It reconstructs the proof config from
	// the DOCUMENT's context, so without its own mirror check it would accept
	// the swapped-proof.@context artifact the classifier path rejects — the
	// same bytes, two verdicts, depending on which entry point a consumer
	// picked. Every entry point pins the member.
	signer, pub, doc := fixture(t)
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, doc, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	proof.Context = []any{"https://attacker.example/context/v2"}
	if err := vc.VerifyProof(ed25519.Verifier{}, pub, proof, doc); err == nil {
		t.Error("VerifyProof accepted a swapped proof-local @context")
	}
}
