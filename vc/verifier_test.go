package vc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

func ed25519Verifier() ed25519.Verifier { return ed25519.Verifier{} }

func mustTime(t *testing.T) time.Time { t.Helper(); return time.Now() }

func signedPub(t *testing.T) []byte { t.Helper(); _, pub, _ := fixture(t); return pub }

const ownerDID = "did:dplaax:poc.dplaax.dev:org:acme"

// pipelineDID is the structural parent of issuerDID, for multi-hop walks.
const pipelineDID = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1"

// didDoc builds a DID Document. When pub is non-nil, it carries an
// AssertionMethod key (vmID) controlled by the document subject.
func didDoc(id, controller, vmID string, pub []byte) *did.DIDDocument {
	fields := did.DocumentFields{ID: id, Controller: controller}
	if pub != nil {
		fields.VerificationMethod = []did.VerificationMethod{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: id,
			PublicKeyJWK: map[string]any{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}}
		fields.AssertionMethod = []string{vmID}
	}
	return did.New(fields)
}

// signedCred builds a genuine signed FirstDrop and returns it with the
// issuer's public key.
func signedCred(t *testing.T) (*vc.PipelinePassCredential, []byte) {
	t.Helper()
	signer, pub, _ := fixture(t)
	cred, err := vc.NewBuilder(signer).BuildFirstDrop(issuerDID, string(keystore.KeyIDSigning), vmID, sampleSubject(), nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	return cred, pub
}

// resolverWith wires the issuer (Process) doc with controller issuerCtrl plus a
// self-controlled owner doc, then any extra docs.
func resolverWith(pub []byte, issuerCtrl string, extra ...*did.DIDDocument) *local.Resolver {
	r := local.New()
	r.Add(didDoc(issuerDID, issuerCtrl, vmID, pub))
	r.Add(didDoc(ownerDID, ownerDID, "", nil))
	for _, d := range extra {
		r.Add(d)
	}
	return r
}

// reUnmarshal round-trips a credential to wire and back, applying mutate to the
// raw wire map in between — the only way to forge a credential a Builder would
// never emit.
func reUnmarshal(t *testing.T, cred *vc.PipelinePassCredential, mutate func(m map[string]any)) *vc.PipelinePassCredential {
	t.Helper()
	wire, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	mutate(m)
	reWire, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var rt vc.PipelinePassCredential
	if err := rt.UnmarshalJSON(reWire); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	return &rt
}

func TestVerify_GenuineCredential_AllAxesVerified(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall=%v, want Verified; axes=%+v", res.Overall, res.Axes)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceVerified {
		t.Errorf("DataIntegrity=%v, want Verified", res.Axes.DataIntegrity)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Errorf("SignerAuthenticity=%v, want Verified", res.Axes.SignerAuthenticity)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceVerified {
		t.Errorf("ChainConsistency=%v, want Verified", res.Axes.ChainConsistency)
	}
}

// A multi-hop controller chain Process → Pipeline → Owner verifies.
func TestVerify_MultiHopControllerChain(t *testing.T) {
	cred, pub := signedCred(t)
	r := resolverWith(pub, pipelineDID, didDoc(pipelineDID, ownerDID, "", nil))
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceVerified {
		t.Errorf("ChainConsistency=%v, want Verified (Process→Pipeline→Owner)", res.Axes.ChainConsistency)
	}
}

func TestVerify_Unsigned_SignerAuthenticityFails(t *testing.T) {
	cred, err := vc.New(vc.CredentialFields{
		Issuer:    issuerDID,
		ValidFrom: mustTime(t),
		Subject:   sampleSubject(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub := signedPub(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (unsigned)", res.Axes.SignerAuthenticity)
	}
	if res.Overall != vc.ConfidenceFailed {
		t.Errorf("Overall=%v, want Failed", res.Overall)
	}
}

func TestVerify_TamperedBody_SignerAuthenticityFails(t *testing.T) {
	cred, pub := signedCred(t)
	tampered := reUnmarshal(t, cred, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["outputHash"] = "sha256:TAMPERED"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), tampered)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (tampered body)", res.Axes.SignerAuthenticity)
	}
}

// FCoT obligation: a proof carrying any member outside the typed six is
// rejected — the extra member is not covered by the signature.
func TestVerify_ExtraProofMember_Rejected(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["proof"].(map[string]any)["domain"] = "https://evil.example"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (extra proof member)", res.Axes.SignerAuthenticity)
	}
}

// FCoT obligation: a proof whose verificationMethod names a DID other than the
// issuer is rejected, even if a key with that fragment exists elsewhere.
func TestVerify_VerificationMethodNotIssuer_Rejected(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["proof"].(map[string]any)["verificationMethod"] = ownerDID + "#signing"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (verificationMethod not issuer)", res.Axes.SignerAuthenticity)
	}
}

func TestVerify_IssuerNotResolvable(t *testing.T) {
	cred, _ := signedCred(t)
	v := vc.NewVerifier(local.New(), ed25519Verifier()) // empty resolver

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (issuer not found)", res.Axes.SignerAuthenticity)
	}
	if res.Overall != vc.ConfidenceFailed {
		t.Errorf("Overall=%v, want Failed", res.Overall)
	}
}

// A controller pointing outside the issuer's owner lineage breaks the chain.
func TestVerify_BrokenControllerChain_Fails(t *testing.T) {
	cred, pub := signedCred(t)
	const foreignOwner = "did:dplaax:poc.dplaax.dev:org:attacker"
	r := resolverWith(pub, foreignOwner, didDoc(foreignOwner, foreignOwner, "", nil))
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceFailed {
		t.Errorf("ChainConsistency=%v, want Failed (controller outside issuer lineage)", res.Axes.ChainConsistency)
	}
}

// An unavailable intermediate controller document is indeterminate, not failed:
// it may resolve later. SignerAuthenticity stays verified (issuer doc present).
func TestVerify_IntermediateControllerUnavailable_Indeterminate(t *testing.T) {
	cred, pub := signedCred(t)
	// Process → Pipeline, but the Pipeline doc is absent.
	r := resolverWith(pub, pipelineDID)
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceIndeterminate {
		t.Errorf("ChainConsistency=%v, want Indeterminate (intermediate unavailable)", res.Axes.ChainConsistency)
	}
	if res.Overall != vc.ConfidenceIndeterminate {
		t.Errorf("Overall=%v, want Indeterminate", res.Overall)
	}
}

func TestVerify_SunsetCryptosuite_Fails(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier(),
		vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseSunset}))

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (Sunset cryptosuite)", res.Axes.SignerAuthenticity)
	}
}

func TestVerify_DeprecatedCryptosuite_StillVerifies(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier(),
		vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseDeprecated}))

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceVerified {
		t.Errorf("SignerAuthenticity=%v, want Verified (Deprecated is still acceptable)", res.Axes.SignerAuthenticity)
	}
}

// A Deprecated cryptosuite verifies, but the verdict MUST carry a notation
// (confidence.cryptosuite-lifecycle: Deprecated is "verified with notation").
func TestVerify_DeprecatedCryptosuite_CarriesNotation(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier(),
		vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseDeprecated}))

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Notations) == 0 {
		t.Fatal("Deprecated cryptosuite: want a notation on the verdict, got none")
	}
	if !strings.Contains(strings.ToLower(strings.Join(res.Notations, " ")), "deprecat") {
		t.Errorf("notation should mention deprecation, got %v", res.Notations)
	}
}

// An Active cryptosuite verifies with no notation.
func TestVerify_ActiveCryptosuite_NoNotation(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier(),
		vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseActive}))

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.Notations) != 0 {
		t.Errorf("Active cryptosuite: want no notation, got %v", res.Notations)
	}
}

// A malformed source commitment (unsorted derived_from) fails the
// data-integrity axis on the wire-form shape check.
func TestVerify_MalformedSourceCommitment_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["derived_from"] = []any{"did:dplaax:poc.dplaax.dev:org:z", "did:dplaax:poc.dplaax.dev:org:a"}
		subj["source_root"] = "f1220" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		subj["source_root_canonical"] = "jcs-rfc8785"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (unsorted derived_from)", res.Axes.DataIntegrity)
	}
}

// A signed body missing the PipelinePassCredential type fails the data-integrity
// axis: the required VC types are part of wire-form well-formedness.
func TestVerify_MissingVCType_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["type"] = []any{"VerifiableCredential"} // PipelinePassCredential dropped
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (missing PipelinePassCredential type)", res.Axes.DataIntegrity)
	}
}

// A present-but-malformed derived_from (non-string element) fails the
// data-integrity axis — the lossy SourceCommitment() view must not let it slip
// through.
func TestVerify_MalformedDerivedFromTypes_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["derived_from"] = []any{float64(123)} // not a string
		subj["source_root"] = "f1220" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		subj["source_root_canonical"] = "jcs-rfc8785"
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (non-string derived_from element)", res.Axes.DataIntegrity)
	}
}

// A present-but-non-string previousCredential fails the data-integrity axis: it
// must not collapse to "absent" and let a bogus origin slip through.
func TestVerify_NonStringPreviousCredential_DataIntegrityFails(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["previousCredential"] = map[string]any{"not": "a string"}
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (non-string previousCredential)", res.Axes.DataIntegrity)
	}
}

// A verificationMethod with no fragment (a bare DID equal to the issuer) is
// rejected: the contract requires an issuer#fragment reference.
func TestVerify_BareDIDVerificationMethod_Rejected(t *testing.T) {
	cred, pub := signedCred(t)
	forged := reUnmarshal(t, cred, func(m map[string]any) {
		m["proof"].(map[string]any)["verificationMethod"] = issuerDID // no '#fragment'
	})
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.Verify(context.Background(), forged)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (verificationMethod lacks a fragment)", res.Axes.SignerAuthenticity)
	}
}

// substitutingResolver returns a fixed document regardless of the requested
// DID — a stand-in for a resolver that fails to enforce doc.ID == requested.
type substitutingResolver struct{ doc *did.DIDDocument }

func (s substitutingResolver) Resolve(_ context.Context, _ string) (*did.DIDDocument, error) {
	return s.doc, nil
}

// SignerAuthenticity independently enforces doc.ID == issuer, not relying on the
// resolver or another axis (registry-substitution defense on the signing path).
func TestVerify_SubstitutedDocID_SignerAuthenticityFails(t *testing.T) {
	cred, pub := signedCred(t)
	doc := didDoc("did:dplaax:poc.dplaax.dev:org:other", "did:dplaax:poc.dplaax.dev:org:other", vmID, pub)
	v := vc.NewVerifier(substitutingResolver{doc: doc}, ed25519Verifier())

	res, err := v.Verify(context.Background(), cred)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity=%v, want Failed (resolved doc.ID != issuer)", res.Axes.SignerAuthenticity)
	}
}

// A context-cancelled call returns an error, not a verdict.
func TestVerify_ContextCancelled_Errors(t *testing.T) {
	cred, pub := signedCred(t)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := v.Verify(ctx, cred); err == nil {
		t.Error("Verify with a cancelled context: want error")
	}
}
