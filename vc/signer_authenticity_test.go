package vc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/provin-line/oss/did"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// exampleCredential is a credential of a type other than
// PipelinePassCredential, signed by issuerDID's #signing key; mutate edits the
// wire map (proof included) before it is parsed.
func exampleCredential(t *testing.T, issuer any, mutate func(m map[string]any)) (*vc.Credential, []byte) {
	t.Helper()
	signer, pub, _ := fixture(t)
	body := map[string]any{
		"@context":          []any{vc.ContextCredentialsV2},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"issuer":            issuer,
		"validFrom":         "2026-11-06T00:00:00Z",
		"credentialSubject": map[string]any{"id": "urn:example:subject", "role": "checker"},
	}
	proof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, body, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatalf("CreateProof: %v", err)
	}
	return parseCredential(t, body, proof, mutate), pub
}

func parseCredential(t *testing.T, body map[string]any, proof *vc.DataIntegrityProof, mutate func(m map[string]any)) *vc.Credential {
	t.Helper()
	pb, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	if err := json.Unmarshal(pb, &pm); err != nil {
		t.Fatal(err)
	}
	wire := map[string]any{}
	for k, v := range body {
		wire[k] = v
	}
	wire["proof"] = pm
	if mutate != nil {
		mutate(wire)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var c vc.Credential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatalf("Credential.UnmarshalJSON: %v", err)
	}
	return &c
}

// asCredential reads a PipelinePassCredential's wire form as a Credential.
func asCredential(t *testing.T, p *vc.PipelinePassCredential) *vc.Credential {
	t.Helper()
	raw, err := p.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var c vc.Credential
	if err := c.UnmarshalJSON(raw); err != nil {
		t.Fatalf("Credential.UnmarshalJSON: %v", err)
	}
	return &c
}

// A credential that is not a PipelinePassCredential is refused by Verify on
// the data-integrity axis, but its issuer's signature verifies on its own.
func TestVerifySignerAuthenticity_AnyCredentialType(t *testing.T) {
	cred, pub := exampleCredential(t, issuerDID, nil)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())

	res, err := v.VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatalf("VerifySignerAuthenticity: %v", err)
	}
	if res.State != vc.ConfidenceVerified {
		t.Fatalf("State = %v, want Verified", res.State)
	}
	if res.SuiteContract != vc.ContractW3CEdDSAJCS2022 {
		t.Errorf("SuiteContract = %q, want %q", res.SuiteContract, vc.ContractW3CEdDSAJCS2022)
	}
	if res.Issuer != issuerDID || res.VerificationMethod != vmID {
		t.Errorf("Issuer, VerificationMethod = %q, %q; want %q, %q", res.Issuer, res.VerificationMethod, issuerDID, vmID)
	}

	raw, err := cred.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var asPass vc.PipelinePassCredential
	if err := asPass.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	full, err := v.Verify(context.Background(), &asPass)
	if err != nil {
		t.Fatal(err)
	}
	if full.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("Verify DataIntegrity = %v, want Failed for a non-PipelinePassCredential", full.Axes.DataIntegrity)
	}
}

// A W3C issuer object ({"id": …}) names the issuer by its id.
func TestVerifySignerAuthenticity_IssuerObject(t *testing.T) {
	cred, pub := exampleCredential(t, map[string]any{"id": issuerDID, "name": "Process 1"}, nil)
	if cred.Issuer() != issuerDID {
		t.Fatalf("Issuer() = %q, want %q", cred.Issuer(), issuerDID)
	}
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())
	res, err := v.VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceVerified {
		t.Errorf("State = %v, want Verified", res.State)
	}
}

// An issuer that is neither a string nor an object with a string id names no
// one, and nothing verifies against it.
func TestVerifySignerAuthenticity_UnnamedIssuerFails(t *testing.T) {
	for _, issuer := range []any{nil, 42, map[string]any{"name": "no id"}, map[string]any{"id": 7}, []any{issuerDID}} {
		cred, pub := exampleCredential(t, issuer, nil)
		if cred.Issuer() != "" {
			t.Errorf("issuer %v: Issuer() = %q, want empty", issuer, cred.Issuer())
		}
		v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())
		res, err := v.VerifySignerAuthenticity(context.Background(), cred)
		if err != nil {
			t.Fatal(err)
		}
		if res.State != vc.ConfidenceFailed {
			t.Errorf("issuer %v: State = %v, want Failed", issuer, res.State)
		}
	}
}

// The signer-authenticity verdict on a credential's wire form is the one Verify
// gives on the same bytes as a PipelinePassCredential, case by case: one
// implementation, two entry points.
func TestVerifySignerAuthenticity_AgreesWithVerify(t *testing.T) {
	genuine, pub := signedCred(t)
	notFound := erroringResolver{err: fmt.Errorf("no such DID: %w", resolver.ErrNotFound)}
	outage := erroringResolver{err: errors.New("dial tcp 203.0.113.7:443: connect: connection refused")}
	substituted := substitutingResolver{doc: didDoc("did:dplaax:poc.dplaax.dev:org:other", "did:dplaax:poc.dplaax.dev:org:other", vmID, pub)}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		r      resolver.Resolver
		opts   []vc.VerifierOption
	}{
		{name: "genuine"},
		{name: "unsigned", mutate: func(m map[string]any) { delete(m, "proof") }},
		{name: "tampered body", mutate: func(m map[string]any) { m["validFrom"] = "2020-01-01T00:00:00Z" }},
		{name: "extra proof member", mutate: func(m map[string]any) { m["proof"].(map[string]any)["nonce"] = "x" }},
		{name: "null proof @context", mutate: func(m map[string]any) { m["proof"].(map[string]any)["@context"] = nil }},
		{name: "wrong proof purpose", mutate: func(m map[string]any) { m["proof"].(map[string]any)["proofPurpose"] = "authentication" }},
		{name: "verification method of another DID", mutate: func(m map[string]any) {
			m["proof"].(map[string]any)["verificationMethod"] = ownerDID + "#signing"
		}},
		{name: "bare DID verification method", mutate: func(m map[string]any) { m["proof"].(map[string]any)["verificationMethod"] = issuerDID }},
		{name: "unparseable created", mutate: func(m map[string]any) { m["proof"].(map[string]any)["created"] = "yesterday" }},
		{name: "no issuer", mutate: func(m map[string]any) { delete(m, "issuer") }},
		{name: "issuer not found", r: notFound},
		{name: "resolver outage", r: outage},
		{name: "substituted document", r: substituted},
		{name: "sunset cryptosuite", opts: []vc.VerifierOption{vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseSunset})}},
		{name: "deprecated cryptosuite", opts: []vc.VerifierOption{vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseDeprecated})}},
		{name: "sunset during an outage", r: outage, opts: []vc.VerifierOption{vc.WithLifecycleRegistry(stubLifecycle{phase: vc.PhaseSunset})}},
	}
	seen := map[vc.ConfidenceState]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pass := genuine
			if tc.mutate != nil {
				pass = reUnmarshal(t, genuine, tc.mutate)
			}
			r := tc.r
			if r == nil {
				r = resolverWith(pub, ownerDID)
			}
			v := vc.NewVerifier(r, ed25519Verifier(), tc.opts...)
			full, err := v.Verify(context.Background(), pass)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.VerifySignerAuthenticity(context.Background(), asCredential(t, pass))
			if err != nil {
				t.Fatal(err)
			}
			if got.State != full.Axes.SignerAuthenticity {
				t.Errorf("State = %v, Verify's SignerAuthenticity = %v", got.State, full.Axes.SignerAuthenticity)
			}
			if got.SuiteContract != full.SuiteContract {
				t.Errorf("SuiteContract = %q, Verify's = %q", got.SuiteContract, full.SuiteContract)
			}
			if !reflect.DeepEqual(got.Notations, full.Notations) {
				t.Errorf("Notations = %v, Verify's = %v", got.Notations, full.Notations)
			}
			checkSignerFields(t, got, pass.Issuer(), vmID)
			seen[got.State] = true
		})
	}
	for _, s := range []vc.ConfidenceState{vc.ConfidenceVerified, vc.ConfidenceIndeterminate, vc.ConfidenceFailed} {
		if !seen[s] {
			t.Errorf("no case reached %v", s)
		}
	}
}

// An issuer that names no one fails, whatever the resolver says: a proof whose
// verificationMethod is a bare fragment must not be matched to the empty
// issuer and sent for resolution.
func TestVerifySignerAuthenticity_EmptyIssuerFailsBeforeResolution(t *testing.T) {
	cred, _ := exampleCredential(t, map[string]any{"name": "no id"}, func(m map[string]any) {
		m["proof"].(map[string]any)["verificationMethod"] = "#signing"
	})
	outage := erroringResolver{err: errors.New("dial tcp 203.0.113.7:443: connect: connection refused")}
	res, err := vc.NewVerifier(outage, ed25519Verifier()).VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceFailed {
		t.Errorf("State = %v, want Failed", res.State)
	}
}

func TestVerifySignerAuthenticity_NilCredentialAndCancelledContext(t *testing.T) {
	cred, pub := exampleCredential(t, issuerDID, nil)
	v := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier())
	if _, err := v.VerifySignerAuthenticity(context.Background(), nil); err == nil {
		t.Error("nil credential: want an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifySignerAuthenticity(ctx, cred); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: err = %v, want context.Canceled", err)
	}
}

// Credential reads the wire under the strict decoder, as PipelinePassCredential
// does.
func TestCredential_UnmarshalJSON_Strict(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate member": `{"issuer":"a","issuer":"b"}`,
		"trailing data":    `{"issuer":"a"} {}`,
		"proof array":      `{"issuer":"a","proof":[{"type":"DataIntegrityProof"}]}`,
		"proof scalar":     `{"issuer":"a","proof":"x"}`,
		"not an object":    `["issuer"]`,
	} {
		var c vc.Credential
		if err := c.UnmarshalJSON([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCredential_Accessors(t *testing.T) {
	genuine, _ := signedCred(t)
	c := asCredential(t, genuine)

	if c.Issuer() != genuine.Issuer() {
		t.Errorf("Issuer() = %q, want %q", c.Issuer(), genuine.Issuer())
	}
	h, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	gh, err := genuine.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h != gh {
		t.Errorf("Hash() = %s, want the PipelinePassCredential's content address %s", h, gh)
	}
	if !reflect.DeepEqual(c.Proof(), genuine.Proof()) {
		t.Errorf("Proof() = %+v, want %+v", c.Proof(), genuine.Proof())
	}
	if !reflect.DeepEqual(c.Body(), genuine.Body()) {
		t.Error("Body() differs from the PipelinePassCredential's body")
	}
	if _, ok := c.Body()["proof"]; ok {
		t.Error("Body() carries the proof")
	}
	c.Body()["issuer"] = "mutated"
	if c.Issuer() != genuine.Issuer() {
		t.Error("Body() is not a copy")
	}
	raw, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	graw, err := genuine.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(graw) {
		t.Error("MarshalJSON differs from the PipelinePassCredential's wire form")
	}

	unsigned := asCredential(t, reUnmarshal(t, genuine, func(m map[string]any) { delete(m, "proof") }))
	if unsigned.Proof() != nil {
		t.Error("Proof() of an unsigned credential is not nil")
	}
}

func TestCredential_Types(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  []string
	}{
		{[]any{"VerifiableCredential", "ExampleCredential"}, []string{"VerifiableCredential", "ExampleCredential"}},
		{"ExampleCredential", []string{"ExampleCredential"}},
		{[]any{"VerifiableCredential", 7}, nil},
		{nil, nil},
		{42, nil},
	} {
		raw, err := json.Marshal(map[string]any{"type": tc.value})
		if err != nil {
			t.Fatal(err)
		}
		var c vc.Credential
		if err := c.UnmarshalJSON(raw); err != nil {
			t.Fatal(err)
		}
		if got := c.Types(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("type %v: Types() = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// Issuer and VerificationMethod are set exactly when the proof verified, as
// SuiteContract is.
func checkSignerFields(t *testing.T, got *vc.SignerAuthenticityResult, issuer, vm string) {
	t.Helper()
	if got.SuiteContract == "" {
		if got.Issuer != "" || got.VerificationMethod != "" {
			t.Errorf("Issuer, VerificationMethod = %q, %q on an unverified proof", got.Issuer, got.VerificationMethod)
		}
		return
	}
	if got.Issuer != issuer || got.VerificationMethod != vm {
		t.Errorf("Issuer, VerificationMethod = %q, %q; want %q, %q", got.Issuer, got.VerificationMethod, issuer, vm)
	}
}

// The two entry points agree under the RDFC contract and the legacy contract
// too, and report which one ran.
func TestVerifySignerAuthenticity_AgreesWithVerifyUnderEveryContract(t *testing.T) {
	signer, pub, _ := fixture(t)
	subject := vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "proc1", TransformationClaim: vc.ClaimConvert,
		InputHash: "sha256:" + repeatHex("ab"), OutputHash: "sha256:" + repeatHex("cd"),
	}
	rdfc, err := vc.NewBuilder(signer, vc.WithCryptosuite(vc.CryptosuiteEdDSARDFC2022)).BuildFirstDrop(
		issuerDID, string(keystore.KeyIDSigning), vmID, subject, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A proof without a proof-local @context, checked against a JWK-encoded
	// key, is read under the legacy contract.
	legacyBody := rdfc.Body()
	delete(legacyBody, "@context")
	legacyProof, err := vc.CreateProof(signer, issuerDID, string(keystore.KeyIDSigning), vmID, legacyBody, vc.CryptosuiteEdDSAJCS2022)
	if err != nil {
		t.Fatal(err)
	}
	legacyWire, err := parseCredential(t, legacyBody, legacyProof, nil).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var legacy vc.PipelinePassCredential
	if err := legacy.UnmarshalJSON(legacyWire); err != nil {
		t.Fatal(err)
	}
	jwkDocs := local.New()
	jwkDocs.Add(did.New(did.DocumentFields{
		Context: did.IssuedDocumentContexts(), ID: issuerDID, Controller: ownerDID,
		VerificationMethod: []did.VerificationMethod{{ID: vmID, Type: "JsonWebKey2020", Controller: issuerDID,
			PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}}},
		AssertionMethod: []string{vmID},
	}))
	jwkDocs.Add(didDoc(ownerDID, ownerDID, "", nil))

	for _, tc := range []struct {
		name string
		cred *vc.PipelinePassCredential
		r    resolver.Resolver
		want vc.SuiteContract
	}{
		{"rdfc", rdfc, resolverWith(pub, ownerDID), vc.ContractW3CEdDSARDFC2022},
		{"legacy", &legacy, jwkDocs, vc.ContractLegacyProvinEdDSAJCSInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := vc.NewVerifier(tc.r, ed25519Verifier())
			full, err := v.Verify(context.Background(), tc.cred)
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.VerifySignerAuthenticity(context.Background(), asCredential(t, tc.cred))
			if err != nil {
				t.Fatal(err)
			}
			if got.State != vc.ConfidenceVerified || full.Axes.SignerAuthenticity != vc.ConfidenceVerified {
				t.Fatalf("State = %v, Verify's SignerAuthenticity = %v; want both Verified", got.State, full.Axes.SignerAuthenticity)
			}
			if got.SuiteContract != tc.want || full.SuiteContract != tc.want {
				t.Errorf("SuiteContract = %q, Verify's = %q; want %q", got.SuiteContract, full.SuiteContract, tc.want)
			}
			checkSignerFields(t, got, issuerDID, vmID)
		})
	}
}

// An issuer object whose id is not the DID of the verification method names
// another issuer, and the proof is not its.
func TestVerifySignerAuthenticity_IssuerObjectOfAnotherDIDFails(t *testing.T) {
	cred, pub := exampleCredential(t, map[string]any{"id": ownerDID}, nil)
	res, err := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier()).VerifySignerAuthenticity(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceFailed {
		t.Errorf("State = %v, want Failed", res.State)
	}
}

// The zero Credential is unsigned and names no issuer: it fails, without a
// panic.
func TestVerifySignerAuthenticity_ZeroCredentialFails(t *testing.T) {
	_, pub := exampleCredential(t, issuerDID, nil)
	res, err := vc.NewVerifier(resolverWith(pub, ownerDID), ed25519Verifier()).VerifySignerAuthenticity(context.Background(), &vc.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != vc.ConfidenceFailed || res.SuiteContract != "" || res.Issuer != "" || res.VerificationMethod != "" {
		t.Errorf("result = %+v, want Failed with nothing set", res)
	}
}

// Verify's own axis fails a credential that names no issuer, before any
// resolution: with a bare-fragment verificationMethod and a resolver outage it
// is not indeterminate.
func TestVerify_EmptyIssuerFailsBeforeResolution(t *testing.T) {
	genuine, _ := signedCred(t)
	cred := reUnmarshal(t, genuine, func(m map[string]any) {
		delete(m, "issuer")
		m["proof"].(map[string]any)["verificationMethod"] = "#signing"
	})
	outage := erroringResolver{err: errors.New("dial tcp 203.0.113.7:443: connect: connection refused")}
	res, err := vc.NewVerifier(outage, ed25519Verifier()).Verify(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
		t.Errorf("SignerAuthenticity = %v, want Failed", res.Axes.SignerAuthenticity)
	}
}
