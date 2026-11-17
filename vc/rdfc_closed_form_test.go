package vc_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

// rdfcChain issues an origin and a successor under eddsa-rdfc-2022, the
// successor committing to its source set (the origin), with a resolver wiring
// their documents. processID is the successor's processId.
func rdfcChain(t *testing.T, processID string) (origin, child *vc.PipelinePassCredential, r *local.Resolver) {
	t.Helper()
	kpA, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	kpB, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(procAOrigin, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpA}); err != nil {
		t.Fatal(err)
	}
	if err := ks.SaveKeyPair(procBSameOrg, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpB}); err != nil {
		t.Fatal(err)
	}
	b := vc.NewBuilder(ks, vc.WithCryptosuite(vc.CryptosuiteEdDSARDFC2022))
	origin, err = b.BuildFirstDrop(procAOrigin, string(keystore.KeyIDSigning), procAOrigin+"#signing", vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "procA", TransformationClaim: vc.ClaimConvert,
		InputHash: chainFixtureInput, OutputHash: "sha256:" + repeatHex("22"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := vc.ComputeSourceRoot([]*vc.PipelinePassCredential{origin}, vc.SourceRootCanonicalJCS)
	if err != nil {
		t.Fatal(err)
	}
	child, err = b.BuildChainPreserving(procBSameOrg, string(keystore.KeyIDSigning), procBSameOrg+"#signing", vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: processID, TransformationClaim: vc.ClaimConvert,
		InputHash: "sha256:" + repeatHex("22"), OutputHash: "sha256:" + repeatHex("33"),
	}, origin, &vc.SourceCommitment{
		DerivedFrom:         []string{procAOrigin},
		SourceRoot:          root,
		SourceRootCanonical: vc.SourceRootCanonicalJCS,
	})
	if err != nil {
		t.Fatal(err)
	}
	r = local.New()
	r.Add(didDoc(procAOrigin, ownerOf(t, procAOrigin), procAOrigin+"#signing", kpA.PublicKey))
	r.Add(didDoc(procBSameOrg, ownerOf(t, procBSameOrg), procBSameOrg+"#signing", kpB.PublicKey))
	r.Add(didDoc(ownerOf(t, procAOrigin), ownerOf(t, procAOrigin), "", nil))
	return origin, child, r
}

// renameIn moves the member from to the name to in the object at m[at] (m
// itself when at is "").
func renameIn(at, from, to string) func(map[string]any) {
	return func(m map[string]any) {
		obj := m
		if at != "" {
			obj = m[at].(map[string]any)
		}
		obj[to] = obj[from]
		delete(obj, from)
	}
}

// nestIn moves the members names of credentialSubject into a @nest group.
func nestIn(names ...string) func(map[string]any) {
	return func(m map[string]any) {
		s := subjectOf(m)
		group := map[string]any{}
		for _, n := range names {
			group[n] = s[n]
			delete(s, n)
		}
		s["@nest"] = group
	}
}

// An eddsa-rdfc-2022 credential written as the profile writes it verifies,
// links and carries a source commitment that verifies.
func TestRDFCCredential_TheProfileFormVerifies(t *testing.T) {
	origin, child, r := rdfcChain(t, "procB")
	v := vc.NewVerifier(r, ed25519Verifier())
	chain := []*vc.PipelinePassCredential{origin, child}
	res, err := v.VerifyChain(context.Background(), chain)
	if err != nil {
		t.Fatal(err)
	}
	if res.Overall != vc.ConfidenceVerified || res.SuiteContract != vc.ContractW3CEdDSARDFC2022 {
		t.Fatalf("VerifyChain = %v under %s (%+v), want Verified under the RDFC contract", res.Overall, res.SuiteContract, res.Axes)
	}
	for i, c := range chain {
		if err := c.ValidateWireForm(); err != nil {
			t.Errorf("credential %d: ValidateWireForm: %v", i, err)
		}
	}
	if err := vc.ValidateChainLinks(chain); err != nil {
		t.Errorf("ValidateChainLinks: %v", err)
	}
	if err := vc.ValidateChainFrom(chain, chainFixtureInput); err != nil {
		t.Errorf("ValidateChainFrom: %v", err)
	}
	st, err := v.VerifySourceCommitment(context.Background(), child, []*vc.PipelinePassCredential{origin})
	if err != nil || st != vc.ConfidenceVerified {
		t.Errorf("VerifySourceCommitment = %v, %v; want Verified", st, err)
	}
}

// subjectTerms are the credentialSubject members vc reads, each with the
// local name of the IRI its term names under the dplaax prefix
// (vc/contexts/vc-v1.jsonld).
var subjectTerms = map[string]string{
	"pipelineId":            "pipelineId",
	"processId":             "processId",
	"transformationClaim":   "transformationClaim",
	"inputHash":             "inputHash",
	"outputHash":            "outputHash",
	"previousCredential":    "previousCredential",
	"derived_from":          "derivedFrom",
	"source_root":           "sourceRoot",
	"source_root_canonical": "sourceRootCanonical",
}

// formCase is a credential form that is not the closed form.
type formCase struct {
	name   string
	mutate func(map[string]any)
}

// formsOutsideTheClosedForm are forms of the successor of rdfcChain that are
// not its closed form: each subject member vc reads written by a compact IRI,
// by a full IRI and in a @nest group, and the other forms listed.
func formsOutsideTheClosedForm() []formCase {
	setSubject := func(name string, value any) func(map[string]any) {
		return func(m map[string]any) { subjectOf(m)[name] = value }
	}
	var cases []formCase
	for _, member := range sortedKeys(subjectTerms) {
		local := subjectTerms[member]
		cases = append(cases,
			formCase{member + " by a compact IRI", renameIn("credentialSubject", member, "dplaax:"+local)},
			formCase{member + " by a full IRI", renameIn("credentialSubject", member, "https://dplaax.dev/vocab#"+local)},
			formCase{member + " in a @nest group", nestIn(member)},
		)
	}
	return append(cases,
		formCase{"@included at the root", func(m map[string]any) {
			m["@included"] = []any{map[string]any{"type": "VerifiableCredential"}}
		}},
		formCase{"@id at the root", func(m map[string]any) { m["@id"] = "urn:example:credential" }},
		formCase{"credentialSubject as a one-element array", func(m map[string]any) {
			m["credentialSubject"] = []any{m["credentialSubject"]}
		}},
		formCase{"a string member as a one-element array", func(m map[string]any) {
			subjectOf(m)["outputHash"] = []any{subjectOf(m)["outputHash"]}
		}},
		formCase{"a string member as a value object", func(m map[string]any) {
			subjectOf(m)["outputHash"] = map[string]any{"@value": subjectOf(m)["outputHash"]}
		}},
		formCase{"derived_from as a string", setSubject("derived_from", procAOrigin)},
		formCase{"derived_from out of order", setSubject("derived_from", []any{procAOrigin, "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:a"})},
		formCase{"derived_from with a duplicate", setSubject("derived_from", []any{procAOrigin, procAOrigin})},
		formCase{"source_root without derived_from", func(m map[string]any) { delete(subjectOf(m), "derived_from") }},
		formCase{"derived_from without source_root_canonical", func(m map[string]any) { delete(subjectOf(m), "source_root_canonical") }},
		formCase{"a subject member named by an IRI", setSubject("https://example.org/extra", "x")},
		formCase{"a root member named by an IRI", func(m map[string]any) { m["https://example.org/extra"] = "x" }},
		formCase{"a root member of another term", func(m map[string]any) { m["name"] = "x" }},
		formCase{"a schema member outside id, type and contentHash", setSubject("schema", map[string]any{
			"id": "https://example.org/schema", "type": "JsonSchema", "contentHash": "sha256:" + repeatHex("44"), "dplaax:extra": "x",
		})},
	)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// An eddsa-rdfc-2022 credential holds only the members vc reads, each under
// its name and in its form. ValidateWireForm, the links (at the credential's
// position, in a chain of two and in a chain of one) and VerifyChain refuse
// any other form.
func TestRDFCCredential_MembersAreWrittenByTheirTerms(t *testing.T) {
	origin, child, r := rdfcChain(t, "procB")
	v := vc.NewVerifier(r, ed25519Verifier())
	for _, tc := range formsOutsideTheClosedForm() {
		bent := reUnmarshal(t, child, tc.mutate)
		for shape, chain := range map[string][]*vc.PipelinePassCredential{
			"two": {origin, bent},
			"one": {bent},
		} {
			t.Run(tc.name+", a chain of "+shape, func(t *testing.T) {
				at := len(chain) - 1
				if err := bent.ValidateWireForm(); err == nil {
					t.Error("ValidateWireForm accepted it")
				}
				var linkErr *vc.ChainLinkError
				if err := vc.ValidateChainLinks(chain); !errors.As(err, &linkErr) || linkErr.Index != at {
					t.Errorf("ValidateChainLinks = %v, want a *ChainLinkError at %d", err, at)
				}
				res, err := v.VerifyChain(context.Background(), chain)
				if err != nil {
					t.Fatal(err)
				}
				if res.Overall == vc.ConfidenceVerified || res.Axes.DataIntegrity != vc.ConfidenceFailed {
					t.Errorf("VerifyChain = %v (%+v), want data integrity failed", res.Overall, res.Axes)
				}
			})
		}
	}
	// ValidateChainFrom refuses an origin not in its closed form, at 0.
	bentOrigin := reUnmarshal(t, origin, renameIn("credentialSubject", "inputHash", "dplaax:inputHash"))
	var linkErr *vc.ChainLinkError
	if err := vc.ValidateChainFrom([]*vc.PipelinePassCredential{bentOrigin}, chainFixtureInput); !errors.As(err, &linkErr) || linkErr.Index != 0 {
		t.Errorf("ValidateChainFrom = %v, want a *ChainLinkError at 0", err)
	}
}

// An eddsa-rdfc-2022 credential carries the source commitment's three members
// together or not at all, at any position in a chain.
func TestRDFCCredential_CommitmentMembersComeTogether(t *testing.T) {
	origin, _, _ := rdfcChain(t, "procB")
	for name, members := range map[string]map[string]any{
		"source_root and source_root_canonical": {"source_root": "f1220" + repeatHex("0f"), "source_root_canonical": vc.SourceRootCanonicalJCS},
		"derived_from and source_root":          {"derived_from": []any{}, "source_root": "f1220" + repeatHex("0f")},
	} {
		bent := reUnmarshal(t, origin, func(m map[string]any) {
			for k, v := range members {
				subjectOf(m)[k] = v
			}
		})
		var linkErr *vc.ChainLinkError
		if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{bent}); !errors.As(err, &linkErr) || linkErr.Index != 0 {
			t.Errorf("%s alone: ValidateChainLinks = %v, want a *ChainLinkError at 0", name, err)
		}
	}
}

// VerifySourceCommitment holds an eddsa-rdfc-2022 credential to its closed
// form: one not in it is failed.
func TestRDFCCredential_SourceCommitmentIsReadInItsForm(t *testing.T) {
	origin, child, r := rdfcChain(t, "procB")
	v := vc.NewVerifier(r, ed25519Verifier())
	for _, tc := range formsOutsideTheClosedForm() {
		bent := reUnmarshal(t, child, tc.mutate)
		st, err := v.VerifySourceCommitment(context.Background(), bent, []*vc.PipelinePassCredential{origin})
		if err != nil || st != vc.ConfidenceFailed {
			t.Errorf("%s: VerifySourceCommitment = %v, %v; want Failed with no error", tc.name, st, err)
		}
	}
}

// The closed form is required of eddsa-rdfc-2022 credentials only: an
// eddsa-jcs-2022 or unsigned credential gives the results it always gave.
func TestJCSAndUnsignedCredentials_FormsAsBefore(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	strip := func(c *vc.PipelinePassCredential) *vc.PipelinePassCredential {
		return reUnmarshal(t, c, func(m map[string]any) { delete(m, "proof") })
	}
	for kind, pair := range map[string][2]*vc.PipelinePassCredential{
		"eddsa-jcs-2022": {origin, child},
		"unsigned":       {strip(origin), strip(child)},
	} {
		o, c := pair[0], pair[1]
		for name, mutate := range map[string]func(map[string]any){
			"a subject member named by an IRI": func(m map[string]any) { subjectOf(m)["https://example.org/extra"] = "x" },
			"a root member named by an IRI":    func(m map[string]any) { m["https://example.org/extra"] = "x" },
			"a root member of another term":    func(m map[string]any) { m["name"] = "x" },
		} {
			bent := reUnmarshal(t, c, mutate)
			if err := bent.ValidateWireForm(); err != nil {
				t.Errorf("%s, %s: ValidateWireForm: %v", kind, name, err)
			}
			if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{o, bent}); err != nil {
				t.Errorf("%s, %s: ValidateChainLinks: %v", kind, name, err)
			}
		}
		for _, member := range sortedKeys(subjectTerms) {
			bent := reUnmarshal(t, o, renameIn("credentialSubject", member, "dplaax:"+subjectTerms[member]))
			if err := vc.ValidateChainLinks([]*vc.PipelinePassCredential{bent}); err != nil {
				t.Errorf("%s, the origin with %s by a compact IRI: ValidateChainLinks = %v, want nil as before", kind, member, err)
			}
		}
	}
}

// eddsa-rdfc-2022 signs a string as its code points: a string in another
// Unicode normalization form is another string, and the signature does not
// verify for it.
func TestRDFCCredential_StringsAreSignedAsWritten(t *testing.T) {
	for name, pair := range map[string][2]string{
		"composed, read decomposed": {"café", "café"},
		"decomposed, read composed": {"café", "café"},
	} {
		_, child, r := rdfcChain(t, pair[0])
		other := reUnmarshal(t, child, func(m map[string]any) { subjectOf(m)["processId"] = pair[1] })
		res, err := vc.NewVerifier(r, ed25519Verifier()).Verify(context.Background(), other)
		if err != nil {
			t.Fatal(err)
		}
		if res.Axes.SignerAuthenticity != vc.ConfidenceFailed {
			t.Errorf("%s: signer authenticity %v, want Failed", name, res.Axes.SignerAuthenticity)
		}
	}
}
