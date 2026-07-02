package vc_test

import (
	"context"
	"testing"

	"github.com/provin-line/oss/crypto"
	"github.com/provin-line/oss/crypto/ed25519"
	"github.com/provin-line/oss/did/dplaax"
	"github.com/provin-line/oss/keystore"
	"github.com/provin-line/oss/resolver/local"
	"github.com/provin-line/oss/vc"
)

const (
	procAOrigin   = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:procA"
	procBSameOrg  = "did:dplaax:poc.dplaax.dev:org:acme:pipeline:p1:process:procB"
	procBOtherOrg = "did:dplaax:poc.dplaax.dev:org:beta:pipeline:p1:process:procB"
)

func ownerOf(t *testing.T, processDID string) string {
	t.Helper()
	d, err := dplaax.Parse(processDID)
	if err != nil {
		t.Fatalf("parse %q: %v", processDID, err)
	}
	return d.OwnerDID().String()
}

// buildChainFixture issues a genuine two-credential chain (origin → child) with
// distinct issuers and a resolver wiring every process and owner document.
func buildChainFixture(t *testing.T, originIssuer, childIssuer string) (origin, child *vc.PipelinePassCredential, r *local.Resolver) {
	t.Helper()
	kpA, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate A: %v", err)
	}
	kpB, err := (ed25519.Generator{}).Generate()
	if err != nil {
		t.Fatalf("Generate B: %v", err)
	}
	ks := newMemKeyStore()
	if err := ks.SaveKeyPair(originIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpA}); err != nil {
		t.Fatalf("SaveKeyPair A: %v", err)
	}
	if err := ks.SaveKeyPair(childIssuer, map[keystore.KeyID]*crypto.KeyPair{keystore.KeyIDSigning: kpB}); err != nil {
		t.Fatalf("SaveKeyPair B: %v", err)
	}
	b := vc.NewBuilder(ed25519.NewSigner(ks))

	const (
		hashIn  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		hashMid = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		hashOut = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	)
	subjA := vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "procA",
		TransformationClaim: vc.ClaimConvert,
		InputHash:           hashIn, OutputHash: hashMid,
	}
	origin, err = b.BuildFirstDrop(originIssuer, string(keystore.KeyIDSigning), originIssuer+"#signing", subjA, nil)
	if err != nil {
		t.Fatalf("BuildFirstDrop: %v", err)
	}
	subjB := vc.CredentialSubjectFields{
		PipelineID: "p1", ProcessID: "procB",
		TransformationClaim: vc.ClaimConvert,
		InputHash:           hashMid, OutputHash: hashOut, // inputHash == origin.outputHash
	}
	child, err = b.BuildChainPreserving(childIssuer, string(keystore.KeyIDSigning), childIssuer+"#signing", subjB, origin, nil)
	if err != nil {
		t.Fatalf("BuildChainPreserving: %v", err)
	}

	r = local.New()
	r.Add(didDoc(originIssuer, ownerOf(t, originIssuer), originIssuer+"#signing", kpA.PublicKey))
	r.Add(didDoc(childIssuer, ownerOf(t, childIssuer), childIssuer+"#signing", kpB.PublicKey))
	r.Add(didDoc(ownerOf(t, originIssuer), ownerOf(t, originIssuer), "", nil))
	r.Add(didDoc(ownerOf(t, childIssuer), ownerOf(t, childIssuer), "", nil))
	return origin, child, r
}

func TestVerifyChain_GenuineTwoHop_Verified(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Overall != vc.ConfidenceVerified {
		t.Errorf("Overall=%v, want Verified; axes=%+v", res.Overall, res.Axes)
	}
}

func TestVerifyChain_Empty_Errors(t *testing.T) {
	v := vc.NewVerifier(local.New(), ed25519Verifier())
	if _, err := v.VerifyChain(context.Background(), nil); err == nil {
		t.Error("VerifyChain on an empty chain: want error")
	}
}

func TestVerifyChain_BrokenLinkage_DataIntegrityFails(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	forged := reUnmarshal(t, child, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["previousCredential"] = "sha256:deadbeef" // not origin's content address
	})
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, forged})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (broken previousCredential linkage)", res.Axes.DataIntegrity)
	}
}

func TestVerifyChain_DataFlowMismatch_DataIntegrityFails(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	forged := reUnmarshal(t, child, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["inputHash"] = "sha256:WRONG" // != origin.outputHash
	})
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, forged})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (outputHash[n] != inputHash[n+1])", res.Axes.DataIntegrity)
	}
}

func TestVerifyChain_OrderingViolation_ChainConsistencyFails(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	// Force the child's proof.created to precede the origin's.
	forged := reUnmarshal(t, child, func(m map[string]any) {
		m["proof"].(map[string]any)["created"] = "2000-01-01T00:00:00Z"
	})
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, forged})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Axes.ChainConsistency != vc.ConfidenceFailed {
		t.Errorf("ChainConsistency=%v, want Failed (created not monotonic)", res.Axes.ChainConsistency)
	}
}

func TestVerifyChain_OriginCarriesPredecessor_DataIntegrityFails(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	forgedOrigin := reUnmarshal(t, origin, func(m map[string]any) {
		subj := m["credentialSubject"].(map[string]any)
		subj["previousCredential"] = "sha256:somethingupstream"
	})
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{forgedOrigin, child})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (chain origin must carry no previousCredential)", res.Axes.DataIntegrity)
	}
}

// A deterministically malformed chain credential is a FAILED verdict, not a Go
// error that a chain walker would map to indeterminate / a transport hole.
func TestVerifyChain_MalformedSubject_FailsNotErrors(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	forged := reUnmarshal(t, child, func(m map[string]any) {
		m["credentialSubject"] = "not-an-object"
	})
	v := vc.NewVerifier(r, ed25519Verifier())

	res, err := v.VerifyChain(context.Background(), []*vc.PipelinePassCredential{origin, forged})
	if err != nil {
		t.Fatalf("VerifyChain returned an error for a deterministic malformation: %v (want a failed verdict)", err)
	}
	if res.Axes.DataIntegrity != vc.ConfidenceFailed {
		t.Errorf("DataIntegrity=%v, want Failed (malformed credentialSubject)", res.Axes.DataIntegrity)
	}
}

// ClassifyChain surfaces an unresolvable owner as an error, not a class — the
// owner cannot be attributed.
func TestClassifyChain_UnresolvableIssuer_Errors(t *testing.T) {
	origin, child, _ := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(local.New(), ed25519Verifier()) // empty resolver

	if _, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child}); err == nil {
		t.Error("ClassifyChain with an unresolvable issuer: want error")
	}
}

func TestClassifyChain_SingleCredential_Origin(t *testing.T) {
	origin, _, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	class, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin})
	if err != nil {
		t.Fatalf("ClassifyChain: %v", err)
	}
	if class != vc.ChainOrigin {
		t.Errorf("class=%v, want ChainOrigin", class)
	}
}

func TestClassifyChain_SingleOwnerDerived(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBSameOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	class, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatalf("ClassifyChain: %v", err)
	}
	if class != vc.ChainSingleOwnerDerived {
		t.Errorf("class=%v, want ChainSingleOwnerDerived (both under acme)", class)
	}
}

func TestClassifyChain_MultiOwnerDerived(t *testing.T) {
	origin, child, r := buildChainFixture(t, procAOrigin, procBOtherOrg)
	v := vc.NewVerifier(r, ed25519Verifier())

	class, err := v.ClassifyChain(context.Background(), []*vc.PipelinePassCredential{origin, child})
	if err != nil {
		t.Fatalf("ClassifyChain: %v", err)
	}
	if class != vc.ChainMultiOwnerDerived {
		t.Errorf("class=%v, want ChainMultiOwnerDerived (acme + beta)", class)
	}
}
